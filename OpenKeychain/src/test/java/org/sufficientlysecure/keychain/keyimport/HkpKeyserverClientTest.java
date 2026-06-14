/*
 * Copyright (C) 2017 Schürmann & Breitmoser GbR
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.sufficientlysecure.keychain.keyimport;


import java.util.List;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.shadows.ShadowLog;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.util.ParcelableProxy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Tests for {@link HkpKeyserverClient} that drive the HKP machine-readable index parser and the
 * HTTP error mapping against a loopback {@link MockWebServer}. No request ever leaves the machine:
 * the client is pointed at 127.0.0.1 and every response is canned.
 *
 * <p>The HKP index format is parsed with hand-written regular expressions, which is exactly the kind
 * of code that rots on unusual but legal server output. Each test pins down one such case so that a
 * regression surfaces here instead of in the field.
 */
@RunWith(KeychainTestRunner.class)
public class HkpKeyserverClientTest {

    /** 40 hex chars (a full v4 fingerprint) so the fingerprint branch of the parser is exercised. */
    private static final String FINGERPRINT = "0000000000000000000000000000000000000001";

    private MockWebServer server;
    private HkpKeyserverClient client;
    private final ParcelableProxy noProxy = ParcelableProxy.getForNoProxy();

    @Before
    public void setUp() throws Exception {
        ShadowLog.stream = System.out;
        server = new MockWebServer();
        server.start();
        client = clientFor(server);
    }

    @After
    public void tearDown() throws Exception {
        server.shutdown();
    }

    private static HkpKeyserverClient clientFor(MockWebServer mockWebServer) {
        String url = "http://" + mockWebServer.getHostName() + ":" + mockWebServer.getPort();
        return HkpKeyserverClient.fromHkpKeyserverAddress(HkpKeyserverAddress.createFromUri(url));
    }

    private void enqueue(int code, String body) {
        server.enqueue(new MockResponse().setResponseCode(code).setBody(body));
    }

    // ------------------------------------------------------------------------------------------
    // search(): guards before the network
    // ------------------------------------------------------------------------------------------

    /**
     * Protects against: a too-short query being sent to the server (wasteful and rejected anyway).
     * It must be stopped locally with a QueryTooShortException before any request is made.
     */
    @Test(expected = KeyserverClient.QueryTooShortException.class)
    public void search_queryShorterThanThreeChars_throwsQueryTooShort() throws Exception {
        client.search("ab", noProxy);
    }

    // ------------------------------------------------------------------------------------------
    // search(): empty results
    // ------------------------------------------------------------------------------------------

    /**
     * Protects against: a 404 ("no such key") being turned into an error instead of an empty result.
     */
    @Test
    public void search_notFound404_returnsEmptyList() throws Exception {
        enqueue(404, "");

        List<ImportKeysListEntry> results = client.search("nobody", noProxy);

        assertNotNull(results);
        assertTrue("404 from keyserver must mean 'no results', not an error", results.isEmpty());
    }

    /**
     * Protects against: servers that signal "nothing found" in the body (with a non-404 status)
     * being treated as an error. The "no keys found" marker must yield an empty result.
     */
    @Test
    public void search_noKeysFoundInBody_returnsEmptyList() throws Exception {
        enqueue(500, "No keys found");

        List<ImportKeysListEntry> results = client.search("nobody", noProxy);

        assertTrue(results.isEmpty());
    }

    // ------------------------------------------------------------------------------------------
    // search(): successful parsing
    // ------------------------------------------------------------------------------------------

    /**
     * Protects against: the happy path breaking. A standard index response must yield one entry with
     * its fingerprint, derived key id and user id populated. This anchors the negative cases below.
     */
    @Test
    public void search_validIndex_parsesEntry() throws Exception {
        enqueue(200, "info:1:1\n"
                + "pub:" + FINGERPRINT + ":1:4096:1136073600::\n"
                + "uid:Alice <alice@example.com>\n");

        List<ImportKeysListEntry> results = client.search("alice", noProxy);

        assertEquals(1, results.size());
        ImportKeysListEntry entry = results.get(0);
        assertEquals("fingerprint must decode to 20 bytes", 20, entry.getFingerprint().length);
        assertEquals("0x0000000000000001", entry.getKeyIdHex());
        assertEquals(1, entry.getUserIds().size());
        assertTrue(entry.getUserIds().contains("Alice <alice@example.com>"));
        assertTrue("a key with no flags and no past expiry must not be revoked", !entry.isRevoked());
        assertTrue("a key with no flags and no past expiry must not be expired", !entry.isExpired());
    }

    /**
     * Protects against: duplicate user-id lines from a server multiplying in the UI. The raw list
     * keeps what the server sent, but the merged/sorted view must collapse identical ids to one.
     */
    @Test
    public void search_duplicateUserIdLines_collapseInMergedView() throws Exception {
        enqueue(200, "info:1:1\n"
                + "pub:" + FINGERPRINT + ":1:4096:1136073600::\n"
                + "uid:Alice <alice@example.com>\n"
                + "uid:Alice <alice@example.com>\n");

        List<ImportKeysListEntry> results = client.search("alice", noProxy);

        assertEquals(1, results.size());
        assertEquals("merged/sorted view must collapse duplicate user ids",
                1, results.get(0).getSortedUserIds().size());
    }

    /**
     * Protects against: the "revoked" flag (r) in the index being dropped, so a revoked key would
     * look usable.
     */
    @Test
    public void search_revokedFlag_marksEntryRevoked() throws Exception {
        enqueue(200, "info:1:1\n"
                + "pub:" + FINGERPRINT + ":1:4096:1136073600::r\n"
                + "uid:Alice <alice@example.com>\n");

        List<ImportKeysListEntry> results = client.search("alice", noProxy);

        assertEquals(1, results.size());
        assertTrue("the 'r' flag must mark the entry revoked", results.get(0).isRevoked());
    }

    /**
     * Protects against: the "expired" flag (e) in the index being dropped.
     */
    @Test
    public void search_expiredFlag_marksEntryExpired() throws Exception {
        enqueue(200, "info:1:1\n"
                + "pub:" + FINGERPRINT + ":1:4096:1136073600::e\n"
                + "uid:Alice <alice@example.com>\n");

        List<ImportKeysListEntry> results = client.search("alice", noProxy);

        assertEquals(1, results.size());
        assertTrue("the 'e' flag must mark the entry expired", results.get(0).isExpired());
    }

    /**
     * Protects against: a key whose expiry date is in the past but which carries no 'e' flag being
     * shown as valid. The client must compute expiry from the date, not trust the flag alone.
     */
    @Test
    public void search_pastExpiryWithoutFlag_marksEntryExpired() throws Exception {
        // creation 2006-01-01, expiry 2007-01-01 (both well in the past), no flags.
        enqueue(200, "info:1:1\n"
                + "pub:" + FINGERPRINT + ":1:4096:1136073600:1167609600:\n"
                + "uid:Alice <alice@example.com>\n");

        List<ImportKeysListEntry> results = client.search("alice", noProxy);

        assertEquals(1, results.size());
        assertTrue("a past expiry date must mark the entry expired even without the 'e' flag",
                results.get(0).isExpired());
    }

    /**
     * Protects against: a malformed key id (neither a 16-digit key id nor a 40-digit fingerprint)
     * crashing the parse or producing a bogus entry. Such a record must be skipped.
     */
    @Test
    public void search_malformedKeyIdLength_skipsRecord() throws Exception {
        enqueue(200, "info:1:1\n"
                + "pub:1234567890:1:4096:1136073600::\n"
                + "uid:Mallory <mallory@example.com>\n");

        List<ImportKeysListEntry> results = client.search("mallory", noProxy);

        assertTrue("a record with an unusable key id must be skipped, leaving no results",
                results.isEmpty());
    }

    // ------------------------------------------------------------------------------------------
    // search(): error / network-failure mapping
    // ------------------------------------------------------------------------------------------

    /**
     * Protects against: a "too many responses" server message being swallowed instead of surfaced as
     * the dedicated repairable error the UI reacts to.
     */
    @Test(expected = KeyserverClient.TooManyResponsesException.class)
    public void search_tooManyResponsesBody_throwsTooMany() throws Exception {
        enqueue(500, "Too many responses, please refine your search");
        client.search("common", noProxy);
    }

    /**
     * Protects against: an "insufficient"/too-short server message being mis-mapped. It must become a
     * QueryTooShortException.
     */
    @Test(expected = KeyserverClient.QueryTooShortException.class)
    public void search_insufficientBody_throwsQueryTooShort() throws Exception {
        enqueue(500, "Insufficient specificity in search");
        client.search("common", noProxy);
    }

    /**
     * Protects against: a 501 (search not implemented) being reported as a generic failure rather
     * than the specific "not implemented" error.
     */
    @Test(expected = KeyserverClient.QueryNotImplementedException.class)
    public void search_notImplemented501_throwsNotImplemented() throws Exception {
        enqueue(501, "");
        client.search("alice", noProxy);
    }

    /**
     * Protects against: an unclassified server error losing its "repairable" nature. A 5xx with no
     * recognised marker must map to the too-short-or-too-many repair hint.
     */
    @Test(expected = KeyserverClient.QueryTooShortOrTooManyResponsesException.class)
    public void search_unclassifiedServerError_throwsRepairableError() throws Exception {
        enqueue(500, "Internal Server Error");
        client.search("alice", noProxy);
    }

    /**
     * Protects against: a connection failure (server unreachable) being turned into a crash or a
     * silent empty result. It must surface as a QueryFailedException with a network message.
     */
    @Test
    public void search_connectionRefused_throwsQueryFailed() throws Exception {
        MockWebServer dead = new MockWebServer();
        dead.start();
        HkpKeyserverClient deadClient = clientFor(dead);
        dead.shutdown(); // nothing is listening on that port any more

        try {
            deadClient.search("alice", noProxy);
            fail("a connection failure must raise QueryFailedException");
        } catch (KeyserverClient.QueryFailedException expected) {
            // expected
        }
    }

    // ------------------------------------------------------------------------------------------
    // get(): key download by id
    // ------------------------------------------------------------------------------------------

    /**
     * Protects against: a 404 on key download being reported as a generic failure instead of the
     * specific "not found" error.
     */
    @Test(expected = KeyserverClient.QueryNotFoundException.class)
    public void get_notFound404_throwsQueryNotFound() throws Exception {
        enqueue(404, "");
        client.get("0x0000000000000001", noProxy);
    }

    /**
     * Protects against: the armored-block extraction breaking. A successful download must return the
     * PGP public key block carved out of the response body.
     */
    @Test
    public void get_success_returnsArmoredBlock() throws Exception {
        String armored = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
                + "\n"
                + "mDummyBodyDoesNotNeedToParseForExtraction\n"
                + "-----END PGP PUBLIC KEY BLOCK-----";
        enqueue(200, "Here is your key:\n" + armored + "\nthanks");

        String result = client.get("0x0000000000000001", noProxy);

        assertNotNull(result);
        assertTrue("must return the BEGIN line of the key block", result.startsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
        assertTrue("must return the END line of the key block", result.trim().endsWith("-----END PGP PUBLIC KEY BLOCK-----"));
    }
}
