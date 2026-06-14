/*
 * Copyright (C) 2024 OpenKeychain contributors
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

import okhttp3.OkHttpClient;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.shadows.ShadowLog;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.util.ParcelableProxy;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Proxy;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Tests for {@link HkpKeyserverClient} search/get response parsing and error handling.
 * Uses OkHttp MockWebServer to intercept all HTTP calls — no real network I/O.
 *
 * Failure modes protected:
 * - Short queries hit the server instead of being rejected locally
 * - 404 response crashes instead of returning empty
 * - "no keys found" error body not recognized
 * - 501 not mapped to correct exception
 * - "too many" / "insufficient" error body not recognized
 * - Unknown error maps to wrong exception type
 * - 40-char fingerprint / 16-char key ID parsing broken
 * - Invalid fingerprint length silently accepted
 * - Revocation/expiry flags not parsed
 * - Date-based expiry detection broken
 * - URL-encoded UIDs not decoded; %% encoding not handled
 * - Malformed numeric field crashes the parser
 * - Armor extraction regex fails on valid keyserver response
 * - 404 on get not distinguished from other errors
 * - Missing armor block not detected
 */
@RunWith(KeychainTestRunner.class)
public class HkpKeyserverClientTest {

    private MockWebServer server;
    private HkpKeyserverClient client;
    private ParcelableProxy noProxy;

    @Before
    public void setUp() throws IOException {
        ShadowLog.stream = System.out;

        server = new MockWebServer();
        server.start();

        String baseUrl = server.url("").toString();
        // Remove trailing slash for HkpKeyserverAddress
        if (baseUrl.endsWith("/")) {
            baseUrl = baseUrl.substring(0, baseUrl.length() - 1);
        }

        HkpKeyserverAddress address = HkpKeyserverAddress.createFromUri(baseUrl);
        client = new HkpKeyserverClient(address, new OkHttpClient());

        // Create a no-proxy: null host → Proxy.NO_PROXY
        noProxy = new ParcelableProxy(null, 0, Proxy.Type.DIRECT, ParcelableProxy.PROXY_MODE_NORMAL);
    }

    @After
    public void tearDown() throws IOException {
        server.shutdown();
    }

    // ---- helpers ----

    private String readResource(String path) throws IOException {
        InputStream is = getClass().getResourceAsStream(path);
        if (is == null) throw new IOException("Resource not found: " + path);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = is.read(buf)) != -1) {
            out.write(buf, 0, n);
        }
        return out.toString("UTF-8");
    }

    private void enqueueResponse(int code, String body) {
        MockResponse response = new MockResponse().setResponseCode(code).setBody(body);
        server.enqueue(response);
    }

    private void enqueueOk(String body) {
        enqueueResponse(200, body);
    }

    // ---- search error handling ----

    @Test(expected = KeyserverClient.QueryTooShortException.class)
    public void search_queryTooShort_throwsQueryTooShortException() throws Exception {
        client.search("ab", noProxy);
    }

    @Test
    public void search_404_returnsEmptyList() throws Exception {
        enqueueResponse(404, "not found");
        ArrayList<ImportKeysListEntry> results = client.search("test", noProxy);
        assertTrue("404 should return empty list", results.isEmpty());
    }

    @Test
    public void search_noKeysFound_returnsEmptyList() throws Exception {
        enqueueResponse(500, "no keys found for query");
        ArrayList<ImportKeysListEntry> results = client.search("test", noProxy);
        assertTrue("'no keys found' body should return empty list", results.isEmpty());
    }

    @Test(expected = KeyserverClient.QueryNotImplementedException.class)
    public void search_501_throwsQueryNotImplemented() throws Exception {
        enqueueResponse(501, "Not Implemented");
        client.search("test", noProxy);
    }

    @Test(expected = KeyserverClient.TooManyResponsesException.class)
    public void search_tooMany_throwsTooManyResponses() throws Exception {
        enqueueResponse(500, "too many results for query");
        client.search("test", noProxy);
    }

    @Test(expected = KeyserverClient.QueryTooShortException.class)
    public void search_insufficient_throwsQueryTooShort() throws Exception {
        enqueueResponse(500, "insufficient search terms");
        client.search("test", noProxy);
    }

    @Test(expected = KeyserverClient.QueryTooShortOrTooManyResponsesException.class)
    public void search_genericError_throwsTooShortOrTooMany() throws Exception {
        enqueueResponse(500, "some unknown error");
        client.search("test", noProxy);
    }

    // ---- search parsing ----

    @Test
    public void search_singleKey_parsesFingerprintAndKeyId() throws Exception {
        String body = readResource("/keyserver-responses/hkp_search_single_key.txt");
        enqueueOk(body);

        ArrayList<ImportKeysListEntry> results = client.search("test", noProxy);

        assertEquals(1, results.size());
        ImportKeysListEntry entry = results.get(0);
        assertNotNull("Fingerprint should be parsed", entry.getFingerprint());
        assertEquals("Key ID should be last 16 chars of fingerprint",
                "0xaaaaaaaaaaaaaaaa", entry.getKeyIdHex());
    }

    @Test
    public void search_singleKey16Char_parsesKeyIdOnly() throws Exception {
        String body = "info:1:1\n" +
                "pub:BBBBBBBBBBBBBBBB:1:4096:1609459200::\n" +
                "uid:Test%20%3Ctest%40example.com%3E:1609459200::\n";
        enqueueOk(body);

        ArrayList<ImportKeysListEntry> results = client.search("test", noProxy);

        assertEquals(1, results.size());
        assertEquals("0xbbbbbbbbbbbbbbbb", results.get(0).getKeyIdHex());
        // Fingerprint should be null for 16-char key IDs (only key ID is set)
        assertNull("Fingerprint should be null for 16-char key ID",
                results.get(0).getFingerprint());
    }

    @Test
    public void search_wrongFingerprintLength_skipsEntry() throws Exception {
        // 8-char key ID — should be skipped (only 16 or 40 accepted)
        String body = "info:1:1\n" +
                "pub:AAAAAAAA:1:4096:1609459200::\n" +
                "uid:Test%20%3Ctest%40example.com%3E:1609459200::\n";
        enqueueOk(body);

        ArrayList<ImportKeysListEntry> results = client.search("test", noProxy);
        assertTrue("8-char key ID should be skipped", results.isEmpty());
    }

    @Test
    public void search_revokedFlag_setsRevoked() throws Exception {
        String body = readResource("/keyserver-responses/hkp_search_revoked_expired.txt");
        enqueueOk(body);

        ArrayList<ImportKeysListEntry> results = client.search("test", noProxy);

        assertEquals(1, results.size());
        assertTrue("Revoked flag 'r' should be parsed", results.get(0).isRevoked());
    }

    @Test
    public void search_expiredFlag_setsExpired() throws Exception {
        String body = readResource("/keyserver-responses/hkp_search_revoked_expired.txt");
        enqueueOk(body);

        ArrayList<ImportKeysListEntry> results = client.search("test", noProxy);

        assertEquals(1, results.size());
        assertTrue("Expired flag 'e' should be parsed", results.get(0).isExpired());
    }

    @Test
    public void search_expiredByDate_setsExpired() throws Exception {
        // Key with no 'e' flag but past expiration date (epoch 1 = Jan 1 1970)
        String body = "info:1:1\n" +
                "pub:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1:4096:1609459200:1:\n" +
                "uid:Old%20%3Cold%40example.com%3E:1609459200::\n";
        enqueueOk(body);

        ArrayList<ImportKeysListEntry> results = client.search("test", noProxy);

        assertEquals(1, results.size());
        assertTrue("Past expiration date should mark key as expired", results.get(0).isExpired());
    }

    @Test
    public void search_multipleKeys_parsesAll() throws Exception {
        String body = readResource("/keyserver-responses/hkp_search_multiple_keys.txt");
        enqueueOk(body);

        ArrayList<ImportKeysListEntry> results = client.search("test", noProxy);

        assertEquals("All 3 keys should be parsed", 3, results.size());
    }

    @Test
    public void search_multipleKeys_correctFlags() throws Exception {
        String body = readResource("/keyserver-responses/hkp_search_multiple_keys.txt");
        enqueueOk(body);

        ArrayList<ImportKeysListEntry> results = client.search("test", noProxy);

        // First key: no flags
        assertFalse(results.get(0).isRevoked());
        assertFalse(results.get(0).isExpired());

        // Second key: expired
        assertTrue("Second key should be expired", results.get(1).isExpired());

        // Third key: revoked
        assertTrue("Third key should be revoked", results.get(2).isRevoked());
    }

    @Test
    public void search_percentEncodedUid_decodesCorrectly() throws Exception {
        String body = readResource("/keyserver-responses/hkp_search_percent_encoded_uid.txt");
        enqueueOk(body);

        ArrayList<ImportKeysListEntry> results = client.search("test", noProxy);

        assertEquals(1, results.size());
        List<String> uids = results.get(0).getUserIds();
        assertTrue("Percent-encoded UID should be decoded",
                uids.get(0).contains("Universität"));
    }

    @Test
    public void search_doublePercent_decodesAsLiteralPercent() throws Exception {
        String body = readResource("/keyserver-responses/hkp_search_percent_encoded_uid.txt");
        enqueueOk(body);

        ArrayList<ImportKeysListEntry> results = client.search("test", noProxy);

        List<String> uids = results.get(0).getUserIds();
        assertTrue("Double percent should decode as literal percent",
                uids.get(1).contains("100%"));
    }

    @Test
    public void search_brokenNumberFormat_skipsEntry() throws Exception {
        // bitSize is "abcd" — should skip the entry
        String body = "info:1:1\n" +
                "pub:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1:abcd:1609459200::\n" +
                "uid:Test%20%3Ctest%40example.com%3E:1609459200::\n";
        enqueueOk(body);

        ArrayList<ImportKeysListEntry> results = client.search("test", noProxy);
        assertTrue("Entry with broken numeric field should be skipped", results.isEmpty());
    }

    @Test
    public void search_setsQueryOnEntries() throws Exception {
        String body = readResource("/keyserver-responses/hkp_search_single_key.txt");
        enqueueOk(body);

        ArrayList<ImportKeysListEntry> results = client.search("myquery", noProxy);
        assertEquals("myquery", results.get(0).getQuery());
    }

    @Test
    public void search_setsKeyserverOnEntries() throws Exception {
        String body = readResource("/keyserver-responses/hkp_search_single_key.txt");
        enqueueOk(body);

        ArrayList<ImportKeysListEntry> results = client.search("test", noProxy);
        assertNotNull(results.get(0).getKeyserver());
    }

    // ---- get() tests ----

    @Test
    public void get_validResponse_extractsArmoredKey() throws Exception {
        String body = readResource("/keyserver-responses/hkp_get_armored_key.txt");
        enqueueOk(body);

        String armoredKey = client.get("0xaaaaaaaaaaaaaaaa", noProxy);

        assertNotNull(armoredKey);
        assertTrue("Extracted key should start with PGP header",
                armoredKey.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
        assertTrue("Extracted key should end with PGP footer",
                armoredKey.contains("-----END PGP PUBLIC KEY BLOCK-----"));
    }

    @Test(expected = KeyserverClient.QueryNotFoundException.class)
    public void get_404_throwsQueryNotFound() throws Exception {
        enqueueResponse(404, "not found");
        client.get("0xaaaaaaaaaaaaaaaa", noProxy);
    }

    @Test(expected = KeyserverClient.QueryFailedException.class)
    public void get_noArmoredBlock_throwsQueryFailed() throws Exception {
        enqueueOk("This is not a PGP key block at all.");
        client.get("0xaaaaaaaaaaaaaaaa", noProxy);
    }

    @Test(expected = KeyserverClient.QueryFailedException.class)
    public void get_serverError_throwsQueryFailed() throws Exception {
        enqueueResponse(500, "Internal Server Error");
        client.get("0xaaaaaaaaaaaaaaaa", noProxy);
    }

    // ---- request verification ----

    @Test
    public void search_sendsCorrectQueryParams() throws Exception {
        String body = readResource("/keyserver-responses/hkp_search_no_keys.txt");
        enqueueOk(body);

        client.search("alice@example.com", noProxy);

        RecordedRequest request = server.takeRequest();
        String path = request.getPath();
        assertTrue("Should query lookup endpoint", path.contains("/pks/lookup"));
        assertTrue("Should include op=index", path.contains("op=index"));
        assertTrue("Should include options=mr", path.contains("options=mr"));
        assertTrue("Should include search param", path.contains("search=alice"));
    }

    @Test
    public void get_sendsCorrectQueryParams() throws Exception {
        String body = readResource("/keyserver-responses/hkp_get_armored_key.txt");
        enqueueOk(body);

        client.get("0xAAAAAAAAAAAAAAAA", noProxy);

        RecordedRequest request = server.takeRequest();
        String path = request.getPath();
        assertTrue("Should query lookup endpoint", path.contains("/pks/lookup"));
        assertTrue("Should include op=get", path.contains("op=get"));
        assertTrue("Should include search param with key ID",
                path.contains("search=0xAAAAAAAAAAAAAAAA"));
    }
}
