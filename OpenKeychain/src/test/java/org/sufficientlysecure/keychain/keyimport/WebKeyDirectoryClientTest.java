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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.shadows.ShadowLog;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.pgp.UncachedKeyRing;
import org.sufficientlysecure.keychain.util.ParcelableProxy;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.Proxy;
import java.security.Security;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Tests for {@link WebKeyDirectoryClient} key parsing, unsupported operations,
 * and edge-case input handling.
 *
 * Failure modes protected:
 * - Non-email input crashes the client instead of returning empty
 * - Corrupt WKD response accepted as valid key
 * - get() silently returns data instead of rejecting
 * - add() silently accepts upload instead of rejecting
 * - Zero-byte WKD response treated as valid
 * - Valid WKD binary key not parsed into entry
 */
@RunWith(KeychainTestRunner.class)
public class WebKeyDirectoryClientTest {

    private WebKeyDirectoryClient client;
    private ParcelableProxy noProxy;

    @BeforeClass
    public static void setUpOnce() {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }

    @Before
    public void setUp() {
        ShadowLog.stream = System.out;
        client = WebKeyDirectoryClient.getInstance();
        noProxy = new ParcelableProxy(null, 0, Proxy.Type.DIRECT, ParcelableProxy.PROXY_MODE_NORMAL);
    }

    // ---- helpers ----

    private byte[] readResourceBytes(String path) throws Exception {
        InputStream is = getClass().getResourceAsStream(path);
        if (is == null) throw new Exception("Resource not found: " + path);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = is.read(buf)) != -1) {
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }

    // ---- search with invalid name ----

    @Test
    public void search_invalidName_returnsEmptyList() throws Exception {
        // "not-an-email" is not a valid WKD name — should return empty without HTTP
        List<ImportKeysListEntry> results = client.search("not-an-email", noProxy);
        assertTrue("Non-email input should return empty list", results.isEmpty());
    }

    @Test
    public void search_emptyString_returnsEmptyList() throws Exception {
        List<ImportKeysListEntry> results = client.search("", noProxy);
        assertTrue("Empty string should return empty list", results.isEmpty());
    }

    @Test
    public void search_nullLike_returnsEmptyList() throws Exception {
        // A string with no @ sign — WKD URL util returns null
        List<ImportKeysListEntry> results = client.search("noemailhere", noProxy);
        assertTrue("String without @ should return empty list", results.isEmpty());
    }

    // ---- unsupported operations ----

    @Test(expected = UnsupportedOperationException.class)
    public void get_throwsUnsupportedOperation() {
        client.get("test", noProxy);
    }

    @Test(expected = UnsupportedOperationException.class)
    public void add_throwsUnsupportedOperation() {
        client.add("armored key", noProxy);
    }

    // ---- parseKeyData tests ----

    @Test(expected = KeyserverClient.QueryFailedException.class)
    public void parseKeyData_emptyBytes_throwsQueryFailed() throws Exception {
        client.parseKeyData(new byte[0]);
    }

    @Test(expected = KeyserverClient.QueryFailedException.class)
    public void parseKeyData_garbageBytes_throwsQueryFailed() throws Exception {
        client.parseKeyData(new byte[]{0x01, 0x02, 0x03, 0x04, 0x05});
    }

    @Test(expected = KeyserverClient.QueryFailedException.class)
    public void parseKeyData_nullBytes_throwsQueryFailed() throws Exception {
        client.parseKeyData(null);
    }

    @Test
    public void parseKeyData_validKeyBytes_returnsSingleEntry() throws Exception {
        // Load a real public key from test resources
        byte[] keyBytes = readResourceBytes("/test-keys/eddsa-sample-1-pub.asc");

        List<ImportKeysListEntry> results = client.parseKeyData(keyBytes);

        assertEquals("Valid key should produce exactly one entry", 1, results.size());
        ImportKeysListEntry entry = results.get(0);
        assertNotNull("Entry should have fingerprint", entry.getFingerprint());
        assertNotNull("Entry should have ParcelableKeyRing", entry.getParcelableKeyRing());
    }

    @Test
    public void parseKeyData_validKeyBytes_correctUserId() throws Exception {
        byte[] keyBytes = readResourceBytes("/test-keys/eddsa-sample-1-pub.asc");

        List<ImportKeysListEntry> results = client.parseKeyData(keyBytes);

        ImportKeysListEntry entry = results.get(0);
        // The eddsa-sample-1 key has "EdDSA sample key 1" as user ID
        assertTrue("Entry should contain expected user ID",
                entry.getUserIds().stream()
                        .anyMatch(uid -> uid.contains("EdDSA sample key 1")));
    }

    @Test
    public void parseKeyData_validKeyBytes_isSecure() throws Exception {
        byte[] keyBytes = readResourceBytes("/test-keys/eddsa-sample-1-pub.asc");

        List<ImportKeysListEntry> results = client.parseKeyData(keyBytes);

        assertTrue("Imported key should be marked secure",
                results.get(0).isSecure());
    }

    @Test
    public void parseKeyData_binaryKeyBytes_returnsSingleEntry() throws Exception {
        // Load key, get its binary (non-armored) form, then parse
        byte[] armoredBytes = readResourceBytes("/test-keys/eddsa-sample-1-pub.asc");
        UncachedKeyRing ring = UncachedKeyRing.decodeFromData(armoredBytes);
        byte[] binaryBytes = ring.getEncoded();

        List<ImportKeysListEntry> results = client.parseKeyData(binaryBytes);

        assertEquals("Binary key data should produce one entry", 1, results.size());
        assertNotNull(results.get(0).getFingerprint());
    }
}
