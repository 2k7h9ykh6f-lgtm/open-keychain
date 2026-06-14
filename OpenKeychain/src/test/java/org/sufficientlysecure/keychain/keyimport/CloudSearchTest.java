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

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.robolectric.shadows.ShadowLog;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.util.ParcelableProxy;

import java.net.Proxy;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link CloudSearch} multi-source orchestration logic.
 * Uses Mockito mocks of {@link KeyserverClient} to avoid real network I/O.
 *
 * Failure modes protected:
 * - All sources disabled returns empty instead of error
 * - Basic single-source path broken
 * - Results from multiple sources not combined
 * - Same key from two sources creates duplicate entries
 * - All-source failure returns empty instead of propagating error
 * - Partial failure with some results incorrectly throws
 * - Partial failure with no results silently returns empty
 */
@RunWith(KeychainTestRunner.class)
public class CloudSearchTest {

    private ParcelableProxy noProxy;

    @Before
    public void setUp() {
        ShadowLog.stream = System.out;
        noProxy = new ParcelableProxy(null, 0, Proxy.Type.DIRECT, ParcelableProxy.PROXY_MODE_NORMAL);
    }

    // ---- helpers ----

    private ImportKeysListEntry makeEntry(byte[] fingerprint, String uid) {
        ImportKeysListEntry entry = new ImportKeysListEntry();
        entry.setFingerprint(fingerprint);
        entry.setSecure(true);
        ArrayList<String> userIds = new ArrayList<>();
        userIds.add(uid);
        entry.setUserIds(userIds);
        return entry;
    }

    private KeyserverClient mockClient(String name) {
        return Mockito.mock(KeyserverClient.class, name);
    }

    // ---- tests ----

    @Test(expected = KeyserverClient.QueryNoEnabledSourceException.class)
    public void search_noServersEnabled_throwsQueryNoEnabledSource() throws Exception {
        List<KeyserverClient> emptyServers = Collections.emptyList();
        CloudSearch.searchWithClients("test", noProxy, emptyServers);
    }

    @Test
    public void search_singleServerReturnsResults_returnsResults() throws Exception {
        byte[] fp = new byte[20];
        java.util.Arrays.fill(fp, (byte) 0xAA);

        KeyserverClient client = mockClient("singleServer");
        ArrayList<ImportKeysListEntry> serverResults = new ArrayList<>();
        serverResults.add(makeEntry(fp, "Alice <alice@test.com>"));
        when(client.search(eq("test"), any(ParcelableProxy.class))).thenReturn(serverResults);

        ArrayList<ImportKeysListEntry> results =
                CloudSearch.searchWithClients("test", noProxy, Collections.singletonList(client));

        assertEquals(1, results.size());
        assertTrue(results.get(0).getUserIds().contains("Alice <alice@test.com>"));
    }

    @Test
    public void search_multipleServersMergeResults() throws Exception {
        byte[] fpA = new byte[20];
        byte[] fpB = new byte[20];
        java.util.Arrays.fill(fpA, (byte) 0xAA);
        java.util.Arrays.fill(fpB, (byte) 0xBB);

        KeyserverClient client1 = mockClient("server1");
        KeyserverClient client2 = mockClient("server2");

        ArrayList<ImportKeysListEntry> results1 = new ArrayList<>();
        results1.add(makeEntry(fpA, "Alice <alice@test.com>"));
        when(client1.search(eq("test"), any(ParcelableProxy.class))).thenReturn(results1);

        ArrayList<ImportKeysListEntry> results2 = new ArrayList<>();
        results2.add(makeEntry(fpB, "Bob <bob@test.com>"));
        when(client2.search(eq("test"), any(ParcelableProxy.class))).thenReturn(results2);

        List<KeyserverClient> clients = Arrays.asList(client1, client2);
        ArrayList<ImportKeysListEntry> results =
                CloudSearch.searchWithClients("test", noProxy, clients);

        assertEquals("Results from both servers should be merged", 2, results.size());
    }

    @Test
    public void search_duplicateKeysAcrossServers_merged() throws Exception {
        byte[] fp = new byte[20];
        java.util.Arrays.fill(fp, (byte) 0xAA);

        KeyserverClient client1 = mockClient("server1");
        KeyserverClient client2 = mockClient("server2");

        ArrayList<ImportKeysListEntry> results1 = new ArrayList<>();
        results1.add(makeEntry(fp, "Alice <alice@test.com>"));
        when(client1.search(eq("test"), any(ParcelableProxy.class))).thenReturn(results1);

        ArrayList<ImportKeysListEntry> results2 = new ArrayList<>();
        results2.add(makeEntry(fp, "Alice <alice@work.com>"));
        when(client2.search(eq("test"), any(ParcelableProxy.class))).thenReturn(results2);

        List<KeyserverClient> clients = Arrays.asList(client1, client2);
        ArrayList<ImportKeysListEntry> results =
                CloudSearch.searchWithClients("test", noProxy, clients);

        assertEquals("Same key from two sources should be merged into one entry",
                1, results.size());
        assertTrue("Merged entry should have UIDs from both sources",
                results.get(0).getUserIds().size() >= 2);
    }

    @Test
    public void search_allServersFail_throwsFirstException() throws Exception {
        KeyserverClient client1 = mockClient("server1");
        KeyserverClient client2 = mockClient("server2");

        when(client1.search(eq("test"), any(ParcelableProxy.class)))
                .thenThrow(new KeyserverClient.QueryFailedException("server1 failed"));
        when(client2.search(eq("test"), any(ParcelableProxy.class)))
                .thenThrow(new KeyserverClient.QueryFailedException("server2 failed"));

        List<KeyserverClient> clients = Arrays.asList(client1, client2);

        try {
            CloudSearch.searchWithClients("test", noProxy, clients);
            fail("Should have thrown CloudSearchFailureException");
        } catch (KeyserverClient.CloudSearchFailureException e) {
            // Expected — should throw one of the exceptions
            assertTrue("Should be a QueryFailedException",
                    e instanceof KeyserverClient.QueryFailedException);
        }
    }

    @Test
    public void search_partialFailureWithResults_returnsResults() throws Exception {
        byte[] fp = new byte[20];
        java.util.Arrays.fill(fp, (byte) 0xAA);

        KeyserverClient workingClient = mockClient("workingServer");
        KeyserverClient failingClient = mockClient("failingServer");

        ArrayList<ImportKeysListEntry> results1 = new ArrayList<>();
        results1.add(makeEntry(fp, "Alice <alice@test.com>"));
        when(workingClient.search(eq("test"), any(ParcelableProxy.class))).thenReturn(results1);

        when(failingClient.search(eq("test"), any(ParcelableProxy.class)))
                .thenThrow(new KeyserverClient.QueryFailedException("server failed"));

        List<KeyserverClient> clients = Arrays.asList(workingClient, failingClient);

        // Should NOT throw — partial failure with results should return results
        ArrayList<ImportKeysListEntry> results =
                CloudSearch.searchWithClients("test", noProxy, clients);

        assertFalse("Partial failure with results should return non-empty list",
                results.isEmpty());
        assertEquals(1, results.size());
    }

    @Test
    public void search_partialFailureNoResults_throwsException() throws Exception {
        KeyserverClient failingClient = mockClient("failingServer");
        KeyserverClient emptyClient = mockClient("emptyServer");

        when(failingClient.search(eq("test"), any(ParcelableProxy.class)))
                .thenThrow(new KeyserverClient.QueryFailedException("server failed"));
        when(emptyClient.search(eq("test"), any(ParcelableProxy.class)))
                .thenReturn(new ArrayList<>());

        List<KeyserverClient> clients = Arrays.asList(failingClient, emptyClient);

        try {
            CloudSearch.searchWithClients("test", noProxy, clients);
            fail("Should have thrown CloudSearchFailureException when all results empty");
        } catch (KeyserverClient.CloudSearchFailureException e) {
            // Expected
            assertTrue(e instanceof KeyserverClient.QueryFailedException);
        }
    }
}
