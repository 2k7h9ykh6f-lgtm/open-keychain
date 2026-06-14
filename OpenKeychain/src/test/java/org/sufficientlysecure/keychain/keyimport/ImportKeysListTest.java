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
import org.robolectric.shadows.ShadowLog;
import org.sufficientlysecure.keychain.KeychainTestRunner;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Tests for {@link ImportKeysList} dedup-merge logic, identity comparison,
 * and supplier synchronization.
 *
 * Failure modes protected:
 * - Duplicate key from two sources creates two list entries instead of merging
 * - Distinct keys incorrectly merged
 * - Non-revoked source overwrites revoked flag from another source
 * - Non-expired source overwrites expired flag
 * - Secure source overwrites insecure flag from another source
 * - User IDs from second source are dropped during merge
 * - User ID list grows with duplicates
 * - Keyserver/fbUsername priority is inverted
 * - Primary user ID not updated when keyserver changes
 * - NPE on null fingerprint comparison
 * - Supplier countdown doesn't decrement
 * - Orchestrator never wakes from wait()
 * - Compound predicate misses edge cases
 */
@RunWith(KeychainTestRunner.class)
public class ImportKeysListTest {

    private static final byte[] FP_A = new byte[20];
    private static final byte[] FP_B = new byte[20];

    @Before
    public void setUp() {
        ShadowLog.stream = System.out;
        Arrays.fill(FP_A, (byte) 0xAA);
        Arrays.fill(FP_B, (byte) 0xBB);
    }

    // ---- helpers ----

    private ImportKeysListEntry makeEntry(byte[] fingerprint) {
        ImportKeysListEntry entry = new ImportKeysListEntry();
        entry.setFingerprint(fingerprint);
        entry.setSecure(true);
        entry.setRevoked(false);
        entry.setExpired(false);
        return entry;
    }

    private ImportKeysListEntry makeEntryWithUids(byte[] fingerprint, String... uids) {
        ImportKeysListEntry entry = makeEntry(fingerprint);
        ArrayList<String> userIds = new ArrayList<>(Arrays.asList(uids));
        entry.setUserIds(userIds);
        return entry;
    }

    // ---- addOrMerge tests ----

    @Test
    public void addOrMerge_sameFingerprint_mergesEntries() {
        ImportKeysList list = new ImportKeysList(1);

        ImportKeysListEntry first = makeEntryWithUids(FP_A, "Alice <alice@example.com>");
        ImportKeysListEntry second = makeEntryWithUids(FP_A, "Bob <bob@example.com>");

        list.add(first);
        list.add(second);

        assertEquals("Same fingerprint should merge into one entry", 1, list.size());
        assertTrue("Merged entry should have both UIDs",
                list.get(0).getUserIds().contains("Alice <alice@example.com>"));
        assertTrue("Merged entry should have both UIDs",
                list.get(0).getUserIds().contains("Bob <bob@example.com>"));
    }

    @Test
    public void addOrMerge_differentFingerprint_addsSeparately() {
        ImportKeysList list = new ImportKeysList(1);

        list.add(makeEntry(FP_A));
        list.add(makeEntry(FP_B));

        assertEquals("Different fingerprints should create separate entries", 2, list.size());
    }

    @Test
    public void mergeDupes_revokedIsSticky() {
        ImportKeysList list = new ImportKeysList(1);

        ImportKeysListEntry revoked = makeEntry(FP_A);
        revoked.setRevoked(true);

        ImportKeysListEntry notRevoked = makeEntry(FP_A);
        notRevoked.setRevoked(false);

        list.add(revoked);
        list.add(notRevoked);

        assertTrue("Revoked flag should be sticky (OR semantics)",
                list.get(0).isRevoked());
    }

    @Test
    public void mergeDupes_expiredIsSticky() {
        ImportKeysList list = new ImportKeysList(1);

        ImportKeysListEntry expired = makeEntry(FP_A);
        expired.setExpired(true);

        ImportKeysListEntry notExpired = makeEntry(FP_A);
        notExpired.setExpired(false);

        list.add(expired);
        list.add(notExpired);

        assertTrue("Expired flag should be sticky (OR semantics)",
                list.get(0).isExpired());
    }

    @Test
    public void mergeDupes_insecureIsSticky() {
        ImportKeysList list = new ImportKeysList(1);

        ImportKeysListEntry insecure = makeEntry(FP_A);
        insecure.setSecure(false);

        ImportKeysListEntry secure = makeEntry(FP_A);
        secure.setSecure(true);

        list.add(insecure);
        list.add(secure);

        assertFalse("Insecure flag should be sticky (AND semantics for secure)",
                list.get(0).isSecure());
    }

    @Test
    public void mergeDupes_combinesUserIds() {
        ImportKeysList list = new ImportKeysList(1);

        ImportKeysListEntry first = makeEntryWithUids(FP_A, "A <a@test.com>");
        ImportKeysListEntry second = makeEntryWithUids(FP_A, "B <b@test.com>");

        list.add(first);
        list.add(second);

        List<String> userIds = list.get(0).getUserIds();
        assertTrue(userIds.contains("A <a@test.com>"));
        assertTrue(userIds.contains("B <b@test.com>"));
        assertEquals(2, userIds.size());
    }

    @Test
    public void mergeDupes_duplicateUserIdsNotAdded() {
        ImportKeysList list = new ImportKeysList(1);

        ImportKeysListEntry first = makeEntryWithUids(FP_A, "A <a@test.com>", "B <b@test.com>");
        ImportKeysListEntry second = makeEntryWithUids(FP_A, "B <b@test.com>", "C <c@test.com>");

        list.add(first);
        list.add(second);

        List<String> userIds = list.get(0).getUserIds();
        assertEquals("No duplicate UIDs should be added", 3, userIds.size());
        assertTrue(userIds.contains("A <a@test.com>"));
        assertTrue(userIds.contains("B <b@test.com>"));
        assertTrue(userIds.contains("C <c@test.com>"));
    }

    @Test
    public void mergeDupes_keyserverOverwritesFbUsername() {
        ImportKeysList list = new ImportKeysList(1);

        ImportKeysListEntry fbEntry = makeEntry(FP_A);
        fbEntry.setFbUsername("alice.fb");

        ImportKeysListEntry keyserverEntry = makeEntry(FP_A);
        HkpKeyserverAddress keyserver = HkpKeyserverAddress.createFromUri("hkps://keys.example.com");
        keyserverEntry.setKeyserver(keyserver);

        list.add(fbEntry);
        list.add(keyserverEntry);

        assertEquals("Keyserver should overwrite fbUsername source",
                keyserver, list.get(0).getKeyserver());
    }

    @Test
    public void mergeDupes_primaryUserIdFollowsKeyserver() {
        ImportKeysList list = new ImportKeysList(1);

        ImportKeysListEntry first = makeEntryWithUids(FP_A, "First <first@test.com>");
        first.setPrimaryUserId("First <first@test.com>");

        ImportKeysListEntry second = makeEntryWithUids(FP_A, "Second <second@test.com>");
        HkpKeyserverAddress keyserver = HkpKeyserverAddress.createFromUri("hkps://keys.example.com");
        second.setKeyserver(keyserver);
        second.setPrimaryUserId("Second <second@test.com>");

        list.add(first);
        list.add(second);

        // When keyserver entry is merged, primary user ID should follow
        assertEquals("Primary user ID should be updated from keyserver entry",
                "Second", list.get(0).getPrimaryUserId().name);
    }

    // ---- hasSameKeyAs tests ----

    @Test
    public void hasSameKeyAs_nullFingerprint_returnsFalse() {
        ImportKeysListEntry entry = new ImportKeysListEntry();
        // fingerprint is null by default
        ImportKeysListEntry other = makeEntry(FP_A);

        assertFalse("Null fingerprint should return false, not NPE",
                entry.hasSameKeyAs(other));
    }

    @Test
    public void hasSameKeyAs_otherNullFingerprint_returnsFalse() {
        ImportKeysListEntry entry = makeEntry(FP_A);
        ImportKeysListEntry other = new ImportKeysListEntry();

        assertFalse("Other null fingerprint should return false, not NPE",
                entry.hasSameKeyAs(other));
    }

    @Test
    public void hasSameKeyAs_sameFingerprint_returnsTrue() {
        ImportKeysListEntry a = makeEntry(FP_A);
        ImportKeysListEntry b = makeEntry(FP_A.clone());

        assertTrue("Same fingerprint bytes should match", a.hasSameKeyAs(b));
    }

    @Test
    public void hasSameKeyAs_differentFingerprint_returnsFalse() {
        ImportKeysListEntry a = makeEntry(FP_A);
        ImportKeysListEntry b = makeEntry(FP_B);

        assertFalse("Different fingerprints should not match", a.hasSameKeyAs(b));
    }

    @Test
    public void hasSameKeyAs_nullOther_returnsFalse() {
        ImportKeysListEntry entry = makeEntry(FP_A);

        assertFalse("Null other entry should return false, not NPE",
                entry.hasSameKeyAs(null));
    }

    // ---- finishedAdding tests ----

    @Test
    public void finishedAdding_decrementsSupplierCount() {
        ImportKeysList list = new ImportKeysList(3);

        assertEquals(3, list.outstandingSuppliers());
        list.finishedAdding();
        assertEquals(2, list.outstandingSuppliers());
        list.finishedAdding();
        assertEquals(1, list.outstandingSuppliers());
        list.finishedAdding();
        assertEquals(0, list.outstandingSuppliers());
    }

    @Test
    public void finishedAdding_notifiesAtZero() throws InterruptedException {
        final ImportKeysList list = new ImportKeysList(1);
        final CountDownLatch latch = new CountDownLatch(1);
        final CountDownLatch waiterReady = new CountDownLatch(1);

        Thread waiter = new Thread(() -> {
            synchronized (list) {
                waiterReady.countDown();
                try {
                    list.wait(5000);
                    latch.countDown();
                } catch (InterruptedException ignored) {
                }
            }
        });
        waiter.start();

        // Wait for the waiter thread to enter the synchronized block
        assertTrue("Waiter thread should start within 2s",
                waiterReady.await(2, TimeUnit.SECONDS));

        list.finishedAdding();

        assertTrue("finishedAdding should notify waiter when count reaches zero",
                latch.await(2, TimeUnit.SECONDS));
    }

    // ---- isRevokedOrExpiredOrInsecure tests ----

    @Test
    public void isRevokedOrExpiredOrInsecure_allFalse_secure() {
        ImportKeysListEntry entry = makeEntry(FP_A);
        assertFalse(entry.isRevokedOrExpiredOrInsecure());
    }

    @Test
    public void isRevokedOrExpiredOrInsecure_revokedOnly_true() {
        ImportKeysListEntry entry = makeEntry(FP_A);
        entry.setRevoked(true);
        assertTrue(entry.isRevokedOrExpiredOrInsecure());
    }

    @Test
    public void isRevokedOrExpiredOrInsecure_expiredOnly_true() {
        ImportKeysListEntry entry = makeEntry(FP_A);
        entry.setExpired(true);
        assertTrue(entry.isRevokedOrExpiredOrInsecure());
    }

    @Test
    public void isRevokedOrExpiredOrInsecure_insecureOnly_true() {
        ImportKeysListEntry entry = makeEntry(FP_A);
        entry.setSecure(false);
        assertTrue(entry.isRevokedOrExpiredOrInsecure());
    }

    @Test
    public void isRevokedOrExpiredOrInsecure_allTrue_true() {
        ImportKeysListEntry entry = makeEntry(FP_A);
        entry.setRevoked(true);
        entry.setExpired(true);
        entry.setSecure(false);
        assertTrue(entry.isRevokedOrExpiredOrInsecure());
    }

    // ---- addAll tests ----

    @Test
    public void addAll_mergesDuplicatesWithinBatch() {
        ImportKeysList list = new ImportKeysList(1);

        ImportKeysListEntry a1 = makeEntryWithUids(FP_A, "A1 <a1@test.com>");
        ImportKeysListEntry a2 = makeEntryWithUids(FP_A, "A2 <a2@test.com>");
        ImportKeysListEntry b = makeEntryWithUids(FP_B, "B <b@test.com>");

        list.addAll(Arrays.asList(a1, a2, b));

        assertEquals(2, list.size());
    }

    @Test
    public void add_returnsTrueAlways() {
        ImportKeysList list = new ImportKeysList(1);
        assertTrue(list.add(makeEntry(FP_A)));
        assertTrue(list.add(makeEntry(FP_A))); // even merge returns true
    }

    // ---- merge order tests ----

    @Test
    public void mergeDupes_fbUsernameSetWhenNoKeyserver() {
        ImportKeysList list = new ImportKeysList(1);

        ImportKeysListEntry first = makeEntry(FP_A);
        ImportKeysListEntry second = makeEntry(FP_A);
        second.setFbUsername("testuser");

        list.add(first);
        list.add(second);

        assertEquals("fbUsername should be set when no keyserver present",
                "testuser", list.get(0).getFbUsername());
    }

    @Test
    public void mergeDupes_fbUsernameNotOverwrittenByKeyserver() {
        ImportKeysList list = new ImportKeysList(1);

        ImportKeysListEntry keyserverEntry = makeEntry(FP_A);
        HkpKeyserverAddress keyserver = HkpKeyserverAddress.createFromUri("hkps://keys.example.com");
        keyserverEntry.setKeyserver(keyserver);

        ImportKeysListEntry fbEntry = makeEntry(FP_A);
        fbEntry.setFbUsername("testuser");

        list.add(keyserverEntry);
        list.add(fbEntry);

        // keyserver was already set, so fbUsername should NOT overwrite it
        assertEquals("Keyserver should not be overwritten by fbUsername",
                keyserver, list.get(0).getKeyserver());
    }
}
