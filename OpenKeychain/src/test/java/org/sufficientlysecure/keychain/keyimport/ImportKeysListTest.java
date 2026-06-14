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


import java.util.ArrayList;
import java.util.Arrays;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.sufficientlysecure.keychain.KeychainTestRunner;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for {@link ImportKeysList}, the duplicate-merging result container used when several
 * cloud sources (keyserver, WKD, Facebook) are searched in parallel.
 *
 * <p>The merge logic is the place where results from independent sources are reconciled, so the
 * tests here pin down the edge cases that silently degrade when that reconciliation is wrong:
 * duplicate keys leaking through, a revoked/expired/insecure verdict from one source being lost,
 * user ids multiplying on merge, and keys without a fingerprint being collapsed (or NPE-ing).
 */
@RunWith(KeychainTestRunner.class)
public class ImportKeysListTest {

    private static ImportKeysListEntry entryWithFingerprint(byte[] fingerprint, String... userIds) {
        ImportKeysListEntry entry = new ImportKeysListEntry();
        entry.setFingerprint(fingerprint);
        entry.setSecure(true);
        entry.setUserIds(new ArrayList<>(Arrays.asList(userIds)));
        if (userIds.length > 0) {
            entry.setPrimaryUserId(userIds[0]);
        }
        return entry;
    }

    /**
     * Protects against: the same key reported by two sources showing up as two separate rows.
     * Two entries that share a fingerprint must collapse into a single list entry.
     */
    @Test
    public void add_sameFingerprint_mergesIntoSingleEntry() {
        ImportKeysList list = new ImportKeysList(2);

        list.add(entryWithFingerprint(new byte[] { 1, 2, 3 }, "Alice <alice@example.com>"));
        list.add(entryWithFingerprint(new byte[] { 1, 2, 3 }, "Alice <alice@example.com>"));

        assertEquals("duplicate fingerprints must merge into one entry", 1, list.size());
    }

    /**
     * Protects against: a key marked revoked by one source being presented as valid because a
     * second source did not flag it. The revoked verdict must be sticky across the merge.
     */
    @Test
    public void merge_revokedFromAnySourceIsSticky() {
        ImportKeysList list = new ImportKeysList(2);

        ImportKeysListEntry existing = entryWithFingerprint(new byte[] { 9 }, "Bob <bob@example.com>");
        existing.setRevoked(false);
        list.add(existing);

        ImportKeysListEntry revokedDuplicate = entryWithFingerprint(new byte[] { 9 }, "Bob <bob@example.com>");
        revokedDuplicate.setRevoked(true);
        list.add(revokedDuplicate);

        assertEquals(1, list.size());
        assertTrue("a revoked verdict from any source must survive the merge", list.get(0).isRevoked());
    }

    /**
     * Protects against: an expired key being shown as usable because another source omitted the
     * expiry flag. The expired verdict must be sticky across the merge.
     */
    @Test
    public void merge_expiredFromAnySourceIsSticky() {
        ImportKeysList list = new ImportKeysList(2);

        ImportKeysListEntry existing = entryWithFingerprint(new byte[] { 7 }, "Carol <carol@example.com>");
        existing.setExpired(false);
        list.add(existing);

        ImportKeysListEntry expiredDuplicate = entryWithFingerprint(new byte[] { 7 }, "Carol <carol@example.com>");
        expiredDuplicate.setExpired(true);
        list.add(expiredDuplicate);

        assertEquals(1, list.size());
        assertTrue("an expired verdict from any source must survive the merge", list.get(0).isExpired());
    }

    /**
     * Protects against: an insecure key (e.g. weak algorithm) being treated as secure after merging
     * with a source that considered it secure. The insecure verdict must be sticky.
     */
    @Test
    public void merge_insecureFromAnySourceIsSticky() {
        ImportKeysList list = new ImportKeysList(2);

        ImportKeysListEntry existing = entryWithFingerprint(new byte[] { 5 }, "Dave <dave@example.com>");
        existing.setSecure(true);
        list.add(existing);

        ImportKeysListEntry insecureDuplicate = entryWithFingerprint(new byte[] { 5 }, "Dave <dave@example.com>");
        insecureDuplicate.setSecure(false);
        list.add(insecureDuplicate);

        assertEquals(1, list.size());
        assertFalse("an insecure verdict from any source must survive the merge", list.get(0).isSecure());
    }

    /**
     * Protects against: user ids multiplying or being lost on merge. The union of user ids from both
     * sources must be kept, with no duplicates.
     */
    @Test
    public void merge_unionsUserIdsWithoutDuplicates() {
        ImportKeysList list = new ImportKeysList(2);

        list.add(entryWithFingerprint(new byte[] { 4 }, "Eve <eve@example.com>"));
        list.add(entryWithFingerprint(new byte[] { 4 }, "Eve <eve@example.com>", "Eve <eve@work.example.com>"));

        assertEquals(1, list.size());
        assertEquals("merged entry must hold the de-duplicated union of user ids",
                2, list.get(0).getUserIds().size());
        assertTrue(list.get(0).getUserIds().contains("Eve <eve@example.com>"));
        assertTrue(list.get(0).getUserIds().contains("Eve <eve@work.example.com>"));
    }

    /**
     * Protects against: NPE or unintended collapse when entries have no fingerprint. Keyserver hits
     * that only return a short key id (no fingerprint) must NOT be merged together, since
     * {@link ImportKeysListEntry#hasSameKeyAs} cannot prove they are the same key.
     */
    @Test
    public void add_entriesWithoutFingerprint_areNotMerged() {
        ImportKeysList list = new ImportKeysList(2);

        ImportKeysListEntry a = new ImportKeysListEntry();
        a.setKeyIdHex("0xdeadbeefdeadbeef");
        a.setUserIds(new ArrayList<>(Arrays.asList("Frank <frank@example.com>")));

        ImportKeysListEntry b = new ImportKeysListEntry();
        b.setKeyIdHex("0xdeadbeefdeadbeef");
        b.setUserIds(new ArrayList<>(Arrays.asList("Frank <frank@example.com>")));

        list.add(a);
        list.add(b);

        assertEquals("entries without fingerprints must not be merged", 2, list.size());
    }

    /**
     * Protects against: distinct keys being wrongly collapsed. Different fingerprints must remain
     * separate entries.
     */
    @Test
    public void add_differentFingerprints_keptSeparate() {
        ImportKeysList list = new ImportKeysList(2);

        list.add(entryWithFingerprint(new byte[] { 1 }, "Grace <grace@example.com>"));
        list.add(entryWithFingerprint(new byte[] { 2 }, "Heidi <heidi@example.com>"));

        assertEquals(2, list.size());
    }

    /**
     * Protects against: the parallel-search completion barrier breaking. Each finished supplier must
     * decrement the outstanding count so the waiting CloudSearch thread can be released exactly once
     * all suppliers report in.
     */
    @Test
    public void finishedAdding_decrementsOutstandingSuppliers() {
        ImportKeysList list = new ImportKeysList(2);
        assertEquals(2, list.outstandingSuppliers());

        list.finishedAdding();
        assertEquals(1, list.outstandingSuppliers());

        list.finishedAdding();
        assertEquals(0, list.outstandingSuppliers());
    }
}
