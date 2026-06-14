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
import java.util.HashSet;
import java.util.Map;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.sufficientlysecure.keychain.KeychainTestRunner;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for {@link ImportKeysListEntry}, focused on identity comparison and on the user-id
 * handling that feeds the import UI. These guard the boundary cases produced by keyserver responses
 * (missing fingerprints, repeated user ids, several addresses for one identity).
 */
@RunWith(KeychainTestRunner.class)
public class ImportKeysListEntryTest {

    private static ImportKeysListEntry entryWith(byte[] fingerprint) {
        ImportKeysListEntry entry = new ImportKeysListEntry();
        entry.setFingerprint(fingerprint);
        return entry;
    }

    /**
     * Protects against: NPE / false matches when a fingerprint is absent. Entries lacking a
     * fingerprint (or compared against null) must never be considered the same key.
     */
    @Test
    public void hasSameKeyAs_withMissingFingerprint_isFalse() {
        ImportKeysListEntry noFingerprint = new ImportKeysListEntry();
        ImportKeysListEntry withFingerprint = entryWith(new byte[] { 1, 2, 3 });

        assertFalse("missing own fingerprint must not match", noFingerprint.hasSameKeyAs(withFingerprint));
        assertFalse("missing other fingerprint must not match", withFingerprint.hasSameKeyAs(noFingerprint));
        assertFalse("null other must not match", withFingerprint.hasSameKeyAs(null));
    }

    /**
     * Protects against: identity comparison regressions. Equal fingerprint bytes are the same key;
     * differing bytes are not.
     */
    @Test
    public void hasSameKeyAs_comparesFingerprintBytes() {
        assertTrue(entryWith(new byte[] { 1, 2, 3 }).hasSameKeyAs(entryWith(new byte[] { 1, 2, 3 })));
        assertFalse(entryWith(new byte[] { 1, 2, 3 }).hasSameKeyAs(entryWith(new byte[] { 9, 9, 9 })));
    }

    /**
     * Protects against: duplicate user ids accumulating when entries are merged. addUserIds must add
     * only previously-unseen ids and report whether anything changed.
     */
    @Test
    public void addUserIds_ignoresDuplicates() {
        ImportKeysListEntry entry = new ImportKeysListEntry();
        entry.setUserIds(new ArrayList<>(Arrays.asList("Alice <alice@example.com>")));

        boolean changedByNew = entry.addUserIds(Arrays.asList("Alice <alice@example.com>", "Bob <bob@example.com>"));
        assertTrue("adding a new id must report a change", changedByNew);
        assertEquals(2, entry.getUserIds().size());

        boolean changedByDuplicate = entry.addUserIds(Arrays.asList("Alice <alice@example.com>"));
        assertFalse("re-adding an existing id must report no change", changedByDuplicate);
        assertEquals(2, entry.getUserIds().size());
    }

    /**
     * Protects against: a keyserver returning the same user id twice (the HKP parser keeps both)
     * surfacing as a duplicated row in the UI. The merged/sorted view must collapse identical ids.
     */
    @Test
    public void sortedUserIds_collapseIdenticalDuplicates() {
        ImportKeysListEntry entry = new ImportKeysListEntry();
        entry.setUserIds(new ArrayList<>(Arrays.asList(
                "Alice <alice@example.com>", "Alice <alice@example.com>")));

        ArrayList<Map.Entry<String, HashSet<String>>> sorted = entry.getSortedUserIds();

        assertEquals("identical user ids must collapse to a single merged entry", 1, sorted.size());
        assertEquals("Alice", sorted.get(0).getKey());
        assertEquals(1, sorted.get(0).getValue().size());
    }

    /**
     * Protects against: several email addresses for one name being shown as unrelated identities.
     * The merged view must group multiple addresses under a single name.
     */
    @Test
    public void sortedUserIds_groupEmailsUnderName() {
        ImportKeysListEntry entry = new ImportKeysListEntry();
        entry.setUserIds(new ArrayList<>(Arrays.asList(
                "Alice <alice@example.com>", "Alice <alice@work.example.com>")));

        ArrayList<Map.Entry<String, HashSet<String>>> sorted = entry.getSortedUserIds();

        assertEquals(1, sorted.size());
        assertEquals("Alice", sorted.get(0).getKey());
        assertEquals("both addresses must be grouped under the single name", 2, sorted.get(0).getValue().size());
        assertTrue(sorted.get(0).getValue().contains("alice@example.com"));
        assertTrue(sorted.get(0).getValue().contains("alice@work.example.com"));
    }

    /**
     * Protects against: the "should this key be highlighted as problematic" predicate drifting.
     * It must be true if the key is revoked, expired, or insecure, and false only when none hold.
     */
    @Test
    public void isRevokedOrExpiredOrInsecure_reflectsAnyProblem() {
        ImportKeysListEntry healthy = new ImportKeysListEntry();
        healthy.setSecure(true);
        healthy.setRevoked(false);
        healthy.setExpired(false);
        assertFalse(healthy.isRevokedOrExpiredOrInsecure());

        ImportKeysListEntry revoked = new ImportKeysListEntry();
        revoked.setSecure(true);
        revoked.setRevoked(true);
        assertTrue(revoked.isRevokedOrExpiredOrInsecure());

        ImportKeysListEntry expired = new ImportKeysListEntry();
        expired.setSecure(true);
        expired.setExpired(true);
        assertTrue(expired.isRevokedOrExpiredOrInsecure());

        ImportKeysListEntry insecure = new ImportKeysListEntry();
        insecure.setSecure(false);
        assertTrue(insecure.isRevokedOrExpiredOrInsecure());
    }
}
