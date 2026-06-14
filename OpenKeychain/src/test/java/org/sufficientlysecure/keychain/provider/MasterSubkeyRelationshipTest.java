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

package org.sufficientlysecure.keychain.provider;


import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.Keys;
import org.sufficientlysecure.keychain.daos.KeyRepository;
import org.sufficientlysecure.keychain.daos.KeyWritableRepository;
import org.sufficientlysecure.keychain.model.UnifiedKeyInfo;
import org.sufficientlysecure.keychain.pgp.UncachedKeyRing;
import org.sufficientlysecure.keychain.support.DatabaseTestHelper;
import org.sufficientlysecure.keychain.support.KeyringTestingHelper;

/**
 * Tests covering master key and subkey relationships.
 *
 * <p>Verifies that after saving a key ring, the database correctly stores:
 * <ul>
 *   <li>Master key at rank 0</li>
 *   <li>Subkeys at rank > 0</li>
 *   <li>Correct capability flags per subkey</li>
 *   <li>Master key ID linkage via getMasterKeyIdBySubkeyId</li>
 *   <li>Unique key IDs across master + subkeys</li>
 *   <li>Subkey count matches expected</li>
 * </ul></p>
 *
 * <p>Each test is isolated: keys inserted during a test are deleted in {@link #tearDown()}.</p>
 */
@RunWith(KeychainTestRunner.class)
public class MasterSubkeyRelationshipTest {

    private DatabaseTestHelper helper;

    @Before
    public void setUp() {
        helper = new DatabaseTestHelper();
    }

    @After
    public void tearDown() {
        helper.cleanupInsertedKeys();
    }

    @Test
    public void testMasterKeyAtRankZero() throws Exception {
        // Generate a key with certify(master) + sign + encrypt subkeys
        UncachedKeyRing ring = helper.generateSimpleKey("Alice <alice@example.com>");
        long masterKeyId = ring.getMasterKeyId();
        Assert.assertTrue("save should succeed", helper.saveAndTrackSecretKeyRing(ring));

        KeyRepository repo = helper.createReadRepository();
        List<Keys> subkeys = repo.getSubKeysByMasterKeyId(masterKeyId);

        Assert.assertFalse("key should have subkeys", subkeys.isEmpty());

        // The first entry (rank=0) must be the master key
        Keys masterEntry = subkeys.get(0);
        Assert.assertEquals("master key must be at rank 0", 0, (int) masterEntry.getRank());
        Assert.assertEquals("master key's key_id must match masterKeyId",
                masterKeyId, (long) masterEntry.getKey_id());
    }

    @Test
    public void testSubkeyRanksAreSequential() throws Exception {
        // Generate key with certify(master) + sign + encrypt = 3 total keys
        UncachedKeyRing ring = helper.generateSimpleKey("Bob <bob@example.com>");
        long masterKeyId = ring.getMasterKeyId();
        Assert.assertTrue("save should succeed", helper.saveAndTrackSecretKeyRing(ring));

        KeyRepository repo = helper.createReadRepository();
        List<Keys> subkeys = repo.getSubKeysByMasterKeyId(masterKeyId);

        Assert.assertEquals("should have 3 keys total (master + 2 subkeys)", 3, subkeys.size());

        // Verify sequential ranks: 0, 1, 2
        for (int i = 0; i < subkeys.size(); i++) {
            Assert.assertEquals("rank should be sequential", i, (int) subkeys.get(i).getRank());
        }
    }

    @Test
    public void testSubkeyCountMatchesGeneratedKey() throws Exception {
        // Key with auth subkey: certify(master) + sign + encrypt + auth = 4 total
        UncachedKeyRing ring = helper.generateKeyWithAuthSubkey("Carol <carol@example.com>");
        long masterKeyId = ring.getMasterKeyId();
        Assert.assertTrue("save should succeed", helper.saveAndTrackSecretKeyRing(ring));

        KeyRepository repo = helper.createReadRepository();
        List<Keys> subkeys = repo.getSubKeysByMasterKeyId(masterKeyId);

        Assert.assertEquals("should have 4 keys (master + sign + encrypt + auth)", 4, subkeys.size());
    }

    @Test
    public void testMasterKeyCapabilityFlags() throws Exception {
        UncachedKeyRing ring = helper.generateSimpleKey("Dave <dave@example.com>");
        long masterKeyId = ring.getMasterKeyId();
        Assert.assertTrue("save should succeed", helper.saveAndTrackSecretKeyRing(ring));

        KeyRepository repo = helper.createReadRepository();
        List<Keys> subkeys = repo.getSubKeysByMasterKeyId(masterKeyId);

        Keys masterEntry = subkeys.get(0);
        Assert.assertEquals("master key rank must be 0", 0, (int) masterEntry.getRank());
        Assert.assertTrue("master key should be able to certify", masterEntry.getCan_certify());
    }

    @Test
    public void testSubkeyCapabilityFlags() throws Exception {
        UncachedKeyRing ring = helper.generateSimpleKey("Eve <eve@example.com>");
        long masterKeyId = ring.getMasterKeyId();
        Assert.assertTrue("save should succeed", helper.saveAndTrackSecretKeyRing(ring));

        KeyRepository repo = helper.createReadRepository();
        List<Keys> subkeys = repo.getSubKeysByMasterKeyId(masterKeyId);

        Assert.assertEquals("expected 3 keys", 3, subkeys.size());

        // rank 0 = master (certify), rank 1 = sign, rank 2 = encrypt
        Keys signKey = subkeys.get(1);
        Assert.assertTrue("subkey at rank 1 should be able to sign", signKey.getCan_sign());
        Assert.assertFalse("sign subkey should not certify", signKey.getCan_certify());

        Keys encryptKey = subkeys.get(2);
        Assert.assertTrue("subkey at rank 2 should be able to encrypt", encryptKey.getCan_encrypt());
        Assert.assertFalse("encrypt subkey should not sign", encryptKey.getCan_sign());
    }

    @Test
    public void testGetMasterKeyIdBySubkeyId() throws Exception {
        UncachedKeyRing ring = helper.generateSimpleKey("Frank <frank@example.com>");
        long masterKeyId = ring.getMasterKeyId();
        Assert.assertTrue("save should succeed", helper.saveAndTrackSecretKeyRing(ring));

        KeyRepository repo = helper.createReadRepository();
        List<Keys> subkeys = repo.getSubKeysByMasterKeyId(masterKeyId);

        // For each subkey, verify getMasterKeyIdBySubkeyId returns the correct master key
        for (Keys subkey : subkeys) {
            Long resolved = repo.getMasterKeyIdBySubkeyId(subkey.getKey_id());
            Assert.assertNotNull("subkey should resolve to a master key", resolved);
            Assert.assertEquals("subkey should map back to correct master key",
                    masterKeyId, (long) resolved);
        }
    }

    @Test
    public void testSubkeyIdsAreUnique() throws Exception {
        UncachedKeyRing ring = helper.generateKeyWithAuthSubkey("Grace <grace@example.com>");
        long masterKeyId = ring.getMasterKeyId();
        Assert.assertTrue("save should succeed", helper.saveAndTrackSecretKeyRing(ring));

        KeyRepository repo = helper.createReadRepository();
        List<Keys> subkeys = repo.getSubKeysByMasterKeyId(masterKeyId);

        Set<Long> keyIds = new HashSet<>();
        for (Keys subkey : subkeys) {
            Assert.assertTrue("key_id should be unique across all keys in the ring",
                    keyIds.add(subkey.getKey_id()));
        }
        Assert.assertEquals("all key IDs should be unique", subkeys.size(), keyIds.size());
    }

    @Test
    public void testMultipleKeysHaveIndependentSubkeys() throws Exception {
        // Insert two different keys and verify their subkeys are independent
        UncachedKeyRing ring1 = helper.generateSimpleKey("Key1 <key1@example.com>");
        UncachedKeyRing ring2 = helper.generateKeyWithAuthSubkey("Key2 <key2@example.com>");
        long masterKeyId1 = ring1.getMasterKeyId();
        long masterKeyId2 = ring2.getMasterKeyId();

        Assert.assertTrue("save ring1 should succeed", helper.saveAndTrackSecretKeyRing(ring1));
        Assert.assertTrue("save ring2 should succeed", helper.saveAndTrackSecretKeyRing(ring2));

        KeyRepository repo = helper.createReadRepository();
        List<Keys> subkeys1 = repo.getSubKeysByMasterKeyId(masterKeyId1);
        List<Keys> subkeys2 = repo.getSubKeysByMasterKeyId(masterKeyId2);

        Assert.assertEquals("ring1 should have 3 keys", 3, subkeys1.size());
        Assert.assertEquals("ring2 should have 4 keys", 4, subkeys2.size());

        // Verify no overlap in key IDs between the two rings
        Set<Long> ids1 = new HashSet<>();
        for (Keys k : subkeys1) ids1.add(k.getKey_id());
        for (Keys k : subkeys2) {
            Assert.assertFalse("ring2 key IDs should not overlap with ring1",
                    ids1.contains(k.getKey_id()));
        }
    }

    @Test
    public void testMasterKeyInfoReflectsSubkeyCapabilities() throws Exception {
        // Verify that UnifiedKeyInfo has_encrypt_key and has_sign_key flags
        // reflect the presence of capable subkeys
        UncachedKeyRing ring = helper.generateSimpleKey("Hank <hank@example.com>");
        long masterKeyId = ring.getMasterKeyId();
        Assert.assertTrue("save should succeed", helper.saveAndTrackSecretKeyRing(ring));

        KeyRepository repo = helper.createReadRepository();
        UnifiedKeyInfo info = repo.getUnifiedKeyInfo(masterKeyId);

        Assert.assertNotNull("UnifiedKeyInfo should not be null", info);
        Assert.assertTrue("should have encrypt key", info.has_encrypt_key());
        Assert.assertTrue("should have sign key", info.has_sign_key());
    }

    @Test
    public void testDeleteKeyRingRemovesSubkeys() throws Exception {
        UncachedKeyRing ring = helper.generateSimpleKey("Ivy <ivy@example.com>");
        long masterKeyId = ring.getMasterKeyId();
        Assert.assertTrue("save should succeed", helper.saveAndTrackSecretKeyRing(ring));

        // Verify key exists
        KeyRepository repo = helper.createReadRepository();
        List<Keys> subkeys = repo.getSubKeysByMasterKeyId(masterKeyId);
        Assert.assertFalse("should have subkeys before deletion", subkeys.isEmpty());

        // Delete
        KeyWritableRepository writable = helper.createWritableRepository();
        boolean deleted = writable.deleteKeyRing(masterKeyId);
        Assert.assertTrue("delete should succeed", deleted);

        // Verify subkeys are gone (cascade delete)
        List<Keys> afterDelete = repo.getSubKeysByMasterKeyId(masterKeyId);
        Assert.assertTrue("subkeys should be empty after deletion", afterDelete.isEmpty());

        // Remove from tracking since we already deleted it
        helper.getInsertedMasterKeyIds().remove(Long.valueOf(masterKeyId));
    }

    @Test
    public void testLoadFromResourceKeyPreservesSubkeyRelationship() throws Exception {
        // Use a pre-built key from test resources to verify real-world keys
        UncachedKeyRing ring = KeyringTestingHelper.readRingFromResource(
                "/test-keys/authenticate_multisub_with_revoked.asc");
        long masterKeyId = ring.getMasterKeyId();
        Assert.assertTrue("save should succeed", helper.saveAndTrackSecretKeyRing(ring));

        KeyRepository repo = helper.createReadRepository();
        List<Keys> subkeys = repo.getSubKeysByMasterKeyId(masterKeyId);

        Assert.assertTrue("resource key should have multiple subkeys", subkeys.size() > 1);

        // Master key at rank 0
        Assert.assertEquals("first entry should be master key (rank 0)",
                0, (int) subkeys.get(0).getRank());
        Assert.assertEquals("master key_id should match",
                masterKeyId, (long) subkeys.get(0).getKey_id());

        // All subkeys should reference the same master key
        for (Keys subkey : subkeys) {
            Assert.assertEquals("all subkeys must reference the same master key",
                    masterKeyId, (long) subkey.getMaster_key_id());
        }
    }

    @Test
    public void testFingerprintsAreNonNull() throws Exception {
        UncachedKeyRing ring = helper.generateSimpleKey("Jake <jake@example.com>");
        long masterKeyId = ring.getMasterKeyId();
        Assert.assertTrue("save should succeed", helper.saveAndTrackSecretKeyRing(ring));

        KeyRepository repo = helper.createReadRepository();
        List<Keys> subkeys = repo.getSubKeysByMasterKeyId(masterKeyId);

        for (Keys subkey : subkeys) {
            Assert.assertNotNull("fingerprint should not be null for rank " + subkey.getRank(),
                    subkey.getFingerprint());
            Assert.assertTrue("fingerprint should have data",
                    subkey.getFingerprint().length > 0);
        }
    }
}
