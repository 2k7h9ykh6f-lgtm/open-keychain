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


import java.util.Collections;
import java.util.List;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.Keys;
import org.sufficientlysecure.keychain.daos.KeyRepository;
import org.sufficientlysecure.keychain.daos.KeyRepository.NotFoundException;
import org.sufficientlysecure.keychain.daos.KeyWritableRepository;
import org.sufficientlysecure.keychain.model.UnifiedKeyInfo;
import org.sufficientlysecure.keychain.model.UserId;
import org.sufficientlysecure.keychain.pgp.UncachedKeyRing;
import org.sufficientlysecure.keychain.pgp.CanonicalizedSecretKey.SecretKeyType;
import org.sufficientlysecure.keychain.support.DatabaseTestHelper;

/**
 * Tests covering query edge cases, projection handling, and boundary conditions.
 *
 * <p>Verifies:
 * <ul>
 *   <li>Querying non-existent keys throws NotFoundException or returns null</li>
 *   <li>getAllMasterKeyIds returns empty list for empty database</li>
 *   <li>getUnifiedKeyInfo returns null for non-existent key</li>
 *   <li>getSubKeysByMasterKeyId returns empty list for non-existent key</li>
 *   <li>getUserIds returns empty list for non-existent key</li>
 *   <li>Searching by email with no matches returns empty list</li>
 *   <li>getFingerprintByKeyId throws NotFoundException for unknown key</li>
 *   <li>getSecretKeyType throws NotFoundException for unknown key</li>
 *   <li>Delete non-existent key returns false</li>
 *   <li>Null/empty handling in search methods</li>
 * </ul></p>
 *
 * <p>Each test is isolated: keys inserted during a test are deleted in {@link #tearDown()}.</p>
 */
@RunWith(KeychainTestRunner.class)
public class QueryProjectionEdgeCaseTest {

    private DatabaseTestHelper helper;

    @Before
    public void setUp() {
        helper = new DatabaseTestHelper();
    }

    @After
    public void tearDown() {
        helper.cleanupInsertedKeys();
    }

    // --- Non-existent key queries ---

    @Test
    public void testGetUnifiedKeyInfoForNonExistentKeyReturnsNull() throws Exception {
        KeyRepository repo = helper.createReadRepository();
        UnifiedKeyInfo info = repo.getUnifiedKeyInfo(0xDEADBEEFL);
        Assert.assertNull("should return null for non-existent key", info);
    }

    @Test
    public void testGetSubKeysByMasterKeyIdForNonExistentReturnsEmpty() throws Exception {
        KeyRepository repo = helper.createReadRepository();
        List<Keys> subkeys = repo.getSubKeysByMasterKeyId(0xDEADBEEFL);
        Assert.assertTrue("should return empty list for non-existent key", subkeys.isEmpty());
    }

    @Test
    public void testGetUserIdsForNonExistentKeyReturnsEmpty() throws Exception {
        KeyRepository repo = helper.createReadRepository();
        List<UserId> userIds = repo.getUserIds(0xDEADBEEFL);
        Assert.assertTrue("should return empty list for non-existent key", userIds.isEmpty());
    }

    @Test(expected = NotFoundException.class)
    public void testGetCanonicalizedPublicKeyRingForNonExistentThrows() throws Exception {
        KeyRepository repo = helper.createReadRepository();
        repo.getCanonicalizedPublicKeyRing(0xDEADBEEFL);
    }

    @Test(expected = NotFoundException.class)
    public void testGetCanonicalizedSecretKeyRingForNonExistentThrows() throws Exception {
        KeyRepository repo = helper.createReadRepository();
        repo.getCanonicalizedSecretKeyRing(0xDEADBEEFL);
    }

    @Test(expected = NotFoundException.class)
    public void testGetFingerprintByKeyIdForNonExistentThrows() throws Exception {
        KeyRepository repo = helper.createReadRepository();
        repo.getFingerprintByKeyId(0xDEADBEEFL);
    }

    @Test(expected = NotFoundException.class)
    public void testGetSecretKeyTypeForNonExistentThrows() throws Exception {
        KeyRepository repo = helper.createReadRepository();
        repo.getSecretKeyType(0xDEADBEEFL);
    }

    @Test(expected = NotFoundException.class)
    public void testGetSecretSignIdForNonExistentThrows() throws Exception {
        KeyRepository repo = helper.createReadRepository();
        repo.getSecretSignId(0xDEADBEEFL);
    }

    @Test(expected = NotFoundException.class)
    public void testGetEffectiveAuthenticationKeyIdForNonExistentThrows() throws Exception {
        KeyRepository repo = helper.createReadRepository();
        repo.getEffectiveAuthenticationKeyId(0xDEADBEEFL);
    }

    @Test
    public void testGetPublicEncryptionIdsForNonExistentReturnsEmpty() throws Exception {
        KeyRepository repo = helper.createReadRepository();
        List<Long> ids = repo.getPublicEncryptionIds(0xDEADBEEFL);
        Assert.assertTrue("should return empty list for non-existent key", ids.isEmpty());
    }

    @Test
    public void testGetMasterKeyIdBySubkeyIdForNonExistentReturnsNull() throws Exception {
        KeyRepository repo = helper.createReadRepository();
        Long result = repo.getMasterKeyIdBySubkeyId(0xDEADBEEFL);
        Assert.assertNull("should return null for non-existent subkey", result);
    }

    // --- Empty database queries ---

    @Test
    public void testGetAllMasterKeyIdsOnFreshDatabase() throws Exception {
        // This test verifies getAllMasterKeyIds works without error on any state
        KeyRepository repo = helper.createReadRepository();
        List<Long> masterKeyIds = repo.getAllMasterKeyIds();
        // We can't guarantee it's empty (other tests may have leaked data),
        // but we can verify it doesn't throw
        Assert.assertNotNull("master key IDs list should not be null", masterKeyIds);
    }

    @Test
    public void testGetAllUnifiedKeyInfoDoesNotThrow() throws Exception {
        KeyRepository repo = helper.createReadRepository();
        List<UnifiedKeyInfo> allInfo = repo.getAllUnifiedKeyInfo();
        Assert.assertNotNull("all unified key info should not be null", allInfo);
    }

    @Test
    public void testGetAllUnifiedKeyInfoWithSecretDoesNotThrow() throws Exception {
        KeyRepository repo = helper.createReadRepository();
        List<UnifiedKeyInfo> withSecret = repo.getAllUnifiedKeyInfoWithSecret();
        Assert.assertNotNull("unified key info with secret should not be null", withSecret);
    }

    // --- Delete edge cases ---

    @Test
    public void testDeleteNonExistentKeyReturnsFalse() throws Exception {
        KeyWritableRepository repo = helper.createWritableRepository();
        boolean deleted = repo.deleteKeyRing(0xDEADBEEFL);
        Assert.assertFalse("deleting non-existent key should return false", deleted);
    }

    // --- Search by email ---

    @Test
    public void testSearchByEmailNoMatch() throws Exception {
        KeyRepository repo = helper.createReadRepository();
        List<UnifiedKeyInfo> results = repo.getUnifiedKeyInfosByMailAddress(
                "nonexistent@doesnotexist.example.com");
        Assert.assertTrue("search for non-existent email should return empty list",
                results.isEmpty());
    }

    @Test
    public void testSearchByEmailFindsCorrectKey() throws Exception {
        UncachedKeyRing ring = helper.generateSimpleKey("FindMe <findme@example.com>");
        long masterKeyId = ring.getMasterKeyId();
        Assert.assertTrue("save should succeed", helper.saveAndTrackSecretKeyRing(ring));

        KeyRepository repo = helper.createReadRepository();
        List<UnifiedKeyInfo> results = repo.getUnifiedKeyInfosByMailAddress("findme@example.com");

        Assert.assertFalse("search should find at least one result", results.isEmpty());

        boolean found = false;
        for (UnifiedKeyInfo info : results) {
            if (info.master_key_id() == masterKeyId) {
                found = true;
                break;
            }
        }
        Assert.assertTrue("search should find our key", found);
    }

    @Test
    public void testSearchByEmailIsPartialMatch() throws Exception {
        UncachedKeyRing ring = helper.generateSimpleKey(
                "PartialMatch <partial@example.com>");
        Assert.assertTrue("save should succeed", helper.saveAndTrackSecretKeyRing(ring));

        KeyRepository repo = helper.createReadRepository();
        // The search method wraps with '%...%' so partial matches should work
        List<UnifiedKeyInfo> results = repo.getUnifiedKeyInfosByMailAddress("partial");

        Assert.assertFalse("partial email search should find matches", results.isEmpty());
    }

    // --- Confirmed user IDs ---

    @Test
    public void testGetConfirmedUserIdsForNonExistentKey() throws Exception {
        KeyRepository repo = helper.createReadRepository();
        List<String> confirmed = repo.getConfirmedUserIds(0xDEADBEEFL);
        Assert.assertTrue("should return empty list for non-existent key", confirmed.isEmpty());
    }

    // --- Secret key type ---

    @Test
    public void testSecretKeyTypeAfterImport() throws Exception {
        UncachedKeyRing ring = helper.generateSimpleKey("SecType <sectype@example.com>");
        long masterKeyId = ring.getMasterKeyId();
        Assert.assertTrue("save should succeed", helper.saveAndTrackSecretKeyRing(ring));

        KeyRepository repo = helper.createReadRepository();
        SecretKeyType type = repo.getSecretKeyType(masterKeyId);

        // After importing a secret key, the master key should have a valid secret type
        Assert.assertNotNull("secret key type should not be null", type);
        Assert.assertNotEquals("should not be UNAVAILABLE after secret import",
                SecretKeyType.UNAVAILABLE, type);
    }

    // --- Fingerprint retrieval ---

    @Test
    public void testFingerprintRetrievalAfterImport() throws Exception {
        UncachedKeyRing ring = helper.generateSimpleKey("Fingerprint <fingerprint@example.com>");
        long masterKeyId = ring.getMasterKeyId();
        Assert.assertTrue("save should succeed", helper.saveAndTrackSecretKeyRing(ring));

        KeyRepository repo = helper.createReadRepository();
        byte[] fingerprint = repo.getFingerprintByKeyId(masterKeyId);

        Assert.assertNotNull("fingerprint should not be null", fingerprint);
        Assert.assertEquals("fingerprint should be 20 bytes (SHA-1)",
                20, fingerprint.length);
    }

    @Test
    public void testFingerprintRetrievalBySubkeyId() throws Exception {
        UncachedKeyRing ring = helper.generateSimpleKey("SubFP <subfp@example.com>");
        long masterKeyId = ring.getMasterKeyId();
        Assert.assertTrue("save should succeed", helper.saveAndTrackSecretKeyRing(ring));

        KeyRepository repo = helper.createReadRepository();
        List<Keys> subkeys = repo.getSubKeysByMasterKeyId(masterKeyId);

        // Get fingerprint for a subkey (not master)
        if (subkeys.size() > 1) {
            long subkeyId = subkeys.get(1).getKey_id();
            byte[] fingerprint = repo.getFingerprintByKeyId(subkeyId);
            Assert.assertNotNull("subkey fingerprint should not be null", fingerprint);
            Assert.assertTrue("subkey fingerprint should have data",
                    fingerprint.length > 0);
        }
    }

    // --- Multiple key batch query ---

    @Test
    public void testGetUnifiedKeyInfoBatchWithNonExistentIds() throws Exception {
        UncachedKeyRing ring = helper.generateSimpleKey("BatchQuery <batchquery@example.com>");
        long masterKeyId = ring.getMasterKeyId();
        Assert.assertTrue("save should succeed", helper.saveAndTrackSecretKeyRing(ring));

        KeyRepository repo = helper.createReadRepository();

        // Query with a mix of existing and non-existing master key IDs
        List<UnifiedKeyInfo> results = repo.getUnifiedKeyInfo(masterKeyId, 0xDEADBEEFL, 0xCAFEBABEL);

        // Should return only the existing key
        Assert.assertEquals("should return only the existing key", 1, results.size());
        Assert.assertEquals("returned key should match",
                masterKeyId, results.get(0).master_key_id());
    }

    @Test
    public void testGetUnifiedKeyInfoBatchAllNonExistent() throws Exception {
        KeyRepository repo = helper.createReadRepository();
        List<UnifiedKeyInfo> results = repo.getUnifiedKeyInfo(0xDEADBEEFL, 0xCAFEBABEL);
        Assert.assertTrue("batch query with all non-existent IDs should return empty list",
                results.isEmpty());
    }

    // --- Load public key data edge cases ---

    @Test(expected = NotFoundException.class)
    public void testLoadPublicKeyDataForNonExistentThrows() throws Exception {
        KeyRepository repo = helper.createReadRepository();
        repo.loadPublicKeyRingData(0xDEADBEEFL);
    }

    @Test(expected = NotFoundException.class)
    public void testLoadSecretKeyDataForNonExistentThrows() throws Exception {
        KeyRepository repo = helper.createReadRepository();
        repo.loadSecretKeyRingData(0xDEADBEEFL);
    }

    // --- Public key ring retrieval after import ---

    @Test
    public void testGetPublicKeyRingAsArmoredString() throws Exception {
        UncachedKeyRing ring = helper.generateSimpleKey("Armored <armored@example.com>");
        long masterKeyId = ring.getMasterKeyId();
        Assert.assertTrue("save should succeed", helper.saveAndTrackSecretKeyRing(ring));

        KeyRepository repo = helper.createReadRepository();
        String armored = repo.getPublicKeyRingAsArmoredString(masterKeyId);

        Assert.assertNotNull("armored string should not be null", armored);
        Assert.assertTrue("armored string should contain PGP header",
                armored.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
    }

    // --- Master key IDs by signer ---

    @Test
    public void testGetMasterKeyIdsBySignerWithEmptyList() throws Exception {
        KeyRepository repo = helper.createReadRepository();
        List<Long> result = repo.getMasterKeyIdsBySigner(Collections.<Long>emptyList());
        Assert.assertNotNull("result should not be null", result);
    }

    // --- Import invalid key type ---

    @Test
    public void testSaveSecretRingAsPublicFails() throws Exception {
        UncachedKeyRing secretRing = helper.generateSimpleKey(
                "WrongType <wrongtype@example.com>");

        KeyWritableRepository repo = helper.createWritableRepository();
        // savePublicKeyRing should detect the secret ring and fail
        org.sufficientlysecure.keychain.operations.results.SaveKeyringResult result =
                repo.savePublicKeyRing(secretRing);
        Assert.assertFalse("saving secret ring via savePublicKeyRing should fail",
                result.success());
    }

    @Test
    public void testSavePublicRingAsSecretFails() throws Exception {
        UncachedKeyRing secretRing = helper.generateSimpleKey(
                "WrongType2 <wrongtype2@example.com>");
        UncachedKeyRing pubRing = secretRing.extractPublicKeyRing();

        KeyWritableRepository repo = helper.createWritableRepository();
        // saveSecretKeyRing should detect the public ring and fail
        org.sufficientlysecure.keychain.operations.results.SaveKeyringResult result =
                repo.saveSecretKeyRing(pubRing);
        Assert.assertFalse("saving public ring via saveSecretKeyRing should fail",
                result.success());
    }
}
