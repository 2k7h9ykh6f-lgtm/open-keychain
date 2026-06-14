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

package org.sufficientlysecure.keychain.provider;


import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.shadows.ShadowLog;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.Keys;
import org.sufficientlysecure.keychain.daos.KeyRepository;
import org.sufficientlysecure.keychain.daos.KeyWritableRepository;
import org.sufficientlysecure.keychain.model.UnifiedKeyInfo;
import org.sufficientlysecure.keychain.model.UserId;
import org.sufficientlysecure.keychain.pgp.UncachedKeyRing;
import org.sufficientlysecure.keychain.pgp.UncachedPublicKey;
import org.sufficientlysecure.keychain.support.KeyringTestingHelper;


/**
 * Regression tests for the local key data layer focused on the <em>consistency</em> of what is
 * persisted and queried back: master/subkey relationships, revocation and expiry fields, user-id
 * ordering, nullable query projections, and graceful handling of absent keys.
 *
 * <p>Isolation: tests run under Robolectric and {@code Constants.IS_RUNNING_UNITTEST} forces
 * {@code KeychainDatabase.getInstance()} to build a brand new database for every test method, so no
 * mutable database state is shared between tests. Each method re-saves its fixture in {@link #setUp()}.
 *
 * <p>Note: {@code KeychainProvider} is a no-op stub, so the "missing projection field" scenario is
 * exercised at the repository query layer (nullable {@link UnifiedKeyInfo} columns and lookups for
 * keys that are not present).
 */
@RunWith(KeychainTestRunner.class)
public class KeyRepositoryConsistencyTest {

    // Secret keyring with a master key, several subkeys, and (at least) one revoked subkey.
    private static final String MULTISUB_WITH_REVOKED =
            "/test-keys/authenticate_multisub_with_revoked.asc";

    private KeyWritableRepository repository;
    private UncachedKeyRing testRing;
    private long masterKeyId;

    @BeforeClass
    public static void setUpOnce() {
        ShadowLog.stream = System.out;
    }

    @Before
    public void setUp() throws Exception {
        repository = KeyWritableRepository.create(RuntimeEnvironment.getApplication());
        testRing = KeyringTestingHelper.saveSecretKeyringFromResource(
                RuntimeEnvironment.getApplication(), MULTISUB_WITH_REVOKED);
        masterKeyId = testRing.getMasterKeyId();
    }

    @Test
    public void masterAndSubkeyRelationshipIsPersisted() throws Exception {
        List<UncachedPublicKey> expectedKeys = KeyringTestingHelper.publicKeysOf(testRing);
        List<Keys> storedKeys = repository.getSubKeysByMasterKeyId(masterKeyId);

        Assert.assertEquals("all (sub)keys of the ring should be stored",
                expectedKeys.size(), storedKeys.size());

        long previousRank = -1;
        boolean sawMasterAtRankZero = false;
        for (Keys storedKey : storedKeys) {
            Assert.assertEquals("every subkey must reference its master key id",
                    masterKeyId, storedKey.getMaster_key_id());

            long rank = storedKey.getRank();
            Assert.assertTrue("subkey ranks must be strictly increasing", rank > previousRank);
            previousRank = rank;

            if (rank == 0) {
                sawMasterAtRankZero = true;
                Assert.assertEquals("rank 0 must be the master key itself",
                        masterKeyId, storedKey.getKey_id());
            }

            // every stored subkey must be resolvable back to its master key
            Long resolvedMaster = repository.getMasterKeyIdBySubkeyId(storedKey.getKey_id());
            Assert.assertNotNull("subkey id must resolve to a master key id", resolvedMaster);
            Assert.assertEquals(masterKeyId, (long) resolvedMaster);
        }
        Assert.assertTrue("a rank 0 master key row must exist", sawMasterAtRankZero);

        // the master fingerprint must round-trip through the database
        UncachedPublicKey masterKey = findKey(expectedKeys, masterKeyId);
        Assert.assertArrayEquals("master fingerprint must round-trip",
                masterKey.getFingerprint(), repository.getFingerprintByKeyId(masterKeyId));
    }

    @Test
    public void revokedSubkeyFlagMatchesTheRing() {
        Map<Long, Boolean> expectedRevoked = new HashMap<>();
        int revokedCount = 0;
        for (UncachedPublicKey key : KeyringTestingHelper.publicKeysOf(testRing)) {
            expectedRevoked.put(key.getKeyId(), key.isMaybeRevoked());
            if (key.isMaybeRevoked()) {
                revokedCount++;
            }
        }
        Assert.assertTrue("fixture is expected to contain a revoked subkey", revokedCount > 0);

        for (Keys storedKey : repository.getSubKeysByMasterKeyId(masterKeyId)) {
            Boolean expected = expectedRevoked.get(storedKey.getKey_id());
            Assert.assertNotNull("unexpected stored subkey " + storedKey.getKey_id(), expected);
            Assert.assertEquals("is_revoked must match the ring for key " + storedKey.getKey_id(),
                    expected.booleanValue(), storedKey.is_revoked());
        }
    }

    @Test
    public void revokedKeysAreExcludedFromEffectiveKeySelection() throws Exception {
        Set<Long> revokedKeyIds = new HashSet<>();
        for (UncachedPublicKey key : KeyringTestingHelper.publicKeysOf(testRing)) {
            if (key.isMaybeRevoked()) {
                revokedKeyIds.add(key.getKeyId());
            }
        }

        long authKeyId = repository.getEffectiveAuthenticationKeyId(masterKeyId);
        Assert.assertFalse("effective auth key must not be a revoked key",
                revokedKeyIds.contains(authKeyId));

        for (Long encryptKeyId : repository.getPublicEncryptionIds(masterKeyId)) {
            Assert.assertFalse("encryption candidates must not include revoked keys",
                    revokedKeyIds.contains(encryptKeyId));
        }
    }

    @Test
    public void expiryFieldIsPersistedConsistently() {
        List<Keys> storedKeys = repository.getSubKeysByMasterKeyId(masterKeyId);

        // every (sub)key of the ring must have a corresponding stored row
        Map<Long, Keys> storedByKeyId = new HashMap<>();
        for (Keys storedKey : storedKeys) {
            storedByKeyId.put(storedKey.getKey_id(), storedKey);
        }
        for (UncachedPublicKey key : KeyringTestingHelper.publicKeysOf(testRing)) {
            Assert.assertNotNull("every ring (sub)key must be stored",
                    storedByKeyId.get(key.getKeyId()));
        }

        // invariants that must hold for every stored key regardless of fixture contents
        for (Keys storedKey : storedKeys) {
            Assert.assertTrue("creation must be a positive unix timestamp",
                    storedKey.getCreation() > 0);
            if (storedKey.getExpiry() != null) {
                Assert.assertTrue("expiry must be a positive unix timestamp",
                        storedKey.getExpiry() > 0);
                Assert.assertTrue("expiry must be after creation",
                        storedKey.getExpiry() > storedKey.getCreation());
            }
        }
    }

    @Test
    public void userIdsAreRankedPrimaryFirstAndRevokedAreFiltered() {
        List<UserId> userIds = repository.getUserIds(masterKeyId);
        Assert.assertFalse("key should expose at least one user id", userIds.isEmpty());

        int rawUserIdCount =
                countRawUserIds(findKey(KeyringTestingHelper.publicKeysOf(testRing), masterKeyId));
        Assert.assertTrue("query must not return more user ids than the ring holds",
                userIds.size() <= rawUserIdCount);

        int previousRank = -1;
        int primaryCount = 0;
        for (int i = 0; i < userIds.size(); i++) {
            UserId userId = userIds.get(i);
            Assert.assertEquals(masterKeyId, userId.master_key_id());
            Assert.assertTrue("user id ranks must be strictly increasing",
                    userId.rank() > previousRank);
            previousRank = userId.rank();
            Assert.assertFalse("revoked user ids must be filtered out of the query",
                    userId.is_revoked());
            if (userId.is_primary()) {
                primaryCount++;
                Assert.assertEquals("the primary user id must sort first", 0, i);
            }
        }
        Assert.assertTrue("there must be at most one primary user id", primaryCount <= 1);
    }

    @Test
    public void unifiedKeyInfoExposesNullableProjectionFields() {
        UnifiedKeyInfo keyInfo = repository.getUnifiedKeyInfo(masterKeyId);
        Assert.assertNotNull(keyInfo);

        // mandatory projection columns
        Assert.assertEquals(masterKeyId, keyInfo.master_key_id());
        Assert.assertNotNull("fingerprint projection must be populated", keyInfo.fingerprint());
        Assert.assertTrue("a saved secret keyring must report has_any_secret",
                keyInfo.has_any_secret());

        // optional/nullable projection columns must be safely accessible (no NPE)
        keyInfo.name();
        keyInfo.email();
        keyInfo.comment();
        keyInfo.verified();

        // derived accessors must stay consistent with the nullable expiry projection
        boolean expectedExpired = keyInfo.expiry() != null
                && keyInfo.expiry() * 1000 < System.currentTimeMillis();
        Assert.assertEquals("is_expired() must agree with the expiry projection",
                expectedExpired, keyInfo.is_expired());
    }

    @Test
    public void queriesForAbsentKeyDegradeGracefully() {
        long absentMasterKeyId = 0x0000DEADBEEF0000L;
        Assert.assertNotEquals("test guard: id must differ from the saved key",
                masterKeyId, absentMasterKeyId);

        Assert.assertNull(repository.getUnifiedKeyInfo(absentMasterKeyId));
        Assert.assertTrue(repository.getSubKeysByMasterKeyId(absentMasterKeyId).isEmpty());
        Assert.assertTrue(repository.getUserIds(absentMasterKeyId).isEmpty());
        Assert.assertNull(repository.getMasterKeyIdBySubkeyId(absentMasterKeyId));

        assertNotFound(() -> repository.getCanonicalizedPublicKeyRing(absentMasterKeyId));
        assertNotFound(() -> repository.getSecretKeyType(absentMasterKeyId));
        assertNotFound(() -> repository.getFingerprintByKeyId(absentMasterKeyId));
    }

    private interface NotFoundCall {
        void run() throws KeyRepository.NotFoundException;
    }

    private static void assertNotFound(NotFoundCall call) {
        try {
            call.run();
            Assert.fail("expected NotFoundException for absent key");
        } catch (KeyRepository.NotFoundException expected) {
            // expected
        }
    }

    private static UncachedPublicKey findKey(List<UncachedPublicKey> keys, long keyId) {
        for (UncachedPublicKey key : keys) {
            if (key.getKeyId() == keyId) {
                return key;
            }
        }
        throw new AssertionError("key not found in ring: " + keyId);
    }

    private static int countRawUserIds(UncachedPublicKey key) {
        int count = 0;
        for (byte[] ignored : key.getUnorderedRawUserIds()) {
            count++;
        }
        return count;
    }
}
