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

package org.sufficientlysecure.keychain.support;


import java.security.Security;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.shadows.ShadowLog;
import org.sufficientlysecure.keychain.daos.KeyRepository;
import org.sufficientlysecure.keychain.daos.KeyWritableRepository;
import org.sufficientlysecure.keychain.operations.results.OperationResult.OperationLog;
import org.sufficientlysecure.keychain.operations.results.PgpEditKeyResult;
import org.sufficientlysecure.keychain.pgp.CanonicalizedSecretKeyRing;
import org.sufficientlysecure.keychain.pgp.PgpKeyOperation;
import org.sufficientlysecure.keychain.pgp.ProgressScaler;
import org.sufficientlysecure.keychain.pgp.UncachedKeyRing;
import org.sufficientlysecure.keychain.service.ChangeUnlockParcel;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.Algorithm;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.Curve;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.SubkeyAdd;
import org.sufficientlysecure.keychain.service.input.CryptoInputParcel;
import org.sufficientlysecure.keychain.util.Passphrase;

/**
 * Helper for isolated database tests.
 *
 * <p>Provides factory methods for creating fresh repository instances, generating test keys
 * with specific properties, and cleaning up after tests. Each helper instance tracks
 * inserted key IDs so they can be cleaned up in {@link #cleanupInsertedKeys()}.</p>
 *
 * <p>Usage pattern in test classes:
 * <pre>
 *   DatabaseTestHelper helper;
 *
 *   {@literal @}Before
 *   public void setUp() {
 *       helper = new DatabaseTestHelper();
 *   }
 *
 *   {@literal @}After
 *   public void tearDown() {
 *       helper.cleanupInsertedKeys();
 *   }
 * </pre></p>
 */
public class DatabaseTestHelper {

    private static final Passphrase TEST_PASSPHRASE = new Passphrase("test-passphrase");

    private final List<Long> insertedMasterKeyIds = new ArrayList<>();

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        }
        ShadowLog.stream = System.out;
    }

    // --- Repository factories ---

    /** Creates a fresh writable repository instance. */
    public KeyWritableRepository createWritableRepository() {
        return KeyWritableRepository.create(RuntimeEnvironment.getApplication());
    }

    /** Creates a fresh read-only repository instance. */
    public KeyRepository createReadRepository() {
        return KeyRepository.create(RuntimeEnvironment.getApplication());
    }

    // --- Key generation helpers ---

    /**
     * Generates a secret key ring with a master key (certify) and two subkeys (sign + encrypt).
     * The key has a single user ID.
     *
     * @param userId the user ID string
     * @return the generated UncachedKeyRing (secret)
     */
    public UncachedKeyRing generateSimpleKey(String userId) throws Exception {
        SaveKeyringParcel.Builder builder = SaveKeyringParcel.buildNewKeyringParcel();
        builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                Algorithm.ECDSA, 0, Curve.NIST_P256, KeyFlags.CERTIFY_OTHER, 0L));
        builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                Algorithm.ECDSA, 0, Curve.NIST_P256, KeyFlags.SIGN_DATA, 0L));
        builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                Algorithm.ECDH, 0, Curve.NIST_P256, KeyFlags.ENCRYPT_COMMS, 0L));
        builder.addUserId(userId);
        builder.setNewUnlock(ChangeUnlockParcel.createUnLockParcelForNewKey(TEST_PASSPHRASE));

        PgpKeyOperation op = new PgpKeyOperation(null);
        PgpEditKeyResult result = op.createSecretKeyRing(builder.build());
        if (!result.success()) {
            throw new RuntimeException("Key generation failed: " + result.getLog().getLast().mType);
        }
        UncachedKeyRing ring = result.getRing();
        return ring.canonicalize(new OperationLog(), 0).getUncachedKeyRing();
    }

    /**
     * Generates a secret key ring with multiple user IDs.
     * The first user ID will be the primary one.
     *
     * @param userIds the user ID strings (first will be primary)
     * @return the generated UncachedKeyRing (secret)
     */
    public UncachedKeyRing generateKeyWithMultipleUserIds(List<String> userIds) throws Exception {
        SaveKeyringParcel.Builder builder = SaveKeyringParcel.buildNewKeyringParcel();
        builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                Algorithm.ECDSA, 0, Curve.NIST_P256, KeyFlags.CERTIFY_OTHER, 0L));
        builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                Algorithm.ECDSA, 0, Curve.NIST_P256, KeyFlags.SIGN_DATA, 0L));
        builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                Algorithm.ECDH, 0, Curve.NIST_P256, KeyFlags.ENCRYPT_COMMS, 0L));
        for (String uid : userIds) {
            builder.addUserId(uid);
        }
        builder.setNewUnlock(ChangeUnlockParcel.createUnLockParcelForNewKey(TEST_PASSPHRASE));

        PgpKeyOperation op = new PgpKeyOperation(null);
        PgpEditKeyResult result = op.createSecretKeyRing(builder.build());
        if (!result.success()) {
            throw new RuntimeException("Key generation failed: " + result.getLog().getLast().mType);
        }
        UncachedKeyRing ring = result.getRing();
        return ring.canonicalize(new OperationLog(), 0).getUncachedKeyRing();
    }

    /**
     * Generates a key with a subkey that has an expiry date.
     *
     * @param userId              the user ID string
     * @param expirySecondsFromNow number of seconds from now until expiry
     * @return the generated UncachedKeyRing (secret)
     */
    public UncachedKeyRing generateKeyWithSubkeyExpiry(String userId, long expirySecondsFromNow)
            throws Exception {
        long expiryUnix = (System.currentTimeMillis() / 1000) + expirySecondsFromNow;

        SaveKeyringParcel.Builder builder = SaveKeyringParcel.buildNewKeyringParcel();
        builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                Algorithm.ECDSA, 0, Curve.NIST_P256, KeyFlags.CERTIFY_OTHER, 0L));
        builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                Algorithm.ECDH, 0, Curve.NIST_P256, KeyFlags.ENCRYPT_COMMS, expiryUnix));
        builder.addUserId(userId);
        builder.setNewUnlock(ChangeUnlockParcel.createUnLockParcelForNewKey(TEST_PASSPHRASE));

        PgpKeyOperation op = new PgpKeyOperation(null);
        PgpEditKeyResult result = op.createSecretKeyRing(builder.build());
        if (!result.success()) {
            throw new RuntimeException("Key generation failed: " + result.getLog().getLast().mType);
        }
        UncachedKeyRing ring = result.getRing();
        return ring.canonicalize(new OperationLog(), 0).getUncachedKeyRing();
    }

    /**
     * Generates a key and then modifies it to revoke a specific user ID.
     *
     * @param userIds     the initial user IDs (at least 2 recommended)
     * @param uidToRevoke the user ID to revoke
     * @return the modified UncachedKeyRing (secret) with the UID revoked
     */
    public UncachedKeyRing generateKeyWithRevokedUserId(List<String> userIds, String uidToRevoke)
            throws Exception {
        UncachedKeyRing ring = generateKeyWithMultipleUserIds(userIds);

        // Now revoke the specified user ID
        SaveKeyringParcel.Builder builder = SaveKeyringParcel.buildChangeKeyringParcel(
                ring.getMasterKeyId(), ring.getFingerprint());
        builder.addRevokeUserId(uidToRevoke);

        CanonicalizedSecretKeyRing secretRing =
                new CanonicalizedSecretKeyRing(ring.getEncoded(), false);
        PgpKeyOperation op = new PgpKeyOperation(new ProgressScaler(null, 0, 100, 100));
        PgpEditKeyResult result = op.modifySecretKeyRing(
                secretRing,
                CryptoInputParcel.createCryptoInputParcel(new Date(), TEST_PASSPHRASE),
                builder.build());
        if (!result.success()) {
            throw new RuntimeException("Key modification (revoke UID) failed: "
                    + result.getLog().getLast().mType);
        }
        UncachedKeyRing modifiedRing = result.getRing();
        return modifiedRing.canonicalize(new OperationLog(), 0).getUncachedKeyRing();
    }

    /**
     * Generates a key and then modifies it to revoke a subkey.
     *
     * @param userId     the user ID string
     * @param subkeyRank the rank of the subkey to revoke (1-based, 0 = master)
     * @return the modified UncachedKeyRing (secret) with the subkey revoked
     */
    public UncachedKeyRing generateKeyWithRevokedSubkey(String userId, int subkeyRank)
            throws Exception {
        UncachedKeyRing ring = generateSimpleKey(userId);

        // Find the subkey ID at the given rank
        long subkeyId = KeyringTestingHelper.getSubkeyId(ring, subkeyRank);

        SaveKeyringParcel.Builder builder = SaveKeyringParcel.buildChangeKeyringParcel(
                ring.getMasterKeyId(), ring.getFingerprint());
        builder.addRevokeSubkey(subkeyId);

        CanonicalizedSecretKeyRing secretRing =
                new CanonicalizedSecretKeyRing(ring.getEncoded(), false);
        PgpKeyOperation op = new PgpKeyOperation(new ProgressScaler(null, 0, 100, 100));
        PgpEditKeyResult result = op.modifySecretKeyRing(
                secretRing,
                CryptoInputParcel.createCryptoInputParcel(new Date(), TEST_PASSPHRASE),
                builder.build());
        if (!result.success()) {
            throw new RuntimeException("Key modification (revoke subkey) failed: "
                    + result.getLog().getLast().mType);
        }
        UncachedKeyRing modifiedRing = result.getRing();
        return modifiedRing.canonicalize(new OperationLog(), 0).getUncachedKeyRing();
    }

    /**
     * Generates a key with an authentication subkey.
     *
     * @param userId the user ID string
     * @return the generated UncachedKeyRing (secret) with certify + sign + encrypt + auth subkeys
     */
    public UncachedKeyRing generateKeyWithAuthSubkey(String userId) throws Exception {
        SaveKeyringParcel.Builder builder = SaveKeyringParcel.buildNewKeyringParcel();
        builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                Algorithm.ECDSA, 0, Curve.NIST_P256, KeyFlags.CERTIFY_OTHER, 0L));
        builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                Algorithm.ECDSA, 0, Curve.NIST_P256, KeyFlags.SIGN_DATA, 0L));
        builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                Algorithm.ECDH, 0, Curve.NIST_P256, KeyFlags.ENCRYPT_COMMS, 0L));
        builder.addSubkeyAdd(SubkeyAdd.createSubkeyAdd(
                Algorithm.ECDSA, 0, Curve.NIST_P256, KeyFlags.AUTHENTICATION, 0L));
        builder.addUserId(userId);
        builder.setNewUnlock(ChangeUnlockParcel.createUnLockParcelForNewKey(TEST_PASSPHRASE));

        PgpKeyOperation op = new PgpKeyOperation(null);
        PgpEditKeyResult result = op.createSecretKeyRing(builder.build());
        if (!result.success()) {
            throw new RuntimeException("Key generation failed: " + result.getLog().getLast().mType);
        }
        UncachedKeyRing ring = result.getRing();
        return ring.canonicalize(new OperationLog(), 0).getUncachedKeyRing();
    }

    // --- Save-and-track helpers ---

    /**
     * Saves a public key ring and tracks the master key ID for cleanup.
     *
     * @return true if save was successful
     */
    public boolean saveAndTrackPublicKeyRing(UncachedKeyRing ring) throws Exception {
        KeyWritableRepository repo = createWritableRepository();
        boolean success = repo.savePublicKeyRing(ring).success();
        if (success) {
            insertedMasterKeyIds.add(ring.getMasterKeyId());
        }
        return success;
    }

    /**
     * Saves a secret key ring and tracks the master key ID for cleanup.
     *
     * @return true if save was successful
     */
    public boolean saveAndTrackSecretKeyRing(UncachedKeyRing ring) throws Exception {
        KeyWritableRepository repo = createWritableRepository();
        boolean success = repo.saveSecretKeyRing(ring).success();
        if (success) {
            insertedMasterKeyIds.add(ring.getMasterKeyId());
        }
        return success;
    }

    /**
     * Deletes all keys that were inserted via {@link #saveAndTrackPublicKeyRing}
     * or {@link #saveAndTrackSecretKeyRing}. Call this in @After.
     */
    public void cleanupInsertedKeys() {
        KeyWritableRepository repo = createWritableRepository();
        for (long masterKeyId : insertedMasterKeyIds) {
            try {
                repo.deleteKeyRing(masterKeyId);
            } catch (Exception ignored) {
                // Best effort cleanup
            }
        }
        insertedMasterKeyIds.clear();
    }

    /**
     * Manually tracks a master key ID for cleanup. Use this when saving keys
     * directly via a repository without using the saveAndTrack helpers.
     */
    public void trackMasterKeyId(long masterKeyId) {
        insertedMasterKeyIds.add(masterKeyId);
    }

    /**
     * Returns a copy of the tracked master key IDs inserted during this test.
     */
    public List<Long> getInsertedMasterKeyIds() {
        return new ArrayList<>(insertedMasterKeyIds);
    }

    /** Returns the test passphrase used for key generation. */
    public static Passphrase getTestPassphrase() {
        return TEST_PASSPHRASE;
    }
}
