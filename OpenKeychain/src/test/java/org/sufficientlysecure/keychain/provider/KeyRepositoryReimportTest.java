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


import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.shadows.ShadowLog;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.daos.KeyRepository;
import org.sufficientlysecure.keychain.daos.KeyWritableRepository;
import org.sufficientlysecure.keychain.operations.results.SaveKeyringResult;
import org.sufficientlysecure.keychain.pgp.UncachedKeyRing;
import org.sufficientlysecure.keychain.support.KeyringTestingHelper;


/**
 * Regression tests for duplicate import / merge behaviour of the local key data layer.
 *
 * <p>These guard the data-consistency hazards of importing the same key more than once: row
 * duplication, losing an already-stored secret key when re-importing only its public half, and
 * incomplete clean-up on delete. Every test gets an isolated per-method database (Robolectric +
 * {@code Constants.IS_RUNNING_UNITTEST}); fresh repository instances are created per operation to
 * mirror how independent import operations behave in production.
 */
@RunWith(KeychainTestRunner.class)
public class KeyRepositoryReimportTest {

    private static final String MULTISUB_WITH_REVOKED =
            "/test-keys/authenticate_multisub_with_revoked.asc";

    private KeyWritableRepository repository;

    @BeforeClass
    public static void setUpOnce() {
        ShadowLog.stream = System.out;
    }

    @Before
    public void setUp() {
        repository = KeyWritableRepository.create(RuntimeEnvironment.getApplication());
    }

    @Test
    public void reimportingIdenticalSecretKeyringKeepsOneConsistentCopy() throws Exception {
        UncachedKeyRing ring = KeyringTestingHelper.readRingFromResource(MULTISUB_WITH_REVOKED);
        long masterKeyId = ring.getMasterKeyId();

        SaveKeyringResult firstImport = newRepository().saveSecretKeyRing(ring);
        Assert.assertTrue("first secret import should succeed", firstImport.success());

        int masterKeyCount = repository.getAllMasterKeyIds().size();
        int subKeyCount = repository.getSubKeysByMasterKeyId(masterKeyId).size();
        int userIdCount = repository.getUserIds(masterKeyId).size();

        SaveKeyringResult secondImport = newRepository().saveSecretKeyRing(ring);
        Assert.assertTrue("re-import should succeed", secondImport.success());

        Assert.assertEquals("re-import must not add a master key",
                masterKeyCount, repository.getAllMasterKeyIds().size());
        Assert.assertEquals("re-import must not duplicate subkeys",
                subKeyCount, repository.getSubKeysByMasterKeyId(masterKeyId).size());
        Assert.assertEquals("re-import must not duplicate user ids",
                userIdCount, repository.getUserIds(masterKeyId).size());
    }

    @Test
    public void reimportingIdenticalPublicKeyringKeepsOneConsistentCopy() throws Exception {
        UncachedKeyRing publicRing =
                KeyringTestingHelper.readRingFromResource(MULTISUB_WITH_REVOKED).extractPublicKeyRing();
        long masterKeyId = publicRing.getMasterKeyId();

        SaveKeyringResult firstImport = newRepository().savePublicKeyRing(publicRing);
        Assert.assertTrue("first public import should succeed", firstImport.success());

        int masterKeyCount = repository.getAllMasterKeyIds().size();
        int subKeyCount = repository.getSubKeysByMasterKeyId(masterKeyId).size();
        int userIdCount = repository.getUserIds(masterKeyId).size();

        SaveKeyringResult secondImport = newRepository().savePublicKeyRing(publicRing);
        Assert.assertTrue("re-import should succeed", secondImport.success());
        Assert.assertTrue("re-import of an existing public key should be flagged as an update",
                secondImport.updated());

        Assert.assertEquals("re-import must not add a master key",
                masterKeyCount, repository.getAllMasterKeyIds().size());
        Assert.assertEquals("re-import must not duplicate subkeys",
                subKeyCount, repository.getSubKeysByMasterKeyId(masterKeyId).size());
        Assert.assertEquals("re-import must not duplicate user ids",
                userIdCount, repository.getUserIds(masterKeyId).size());
    }

    @Test
    public void reimportingPublicKeyringPreservesExistingSecret() throws Exception {
        UncachedKeyRing secretRing = KeyringTestingHelper.readRingFromResource(MULTISUB_WITH_REVOKED);
        long masterKeyId = secretRing.getMasterKeyId();

        Assert.assertTrue(newRepository().saveSecretKeyRing(secretRing).success());
        // sanity: the secret key is present
        repository.getCanonicalizedSecretKeyRing(masterKeyId);
        Assert.assertTrue(repository.getUnifiedKeyInfo(masterKeyId).has_any_secret());

        // re-importing only the public half must not drop the stored secret key
        UncachedKeyRing publicRing = secretRing.extractPublicKeyRing();
        SaveKeyringResult publicReimport = newRepository().savePublicKeyRing(publicRing);
        Assert.assertTrue("public re-import should succeed", publicReimport.success());

        // the secret key must still be retrievable and still reported
        repository.getCanonicalizedSecretKeyRing(masterKeyId);
        Assert.assertTrue("public re-import must not drop the existing secret",
                repository.getUnifiedKeyInfo(masterKeyId).has_any_secret());
    }

    @Test
    public void deletingKeyRingRemovesAllAssociatedRows() throws Exception {
        UncachedKeyRing ring = KeyringTestingHelper.readRingFromResource(MULTISUB_WITH_REVOKED);
        long masterKeyId = ring.getMasterKeyId();

        Assert.assertTrue(newRepository().saveSecretKeyRing(ring).success());
        Assert.assertFalse(repository.getSubKeysByMasterKeyId(masterKeyId).isEmpty());

        boolean deleted = newRepository().deleteKeyRing(masterKeyId);
        Assert.assertTrue("delete should report success", deleted);

        Assert.assertNull(repository.getUnifiedKeyInfo(masterKeyId));
        Assert.assertTrue("subkeys must be removed on cascade",
                repository.getSubKeysByMasterKeyId(masterKeyId).isEmpty());
        Assert.assertTrue("user ids must be removed on cascade",
                repository.getUserIds(masterKeyId).isEmpty());
        Assert.assertTrue("no master keys should remain",
                repository.getAllMasterKeyIds().isEmpty());

        try {
            repository.getCanonicalizedPublicKeyRing(masterKeyId);
            Assert.fail("expected NotFoundException after delete");
        } catch (KeyRepository.NotFoundException expected) {
            // expected
        }
    }

    private static KeyWritableRepository newRepository() {
        return KeyWritableRepository.create(RuntimeEnvironment.getApplication());
    }
}
