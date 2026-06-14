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


import java.util.List;

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
import org.sufficientlysecure.keychain.model.UserId;
import org.sufficientlysecure.keychain.operations.results.SaveKeyringResult;
import org.sufficientlysecure.keychain.pgp.UncachedKeyRing;
import org.sufficientlysecure.keychain.support.DatabaseTestHelper;
import org.sufficientlysecure.keychain.support.KeyringTestingHelper;

/**
 * Tests covering duplicate import and merge behavior.
 *
 * <p>Verifies:
 * <ul>
 *   <li>Re-importing the same key returns UPDATED flag</li>
 *   <li>Data consistency after re-import (subkey count, UID count unchanged)</li>
 *   <li>Importing public key then secret key merges correctly</li>
 *   <li>Importing secret key then public key merges correctly</li>
 *   <li>Cooper pair collision keys are handled correctly</li>
 *   <li>Symantec key pair (secret without self-cert) merges correctly</li>
 * </ul></p>
 *
 * <p>Each test is isolated: keys inserted during a test are deleted in {@link #tearDown()}.</p>
 */
@RunWith(KeychainTestRunner.class)
public class DuplicateImportMergeTest {

    private DatabaseTestHelper helper;

    @Before
    public void setUp() {
        helper = new DatabaseTestHelper();
    }

    @After
    public void tearDown() {
        helper.cleanupInsertedKeys();
    }

    // --- Same key re-import ---

    @Test
    public void testReimportSamePublicKeyReturnsUpdated() throws Exception {
        UncachedKeyRing ring = helper.generateSimpleKey("Reimport <reimport@example.com>");
        UncachedKeyRing pubRing = ring.extractPublicKeyRing();

        KeyWritableRepository repo = helper.createWritableRepository();

        // First import
        SaveKeyringResult first = repo.savePublicKeyRing(pubRing);
        Assert.assertTrue("first import should succeed", first.success());
        helper.trackMasterKeyId(ring.getMasterKeyId());

        // Second import of same key
        SaveKeyringResult second = repo.savePublicKeyRing(pubRing);
        Assert.assertTrue("second import should succeed", second.success());
        Assert.assertTrue("second import should indicate UPDATED",
                second.updated());
    }

    @Test
    public void testReimportSameSecretKeyReturnsUpdated() throws Exception {
        UncachedKeyRing ring = helper.generateSimpleKey("ReimportSec <reimportsec@example.com>");

        KeyWritableRepository repo = helper.createWritableRepository();

        // First import
        SaveKeyringResult first = repo.saveSecretKeyRing(ring);
        Assert.assertTrue("first import should succeed", first.success());
        helper.trackMasterKeyId(ring.getMasterKeyId());

        // Second import of same key
        SaveKeyringResult second = repo.saveSecretKeyRing(ring);
        Assert.assertTrue("second import should succeed", second.success());
        Assert.assertTrue("second import should indicate UPDATED",
                second.updated());
    }

    @Test
    public void testReimportPreservesSubkeyCount() throws Exception {
        UncachedKeyRing ring = helper.generateSimpleKey("PreserveSubkeys <preserve@example.com>");
        long masterKeyId = ring.getMasterKeyId();
        UncachedKeyRing pubRing = ring.extractPublicKeyRing();

        KeyWritableRepository repo = helper.createWritableRepository();

        // First import
        repo.savePublicKeyRing(pubRing);
        helper.trackMasterKeyId(masterKeyId);

        KeyRepository readRepo = helper.createReadRepository();
        List<Keys> subkeysBefore = readRepo.getSubKeysByMasterKeyId(masterKeyId);
        int countBefore = subkeysBefore.size();

        // Re-import
        repo.savePublicKeyRing(pubRing);

        List<Keys> subkeysAfter = readRepo.getSubKeysByMasterKeyId(masterKeyId);
        Assert.assertEquals("subkey count should be preserved after re-import",
                countBefore, subkeysAfter.size());
    }

    @Test
    public void testReimportPreservesUserIdCount() throws Exception {
        UncachedKeyRing ring = helper.generateSimpleKey("PreserveUIDs <preserveuids@example.com>");
        long masterKeyId = ring.getMasterKeyId();
        UncachedKeyRing pubRing = ring.extractPublicKeyRing();

        KeyWritableRepository repo = helper.createWritableRepository();

        // First import
        repo.savePublicKeyRing(pubRing);
        helper.trackMasterKeyId(masterKeyId);

        KeyRepository readRepo = helper.createReadRepository();
        List<UserId> uidsBefore = readRepo.getUserIds(masterKeyId);
        int countBefore = uidsBefore.size();

        // Re-import
        repo.savePublicKeyRing(pubRing);

        List<UserId> uidsAfter = readRepo.getUserIds(masterKeyId);
        Assert.assertEquals("UID count should be preserved after re-import",
                countBefore, uidsAfter.size());
    }

    @Test
    public void testReimportPreservesFingerprint() throws Exception {
        UncachedKeyRing ring = helper.generateSimpleKey("PreserveFP <preservefp@example.com>");
        long masterKeyId = ring.getMasterKeyId();
        UncachedKeyRing pubRing = ring.extractPublicKeyRing();

        KeyWritableRepository repo = helper.createWritableRepository();

        // First import
        repo.savePublicKeyRing(pubRing);
        helper.trackMasterKeyId(masterKeyId);

        KeyRepository readRepo = helper.createReadRepository();
        UnifiedKeyInfo infoBefore = readRepo.getUnifiedKeyInfo(masterKeyId);
        byte[] fpBefore = infoBefore.fingerprint();

        // Re-import
        repo.savePublicKeyRing(pubRing);

        UnifiedKeyInfo infoAfter = readRepo.getUnifiedKeyInfo(masterKeyId);
        Assert.assertArrayEquals("fingerprint should be preserved after re-import",
                fpBefore, infoAfter.fingerprint());
    }

    // --- Public then secret merge ---

    @Test
    public void testImportPublicThenSecretMergesCorrectly() throws Exception {
        UncachedKeyRing ring = helper.generateSimpleKey("PubThenSec <pubthensec@example.com>");
        long masterKeyId = ring.getMasterKeyId();
        UncachedKeyRing pubRing = ring.extractPublicKeyRing();

        KeyWritableRepository repo = helper.createWritableRepository();

        // Import public first
        SaveKeyringResult pubResult = repo.savePublicKeyRing(pubRing);
        Assert.assertTrue("public import should succeed", pubResult.success());
        helper.trackMasterKeyId(masterKeyId);

        // Then import secret
        SaveKeyringResult secResult = repo.saveSecretKeyRing(ring);
        Assert.assertTrue("secret import should succeed", secResult.success());

        // Verify secret is now available
        KeyRepository readRepo = helper.createReadRepository();
        UnifiedKeyInfo info = readRepo.getUnifiedKeyInfo(masterKeyId);
        Assert.assertNotNull("info should not be null", info);
        Assert.assertTrue("key should have secret material after secret import",
                info.has_any_secret());
    }

    @Test
    public void testImportSecretThenPublicMergesCorrectly() throws Exception {
        UncachedKeyRing ring = helper.generateSimpleKey("SecThenPub <secthenpub@example.com>");
        long masterKeyId = ring.getMasterKeyId();
        UncachedKeyRing pubRing = ring.extractPublicKeyRing();

        KeyWritableRepository repo = helper.createWritableRepository();

        // Import secret first
        SaveKeyringResult secResult = repo.saveSecretKeyRing(ring);
        Assert.assertTrue("secret import should succeed", secResult.success());
        helper.trackMasterKeyId(masterKeyId);

        // Then import public
        SaveKeyringResult pubResult = repo.savePublicKeyRing(pubRing);
        Assert.assertTrue("public import should succeed", pubResult.success());

        // Verify data is consistent
        KeyRepository readRepo = helper.createReadRepository();
        UnifiedKeyInfo info = readRepo.getUnifiedKeyInfo(masterKeyId);
        Assert.assertNotNull("info should not be null", info);
        Assert.assertTrue("key should still have secret material",
                info.has_any_secret());
    }

    // --- Cooper pair collision ---

    @Test
    public void testCooperPairFirstKeySucceedsSecondFails() throws Exception {
        UncachedKeyRing first = KeyringTestingHelper.readRingFromResource(
                "/test-keys/cooperpair/9E669861368BCA0BE42DAF7DDDA252EBB8EBE1AF.asc");
        UncachedKeyRing second = KeyringTestingHelper.readRingFromResource(
                "/test-keys/cooperpair/A55120427374F3F7AA5F1166DDA252EBB8EBE1AF.asc");

        KeyWritableRepository repo = helper.createWritableRepository();

        SaveKeyringResult firstResult = repo.savePublicKeyRing(first);
        Assert.assertTrue("first cooper pair key import should succeed", firstResult.success());
        helper.trackMasterKeyId(first.getMasterKeyId());

        SaveKeyringResult secondResult = repo.savePublicKeyRing(second);
        Assert.assertFalse("second cooper pair key import should fail (collision)",
                secondResult.success());
    }

    // --- Symantec secret-without-self-cert ---

    @Test
    public void testSymantecPublicKeyThenSecretMerge() throws Exception {
        UncachedKeyRing pubKey = KeyringTestingHelper.readRingFromResource(
                "/test-keys/symantec_public.asc");
        UncachedKeyRing secKey = KeyringTestingHelper.readRingFromResource(
                "/test-keys/symantec_secret.asc");

        KeyWritableRepository repo = helper.createWritableRepository();

        // Import public first
        SaveKeyringResult pubResult = repo.savePublicKeyRing(pubKey);
        Assert.assertTrue("public keyring import should succeed", pubResult.success());
        helper.trackMasterKeyId(pubKey.getMasterKeyId());

        // Then import secret (which lacks self-certificates)
        SaveKeyringResult secResult = repo.saveSecretKeyRing(secKey);
        Assert.assertTrue("secret keyring import after pub should succeed (merge self-certs)",
                secResult.success());

        // Verify the key has secret material
        KeyRepository readRepo = helper.createReadRepository();
        UnifiedKeyInfo info = readRepo.getUnifiedKeyInfo(pubKey.getMasterKeyId());
        Assert.assertNotNull("info should not be null", info);
        Assert.assertTrue("key should have secret material", info.has_any_secret());
    }

    @Test
    public void testSymantecSecretAloneFails() throws Exception {
        UncachedKeyRing secKey = KeyringTestingHelper.readRingFromResource(
                "/test-keys/symantec_secret.asc");

        KeyWritableRepository repo = helper.createWritableRepository();

        // Import secret alone (without public key) should fail due to missing self-cert
        SaveKeyringResult result = repo.saveSecretKeyRing(secKey);
        Assert.assertFalse("secret keyring import without public key should fail",
                result.success());
    }

    // --- Delete then re-import ---

    @Test
    public void testDeleteThenReimportSucceeds() throws Exception {
        UncachedKeyRing ring = helper.generateSimpleKey("DelReimport <delreimport@example.com>");
        long masterKeyId = ring.getMasterKeyId();

        KeyWritableRepository repo = helper.createWritableRepository();

        // First import
        SaveKeyringResult first = repo.saveSecretKeyRing(ring);
        Assert.assertTrue("first import should succeed", first.success());

        // Delete
        boolean deleted = repo.deleteKeyRing(masterKeyId);
        Assert.assertTrue("delete should succeed", deleted);

        // Re-import
        SaveKeyringResult second = repo.saveSecretKeyRing(ring);
        Assert.assertTrue("re-import after delete should succeed", second.success());
        helper.trackMasterKeyId(masterKeyId);

        // Verify data is accessible
        KeyRepository readRepo = helper.createReadRepository();
        UnifiedKeyInfo info = readRepo.getUnifiedKeyInfo(masterKeyId);
        Assert.assertNotNull("info should be available after re-import", info);
    }

    @Test
    public void testReimportAfterDeleteIsNotUpdated() throws Exception {
        UncachedKeyRing ring = helper.generateSimpleKey("NotUpdated <notupdated@example.com>");
        long masterKeyId = ring.getMasterKeyId();
        UncachedKeyRing pubRing = ring.extractPublicKeyRing();

        KeyWritableRepository repo = helper.createWritableRepository();

        // Import, delete, re-import
        repo.savePublicKeyRing(pubRing);
        repo.deleteKeyRing(masterKeyId);

        SaveKeyringResult result = repo.savePublicKeyRing(pubRing);
        Assert.assertTrue("re-import should succeed", result.success());
        // After delete, this is effectively a new import, not an update
        Assert.assertFalse("re-import after delete should not have UPDATED flag",
                result.updated());
        helper.trackMasterKeyId(masterKeyId);
    }

    // --- Data consistency after merge ---

    @Test
    public void testSubkeyDataConsistentAfterReimport() throws Exception {
        UncachedKeyRing ring = helper.generateKeyWithAuthSubkey("Consistent <consistent@example.com>");
        long masterKeyId = ring.getMasterKeyId();

        KeyWritableRepository repo = helper.createWritableRepository();

        // First import
        repo.saveSecretKeyRing(ring);
        helper.trackMasterKeyId(masterKeyId);

        KeyRepository readRepo = helper.createReadRepository();
        List<Keys> subkeysBefore = readRepo.getSubKeysByMasterKeyId(masterKeyId);

        // Record properties before
        int countBefore = subkeysBefore.size();
        long[] keyIdsBefore = new long[subkeysBefore.size()];
        boolean[] canSignBefore = new boolean[subkeysBefore.size()];
        boolean[] canEncryptBefore = new boolean[subkeysBefore.size()];
        for (int i = 0; i < subkeysBefore.size(); i++) {
            keyIdsBefore[i] = subkeysBefore.get(i).getKey_id();
            canSignBefore[i] = subkeysBefore.get(i).getCan_sign();
            canEncryptBefore[i] = subkeysBefore.get(i).getCan_encrypt();
        }

        // Re-import
        repo.saveSecretKeyRing(ring);

        // Verify consistency
        List<Keys> subkeysAfter = readRepo.getSubKeysByMasterKeyId(masterKeyId);
        Assert.assertEquals("subkey count should be preserved", countBefore, subkeysAfter.size());

        for (int i = 0; i < subkeysAfter.size(); i++) {
            Assert.assertEquals("key_id at rank " + i + " should be preserved",
                    keyIdsBefore[i], (long) subkeysAfter.get(i).getKey_id());
            Assert.assertEquals("can_sign at rank " + i + " should be preserved",
                    canSignBefore[i], subkeysAfter.get(i).getCan_sign());
            Assert.assertEquals("can_encrypt at rank " + i + " should be preserved",
                    canEncryptBefore[i], subkeysAfter.get(i).getCan_encrypt());
        }
    }
}
