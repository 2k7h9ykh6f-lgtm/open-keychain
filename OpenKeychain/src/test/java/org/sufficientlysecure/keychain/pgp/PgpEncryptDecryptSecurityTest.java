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

package org.sufficientlysecure.keychain.pgp;


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.security.Security;
import java.util.ArrayList;
import java.util.Date;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openintents.openpgp.OpenPgpDecryptionResult;
import org.openintents.openpgp.OpenPgpSignatureResult;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.shadows.ShadowLog;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.daos.KeyWritableRepository;
import org.sufficientlysecure.keychain.operations.results.DecryptVerifyResult;
import org.sufficientlysecure.keychain.operations.results.OperationResult.LogType;
import org.sufficientlysecure.keychain.operations.results.OperationResult.OperationLog;
import org.sufficientlysecure.keychain.operations.results.PgpSignEncryptResult;
import org.sufficientlysecure.keychain.service.input.CryptoInputParcel;
import org.sufficientlysecure.keychain.support.KeyringTestingHelper;
import org.sufficientlysecure.keychain.util.InputData;
import org.sufficientlysecure.keychain.util.Passphrase;
import org.sufficientlysecure.keychain.util.TestingUtils;


/**
 * Security-focused tests for PGP encrypt/decrypt/sign/verify operations.
 *
 * Covers combination scenarios and error inputs that the happy-path tests in
 * {@link PgpEncryptDecryptTest} do not exercise:
 * <ul>
 *   <li>Signer mismatch (missing / unknown signing key)</li>
 *   <li>Missing private key for decryption</li>
 *   <li>Wrong passphrase (asymmetric and symmetric)</li>
 *   <li>Corrupted ciphertext and corrupted cleartext signature</li>
 *   <li>Sign-only message round-trip</li>
 *   <li>Encrypt-then-sign round-trip</li>
 *   <li>Detached-signature verification with wrong data / wrong signer</li>
 * </ul>
 *
 * Uses the same test keys from {@code test-keys/encrypt_decrypt_key_*.sec} as
 * the existing test suite, and reuses the
 * {@link #operationWithFakePassphraseCache} helper pattern.
 */
@SuppressWarnings("WeakerAccess")
@RunWith(KeychainTestRunner.class)
public class PgpEncryptDecryptSecurityTest {

    static UncachedKeyRing mStaticRing1, mStaticRing2;
    static Passphrase mKeyPhrase1, mKeyPhrase2;
    static PrintStream oldShadowStream;

    static final String PLAINTEXT = "dies ist ein plaintext ☭";

    /**
     * Lightweight holder that pairs a {@link DecryptVerifyResult} with the
     * bytes written to the {@link ByteArrayOutputStream} during the 4-arg
     * {@code execute()} call.  The 4-arg overload does <em>not</em> populate
     * {@code result.getOutputBytes()}, so callers must use {@link #output}.
     */
    static class DecryptOutput {
        final DecryptVerifyResult result;
        final byte[] output;

        DecryptOutput(DecryptVerifyResult result, byte[] output) {
            this.result = result;
            this.output = output;
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    // Setup
    // ──────────────────────────────────────────────────────────────────────

    @BeforeClass
    public static void setUpOnce() throws Exception {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        oldShadowStream = ShadowLog.stream;

        mKeyPhrase1 = new Passphrase("RsKrW^raOPcnQ=ZJr-pP");
        mStaticRing1 = KeyringTestingHelper.readRingFromResource(
                "/test-keys/encrypt_decrypt_key_1.sec");

        mKeyPhrase2 = new Passphrase("x");
        mStaticRing2 = KeyringTestingHelper.readRingFromResource(
                "/test-keys/encrypt_decrypt_key_2.sec");
    }

    @Before
    public void setUp() {
        KeyWritableRepository databaseInteractor =
                KeyWritableRepository.create(RuntimeEnvironment.getApplication());

        ShadowLog.stream = oldShadowStream;

        databaseInteractor.saveSecretKeyRing(mStaticRing1);
        databaseInteractor.saveSecretKeyRing(mStaticRing2);

        ShadowLog.stream = System.out;
    }

    // ======================================================================
    //  Table-driven: Wrong passphrase (asymmetric + symmetric)
    // ======================================================================

    @Test
    public void testDecryptWithWrongPassphrase() throws Exception {
        byte[] asymmetricCiphertext = encryptToKeys(
                PLAINTEXT, new long[] { mStaticRing1.getMasterKeyId() });
        byte[] symmetricCiphertext = encryptSymmetric(
                PLAINTEXT, TestingUtils.testPassphrase0);
        Passphrase wrongPass = new Passphrase("this is definitely the wrong passphrase");

        // Each row: { scenario label, ciphertext, wrong passphrase, allowSymmetric }
        Object[][] scenarios = {
                { "wrong_asymmetric_passphrase", asymmetricCiphertext, wrongPass, false },
                { "wrong_symmetric_passphrase",  symmetricCiphertext,  wrongPass, true  },
        };

        for (Object[] row : scenarios) {
            String scenario          = (String) row[0];
            byte[] ciphertext        = (byte[]) row[1];
            Passphrase badPassphrase = (Passphrase) row[2];
            boolean allowSymmetric   = (boolean) row[3];

            DecryptOutput dec = decryptRaw(ciphertext, badPassphrase, allowSymmetric);
            DecryptVerifyResult result = dec.result;

            Assert.assertFalse("decryption with wrong passphrase must fail [" + scenario + "]",
                    result.success());
            Assert.assertFalse("must not be pending [" + scenario + "]",
                    result.isPending());
            Assert.assertEquals("output must be empty [" + scenario + "]",
                    0, dec.output.length);
            Assert.assertNull("decryptionResult must be null on error [" + scenario + "]",
                    result.getDecryptionResult());
            Assert.assertNull("signatureResult must be null on error [" + scenario + "]",
                    result.getSignatureResult());

            OperationLog log = result.getLog();
            Assert.assertTrue(
                    "log must contain a passphrase-related error [" + scenario + "]",
                    log.containsType(LogType.MSG_DC_ERROR_BAD_PASSPHRASE)
                            || log.containsType(LogType.MSG_DC_ERROR_SYM_PASSPHRASE));
        }
    }

    // ======================================================================
    //  Table-driven: Corrupted ciphertext (position × corruption type)
    // ======================================================================

    @Test
    public void testDecryptCorruptedCiphertext() throws Exception {
        byte[] asymmetricCiphertext = encryptToKeys(
                PLAINTEXT, new long[] { mStaticRing1.getMasterKeyId() });
        byte[] symmetricCiphertext = encryptSymmetric(
                PLAINTEXT, TestingUtils.testPassphrase0);

        // Each row: { label, corrupted ciphertext, decryption passphrase, allowSymmetric }
        Object[][] scenarios = {
                // corruption near start — likely hits session-key packet
                { "corrupt_start_asymmetric",
                        corruptAtOffset(asymmetricCiphertext, 5),
                        mKeyPhrase1, false },
                // corruption in the middle — hits encrypted-data body
                { "corrupt_middle_asymmetric",
                        corruptAtFraction(asymmetricCiphertext, 0.5),
                        mKeyPhrase1, false },
                // corruption near end — likely hits integrity / MDC
                { "corrupt_end_asymmetric",
                        corruptAtOffset(asymmetricCiphertext,
                                asymmetricCiphertext.length - 10),
                        mKeyPhrase1, false },
                // symmetric message, corruption in body
                { "corrupt_middle_symmetric",
                        corruptAtFraction(symmetricCiphertext, 0.5),
                        TestingUtils.testPassphrase0, true },
        };

        for (Object[] row : scenarios) {
            String label               = (String) row[0];
            byte[] ciphertext          = (byte[]) row[1];
            Passphrase decryptPassphrase = (Passphrase) row[2];
            boolean allowSymmetric     = (boolean) row[3];

            DecryptOutput dec = decryptRaw(ciphertext, decryptPassphrase, allowSymmetric);
            DecryptVerifyResult result = dec.result;

            Assert.assertFalse("decryption of corrupted ciphertext must fail [" + label + "]",
                    result.success());
            Assert.assertEquals("output must be empty [" + label + "]",
                    0, dec.output.length);

            OperationLog log = result.getLog();
            Assert.assertTrue(
                    "log must contain a corruption / IO / PGP error [" + label + "]",
                    log.containsType(LogType.MSG_DC_ERROR_CORRUPT_DATA)
                            || log.containsType(LogType.MSG_DC_ERROR_IO)
                            || log.containsType(LogType.MSG_DC_ERROR_PGP_EXCEPTION)
                            || log.containsType(LogType.MSG_DC_ERROR_INTEGRITY_CHECK)
                            || log.containsType(LogType.MSG_DC_ERROR_INVALID_DATA));
        }
    }

    // ======================================================================
    //  Signer mismatch — signing key not available for verification
    // ======================================================================

    @Test
    public void testDetachedSignatureVerifySignerKeyMissing() {
        byte[] detachedSig = signDetached(PLAINTEXT,
                mStaticRing1.getMasterKeyId(),
                KeyringTestingHelper.getSubkeyId(mStaticRing1, 1),
                mKeyPhrase1);

        // Remove the signer's keyring from the database
        KeyWritableRepository.create(RuntimeEnvironment.getApplication())
                .deleteKeyRing(mStaticRing1.getMasterKeyId());

        DecryptOutput dec = verifyDetached(detachedSig, PLAINTEXT.getBytes());
        DecryptVerifyResult result = dec.result;

        Assert.assertTrue("operation must succeed (verify result is informational)",
                result.success());
        Assert.assertNotNull("signature result must be present", result.getSignatureResult());
        Assert.assertEquals("signature result must indicate missing key",
                OpenPgpSignatureResult.RESULT_KEY_MISSING,
                result.getSignatureResult().getResult());
        Assert.assertEquals("decryption result must be NOT_ENCRYPTED",
                OpenPgpDecryptionResult.RESULT_NOT_ENCRYPTED,
                result.getDecryptionResult().getResult());
    }

    @Test
    public void testDetachedSignatureVerifySignerKeyUnknown() {
        // Sign with key2 — verification will look for key2's public key
        byte[] detachedSig = signDetached(PLAINTEXT,
                mStaticRing2.getMasterKeyId(),
                KeyringTestingHelper.getSubkeyId(mStaticRing2, 1),
                mKeyPhrase2);

        // Remove key2 from DB so the signing key is missing
        KeyWritableRepository.create(RuntimeEnvironment.getApplication())
                .deleteKeyRing(mStaticRing2.getMasterKeyId());

        DecryptOutput dec = verifyDetached(detachedSig, PLAINTEXT.getBytes());
        DecryptVerifyResult result = dec.result;

        Assert.assertTrue("operation must succeed (verify result is informational)",
                result.success());
        Assert.assertEquals("signature result must indicate key missing",
                OpenPgpSignatureResult.RESULT_KEY_MISSING,
                result.getSignatureResult().getResult());
    }

    // ======================================================================
    //  Detached signature — wrong data produces invalid signature
    // ======================================================================

    @Test
    public void testDetachedSignatureVerifyWithWrongData() {
        byte[] detachedSig = signDetached(PLAINTEXT,
                mStaticRing1.getMasterKeyId(),
                KeyringTestingHelper.getSubkeyId(mStaticRing1, 1),
                mKeyPhrase1);

        String wrongData = "dies ist ein GANZ ANDERER plaintext ☠";

        DecryptOutput dec = verifyDetached(detachedSig, wrongData.getBytes());
        DecryptVerifyResult result = dec.result;

        Assert.assertTrue("operation must succeed (signature check is informational)",
                result.success());
        Assert.assertNotNull("signature result must be present", result.getSignatureResult());
        Assert.assertEquals("signature must be reported as invalid",
                OpenPgpSignatureResult.RESULT_INVALID_SIGNATURE,
                result.getSignatureResult().getResult());
        Assert.assertTrue("log must contain bad-signature entry",
                result.getLog().containsType(LogType.MSG_DC_CLEAR_SIGNATURE_BAD));
    }

    // ======================================================================
    //  Missing private key — decryption impossible
    // ======================================================================

    @Test
    public void testDecryptWithMissingPrivateKey() {
        byte[] ciphertext = encryptToKeys(PLAINTEXT,
                new long[] { mStaticRing1.getMasterKeyId() });

        // Delete the recipient's keyring from the database
        KeyWritableRepository.create(RuntimeEnvironment.getApplication())
                .deleteKeyRing(mStaticRing1.getMasterKeyId());

        DecryptOutput dec = decryptRaw(ciphertext, mKeyPhrase1, false);
        DecryptVerifyResult result = dec.result;

        Assert.assertFalse("decryption must fail when private key is missing",
                result.success());
        Assert.assertEquals("output must be empty", 0, dec.output.length);
        Assert.assertTrue("log must indicate key not found",
                result.getLog().containsType(LogType.MSG_DC_ASKIP_NO_KEY)
                        || result.getLog().containsType(LogType.MSG_DC_ERROR_NO_KEY));
    }

    // ======================================================================
    //  Empty / garbage input
    // ======================================================================

    @Test
    public void testDecryptVerifyWithEmptyInput() {
        DecryptOutput dec = decryptRaw(new byte[0], mKeyPhrase1, false);

        Assert.assertFalse("decryption of empty input must fail", dec.result.success());
        Assert.assertEquals("output must be empty", 0, dec.output.length);
    }

    @Test
    public void testDecryptVerifyWithGarbageInput() {
        byte[] garbage = new byte[] {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

        DecryptOutput dec = decryptRaw(garbage, mKeyPhrase1, false);

        Assert.assertFalse("decryption of garbage input must fail", dec.result.success());
        Assert.assertEquals("output must be empty", 0, dec.output.length);
    }

    // ======================================================================
    //  Sign-only message (binary, non-cleartext) — round-trip
    // ======================================================================

    @Test
    public void testSignOnlyRoundTrip() {
        byte[] signedMessage = signBinary(PLAINTEXT,
                mStaticRing1.getMasterKeyId(),
                KeyringTestingHelper.getSubkeyId(mStaticRing1, 1),
                mKeyPhrase1);

        DecryptOutput dec = decryptOrVerify(signedMessage, null, false);
        DecryptVerifyResult result = dec.result;

        Assert.assertTrue("verification of sign-only message must succeed", result.success());
        Assert.assertArrayEquals("output must equal original plaintext",
                PLAINTEXT.getBytes(), dec.output);
        Assert.assertEquals("decryptionResult must be NOT_ENCRYPTED",
                OpenPgpDecryptionResult.RESULT_NOT_ENCRYPTED,
                result.getDecryptionResult().getResult());
        Assert.assertEquals("signatureResult must be VALID_KEY_CONFIRMED",
                OpenPgpSignatureResult.RESULT_VALID_KEY_CONFIRMED,
                result.getSignatureResult().getResult());
    }

    @Test
    public void testSignOnlyCleartextRoundTrip() {
        byte[] cleartextSigned = signCleartext(PLAINTEXT,
                mStaticRing1.getMasterKeyId(),
                KeyringTestingHelper.getSubkeyId(mStaticRing1, 1),
                mKeyPhrase1);

        DecryptOutput dec = decryptOrVerify(cleartextSigned, null, false);
        DecryptVerifyResult result = dec.result;

        Assert.assertTrue("verification of cleartext-signed message must succeed",
                result.success());
        Assert.assertEquals("decryptionResult must be NOT_ENCRYPTED",
                OpenPgpDecryptionResult.RESULT_NOT_ENCRYPTED,
                result.getDecryptionResult().getResult());
        Assert.assertEquals("signatureResult must be VALID_KEY_CONFIRMED",
                OpenPgpSignatureResult.RESULT_VALID_KEY_CONFIRMED,
                result.getSignatureResult().getResult());
    }

    // ======================================================================
    //  Encrypt-then-sign — decrypt and verify in one operation
    // ======================================================================

    @Test
    public void testEncryptThenSignRoundTrip() {
        // Encrypt to key2, sign with key1
        byte[] ciphertext = encryptAndSign(PLAINTEXT,
                new long[] { mStaticRing2.getMasterKeyId() },
                mStaticRing1.getMasterKeyId(),
                KeyringTestingHelper.getSubkeyId(mStaticRing1, 1),
                mKeyPhrase1);

        // Decrypt with key2's passphrase; signature verification uses key1's
        // public key (no passphrase needed for verification).
        PgpDecryptVerifyOperation op = operationWithFakePassphraseCache(
                mKeyPhrase2, mStaticRing2.getMasterKeyId(), null);
        PgpDecryptVerifyInputParcel input = PgpDecryptVerifyInputParcel.builder().build();
        ByteArrayInputStream in = new ByteArrayInputStream(ciphertext);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        InputData data = new InputData(in, in.available());
        DecryptVerifyResult result = op.execute(
                input, CryptoInputParcel.createCryptoInputParcel(), data, out);

        Assert.assertTrue("decrypt+verify of encrypted+signed message must succeed",
                result.success());
        Assert.assertArrayEquals("decrypted output must equal plaintext",
                PLAINTEXT.getBytes(), out.toByteArray());
        Assert.assertEquals("decryptionResult must be RESULT_ENCRYPTED",
                OpenPgpDecryptionResult.RESULT_ENCRYPTED,
                result.getDecryptionResult().getResult());
        Assert.assertEquals("signatureResult must be VALID_KEY_CONFIRMED",
                OpenPgpSignatureResult.RESULT_VALID_KEY_CONFIRMED,
                result.getSignatureResult().getResult());
    }

    @Test
    public void testEncryptThenSignWithSenderAddress() {
        byte[] ciphertext = encryptAndSign(PLAINTEXT,
                new long[] { mStaticRing2.getMasterKeyId() },
                mStaticRing1.getMasterKeyId(),
                KeyringTestingHelper.getSubkeyId(mStaticRing1, 1),
                mKeyPhrase1);

        // Decrypt with key2 + provide a sender address for verification
        PgpDecryptVerifyOperation op = operationWithFakePassphraseCache(
                mKeyPhrase2, mStaticRing2.getMasterKeyId(), null);
        PgpDecryptVerifyInputParcel input = PgpDecryptVerifyInputParcel.builder()
                .setSenderAddress("bloom@example.com")
                .build();
        ByteArrayInputStream in = new ByteArrayInputStream(ciphertext);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        InputData data = new InputData(in, in.available());
        DecryptVerifyResult result = op.execute(
                input, CryptoInputParcel.createCryptoInputParcel(), data, out);

        Assert.assertTrue("decrypt+verify with sender address must succeed",
                result.success());
        Assert.assertEquals("decryptionResult must be RESULT_ENCRYPTED",
                OpenPgpDecryptionResult.RESULT_ENCRYPTED,
                result.getDecryptionResult().getResult());
        Assert.assertNotNull("signatureResult must be present",
                result.getSignatureResult());
        // Signature validity should not be degraded by the sender-address check
        Assert.assertNotEquals("signature must not be reported as missing",
                OpenPgpSignatureResult.RESULT_NO_SIGNATURE,
                result.getSignatureResult().getResult());
    }

    // ======================================================================
    //  Key-disallowed scenario
    // ======================================================================

    @Test
    public void testDecryptWithDisallowedKey() {
        byte[] ciphertext = encryptToKeys(PLAINTEXT,
                new long[] { mStaticRing1.getMasterKeyId() });

        // Empty allowed-key list — no key is permitted for decryption
        PgpDecryptVerifyOperation op = operationWithFakePassphraseCache(
                mKeyPhrase1, null, null);
        PgpDecryptVerifyInputParcel input = PgpDecryptVerifyInputParcel.builder()
                .setAllowedKeyIds(new ArrayList<Long>())
                .build();
        ByteArrayInputStream in = new ByteArrayInputStream(ciphertext);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        InputData data = new InputData(in, in.available());
        DecryptVerifyResult result = op.execute(
                input, CryptoInputParcel.createCryptoInputParcel(), data, out);

        Assert.assertFalse("decryption must fail when no key is allowed",
                result.success());
        Assert.assertTrue("result must indicate keys-disallowed",
                result.isKeysDisallowed());
    }

    // ======================================================================
    //  Corrupted cleartext signature — verification must detect tampering
    // ======================================================================

    @Test
    public void testCorruptedCleartextSignature() {
        byte[] cleartextSigned = signCleartext(PLAINTEXT,
                mStaticRing1.getMasterKeyId(),
                KeyringTestingHelper.getSubkeyId(mStaticRing1, 1),
                mKeyPhrase1);

        // Corrupt a byte inside the base64-encoded signature block
        String signed = new String(cleartextSigned);
        int sigBlockStart = signed.indexOf("-----BEGIN PGP SIGNATURE-----");
        Assert.assertTrue("cleartext output must contain a signature block",
                sigBlockStart >= 0);

        int corruptPos = sigBlockStart + 80;
        if (corruptPos >= signed.length()) {
            corruptPos = sigBlockStart + 40;
        }

        char original = signed.charAt(corruptPos);
        char replacement = (original == 'A') ? 'B' : 'A';
        String corrupted = signed.substring(0, corruptPos)
                + replacement
                + signed.substring(corruptPos + 1);

        DecryptOutput dec = decryptOrVerify(corrupted.getBytes(), null, false);
        DecryptVerifyResult result = dec.result;

        // The operation should complete (not throw), but the signature must be
        // reported as either invalid or an error.
        if (result.success()) {
            Assert.assertNotEquals("corrupted signature must not be reported as valid",
                    OpenPgpSignatureResult.RESULT_VALID_KEY_CONFIRMED,
                    result.getSignatureResult().getResult());
            Assert.assertNotEquals("corrupted signature must not be unconfirmed-valid",
                    OpenPgpSignatureResult.RESULT_VALID_KEY_UNCONFIRMED,
                    result.getSignatureResult().getResult());
        }
        // If the operation itself fails, that is also an acceptable outcome.
    }

    // ======================================================================
    //  Cross-key encrypt/decrypt — encrypt to key2, only key1 in DB after
    //  key2 deletion → decryption impossible
    // ======================================================================

    @Test
    public void testDecryptAfterRecipientKeyDeleted() {
        // Encrypt to BOTH keys
        byte[] ciphertext = encryptToKeys(PLAINTEXT,
                new long[] { mStaticRing1.getMasterKeyId(), mStaticRing2.getMasterKeyId() });

        // Delete key1 — only key2 remains
        KeyWritableRepository.create(RuntimeEnvironment.getApplication())
                .deleteKeyRing(mStaticRing1.getMasterKeyId());

        // Decrypt with key2's passphrase — should still succeed
        PgpDecryptVerifyOperation op = operationWithFakePassphraseCache(
                mKeyPhrase2, mStaticRing2.getMasterKeyId(), null);
        PgpDecryptVerifyInputParcel input = PgpDecryptVerifyInputParcel.builder().build();
        ByteArrayInputStream in = new ByteArrayInputStream(ciphertext);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        InputData data = new InputData(in, in.available());
        DecryptVerifyResult result = op.execute(
                input, CryptoInputParcel.createCryptoInputParcel(), data, out);

        Assert.assertTrue("decryption must succeed with remaining key",
                result.success());
        Assert.assertArrayEquals("decrypted output must equal plaintext",
                PLAINTEXT.getBytes(), out.toByteArray());
        Assert.assertTrue("log must show first key was skipped",
                result.getLog().containsType(LogType.MSG_DC_ASKIP_NO_KEY));
    }

    // ======================================================================
    //  Helper methods — encrypt / sign / decrypt wrappers
    // ======================================================================

    private byte[] encryptToKeys(String plaintext, long[] masterKeyIds) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayInputStream in = new ByteArrayInputStream(plaintext.getBytes());

        PgpSignEncryptOperation op = new PgpSignEncryptOperation(
                RuntimeEnvironment.getApplication(),
                KeyWritableRepository.create(RuntimeEnvironment.getApplication()), null);

        InputData data = new InputData(in, in.available());

        PgpSignEncryptData.Builder pgpData = PgpSignEncryptData.builder();
        pgpData.setEncryptionMasterKeyIds(masterKeyIds);
        pgpData.setSymmetricEncryptionAlgorithm(
                PgpSecurityConstants.OpenKeychainSymmetricKeyAlgorithmTags.AES_128);

        PgpSignEncryptResult result = op.execute(pgpData.build(),
                CryptoInputParcel.createCryptoInputParcel(new Date()), data, out);
        Assert.assertTrue("encryption must succeed", result.success());

        return out.toByteArray();
    }

    private byte[] encryptSymmetric(String plaintext, Passphrase passphrase) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayInputStream in = new ByteArrayInputStream(plaintext.getBytes());

        PgpSignEncryptOperation op = new PgpSignEncryptOperation(
                RuntimeEnvironment.getApplication(),
                KeyWritableRepository.create(RuntimeEnvironment.getApplication()), null);

        InputData data = new InputData(in, in.available());

        PgpSignEncryptData.Builder pgpData = PgpSignEncryptData.builder();
        pgpData.setSymmetricPassphrase(passphrase);
        pgpData.setSymmetricEncryptionAlgorithm(
                PgpSecurityConstants.OpenKeychainSymmetricKeyAlgorithmTags.AES_128);

        PgpSignEncryptResult result = op.execute(pgpData.build(),
                CryptoInputParcel.createCryptoInputParcel(new Date()), data, out);
        Assert.assertTrue("symmetric encryption must succeed", result.success());

        return out.toByteArray();
    }

    private byte[] encryptAndSign(String plaintext, long[] encryptionMasterKeyIds,
            long signMasterKeyId, Long signSubKeyId, Passphrase signPassphrase) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayInputStream in = new ByteArrayInputStream(plaintext.getBytes());

        PgpSignEncryptOperation op = new PgpSignEncryptOperation(
                RuntimeEnvironment.getApplication(),
                KeyWritableRepository.create(RuntimeEnvironment.getApplication()), null);

        InputData data = new InputData(in, in.available());

        PgpSignEncryptData.Builder pgpData = PgpSignEncryptData.builder();
        pgpData.setEncryptionMasterKeyIds(encryptionMasterKeyIds);
        pgpData.setSignatureMasterKeyId(signMasterKeyId);
        pgpData.setSignatureSubKeyId(signSubKeyId);
        pgpData.setSymmetricEncryptionAlgorithm(
                PgpSecurityConstants.OpenKeychainSymmetricKeyAlgorithmTags.AES_128);

        PgpSignEncryptResult result = op.execute(pgpData.build(),
                CryptoInputParcel.createCryptoInputParcel(new Date(), signPassphrase),
                data, out);
        Assert.assertTrue("encrypt+sign must succeed", result.success());

        return out.toByteArray();
    }

    private byte[] signBinary(String plaintext, long signMasterKeyId,
            long signSubKeyId, Passphrase signPassphrase) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayInputStream in = new ByteArrayInputStream(plaintext.getBytes());

        PgpSignEncryptOperation op = new PgpSignEncryptOperation(
                RuntimeEnvironment.getApplication(),
                KeyWritableRepository.create(RuntimeEnvironment.getApplication()), null);

        InputData data = new InputData(in, in.available());

        PgpSignEncryptData.Builder pgpData = PgpSignEncryptData.builder();
        pgpData.setSignatureMasterKeyId(signMasterKeyId);
        pgpData.setSignatureSubKeyId(signSubKeyId);
        pgpData.setCleartextSignature(false);
        pgpData.setDetachedSignature(false);

        PgpSignEncryptResult result = op.execute(pgpData.build(),
                CryptoInputParcel.createCryptoInputParcel(signPassphrase), data, out);
        Assert.assertTrue("binary signing must succeed", result.success());

        return out.toByteArray();
    }

    private byte[] signCleartext(String plaintext, long signMasterKeyId,
            long signSubKeyId, Passphrase signPassphrase) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayInputStream in = new ByteArrayInputStream(plaintext.getBytes());

        PgpSignEncryptOperation op = new PgpSignEncryptOperation(
                RuntimeEnvironment.getApplication(),
                KeyWritableRepository.create(RuntimeEnvironment.getApplication()), null);

        InputData data = new InputData(in, in.available());

        PgpSignEncryptData.Builder pgpData = PgpSignEncryptData.builder();
        pgpData.setSignatureMasterKeyId(signMasterKeyId);
        pgpData.setSignatureSubKeyId(signSubKeyId);
        pgpData.setCleartextSignature(true);
        pgpData.setEnableAsciiArmorOutput(true);
        pgpData.setDetachedSignature(false);

        PgpSignEncryptResult result = op.execute(pgpData.build(),
                CryptoInputParcel.createCryptoInputParcel(signPassphrase), data, out);
        Assert.assertTrue("cleartext signing must succeed", result.success());

        return out.toByteArray();
    }

    private byte[] signDetached(String plaintext, long signMasterKeyId,
            long signSubKeyId, Passphrase signPassphrase) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayInputStream in = new ByteArrayInputStream(plaintext.getBytes());

        PgpSignEncryptOperation op = new PgpSignEncryptOperation(
                RuntimeEnvironment.getApplication(),
                KeyWritableRepository.create(RuntimeEnvironment.getApplication()), null);

        InputData data = new InputData(in, in.available());

        PgpSignEncryptData.Builder pgpData = PgpSignEncryptData.builder();
        pgpData.setSignatureMasterKeyId(signMasterKeyId);
        pgpData.setSignatureSubKeyId(signSubKeyId);
        pgpData.setDetachedSignature(true);

        PgpSignEncryptResult result = op.execute(pgpData.build(),
                CryptoInputParcel.createCryptoInputParcel(signPassphrase), data, out);
        Assert.assertTrue("detached signing must succeed", result.success());
        Assert.assertNotNull("detached signature bytes must be set",
                result.getDetachedSignature());

        return result.getDetachedSignature();
    }

    /**
     * Decrypt / verify with explicit passphrase.
     */
    private DecryptOutput decryptRaw(byte[] ciphertext, Passphrase passphrase,
            boolean allowSymmetric) {
        PgpDecryptVerifyOperation op = new PgpDecryptVerifyOperation(
                RuntimeEnvironment.getApplication(),
                KeyWritableRepository.create(RuntimeEnvironment.getApplication()), null);
        PgpDecryptVerifyInputParcel input = PgpDecryptVerifyInputParcel.builder()
                .setAllowSymmetricDecryption(allowSymmetric)
                .build();

        CryptoInputParcel cryptoInput = (passphrase != null)
                ? CryptoInputParcel.createCryptoInputParcel(passphrase)
                : CryptoInputParcel.createCryptoInputParcel();

        ByteArrayInputStream in = new ByteArrayInputStream(ciphertext);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        InputData data = new InputData(in, in.available());
        DecryptVerifyResult result = op.execute(input, cryptoInput, data, out);
        return new DecryptOutput(result, out.toByteArray());
    }

    /**
     * Decrypt / verify using the fake-passphrase-cache pattern.
     */
    private DecryptOutput decryptOrVerify(byte[] data, Passphrase cachedPassphrase,
            boolean allowSymmetric) {
        PgpDecryptVerifyOperation op = operationWithFakePassphraseCache(
                cachedPassphrase, null, null);
        PgpDecryptVerifyInputParcel input = PgpDecryptVerifyInputParcel.builder()
                .setAllowSymmetricDecryption(allowSymmetric)
                .build();
        ByteArrayInputStream in = new ByteArrayInputStream(data);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        InputData inputData = new InputData(in, in.available());
        DecryptVerifyResult result = op.execute(
                input, CryptoInputParcel.createCryptoInputParcel(), inputData, out);
        return new DecryptOutput(result, out.toByteArray());
    }

    private DecryptOutput verifyDetached(byte[] detachedSig, byte[] data) {
        PgpDecryptVerifyOperation op = operationWithFakePassphraseCache(null, null, null);
        PgpDecryptVerifyInputParcel input = PgpDecryptVerifyInputParcel.builder()
                .setDetachedSignature(detachedSig)
                .build();
        ByteArrayInputStream in = new ByteArrayInputStream(data);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        InputData inputData = new InputData(in, in.available());
        DecryptVerifyResult result = op.execute(
                input, CryptoInputParcel.createCryptoInputParcel(), inputData, out);
        return new DecryptOutput(result, out.toByteArray());
    }

    // ──────────────────────────────────────────────────────────────────────
    // Corruption utilities
    // ──────────────────────────────────────────────────────────────────────

    private static byte[] corruptAtOffset(byte[] data, int offset) {
        byte[] corrupted = data.clone();
        if (offset < 0) {
            offset = 0;
        }
        if (offset >= corrupted.length) {
            offset = corrupted.length - 1;
        }
        corrupted[offset] ^= 0xFF;
        return corrupted;
    }

    private static byte[] corruptAtFraction(byte[] data, double fraction) {
        int offset = (int) (data.length * fraction);
        return corruptAtOffset(data, offset);
    }

    // ──────────────────────────────────────────────────────────────────────
    // Fake-passphrase-cache helper (same pattern as PgpEncryptDecryptTest)
    // ──────────────────────────────────────────────────────────────────────

    private PgpDecryptVerifyOperation operationWithFakePassphraseCache(
            final Passphrase passphrase, final Long checkMasterKeyId,
            final Long checkSubKeyId) {

        return new PgpDecryptVerifyOperation(RuntimeEnvironment.getApplication(),
                KeyWritableRepository.create(RuntimeEnvironment.getApplication()), null) {
            @Override
            public Passphrase getCachedPassphrase(long masterKeyId, long subKeyId)
                    throws NoSecretKeyException {
                if (checkMasterKeyId != null) {
                    Assert.assertEquals(
                            "requested passphrase should be for expected master key id",
                            (long) checkMasterKeyId, masterKeyId);
                }
                if (checkSubKeyId != null) {
                    Assert.assertEquals(
                            "requested passphrase should be for expected sub key id",
                            (long) checkSubKeyId, subKeyId);
                }
                if (passphrase == null) {
                    return null;
                }
                return passphrase;
            }
        };
    }
}
