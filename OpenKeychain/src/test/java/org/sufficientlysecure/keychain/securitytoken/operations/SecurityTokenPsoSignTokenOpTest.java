/*
 * Copyright (C) 2018 Schürmann & Breitmoser GbR
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

package org.sufficientlysecure.keychain.securitytoken.operations;


import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.securitytoken.CardException;
import org.sufficientlysecure.keychain.securitytoken.CommandApdu;
import org.sufficientlysecure.keychain.securitytoken.OpenPgpCapabilities;
import org.sufficientlysecure.keychain.securitytoken.OpenPgpCommandApduFactory;
import org.sufficientlysecure.keychain.securitytoken.ResponseApdu;
import org.sufficientlysecure.keychain.securitytoken.SecurityTokenConnection;

import java.io.IOException;

import static org.junit.Assert.*;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;


@RunWith(KeychainTestRunner.class)
public class SecurityTokenPsoSignTokenOpTest {

    // RSA capabilities from a YubiKey NEO (RSA 2048, CRT_WITH_MODULUS)
    private static final String RSA_CAPS_HEX =
            "6e81de4f10d27600012401020000060364311500005f520f0073000080000000000000000000007381b7c00a" +
            "f00000ff04c000ff00ffc106010800001103c206010800001103c306010800001103c407007f7f7f03" +
            "0303c53c4ec5fee25c4e89654d58cad8492510a89d3c3d8468da7b24e15bfc624c6a792794f15b7599" +
            "915f703aab55ed25424d60b17026b7b06c6ad4b9be30a3c63c00000000000000000000000000000000" +
            "0000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
            "000000000cd0c59cd0f2a59cd0af059cd0c95";

    // EC capabilities: ECDSA P-256 (sign), ECDH P-256 (encrypt), ECDSA P-256 (auth)
    // Same structure as RSA caps but with C1/C2/C3 replaced by EC key formats.
    // C1=ECDSA P-256: 13 08 2A8648CE3D030107
    // C2=ECDH  P-256: 12 08 2A8648CE3D030107
    // C3=ECDSA P-256: 13 08 2A8648CE3D030107
    private static final String EC_CAPS_HEX =
            "6e81ee4f10d27600012401020000060364311500005f520f0073000080000000000000000000007381cd" +
            "c00af00000ff04c000ff00ffc10a13082a8648ce3d030107c20a12082a8648ce3d030107c30a13082a" +
            "8648ce3d030107c407007f7f7f030303c53c4ec5fee25c4e89654d58cad8492510a89d3c3d8468da7b" +
            "24e15bfc624c6a792794f15b7599915f703aab55ed25424d60b17026b7b06c6ad4b9be30a3c63c0000" +
            "0000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
            "0000000000000000000000cd0c59cd0f2a59cd0af059cd0c95";

    private SecurityTokenConnection connection;
    private OpenPgpCommandApduFactory commandFactory;
    private SecurityTokenPsoSignTokenOp signOp;

    @Before
    public void setUp() {
        connection = mock(SecurityTokenConnection.class);
        commandFactory = mock(OpenPgpCommandApduFactory.class);
        when(connection.getCommandFactory()).thenReturn(commandFactory);
        signOp = SecurityTokenPsoSignTokenOp.create(connection);
    }

    // ---------- RSA signing ----------

    @Test
    public void testRsaSign_sha256_returnsSignature() throws Exception {
        OpenPgpCapabilities caps = OpenPgpCapabilities.fromBytes(Hex.decode(RSA_CAPS_HEX));
        when(connection.getOpenPgpCapabilities()).thenReturn(caps);

        byte[] hash = new byte[32]; // SHA-256 hash
        byte[] expectedSig = new byte[256]; // 2048-bit RSA signature
        for (int i = 0; i < expectedSig.length; i++) expectedSig[i] = (byte) (i & 0xff);

        CommandApdu signCmd = mock(CommandApdu.class);
        when(commandFactory.createComputeDigitalSignatureCommand(any(byte[].class)))
                .thenReturn(signCmd);
        when(connection.communicate(signCmd))
                .thenReturn(ResponseApdu.fromBytes(concat(expectedSig, new byte[]{(byte) 0x90, 0x00})));

        byte[] result = signOp.calculateSignature(hash, HashAlgorithmTags.SHA256);

        assertArrayEquals(expectedSig, result);
        verify(connection).verifyPinForSignature();
        verify(commandFactory).createComputeDigitalSignatureCommand(any(byte[].class));
    }

    @Test
    public void testRsaSign_sha512_returnsSignature() throws Exception {
        OpenPgpCapabilities caps = OpenPgpCapabilities.fromBytes(Hex.decode(RSA_CAPS_HEX));
        when(connection.getOpenPgpCapabilities()).thenReturn(caps);

        byte[] hash = new byte[64]; // SHA-512 hash
        byte[] expectedSig = new byte[256];
        for (int i = 0; i < expectedSig.length; i++) expectedSig[i] = (byte) (0xAA ^ i);

        CommandApdu signCmd = mock(CommandApdu.class);
        when(commandFactory.createComputeDigitalSignatureCommand(any(byte[].class)))
                .thenReturn(signCmd);
        when(connection.communicate(signCmd))
                .thenReturn(ResponseApdu.fromBytes(concat(expectedSig, new byte[]{(byte) 0x90, 0x00})));

        byte[] result = signOp.calculateSignature(hash, HashAlgorithmTags.SHA512);

        assertArrayEquals(expectedSig, result);
    }

    @Test
    public void testRsaSign_wrongSignatureLength_throwsIOException() throws Exception {
        OpenPgpCapabilities caps = OpenPgpCapabilities.fromBytes(Hex.decode(RSA_CAPS_HEX));
        when(connection.getOpenPgpCapabilities()).thenReturn(caps);

        byte[] hash = new byte[32];
        // Card returns only 128 bytes instead of expected 256 (2048/8)
        byte[] badSig = new byte[128];

        CommandApdu signCmd = mock(CommandApdu.class);
        when(commandFactory.createComputeDigitalSignatureCommand(any(byte[].class)))
                .thenReturn(signCmd);
        when(connection.communicate(signCmd))
                .thenReturn(ResponseApdu.fromBytes(concat(badSig, new byte[]{(byte) 0x90, 0x00})));

        try {
            signOp.calculateSignature(hash, HashAlgorithmTags.SHA256);
            fail("Expected IOException for bad RSA signature length");
        } catch (IOException e) {
            assertTrue(e.getMessage().contains("Bad signature length"));
        }
    }

    // ---------- ECDSA signing ----------

    @Test
    public void testEcdsaSign_sha256_returnsDerEncodedSignature() throws Exception {
        OpenPgpCapabilities caps = OpenPgpCapabilities.fromBytes(Hex.decode(EC_CAPS_HEX));
        when(connection.getOpenPgpCapabilities()).thenReturn(caps);

        byte[] hash = new byte[32]; // SHA-256

        // Simulated card response: 64 bytes = r (32) || s (32) for P-256
        // r = 0102...202122 (positive first byte, no leading zero needed)
        // s = 7f01...203f (positive first byte, no leading zero needed)
        byte[] r = new byte[32];
        byte[] s = new byte[32];
        for (int i = 0; i < 32; i++) {
            r[i] = (byte) (i + 1);
            s[i] = (byte) (0x7f - i);
        }
        byte[] rawSig = concat(r, s);

        CommandApdu signCmd = mock(CommandApdu.class);
        when(commandFactory.createComputeDigitalSignatureCommand(any(byte[].class)))
                .thenReturn(signCmd);
        when(connection.communicate(signCmd))
                .thenReturn(ResponseApdu.fromBytes(concat(rawSig, new byte[]{(byte) 0x90, 0x00})));

        byte[] result = signOp.calculateSignature(hash, HashAlgorithmTags.SHA256);

        // Result must be a valid ASN.1 DER SEQUENCE { INTEGER r, INTEGER s }
        assertNotNull(result);
        assertEquals("Expected DER SEQUENCE tag", 0x30, result[0] & 0xff);

        // Verify the DER structure can be parsed back
        // SEQUENCE { INTEGER(r), INTEGER(s) }
        int seqLen = result[1] & 0xff;
        assertTrue("DER sequence length should be positive", seqLen > 0);
        assertEquals("Expected first INTEGER tag", 0x02, result[2] & 0xff);
    }

    @Test
    public void testEcdsaSign_sha384_returnsDerEncodedSignature() throws Exception {
        OpenPgpCapabilities caps = OpenPgpCapabilities.fromBytes(Hex.decode(EC_CAPS_HEX));
        when(connection.getOpenPgpCapabilities()).thenReturn(caps);

        byte[] hash = new byte[48]; // SHA-384

        byte[] rawSig = new byte[64]; // r(32) || s(32) for P-256
        for (int i = 0; i < 64; i++) rawSig[i] = (byte) (i + 0x10);

        CommandApdu signCmd = mock(CommandApdu.class);
        when(commandFactory.createComputeDigitalSignatureCommand(any(byte[].class)))
                .thenReturn(signCmd);
        when(connection.communicate(signCmd))
                .thenReturn(ResponseApdu.fromBytes(concat(rawSig, new byte[]{(byte) 0x90, 0x00})));

        byte[] result = signOp.calculateSignature(hash, HashAlgorithmTags.SHA384);

        assertNotNull(result);
        assertEquals(0x30, result[0] & 0xff);
    }

    @Test
    public void testEcdsaSign_oddSignatureLength_throwsIOException() throws Exception {
        OpenPgpCapabilities caps = OpenPgpCapabilities.fromBytes(Hex.decode(EC_CAPS_HEX));
        when(connection.getOpenPgpCapabilities()).thenReturn(caps);

        byte[] hash = new byte[32];
        // Card returns an odd number of bytes — invalid for r||s split
        byte[] oddSig = new byte[63];

        CommandApdu signCmd = mock(CommandApdu.class);
        when(commandFactory.createComputeDigitalSignatureCommand(any(byte[].class)))
                .thenReturn(signCmd);
        when(connection.communicate(signCmd))
                .thenReturn(ResponseApdu.fromBytes(concat(oddSig, new byte[]{(byte) 0x90, 0x00})));

        try {
            signOp.calculateSignature(hash, HashAlgorithmTags.SHA256);
            fail("Expected IOException for odd EC signature length");
        } catch (IOException e) {
            assertTrue(e.getMessage().contains("Bad signature length"));
        }
    }

    // ---------- APDU error status codes ----------

    @Test
    public void testSign_apduReturnsErrorStatus_throwsCardException() throws Exception {
        OpenPgpCapabilities caps = OpenPgpCapabilities.fromBytes(Hex.decode(RSA_CAPS_HEX));
        when(connection.getOpenPgpCapabilities()).thenReturn(caps);

        byte[] hash = new byte[32];

        CommandApdu signCmd = mock(CommandApdu.class);
        when(commandFactory.createComputeDigitalSignatureCommand(any(byte[].class)))
                .thenReturn(signCmd);
        // 0x6982 = Security status not satisfied (e.g., key slot not usable)
        when(connection.communicate(signCmd))
                .thenReturn(ResponseApdu.fromBytes(Hex.decode("6982")));

        try {
            signOp.calculateSignature(hash, HashAlgorithmTags.SHA256);
            fail("Expected CardException");
        } catch (CardException e) {
            assertEquals("Expected SW 0x6982", (short) 0x6982, e.getResponseCode());
        }
    }

    @Test
    public void testSign_apduReturnsFileNotFound_throwsCardException() throws Exception {
        OpenPgpCapabilities caps = OpenPgpCapabilities.fromBytes(Hex.decode(RSA_CAPS_HEX));
        when(connection.getOpenPgpCapabilities()).thenReturn(caps);

        byte[] hash = new byte[32];

        CommandApdu signCmd = mock(CommandApdu.class);
        when(commandFactory.createComputeDigitalSignatureCommand(any(byte[].class)))
                .thenReturn(signCmd);
        // 0x6A82 = File not found (signing key slot does not exist)
        when(connection.communicate(signCmd))
                .thenReturn(ResponseApdu.fromBytes(Hex.decode("6A82")));

        try {
            signOp.calculateSignature(hash, HashAlgorithmTags.SHA256);
            fail("Expected CardException for file-not-found");
        } catch (CardException e) {
            assertEquals((short) 0x6A82, e.getResponseCode());
        }
    }

    @Test
    public void testSign_apduReturnsConditionsNotSatisfied_throwsCardException() throws Exception {
        OpenPgpCapabilities caps = OpenPgpCapabilities.fromBytes(Hex.decode(RSA_CAPS_HEX));
        when(connection.getOpenPgpCapabilities()).thenReturn(caps);

        byte[] hash = new byte[32];

        CommandApdu signCmd = mock(CommandApdu.class);
        when(commandFactory.createComputeDigitalSignatureCommand(any(byte[].class)))
                .thenReturn(signCmd);
        // 0x6985 = Conditions of use not satisfied
        when(connection.communicate(signCmd))
                .thenReturn(ResponseApdu.fromBytes(Hex.decode("6985")));

        try {
            signOp.calculateSignature(hash, HashAlgorithmTags.SHA256);
            fail("Expected CardException");
        } catch (CardException e) {
            assertEquals((short) 0x6985, e.getResponseCode());
        }
    }

    // ---------- User cancellation / card disconnect ----------

    @Test
    public void testSign_cardDisconnects_throwsIOException() throws Exception {
        OpenPgpCapabilities caps = OpenPgpCapabilities.fromBytes(Hex.decode(RSA_CAPS_HEX));
        when(connection.getOpenPgpCapabilities()).thenReturn(caps);

        byte[] hash = new byte[32];

        CommandApdu signCmd = mock(CommandApdu.class);
        when(commandFactory.createComputeDigitalSignatureCommand(any(byte[].class)))
                .thenReturn(signCmd);
        when(connection.communicate(signCmd))
                .thenThrow(new IOException("Card disconnected"));

        try {
            signOp.calculateSignature(hash, HashAlgorithmTags.SHA256);
            fail("Expected IOException for card disconnect");
        } catch (IOException e) {
            assertTrue(e.getMessage().contains("Card disconnected"));
        }
    }

    @Test
    public void testSign_userCancellation_throwsIOException() throws Exception {
        // When the user taps "Cancel" on the NFC dialog or removes the token,
        // the transport layer throws an IOException.
        byte[] hash = new byte[32];
        when(connection.getOpenPgpCapabilities())
                .thenThrow(new IOException("User cancelled operation"));

        try {
            signOp.calculateSignature(hash, HashAlgorithmTags.SHA256);
            fail("Expected IOException for user cancellation");
        } catch (IOException e) {
            assertTrue(e.getMessage().contains("User cancelled"));
        }
    }

    // ---------- Authentication signature (INTERNAL AUTHENTICATE) ----------

    @Test
    public void testAuthSign_rsa_returnsSignature() throws Exception {
        OpenPgpCapabilities caps = OpenPgpCapabilities.fromBytes(Hex.decode(RSA_CAPS_HEX));
        when(connection.getOpenPgpCapabilities()).thenReturn(caps);

        byte[] hash = new byte[32];
        byte[] expectedSig = new byte[256];
        for (int i = 0; i < expectedSig.length; i++) expectedSig[i] = (byte) (i & 0xff);

        CommandApdu authCmd = mock(CommandApdu.class);
        when(commandFactory.createInternalAuthCommand(any(byte[].class)))
                .thenReturn(authCmd);
        when(connection.communicate(authCmd))
                .thenReturn(ResponseApdu.fromBytes(concat(expectedSig, new byte[]{(byte) 0x90, 0x00})));

        byte[] result = signOp.calculateAuthenticationSignature(hash, HashAlgorithmTags.SHA256);

        assertArrayEquals(expectedSig, result);
        verify(connection).verifyPinForOther();
        verify(commandFactory).createInternalAuthCommand(any(byte[].class));
    }

    @Test
    public void testAuthSign_apduError_throwsCardException() throws Exception {
        OpenPgpCapabilities caps = OpenPgpCapabilities.fromBytes(Hex.decode(RSA_CAPS_HEX));
        when(connection.getOpenPgpCapabilities()).thenReturn(caps);

        byte[] hash = new byte[32];

        CommandApdu authCmd = mock(CommandApdu.class);
        when(commandFactory.createInternalAuthCommand(any(byte[].class)))
                .thenReturn(authCmd);
        when(connection.communicate(authCmd))
                .thenReturn(ResponseApdu.fromBytes(Hex.decode("6982")));

        try {
            signOp.calculateAuthenticationSignature(hash, HashAlgorithmTags.SHA256);
            fail("Expected CardException for auth sign failure");
        } catch (CardException e) {
            assertEquals((short) 0x6982, e.getResponseCode());
        }
    }

    // ---------- Invalid inputs ----------

    @Test
    public void testSign_unsupportedHashAlgo_throwsIOException() throws Exception {
        OpenPgpCapabilities caps = OpenPgpCapabilities.fromBytes(Hex.decode(RSA_CAPS_HEX));
        when(connection.getOpenPgpCapabilities()).thenReturn(caps);

        byte[] hash = new byte[16]; // MD5-size hash

        try {
            signOp.calculateSignature(hash, 99); // unsupported algo
            fail("Expected IOException for unsupported hash algorithm");
        } catch (IOException e) {
            assertTrue(e.getMessage().contains("Not supported hash algo"));
        }
    }

    @Test
    public void testSign_badHashLength_sha256_throwsIOException() throws Exception {
        OpenPgpCapabilities caps = OpenPgpCapabilities.fromBytes(Hex.decode(RSA_CAPS_HEX));
        when(connection.getOpenPgpCapabilities()).thenReturn(caps);

        // SHA-256 expects exactly 32 bytes, provide 20
        byte[] hash = new byte[20];

        try {
            signOp.calculateSignature(hash, HashAlgorithmTags.SHA256);
            fail("Expected IOException for wrong hash length");
        } catch (IOException e) {
            assertTrue(e.getMessage().contains("Bad hash length"));
        }
    }

    @Test
    public void testSign_badHashLength_sha1_throwsIOException() throws Exception {
        OpenPgpCapabilities caps = OpenPgpCapabilities.fromBytes(Hex.decode(RSA_CAPS_HEX));
        when(connection.getOpenPgpCapabilities()).thenReturn(caps);

        // SHA-1 expects exactly 20 bytes, provide 32
        byte[] hash = new byte[32];

        try {
            signOp.calculateSignature(hash, HashAlgorithmTags.SHA1);
            fail("Expected IOException for wrong SHA-1 hash length");
        } catch (IOException e) {
            assertTrue(e.getMessage().contains("Bad hash length"));
        }
    }

    // ---------- Helper ----------

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
}
