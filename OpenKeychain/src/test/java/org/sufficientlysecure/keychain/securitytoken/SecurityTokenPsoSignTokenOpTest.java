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

package org.sufficientlysecure.keychain.securitytoken;


import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.stubbing.Answer;
import org.robolectric.shadows.ShadowLog;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.securitytoken.SecurityTokenInfo.TokenType;
import org.sufficientlysecure.keychain.securitytoken.SecurityTokenInfo.TransportType;
import org.sufficientlysecure.keychain.securitytoken.operations.SecurityTokenPsoSignTokenOp;
import org.sufficientlysecure.keychain.securitytoken.usb.UsbTransportException;
import org.sufficientlysecure.keychain.util.Passphrase;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;


/**
 * Hardware-independent tests for {@link SecurityTokenPsoSignTokenOp} (PERFORM SECURITY OPERATION:
 * COMPUTE DIGITAL SIGNATURE).
 *
 * A real {@link SecurityTokenConnection} is driven through its real PIN-verification and APDU
 * plumbing; only the {@link Transport} (the NFC/USB seam) is a Mockito double that replays queued
 * {@link ResponseApdu}s or throws a queued {@link IOException} to model a removed/cancelled token.
 * The connection is configured with a YubiKey-NEO capabilities blob, so the signing key is RSA-2048.
 */
@RunWith(KeychainTestRunner.class)
public class SecurityTokenPsoSignTokenOpTest {

    // YubiKey NEO "application related data" (DO 0x6E) with RSA-2048 keys, no secure messaging/KDF.
    private static final String CARD_CAPABILITIES_HEX =
            "6e81de4f10d27600012401020000060364311500005f520f0073000080000000000000000000007381b7c00af" +
                    "00000ff04c000ff00ffc106010800001103c206010800001103c306010800001103c407007f7f7f03" +
                    "0303c53c4ec5fee25c4e89654d58cad8492510a89d3c3d8468da7b24e15bfc624c6a792794f15b759" +
                    "9915f703aab55ed25424d60b17026b7b06c6ad4b9be30a3c63c000000000000000000000000000000" +
                    "000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                    "000000000cd0c59cd0f2a59cd0af059cd0c95";

    // A 32-byte value, the correct length for a SHA-256 digest.
    private static final byte[] SHA256_HASH =
            Hex.decode("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");

    // RSA-2048 produces a 256-byte signature.
    private static final int RSA2048_SIGNATURE_LENGTH = 256;

    private static final int INS_VERIFY = 0x20;
    private static final int INS_PERFORM_SECURITY_OPERATION = 0x2a;
    private static final int P1_PSO_COMPUTE_DIGITAL_SIGNATURE = 0x9e;
    private static final int P2_PSO_COMPUTE_DIGITAL_SIGNATURE = 0x9a;

    private Transport transport;

    private final LinkedList<Object> nextTransceiveResults = new LinkedList<>();
    private final List<CommandApdu> sentCommands = new ArrayList<>();

    private SecurityTokenConnection connection;

    @Before
    public void setUp() throws Exception {
        ShadowLog.stream = System.out;
        nextTransceiveResults.clear();
        sentCommands.clear();

        transport = mock(Transport.class);
        when(transport.getTransportType()).thenReturn(TransportType.USB);
        when(transport.getTokenTypeIfAvailable()).thenReturn(TokenType.YUBIKEY_NEO);
        when(transport.isConnected()).thenReturn(true);
        when(transport.transceive(any(CommandApdu.class))).thenAnswer((Answer<ResponseApdu>) invocation -> {
            CommandApdu command = invocation.getArgument(0);
            sentCommands.add(command);

            Object next = nextTransceiveResults.poll();
            if (next == null) {
                throw new AssertionError("Unexpected transceive, no queued result for: " + command);
            }
            if (next instanceof IOException) {
                throw (IOException) next;
            }
            return (ResponseApdu) next;
        });

        connection = new SecurityTokenConnection(
                transport, new Passphrase("123456"), new OpenPgpCommandApduFactory());
        connection.determineTokenType();
        connection.setConnectionCapabilities(OpenPgpCapabilities.fromBytes(Hex.decode(CARD_CAPABILITIES_HEX)));
    }

    @Test
    public void calculateSignature_validRsaSignature_isReturnedUnchanged() throws Exception {
        byte[] cardSignature = filledBytes(RSA2048_SIGNATURE_LENGTH, (byte) 0xab);

        enqueueResponse("9000");                       // VERIFY PW1 (mode 0x81) succeeds
        enqueueResponse(cardSignature, 0x90, 0x00);    // PSO:CDS returns the signature

        byte[] result = SecurityTokenPsoSignTokenOp.create(connection)
                .calculateSignature(SHA256_HASH, HashAlgorithmTags.SHA256);

        assertArrayEquals(cardSignature, result);

        // exactly one VERIFY followed by one PSO:CDS were sent to the card
        assertEquals(2, sentCommands.size());
        assertEquals(INS_VERIFY, sentCommands.get(0).getINS());
        CommandApdu pso = sentCommands.get(1);
        assertEquals(INS_PERFORM_SECURITY_OPERATION, pso.getINS());
        assertEquals(P1_PSO_COMPUTE_DIGITAL_SIGNATURE, pso.getP1());
        assertEquals(P2_PSO_COMPUTE_DIGITAL_SIGNATURE, pso.getP2());
    }

    @Test
    public void calculateSignature_signKeySlotNotPresent_throwsCardException() throws Exception {
        enqueueResponse("9000"); // PIN ok
        enqueueResponse("6a88"); // 0x6A88 = referenced data (the signing key) not found

        try {
            SecurityTokenPsoSignTokenOp.create(connection)
                    .calculateSignature(SHA256_HASH, HashAlgorithmTags.SHA256);
            fail("expected CardException when the signing key slot is empty");
        } catch (CardException e) {
            assertEquals((short) 0x6a88, e.getResponseCode());
        }
    }

    @Test
    public void calculateSignature_cardReturnsErrorStatus_throwsCardException() throws Exception {
        enqueueResponse("9000"); // PIN ok
        enqueueResponse("6581"); // 0x6581 = memory failure during the operation

        try {
            SecurityTokenPsoSignTokenOp.create(connection)
                    .calculateSignature(SHA256_HASH, HashAlgorithmTags.SHA256);
            fail("expected CardException for a non-9000 status word");
        } catch (CardException e) {
            assertEquals((short) 0x6581, e.getResponseCode());
        }
    }

    @Test
    public void calculateSignature_tokenRemovedDuringSigning_propagatesIOException() throws Exception {
        enqueueResponse("9000"); // PIN ok
        // The user pulls the token (or cancels) while the COMPUTE DIGITAL SIGNATURE APDU is in flight.
        UsbTransportException tokenRemoved = new UsbTransportException("token removed during signing");
        enqueueException(tokenRemoved);

        try {
            SecurityTokenPsoSignTokenOp.create(connection)
                    .calculateSignature(SHA256_HASH, HashAlgorithmTags.SHA256);
            fail("expected the transport IOException to propagate");
        } catch (IOException e) {
            // must be propagated as-is, not swallowed or downgraded to a wrong/empty signature
            assertSame(tokenRemoved, e);
        }
    }

    @Test
    public void calculateSignature_pinRejected_failsBeforeSigning() throws Exception {
        enqueueResponse("63c1"); // wrong PIN, 1 try left -> verification fails

        try {
            SecurityTokenPsoSignTokenOp.create(connection)
                    .calculateSignature(SHA256_HASH, HashAlgorithmTags.SHA256);
            fail("expected CardException from PIN verification");
        } catch (CardException e) {
            assertEquals((short) 0x63c1, e.getResponseCode());
        }

        // the signing APDU must never be attempted once the PIN was rejected
        assertEquals(1, sentCommands.size());
        assertEquals(INS_VERIFY, sentCommands.get(0).getINS());
    }

    @Test
    public void calculateSignature_signatureWrongLength_throwsPlainIOException() throws Exception {
        enqueueResponse("9000");                                          // PIN ok
        enqueueResponse(filledBytes(128, (byte) 0x01), 0x90, 0x00);       // too short for RSA-2048

        try {
            SecurityTokenPsoSignTokenOp.create(connection)
                    .calculateSignature(SHA256_HASH, HashAlgorithmTags.SHA256);
            fail("expected an IOException for a wrongly sized signature");
        } catch (CardException e) {
            fail("a malformed signature length is a parsing error, not a card status error: " + e);
        } catch (IOException e) {
            assertTrue("message should mention the bad length, was: " + e.getMessage(),
                    e.getMessage().contains("Bad signature length"));
        }
    }

    // region helpers

    private void enqueueResponse(String responseApduHex) {
        nextTransceiveResults.add(ResponseApdu.fromBytes(Hex.decode(responseApduHex)));
    }

    private void enqueueResponse(byte[] data, int sw1, int sw2) {
        byte[] responseApdu = Arrays.copyOf(data, data.length + 2);
        responseApdu[responseApdu.length - 2] = (byte) sw1;
        responseApdu[responseApdu.length - 1] = (byte) sw2;
        nextTransceiveResults.add(ResponseApdu.fromBytes(responseApdu));
    }

    private void enqueueException(IOException exception) {
        nextTransceiveResults.add(exception);
    }

    private static byte[] filledBytes(int length, byte value) {
        byte[] bytes = new byte[length];
        Arrays.fill(bytes, value);
        return bytes;
    }

    // endregion
}
