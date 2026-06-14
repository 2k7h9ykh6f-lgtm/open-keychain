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

import org.bouncycastle.util.encoders.Hex;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.stubbing.Answer;
import org.robolectric.shadows.ShadowLog;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.securitytoken.SecurityTokenInfo.TokenType;
import org.sufficientlysecure.keychain.securitytoken.SecurityTokenInfo.TransportType;
import org.sufficientlysecure.keychain.securitytoken.operations.PsoDecryptTokenOp;
import org.sufficientlysecure.keychain.util.Passphrase;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;


/**
 * Hardware-independent tests for {@link PsoDecryptTokenOp} (PERFORM SECURITY OPERATION: DECIPHER).
 *
 * The interesting hardware path here is APDU command-chaining: when a payload does not fit into a
 * single short APDU and the card advertises chaining (which the YubiKey-NEO capabilities blob used
 * below does), {@link SecurityTokenConnection} splits the command into several APDUs and sends them
 * one after another over NFC/USB. Driving a real RSA-2048 ciphertext through the faked
 * {@link Transport} lets us assert that splitting, the chaining-class byte and reassembly all work
 * without a physical card.
 */
@RunWith(KeychainTestRunner.class)
public class PsoDecryptTokenOpTest {

    // YubiKey NEO "application related data" (DO 0x6E): RSA-2048 keys, chaining supported, no SM/KDF.
    private static final String CARD_CAPABILITIES_HEX =
            "6e81de4f10d27600012401020000060364311500005f520f0073000080000000000000000000007381b7c00af" +
                    "00000ff04c000ff00ffc106010800001103c206010800001103c306010800001103c407007f7f7f03" +
                    "0303c53c4ec5fee25c4e89654d58cad8492510a89d3c3d8468da7b24e15bfc624c6a792794f15b759" +
                    "9915f703aab55ed25424d60b17026b7b06c6ad4b9be30a3c63c000000000000000000000000000000" +
                    "000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                    "000000000cd0c59cd0f2a59cd0af059cd0c95";

    private static final int CLA_CHAINING = 0x10;
    private static final int INS_VERIFY = 0x20;
    private static final int P2_VERIFY_PW1_OTHER = 0x82;
    private static final int INS_PERFORM_SECURITY_OPERATION = 0x2a;
    private static final int P1_PSO_DECIPHER = 0x80;
    private static final int P2_PSO_DECIPHER = 0x86;
    private static final int MAX_SHORT_APDU_DATA = 254;

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
    public void verifyAndDecryptSessionKey_rsaPayloadIsChained_returnsPlaintext() throws Exception {
        // 2048-bit MPI: 2 length bytes (0x0800 = 2048 bits) + 256 body bytes.
        // The DECIPHER payload is body + 1 padding byte = 257 bytes, i.e. larger than a short APDU,
        // so the connection must chain it into two commands.
        byte[] encryptedSessionKeyMpi = mpi(0x0800, filledBytes(256, (byte) 0xcd));
        byte[] plaintextSessionKey = Hex.decode("090102030405060708090a0b0c0d0e0f10");

        enqueueResponse("9000");                              // VERIFY PW1 (mode 0x82)
        enqueueResponse("9000");                              // first (chained) DECIPHER command
        enqueueResponse(plaintextSessionKey, 0x90, 0x00);     // last DECIPHER command -> plaintext

        byte[] result = PsoDecryptTokenOp.create(connection)
                .verifyAndDecryptSessionKey(encryptedSessionKeyMpi, null);

        assertArrayEquals(plaintextSessionKey, result);

        // VERIFY, then exactly two chained DECIPHER APDUs
        assertEquals(3, sentCommands.size());

        CommandApdu verify = sentCommands.get(0);
        assertEquals(INS_VERIFY, verify.getINS());
        assertEquals(P2_VERIFY_PW1_OTHER, verify.getP2());

        CommandApdu firstChunk = sentCommands.get(1);
        assertEquals("non-final chained APDU must set the chaining class bit",
                CLA_CHAINING, firstChunk.getCLA());
        assertEquals(INS_PERFORM_SECURITY_OPERATION, firstChunk.getINS());
        assertEquals(P1_PSO_DECIPHER, firstChunk.getP1());
        assertEquals(P2_PSO_DECIPHER, firstChunk.getP2());
        assertEquals(MAX_SHORT_APDU_DATA, firstChunk.getData().length);

        CommandApdu lastChunk = sentCommands.get(2);
        assertEquals("final chained APDU must clear the chaining class bit", 0x00, lastChunk.getCLA());
        assertEquals(INS_PERFORM_SECURITY_OPERATION, lastChunk.getINS());
        // 257-byte payload split as 254 + 3
        assertEquals(257 - MAX_SHORT_APDU_DATA, lastChunk.getData().length);
    }

    @Test
    public void verifyAndDecryptSessionKey_cardReturnsError_throwsCardException() throws Exception {
        // Small MPI (1024-bit) so the single DECIPHER command fits a short APDU.
        byte[] encryptedSessionKeyMpi = mpi(0x0400, filledBytes(128, (byte) 0xee));

        enqueueResponse("9000"); // PIN ok
        enqueueResponse("6985"); // conditions of use not satisfied

        try {
            PsoDecryptTokenOp.create(connection)
                    .verifyAndDecryptSessionKey(encryptedSessionKeyMpi, null);
            fail("expected CardException for a failed DECIPHER");
        } catch (CardException e) {
            assertEquals((short) 0x6985, e.getResponseCode());
        }
    }

    @Test
    public void verifyAndDecryptSessionKey_pinRejected_failsBeforeDecipher() throws Exception {
        byte[] encryptedSessionKeyMpi = mpi(0x0400, filledBytes(128, (byte) 0xee));

        enqueueResponse("63c2"); // wrong PIN -> verifyPinForOther fails

        try {
            PsoDecryptTokenOp.create(connection)
                    .verifyAndDecryptSessionKey(encryptedSessionKeyMpi, null);
            fail("expected CardException from PIN verification");
        } catch (CardException e) {
            assertEquals((short) 0x63c2, e.getResponseCode());
        }

        // the DECIPHER APDU must never be sent once the PIN was rejected
        assertEquals(1, sentCommands.size());
        assertEquals(INS_VERIFY, sentCommands.get(0).getINS());
    }

    // region helpers

    /** Builds an OpenPGP MPI: a two-byte big-endian bit length followed by the value bytes. */
    private static byte[] mpi(int bitLength, byte[] body) {
        byte[] mpi = new byte[body.length + 2];
        mpi[0] = (byte) ((bitLength >> 8) & 0xff);
        mpi[1] = (byte) (bitLength & 0xff);
        System.arraycopy(body, 0, mpi, 2, body.length);
        return mpi;
    }

    private void enqueueResponse(String responseApduHex) {
        nextTransceiveResults.add(ResponseApdu.fromBytes(Hex.decode(responseApduHex)));
    }

    private void enqueueResponse(byte[] data, int sw1, int sw2) {
        byte[] responseApdu = Arrays.copyOf(data, data.length + 2);
        responseApdu[responseApdu.length - 2] = (byte) sw1;
        responseApdu[responseApdu.length - 1] = (byte) sw2;
        nextTransceiveResults.add(ResponseApdu.fromBytes(responseApdu));
    }

    private static byte[] filledBytes(int length, byte value) {
        byte[] bytes = new byte[length];
        Arrays.fill(bytes, value);
        return bytes;
    }

    // endregion
}
