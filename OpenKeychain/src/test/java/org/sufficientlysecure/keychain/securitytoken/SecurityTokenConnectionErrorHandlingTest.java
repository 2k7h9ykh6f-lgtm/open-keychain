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

package org.sufficientlysecure.keychain.securitytoken;


import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.stubbing.Answer;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.shadows.ShadowLog;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.securitytoken.SecurityTokenInfo.TokenType;
import org.sufficientlysecure.keychain.securitytoken.SecurityTokenInfo.TransportType;
import org.sufficientlysecure.keychain.securitytoken.usb.UsbTransportException;
import org.sufficientlysecure.keychain.util.Passphrase;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;


/**
 * Hardware-independent regression tests for the error paths of {@link SecurityTokenConnection}.
 *
 * The only point that touches real NFC/USB hardware is the {@link Transport} interface. Here it is
 * replaced by a Mockito double whose {@code transceive} either replays a queued {@link ResponseApdu}
 * or throws a queued {@link IOException} (which is how the real NFC/USB transports report a removed
 * card or an interrupted/cancelled exchange). This lets us exercise PIN-retry, disconnect and
 * error-status-word handling on the JVM/Robolectric without any device attached.
 */
@RunWith(KeychainTestRunner.class)
public class SecurityTokenConnectionErrorHandlingTest {

    // YubiKey NEO "application related data" (DO 0x6E): RSA-2048 keys, no secure messaging, no KDF.
    // Re-used verbatim from SecurityTokenConnectionTest – a known-good capabilities blob, so the
    // connection is wired with realistic key formats and PW-status bytes.
    private static final String CARD_CAPABILITIES_HEX =
            "6e81de4f10d27600012401020000060364311500005f520f0073000080000000000000000000007381b7c00af" +
                    "00000ff04c000ff00ffc106010800001103c206010800001103c306010800001103c407007f7f7f03" +
                    "0303c53c4ec5fee25c4e89654d58cad8492510a89d3c3d8468da7b24e15bfc624c6a792794f15b759" +
                    "9915f703aab55ed25424d60b17026b7b06c6ad4b9be30a3c63c000000000000000000000000000000" +
                    "000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                    "000000000cd0c59cd0f2a59cd0af059cd0c95";

    private Transport transport;

    /** FIFO of {@link ResponseApdu} (to return) or {@link IOException} (to throw) per transceive. */
    private final LinkedList<Object> nextTransceiveResults = new LinkedList<>();
    /** Every command actually handed to the transport, for white-box assertions. */
    private final List<CommandApdu> sentCommands = new ArrayList<>();

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
    }

    // region PIN error / retry handling

    @Test
    public void verifyPinForSignature_wrongPin_throwsCardExceptionWithRetryStatus() throws Exception {
        SecurityTokenConnection connection = connectionWithCapabilities();
        enqueueResponse("63c2"); // 0x63CX = wrong PIN, X tries left (here: 2)

        try {
            connection.verifyPinForSignature();
            fail("expected CardException for a wrong PIN");
        } catch (CardException e) {
            assertEquals((short) 0x63c2, e.getResponseCode());
        }

        assertEquals(1, sentCommands.size());
        assertVerifyPw1Signature(sentCommands.get(0));
    }

    @Test
    public void verifyPinForSignature_retryAfterWrongPin_succeeds() throws Exception {
        SecurityTokenConnection connection = connectionWithCapabilities();
        enqueueResponse("63c2"); // first attempt: wrong PIN
        enqueueResponse("9000"); // retry: correct PIN

        try {
            connection.verifyPinForSignature();
            fail("first attempt should fail");
        } catch (CardException expected) {
            // a failed verification must NOT mark PW1 as validated, otherwise a retry would be skipped
        }

        connection.verifyPinForSignature(); // retry must actually re-send a VERIFY and succeed

        assertEquals(2, sentCommands.size());
        assertVerifyPw1Signature(sentCommands.get(0));
        assertVerifyPw1Signature(sentCommands.get(1));
    }

    @Test
    public void verifyPinForSignature_alreadyValidated_isNotReVerified() throws Exception {
        SecurityTokenConnection connection = connectionWithCapabilities();
        enqueueResponse("9000");

        connection.verifyPinForSignature(); // validates PW1
        connection.verifyPinForSignature(); // must short-circuit, no second VERIFY sent

        assertEquals(1, sentCommands.size());
    }

    @Test
    public void verifyPinForOther_blockedPin_throwsCardException() throws Exception {
        SecurityTokenConnection connection = connectionWithCapabilities();
        enqueueResponse("6983"); // authentication method blocked (retry counter exhausted)

        try {
            connection.verifyPinForOther();
            fail("expected CardException for a blocked PIN");
        } catch (CardException e) {
            assertEquals((short) 0x6983, e.getResponseCode());
        }
    }

    // endregion

    // region APDU error status codes

    @Test
    public void connectToDevice_appletSelectionReturnsErrorStatus_throwsAndReleases() throws Exception {
        SecurityTokenConnection connection = freshConnection();
        enqueueResponse("6a82"); // SELECT OpenPGP applet -> file/applet not found

        try {
            connection.connectToDevice(RuntimeEnvironment.getApplication());
            fail("expected CardException when applet selection fails");
        } catch (CardException e) {
            assertEquals((short) 0x6a82, e.getResponseCode());
        }

        // even on a logical card error the transport must be released so the reader is not left open
        verify(transport).release();
    }

    // endregion

    // region card disconnect handling

    @Test
    public void connectToDevice_transportConnectThrows_releasesAndRethrows() throws Exception {
        SecurityTokenConnection connection = freshConnection();
        IOException disconnected = new IOException("device disconnected before applet selection");
        doThrow(disconnected).when(transport).connect();

        try {
            connection.connectToDevice(RuntimeEnvironment.getApplication());
            fail("expected the connect IOException to propagate");
        } catch (IOException e) {
            assertSame(disconnected, e);
        }

        verify(transport).release();
        assertTrue("no APDU may be sent once the link is already gone", sentCommands.isEmpty());
    }

    @Test
    public void refreshConnectionCapabilities_tokenRemovedMidExchange_propagatesIOException() throws Exception {
        SecurityTokenConnection connection = connectionWithCapabilities();
        // UsbTransportException (an IOException) is what UsbTransport raises when the card vanishes
        // mid-exchange; NfcTransport raises a comparable IOException on tag loss.
        UsbTransportException tokenRemoved = new UsbTransportException("card removed mid-exchange");
        enqueueException(tokenRemoved);

        try {
            connection.refreshConnectionCapabilities();
            fail("expected an IOException when the card is removed mid-exchange");
        } catch (IOException e) {
            assertSame(tokenRemoved, e);
        }
    }

    @Test
    public void isConnected_reflectsTransportConnectionState() {
        SecurityTokenConnection connection = freshConnection();

        when(transport.isConnected()).thenReturn(false);
        assertFalse(connection.isConnected());

        when(transport.isConnected()).thenReturn(true);
        assertTrue(connection.isConnected());
    }

    // endregion

    // region helpers

    private void enqueueResponse(String responseApduHex) {
        nextTransceiveResults.add(ResponseApdu.fromBytes(Hex.decode(responseApduHex)));
    }

    private void enqueueException(IOException exception) {
        nextTransceiveResults.add(exception);
    }

    private SecurityTokenConnection freshConnection() {
        return new SecurityTokenConnection(
                transport, new Passphrase("123456"), new OpenPgpCommandApduFactory());
    }

    private SecurityTokenConnection connectionWithCapabilities() throws IOException {
        SecurityTokenConnection connection = freshConnection();
        connection.determineTokenType();
        connection.setConnectionCapabilities(OpenPgpCapabilities.fromBytes(Hex.decode(CARD_CAPABILITIES_HEX)));
        return connection;
    }

    private static void assertVerifyPw1Signature(CommandApdu command) {
        assertEquals(0x00, command.getCLA());
        assertEquals(0x20, command.getINS()); // VERIFY
        assertEquals(0x81, command.getP2());   // PW1 mode 0x81 (signature)
    }

    // endregion
}
