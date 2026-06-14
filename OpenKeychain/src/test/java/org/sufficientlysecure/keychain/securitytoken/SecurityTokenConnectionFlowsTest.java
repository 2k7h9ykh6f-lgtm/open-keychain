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

import org.bouncycastle.util.encoders.Hex;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.stubbing.Answer;
import org.robolectric.shadows.ShadowLog;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.securitytoken.SecurityTokenInfo.TokenType;
import org.sufficientlysecure.keychain.securitytoken.SecurityTokenInfo.TransportType;
import org.sufficientlysecure.keychain.util.Passphrase;

import java.io.IOException;
import java.util.LinkedList;

import static org.junit.Assert.*;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;


/**
 * Tests for {@link SecurityTokenConnection} covering PIN verification flows,
 * card disconnect / transport error handling, and APDU dialog correctness.
 *
 * Uses the queue-based mock-Transport pattern from {@link SecurityTokenConnectionTest}:
 * expected commands and responses are enqueued in order, and the mock Transport
 * asserts each transceive() call matches the head of the queue.
 */
@RunWith(KeychainTestRunner.class)
public class SecurityTokenConnectionFlowsTest {

    private Transport transport;

    private LinkedList<CommandApdu> expectCommands;
    private LinkedList<ResponseApdu> expectReplies;

    /**
     * YubiKey NEO Application Related Data — RSA 2048, PW-status byte[0] = 0x00
     * (PW1 is single-use: must be re-verified before each signature).
     * isPw1ValidForMultipleSignatures() returns false.
     */
    private static final String CAPS_HEX =
            "6e81de4f10d27600012401020000060364311500005f520f0073000080000000000000000000007381b7c00af" +
            "00000ff04c000ff00ffc106010800001103c206010800001103c306010800001103c407007f7f7f03" +
            "0303c53c4ec5fee25c4e89654d58cad8492510a89d3c3d8468da7b24e15bfc624c6a792794f15b759" +
            "9915f703aab55ed25424d60b17026b7b06c6ad4b9be30a3c63c000000000000000000000000000000" +
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
            "000000000cd0c59cd0f2a59cd0af059cd0c95";

    /**
     * Same capabilities but with PW-status byte[0] = 0x01
     * (PW1 is valid for multiple signatures — no re-verify needed).
     */
    private static final String CAPS_MULTI_SIGN_HEX =
            "6e81de4f10d27600012401020000060364311500005f520f0073000080000000000000000000007381b7c00af" +
            "00000ff04c000ff00ffc106010800001103c206010800001103c306010800001103c407017f7f7f03" +
            "0303c53c4ec5fee25c4e89654d58cad8492510a89d3c3d8468da7b24e15bfc624c6a792794f15b759" +
            "9915f703aab55ed25424d60b17026b7b06c6ad4b9be30a3c63c000000000000000000000000000000" +
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
            "000000000cd0c59cd0f2a59cd0af059cd0c95";

    private static final String PIN = "123456";

    @Before
    public void setUp() {
        ShadowLog.stream = System.out;

        transport = mock(Transport.class);
        when(transport.getTransportType()).thenReturn(TransportType.USB);
        when(transport.getTokenTypeIfAvailable()).thenReturn(TokenType.YUBIKEY_NEO);

        expectCommands = new LinkedList<>();
        expectReplies = new LinkedList<>();
        when(transport.transceive(any(CommandApdu.class))).thenAnswer((Answer<ResponseApdu>) invocation -> {
            CommandApdu actual = invocation.getArgument(0);
            CommandApdu expected = expectCommands.poll();
            assertEquals("APDU mismatch", expected, actual);
            return expectReplies.poll();
        });
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private void expect(String cmdHex, String respHex) {
        expectCommands.add(CommandApdu.fromBytes(Hex.decode(cmdHex)));
        expectReplies.add(ResponseApdu.fromBytes(Hex.decode(respHex)));
    }

    private void verifyDialog() {
        assertTrue("Unconsumed expected commands: " + expectCommands, expectCommands.isEmpty());
        assertTrue("Unconsumed expected replies: " + expectReplies, expectReplies.isEmpty());
    }

    /**
     * Creates a SecurityTokenConnection, connects it (SELECT + GET DATA),
     * and leaves the transport ready for the next APDU exchange.
     */
    private SecurityTokenConnection createConnectedInstance(String capsHex) throws Exception {
        SecurityTokenConnection conn = new SecurityTokenConnection(
                transport, new Passphrase(PIN), new OpenPgpCommandApduFactory());
        enqueueConnectDialog(capsHex);
        conn.connectToDevice(null);
        return conn;
    }

    private void enqueueConnectDialog(String capsHex) {
        expect("00a4040006d27600012401", "9000"); // SELECT OpenPGP applet
        expect("00ca006e00", capsHex);              // GET DATA — Application Related Data
    }

    // =========================================================================
    // PIN verification — success
    // =========================================================================

    @Test
    public void testVerifyPinForSignature_success() throws Exception {
        SecurityTokenConnection conn = createConnectedInstance(CAPS_HEX);

        // VERIFY PW1 for signature: CLA=00 INS=20 P1=00 P2=81 Lc=06 DATA=313233343536
        expect("0020008106313233343536", "9000");

        conn.verifyPinForSignature();

        verifyDialog();
    }

    @Test
    public void testVerifyPinForOther_success() throws Exception {
        SecurityTokenConnection conn = createConnectedInstance(CAPS_HEX);

        // VERIFY PW1 for other: CLA=00 INS=20 P1=00 P2=82 Lc=06 DATA=313233343536
        expect("0020008206313233343536", "9000");

        conn.verifyPinForOther();

        verifyDialog();
    }

    @Test
    public void testVerifyAdminPin_success() throws Exception {
        SecurityTokenConnection conn = createConnectedInstance(CAPS_HEX);

        String adminPin = "12345678";
        // VERIFY PW3: CLA=00 INS=20 P1=00 P2=83 Lc=08 DATA=3132333435363738
        expect("00200083083132333435363738", "9000");

        conn.verifyAdminPin(new Passphrase(adminPin));

        verifyDialog();
    }

    // =========================================================================
    // PIN verification — failure (wrong PIN / retry counter)
    // =========================================================================

    @Test
    public void testVerifyPinForSignature_badPin_throwsCardException() throws Exception {
        SecurityTokenConnection conn = createConnectedInstance(CAPS_HEX);

        // 0x63C0 = verification failed, 0 retries remaining
        expect("0020008106313233343536", "63C0");

        try {
            conn.verifyPinForSignature();
            fail("Expected CardException for bad PIN");
        } catch (CardException e) {
            assertEquals((short) 0x63C0, e.getResponseCode());
        }

        verifyDialog();
    }

    @Test
    public void testVerifyPinForSignature_badPinWithRetriesLeft_throwsCardException() throws Exception {
        SecurityTokenConnection conn = createConnectedInstance(CAPS_HEX);

        // 0x63C2 = verification failed, 2 retries remaining
        expect("0020008106313233343536", "63C2");

        try {
            conn.verifyPinForSignature();
            fail("Expected CardException for bad PIN with retries left");
        } catch (CardException e) {
            assertEquals((short) 0x63C2, e.getResponseCode());
        }

        verifyDialog();
    }

    @Test
    public void testVerifyPinForOther_badPin_throwsCardException() throws Exception {
        SecurityTokenConnection conn = createConnectedInstance(CAPS_HEX);

        expect("0020008206313233343536", "63C0");

        try {
            conn.verifyPinForOther();
            fail("Expected CardException for bad PIN");
        } catch (CardException e) {
            assertEquals((short) 0x63C0, e.getResponseCode());
        }

        verifyDialog();
    }

    @Test
    public void testVerifyAdminPin_badPin_throwsCardException() throws Exception {
        SecurityTokenConnection conn = createConnectedInstance(CAPS_HEX);

        expect("00200083083132333435363738", "63C0");

        try {
            conn.verifyAdminPin(new Passphrase("12345678"));
            fail("Expected CardException for bad admin PIN");
        } catch (CardException e) {
            assertEquals((short) 0x63C0, e.getResponseCode());
        }

        verifyDialog();
    }

    @Test
    public void testVerifyPin_retryThenSucceed() throws Exception {
        SecurityTokenConnection conn = createConnectedInstance(CAPS_HEX);

        // First attempt: bad PIN
        expect("0020008106313233343536", "63C2");
        try {
            conn.verifyPinForSignature();
            fail("Expected CardException on first attempt");
        } catch (CardException e) {
            assertEquals((short) 0x63C2, e.getResponseCode());
        }

        // Second attempt: correct PIN succeeds
        expect("0020008106313233343536", "9000");
        conn.verifyPinForSignature();

        verifyDialog();
    }

    // =========================================================================
    // PIN verification — no PIN cached
    // =========================================================================

    @Test
    public void testVerifyPin_noPinCached_throwsIllegalState() throws Exception {
        // Connection created WITHOUT a PIN
        SecurityTokenConnection conn = new SecurityTokenConnection(
                transport, null, new OpenPgpCommandApduFactory());
        conn.setConnectionCapabilities(OpenPgpCapabilities.fromBytes(Hex.decode(CAPS_HEX)));

        try {
            conn.verifyPinForSignature();
            fail("Expected IllegalStateException when no PIN is cached");
        } catch (IllegalStateException e) {
            assertTrue(e.getMessage().contains("Pin"));
        }
    }

    @Test
    public void testVerifyPinForOther_noPinCached_throwsIllegalState() throws Exception {
        SecurityTokenConnection conn = new SecurityTokenConnection(
                transport, null, new OpenPgpCommandApduFactory());
        conn.setConnectionCapabilities(OpenPgpCapabilities.fromBytes(Hex.decode(CAPS_HEX)));

        try {
            conn.verifyPinForOther();
            fail("Expected IllegalStateException when no PIN is cached");
        } catch (IllegalStateException e) {
            assertTrue(e.getMessage().contains("Pin"));
        }
    }

    // =========================================================================
    // PIN validation caching — skip redundant VERIFY
    // =========================================================================

    @Test
    public void testVerifyPin_alreadyValidated_skipsSecondVerify() throws Exception {
        SecurityTokenConnection conn = createConnectedInstance(CAPS_MULTI_SIGN_HEX);

        // First verification sends VERIFY
        expect("0020008106313233343536", "9000");
        conn.verifyPinForSignature();

        // Second call should NOT send any APDU (PIN already validated for multi-sign)
        conn.verifyPinForSignature();

        verifyDialog();
    }

    @Test
    public void testVerifyPinForOther_alreadyValidated_skipsSecondVerify() throws Exception {
        SecurityTokenConnection conn = createConnectedInstance(CAPS_HEX);

        expect("0020008206313233343536", "9000");
        conn.verifyPinForOther();

        // Already validated — no APDU sent
        conn.verifyPinForOther();

        verifyDialog();
    }

    @Test
    public void testAdminPin_alreadyValidated_skipsSecondVerify() throws Exception {
        SecurityTokenConnection conn = createConnectedInstance(CAPS_HEX);

        expect("00200083083132333435363738", "9000");
        conn.verifyAdminPin(new Passphrase("12345678"));

        conn.verifyAdminPin(new Passphrase("12345678"));

        verifyDialog();
    }

    // =========================================================================
    // invalidateSingleUsePw1 — single-use vs multi-use PW1
    // =========================================================================

    @Test
    public void testInvalidateSingleUsePw1_singleUse_resetsFlag() throws Exception {
        // PW-status byte[0] = 0x00 → single-use
        SecurityTokenConnection conn = createConnectedInstance(CAPS_HEX);

        // Verify PIN
        expect("0020008106313233343536", "9000");
        conn.verifyPinForSignature();

        // Invalidate (single-use mode)
        conn.invalidateSingleUsePw1();

        // Must re-verify → sends VERIFY again
        expect("0020008106313233343536", "9000");
        conn.verifyPinForSignature();

        verifyDialog();
    }

    @Test
    public void testInvalidateSingleUsePw1_multiUse_keepsFlag() throws Exception {
        // PW-status byte[0] = 0x01 → multi-use
        SecurityTokenConnection conn = createConnectedInstance(CAPS_MULTI_SIGN_HEX);

        expect("0020008106313233343536", "9000");
        conn.verifyPinForSignature();

        // Invalidate should be a no-op in multi-use mode
        conn.invalidateSingleUsePw1();

        // Should NOT re-verify
        conn.verifyPinForSignature();

        verifyDialog();
    }

    @Test
    public void testInvalidatePw3_resetsAdminFlag() throws Exception {
        SecurityTokenConnection conn = createConnectedInstance(CAPS_HEX);

        // Verify admin PIN
        expect("00200083083132333435363738", "9000");
        conn.verifyAdminPin(new Passphrase("12345678"));

        // Invalidate
        conn.invalidatePw3();

        // Must re-verify
        expect("00200083083132333435363738", "9000");
        conn.verifyAdminPin(new Passphrase("12345678"));

        verifyDialog();
    }

    // =========================================================================
    // Card disconnect / transport error
    // =========================================================================

    @Test
    public void testCommunicate_cardDisconnect_throwsIOException() throws Exception {
        SecurityTokenConnection conn = createConnectedInstance(CAPS_HEX);

        when(transport.transceive(any(CommandApdu.class)))
                .thenThrow(new IOException("Card disconnected"));

        CommandApdu cmd = CommandApdu.create(0x00, 0xCA, 0x00, 0x6E, 65536);
        try {
            conn.communicate(cmd);
            fail("Expected IOException for card disconnect");
        } catch (IOException e) {
            assertTrue(e.getMessage().contains("disconnected"));
        }
    }

    @Test
    public void testConnectToDevice_transportConnectFails_releasesAndThrows() throws Exception {
        SecurityTokenConnection conn = new SecurityTokenConnection(
                transport, new Passphrase(PIN), new OpenPgpCommandApduFactory());

        when(transport.connect()).thenThrow(new IOException("USB device not found"));

        try {
            conn.connectToDevice(null);
            fail("Expected IOException for transport connect failure");
        } catch (IOException e) {
            assertTrue(e.getMessage().contains("USB device not found"));
        }

        verify(transport).release();
    }

    @Test
    public void testConnectToDevice_selectFails_releasesAndThrows() throws Exception {
        SecurityTokenConnection conn = new SecurityTokenConnection(
                transport, new Passphrase(PIN), new OpenPgpCommandApduFactory());

        // SELECT returns non-success → CardException
        expect("00a4040006d27600012401", "6A82");

        try {
            conn.connectToDevice(null);
            fail("Expected CardException when SELECT fails");
        } catch (CardException e) {
            assertEquals((short) 0x6A82, e.getResponseCode());
        }

        verify(transport).release();
    }

    @Test
    public void testConnectToDevice_getDataFails_releasesAndThrows() throws Exception {
        SecurityTokenConnection conn = new SecurityTokenConnection(
                transport, new Passphrase(PIN), new OpenPgpCommandApduFactory());

        // SELECT succeeds but GET DATA fails
        expect("00a4040006d27600012401", "9000");
        expect("00ca006e00", "6985");

        try {
            conn.connectToDevice(null);
            fail("Expected CardException when GET DATA fails");
        } catch (CardException e) {
            assertEquals((short) 0x6985, e.getResponseCode());
        }

        verify(transport).release();
    }

    @Test
    public void testVerifyPin_transportFails_throwsIOException() throws Exception {
        SecurityTokenConnection conn = createConnectedInstance(CAPS_HEX);

        // Transport throws IOException during VERIFY (e.g., NFC tag removed)
        when(transport.transceive(any(CommandApdu.class)))
                .thenThrow(new IOException("NFC tag removed"));

        try {
            conn.verifyPinForSignature();
            fail("Expected IOException for NFC tag removal");
        } catch (IOException e) {
            assertTrue(e.getMessage().contains("NFC tag removed"));
        }
    }

    // =========================================================================
    // isConnected delegates to transport
    // =========================================================================

    @Test
    public void testIsConnected_delegatesToTransport() {
        SecurityTokenConnection conn = new SecurityTokenConnection(
                transport, new Passphrase(PIN), new OpenPgpCommandApduFactory());

        when(transport.isConnected()).thenReturn(true);
        assertTrue(conn.isConnected());

        when(transport.isConnected()).thenReturn(false);
        assertFalse(conn.isConnected());
    }
}
