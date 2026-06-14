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

package org.sufficientlysecure.keychain.keyimport;


import java.nio.charset.Charset;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.shadows.ShadowLog;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.pgp.UncachedKeyRing;

import static org.junit.Assert.fail;

/**
 * Robustness tests for {@link UncachedKeyRing#decodeFromData(byte[])}, the single decode seam that
 * every keyring entering the app flows through: pasted/loaded ASCII armor, raw binary keyrings, and
 * the bytes returned by a Web Key Directory lookup.
 *
 * <p>If this decoder ever accepted malformed input and returned a bogus ring instead of throwing,
 * the failure would propagate into every import path at once. Each test feeds a different class of
 * broken input and asserts the decoder rejects it (throws) rather than silently succeeding.
 */
@RunWith(KeychainTestRunner.class)
public class KeyImportDecodeRobustnessTest {

    private static final Charset UTF_8 = Charset.forName("UTF-8");

    @BeforeClass
    public static void setUpOnce() {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        ShadowLog.stream = System.out;
    }

    private static void assertRejected(String description, byte[] data) {
        try {
            UncachedKeyRing ring = UncachedKeyRing.decodeFromData(data);
            fail("decode should reject " + description + " but returned: " + ring);
        } catch (Exception expected) {
            // Expected: malformed input must be rejected, never accepted as a keyring.
        }
    }

    /**
     * Protects against: invalid ASCII armor (correct envelope, broken body) being accepted on the
     * armor-paste import path.
     */
    @Test
    public void decode_invalidArmorBody_isRejected() {
        String armor = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
                + "\n"
                + "this is not valid base64 radix-64 data !!!\n"
                + "=AAAA\n"
                + "-----END PGP PUBLIC KEY BLOCK-----\n";
        assertRejected("invalid armor body", armor.getBytes(UTF_8));
    }

    /**
     * Protects against: a truncated armor block (header only, no payload or footer) being accepted.
     */
    @Test
    public void decode_truncatedArmor_isRejected() {
        String armor = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n";
        assertRejected("truncated armor", armor.getBytes(UTF_8));
    }

    /**
     * Protects against: arbitrary binary (e.g. a corrupt download or a Web Key Directory endpoint
     * returning the wrong content) being parsed as a binary keyring.
     */
    @Test
    public void decode_garbageBinary_isRejected() {
        byte[] garbage = new byte[256];
        for (int i = 0; i < garbage.length; i++) {
            garbage[i] = (byte) i;
        }
        assertRejected("arbitrary binary data", garbage);
    }

    /**
     * Protects against: plain text (e.g. an HTML error page returned by a server) being mistaken for
     * a keyring on any import or lookup path.
     */
    @Test
    public void decode_plainText_isRejected() {
        assertRejected("plain text", "Just some text, definitely not a key.".getBytes(UTF_8));
    }
}
