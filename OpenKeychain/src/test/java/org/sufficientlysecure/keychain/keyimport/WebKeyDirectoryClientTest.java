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


import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.util.ParcelableProxy;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for {@link WebKeyDirectoryClient} that exercise the inputs which can be resolved
 * <em>without</em> any network access: names that cannot be turned into a Web Key Directory URL.
 *
 * <p>For these inputs the client must short-circuit to an empty result before opening a socket.
 * Driving only non-resolvable names keeps the test fully offline (a valid e-mail would trigger a
 * real lookup, which is exactly what we avoid here).
 */
@RunWith(KeychainTestRunner.class)
public class WebKeyDirectoryClientTest {

    private final WebKeyDirectoryClient client = WebKeyDirectoryClient.getInstance();
    private final ParcelableProxy noProxy = ParcelableProxy.getForNoProxy();

    /**
     * Protects against: a non-e-mail query (e.g. a plain keyword) being treated as a WKD lookup.
     * It must yield an empty result without contacting any server.
     */
    @Test
    public void search_plainKeyword_returnsEmptyWithoutNetwork() throws Exception {
        List<ImportKeysListEntry> result = client.search("notanemail", noProxy);

        assertNotNull(result);
        assertTrue("a non-e-mail name must not produce WKD results", result.isEmpty());
    }

    /**
     * Protects against: a blank query causing an exception or a spurious lookup. Must be empty.
     */
    @Test
    public void search_blankName_returnsEmpty() throws Exception {
        assertTrue(client.search("", noProxy).isEmpty());
        assertTrue(client.search("   ", noProxy).isEmpty());
    }

    /**
     * Protects against: a malformed "almost a URL" name slipping past the guard. A string that is
     * neither an e-mail nor a well-known-openpgpkey URL must resolve to no WKD endpoint, hence empty.
     */
    @Test
    public void search_nonWellKnownUrl_returnsEmpty() throws Exception {
        assertTrue(client.search("https://example.com/not-the-right-path", noProxy).isEmpty());
    }
}
