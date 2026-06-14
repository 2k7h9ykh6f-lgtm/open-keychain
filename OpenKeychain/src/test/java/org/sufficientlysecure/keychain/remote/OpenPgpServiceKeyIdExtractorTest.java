package org.sufficientlysecure.keychain.remote;


import java.util.ArrayList;
import java.util.Arrays;

import android.app.PendingIntent;
import android.content.ContentResolver;
import android.content.Intent;
import android.database.MatrixCursor;
import android.net.Uri;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openintents.openpgp.util.OpenPgpApi;
import org.sufficientlysecure.keychain.BuildConfig;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.provider.KeychainExternalContract;
import org.sufficientlysecure.keychain.provider.KeychainExternalContract.AutocryptStatus;
import org.sufficientlysecure.keychain.remote.OpenPgpServiceKeyIdExtractor.KeyIdResult;
import org.sufficientlysecure.keychain.remote.OpenPgpServiceKeyIdExtractor.KeyIdResultStatus;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link OpenPgpServiceKeyIdExtractor}, covering key ID extraction from intents
 * carrying key IDs, user IDs, autocrypt state, and various edge-case / boundary inputs
 * that external applications may pass via the OpenPGP API.
 *
 * <p>Test categories:
 * <ul>
 *   <li>Pre-selected key IDs ({@code EXTRA_KEY_IDS_SELECTED})</li>
 *   <li>User ID → key ID resolution (OK / MISSING / DUPLICATE / NO_KEYS)</li>
 *   <li>Autocrypt key resolution priority over UID keys</li>
 *   <li>{@code allKeysConfirmed} flag (verified vs unverified)</li>
 *   <li>{@code combinedAutocryptState} (minimum across recipients)</li>
 *   <li>Mixed extras ({@code EXTRA_USER_IDS} + {@code EXTRA_KEY_IDS})</li>
 *   <li>Explicit key IDs ({@code EXTRA_KEY_IDS}) merging</li>
 *   <li>Case-sensitive email matching</li>
 *   <li>Malformed / boundary user IDs</li>
 *   <li>Calling package passed correctly to content resolver</li>
 *   <li>Error handling (null cursor, missing address in cursor)</li>
 * </ul>
 */
@SuppressWarnings("unchecked")
@RunWith(KeychainTestRunner.class)
public class OpenPgpServiceKeyIdExtractorTest {

    // ── Shared test constants ────────────────────────────────────────────
    private static final long[] KEY_IDS = new long[] { 123L, 234L };
    private static final String[] USER_IDS =
            new String[] { "user1@example.org", "User 2 <user2@example.org>" };
    private static final String CALLER_PKG = BuildConfig.APPLICATION_ID;

    private OpenPgpServiceKeyIdExtractor extractor;
    private ContentResolver contentResolver;
    private ApiPendingIntentFactory apiPendingIntentFactory;

    @Before
    public void setUp() throws Exception {
        contentResolver = mock(ContentResolver.class);
        apiPendingIntentFactory = mock(ApiPendingIntentFactory.class);
        extractor = OpenPgpServiceKeyIdExtractor.getInstance(contentResolver, apiPendingIntentFactory);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 1. Pre-selected key IDs (EXTRA_KEY_IDS_SELECTED)
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    public void returnKeyIdsFromIntent__withKeyIdsSelectedExtra() throws Exception {
        Intent intent = new Intent();
        intent.putExtra(OpenPgpApi.EXTRA_KEY_IDS_SELECTED, KEY_IDS);
        intent.putExtra(OpenPgpApi.EXTRA_USER_IDS, USER_IDS); // should be ignored

        KeyIdResult result = extractor.returnKeyIdsFromIntent(intent, false, CALLER_PKG);

        assertEquals(KeyIdResultStatus.OK, result.getStatus());
        assertFalse(result.hasKeySelectionPendingIntent());
        assertArrayEqualsSorted(KEY_IDS, result.getKeyIds());
    }

    /**
     * When KEY_IDS_SELECTED is set, allKeysConfirmed should be false regardless
     * (the selected-keys path does not carry verification info).
     */
    @Test
    public void returnKeyIdsFromIntent__withKeyIdsSelectedExtra__allKeysConfirmedFalse() throws Exception {
        Intent intent = new Intent();
        intent.putExtra(OpenPgpApi.EXTRA_KEY_IDS_SELECTED, KEY_IDS);

        KeyIdResult result = extractor.returnKeyIdsFromIntent(intent, false, CALLER_PKG);

        assertFalse(result.isAllKeysConfirmed());
    }

    /**
     * When KEY_IDS_SELECTED is combined with EXTRA_KEY_IDS, both sets should be
     * merged into the final key ID array.
     */
    @Test
    public void returnKeyIdsFromIntent__withKeyIdsSelected__andExplicitKeyIds__mergesBoth() throws Exception {
        Intent intent = new Intent();
        intent.putExtra(OpenPgpApi.EXTRA_KEY_IDS_SELECTED, new long[] { 100L });
        intent.putExtra(OpenPgpApi.EXTRA_KEY_IDS, new long[] { 200L });

        KeyIdResult result = extractor.returnKeyIdsFromIntent(intent, false, CALLER_PKG);

        assertEquals(KeyIdResultStatus.OK, result.getStatus());
        assertArrayEqualsSorted(new long[] { 100L, 200L }, result.getKeyIds());
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 2. Explicit key IDs only (EXTRA_KEY_IDS, no user IDs)
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * When only EXTRA_KEY_IDS is provided (no user IDs, no selected keys),
     * status is NO_KEYS_ERROR but the explicit IDs are still accessible.
     */
    @Test
    public void returnKeyIdsFromIntent__withKeyIdsExtra() throws Exception {
        Intent intent = new Intent();
        intent.putExtra(OpenPgpApi.EXTRA_KEY_IDS, KEY_IDS);

        KeyIdResult result = extractor.returnKeyIdsFromIntent(intent, false, CALLER_PKG);

        assertEquals(KeyIdResultStatus.NO_KEYS_ERROR, result.getStatus());
        assertFalse(result.hasKeySelectionPendingIntent());
        assertArrayEqualsSorted(KEY_IDS, result.getKeyIds());
    }

    /**
     * EXTRA_KEY_IDS with an empty long[] should still yield NO_KEYS_ERROR,
     * and getKeyIds() should return an empty array.
     */
    @Test
    public void returnKeyIdsFromIntent__withEmptyKeyIdsExtra() throws Exception {
        Intent intent = new Intent();
        intent.putExtra(OpenPgpApi.EXTRA_KEY_IDS, new long[0]);

        KeyIdResult result = extractor.returnKeyIdsFromIntent(intent, false, CALLER_PKG);

        assertEquals(KeyIdResultStatus.NO_KEYS_ERROR, result.getStatus());
        assertEquals(0, result.getKeyIds().length);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 3. Empty / missing extras
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Empty EXTRA_USER_IDS array → NO_KEYS with a select-key PendingIntent.
     */
    @Test
    public void returnKeyIdsFromIntent__withNoData() throws Exception {
        Intent intent = intentWithUserIds(new String[] {});
        PendingIntent pi = mockSelectPubkeyPendingIntent();

        KeyIdResult result = extractor.returnKeyIdsFromIntent(intent, false, CALLER_PKG);

        assertEquals(KeyIdResultStatus.NO_KEYS, result.getStatus());
        assertTrue(result.hasKeySelectionPendingIntent());
        assertSame(pi, result.getKeySelectionPendingIntent());
    }

    /**
     * new String[0] is functionally identical to an empty String[].
     */
    @Test
    public void returnKeyIdsFromIntent__withEmptyUserId() throws Exception {
        Intent intent = intentWithUserIds(new String[0]);
        PendingIntent pi = mockSelectPubkeyPendingIntent();

        KeyIdResult result = extractor.returnKeyIdsFromIntent(intent, false, CALLER_PKG);

        assertEquals(KeyIdResultStatus.NO_KEYS, result.getStatus());
        assertTrue(result.hasKeySelectionPendingIntent());
        assertSame(pi, result.getKeySelectionPendingIntent());
    }

    /**
     * No extras at all, askIfNoUserIdsProvided = true → NO_KEYS with PendingIntent.
     */
    @Test
    public void returnKeyIdsFromIntent__withNoData__askIfNoData() throws Exception {
        Intent intent = new Intent();
        PendingIntent pi = mockSelectPubkeyPendingIntent();

        KeyIdResult result = extractor.returnKeyIdsFromIntent(intent, true, CALLER_PKG);

        assertEquals(KeyIdResultStatus.NO_KEYS, result.getStatus());
        assertTrue(result.hasKeySelectionPendingIntent());
        assertSame(pi, result.getKeySelectionPendingIntent());
    }

    /**
     * No extras at all, askIfNoUserIdsProvided = false → NO_KEYS_ERROR (no PendingIntent).
     */
    @Test
    public void returnKeyIdsFromIntent__withNoExtras__askFalse__returnsNoKeysError() throws Exception {
        Intent intent = new Intent();

        KeyIdResult result = extractor.returnKeyIdsFromIntent(intent, false, CALLER_PKG);

        assertEquals(KeyIdResultStatus.NO_KEYS_ERROR, result.getStatus());
        assertFalse(result.hasKeySelectionPendingIntent());
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 4. User ID resolution → OK
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Standard happy-path: two user IDs, both resolve to unverified UID keys.
     */
    @Test
    public void returnKeyIdsFromIntent__withUserIds() throws Exception {
        Intent intent = intentWithUserIds(USER_IDS);
        mockContentResolver(cursor()
                .addUidRow(USER_IDS[0], 123L, KeychainExternalContract.KEY_STATUS_UNVERIFIED, 1)
                .addUidRow(USER_IDS[1], 234L, KeychainExternalContract.KEY_STATUS_UNVERIFIED, 1));

        KeyIdResult result = extractor.returnKeyIdsFromIntent(intent, false, CALLER_PKG);

        assertEquals(KeyIdResultStatus.OK, result.getStatus());
        assertFalse(result.hasKeySelectionPendingIntent());
        assertArrayEqualsSorted(KEY_IDS, result.getKeyIds());
    }

    /**
     * Single user ID resolving to a single key.
     */
    @Test
    public void returnKeyIdsFromIntent__withSingleUserId__resolvesOk() throws Exception {
        String[] userIds = new String[] { "alice@example.org" };
        Intent intent = intentWithUserIds(userIds);
        mockContentResolver(cursor()
                .addUidRow("alice@example.org", 42L, KeychainExternalContract.KEY_STATUS_VERIFIED, 1));

        KeyIdResult result = extractor.returnKeyIdsFromIntent(intent, false, CALLER_PKG);

        assertEquals(KeyIdResultStatus.OK, result.getStatus());
        assertArrayEqualsSorted(new long[] { 42L }, result.getKeyIds());
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 5. allKeysConfirmed flag
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * All UID keys verified → allKeysConfirmed = true.
     */
    @Test
    public void returnKeyIdsFromIntent__allKeysVerified__allKeysConfirmedTrue() throws Exception {
        Intent intent = intentWithUserIds(USER_IDS);
        mockContentResolver(cursor()
                .addUidRow(USER_IDS[0], 123L, KeychainExternalContract.KEY_STATUS_VERIFIED, 1)
                .addUidRow(USER_IDS[1], 234L, KeychainExternalContract.KEY_STATUS_VERIFIED, 1));

        KeyIdResult result = extractor.returnKeyIdsFromIntent(intent, false, CALLER_PKG);

        assertEquals(KeyIdResultStatus.OK, result.getStatus());
        assertTrue(result.isAllKeysConfirmed());
    }

    /**
     * One UID key verified, one unverified → allKeysConfirmed = false.
     */
    @Test
    public void returnKeyIdsFromIntent__oneKeyUnverified__allKeysConfirmedFalse() throws Exception {
        Intent intent = intentWithUserIds(USER_IDS);
        mockContentResolver(cursor()
                .addUidRow(USER_IDS[0], 123L, KeychainExternalContract.KEY_STATUS_VERIFIED, 1)
                .addUidRow(USER_IDS[1], 234L, KeychainExternalContract.KEY_STATUS_UNVERIFIED, 1));

        KeyIdResult result = extractor.returnKeyIdsFromIntent(intent, false, CALLER_PKG);

        assertEquals(KeyIdResultStatus.OK, result.getStatus());
        assertFalse(result.isAllKeysConfirmed());
    }

    /**
     * All UID keys unverified → allKeysConfirmed = false.
     */
    @Test
    public void returnKeyIdsFromIntent__allKeysUnverified__allKeysConfirmedFalse() throws Exception {
        Intent intent = intentWithUserIds(USER_IDS);
        mockContentResolver(cursor()
                .addUidRow(USER_IDS[0], 123L, KeychainExternalContract.KEY_STATUS_UNVERIFIED, 1)
                .addUidRow(USER_IDS[1], 234L, KeychainExternalContract.KEY_STATUS_UNVERIFIED, 1));

        KeyIdResult result = extractor.returnKeyIdsFromIntent(intent, false, CALLER_PKG);

        assertFalse(result.isAllKeysConfirmed());
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 6. Autocrypt key resolution (autocrypt takes priority over UID keys)
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * When both autocrypt and UID keys exist for an address, the autocrypt key
     * is selected and the UID key is ignored.
     */
    @Test
    public void returnKeyIdsFromIntent__autocryptKeyTakesPriorityOverUidKey() throws Exception {
        String[] userIds = new String[] { "alice@example.org" };
        Intent intent = intentWithUserIds(userIds);
        // autocryptMasterKeyId=999, uidMasterKeyId=123 → expect 999
        mockContentResolver(cursor()
                .addFullRow("alice@example.org",
                        123L, KeychainExternalContract.KEY_STATUS_VERIFIED, 1,
                        999L, KeychainExternalContract.KEY_STATUS_VERIFIED,
                        AutocryptStatus.AUTOCRYPT_PEER_MUTUAL));

        KeyIdResult result = extractor.returnKeyIdsFromIntent(intent, false, CALLER_PKG);

        assertEquals(KeyIdResultStatus.OK, result.getStatus());
        assertArrayEqualsSorted(new long[] { 999L }, result.getKeyIds());
    }

    /**
     * Autocrypt key with UID key status VERIFIED but autocrypt key status UNVERIFIED
     * → allKeysConfirmed should be false (autocrypt verification status is used).
     */
    @Test
    public void returnKeyIdsFromIntent__autocryptKeyUnverified__allKeysConfirmedFalse() throws Exception {
        String[] userIds = new String[] { "alice@example.org" };
        Intent intent = intentWithUserIds(userIds);
        mockContentResolver(cursor()
                .addFullRow("alice@example.org",
                        123L, KeychainExternalContract.KEY_STATUS_VERIFIED, 1,
                        999L, KeychainExternalContract.KEY_STATUS_UNVERIFIED,
                        AutocryptStatus.AUTOCRYPT_PEER_AVAILABLE));

        KeyIdResult result = extractor.returnKeyIdsFromIntent(intent, false, CALLER_PKG);

        assertEquals(KeyIdResultStatus.OK, result.getStatus());
        assertFalse(result.isAllKeysConfirmed());
    }

    /**
     * Autocrypt key with status VERIFIED → allKeysConfirmed = true.
     */
    @Test
    public void returnKeyIdsFromIntent__autocryptKeyVerified__allKeysConfirmedTrue() throws Exception {
        String[] userIds = new String[] { "alice@example.org" };
        Intent intent = intentWithUserIds(userIds);
        mockContentResolver(cursor()
                .addFullRow("alice@example.org",
                        123L, KeychainExternalContract.KEY_STATUS_UNVERIFIED, 1,
                        999L, KeychainExternalContract.KEY_STATUS_VERIFIED,
                        AutocryptStatus.AUTOCRYPT_PEER_MUTUAL));

        KeyIdResult result = extractor.returnKeyIdsFromIntent(intent, false, CALLER_PKG);

        assertEquals(KeyIdResultStatus.OK, result.getStatus());
        assertTrue(result.isAllKeysConfirmed());
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 7. combinedAutocryptState (minimum / weakest-link semantics)
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Single recipient with AUTOCRYPT_PEER_MUTUAL → combined state = MUTUAL.
     */
    @Test
    public void returnKeyIdsFromIntent__singleAutocryptMutual__stateIsMutual() throws Exception {
        String[] userIds = new String[] { "alice@example.org" };
        Intent intent = intentWithUserIds(userIds);
        mockContentResolver(cursor()
                .addFullRow("alice@example.org",
                        null, 0, 0,
                        999L, KeychainExternalContract.KEY_STATUS_VERIFIED,
                        AutocryptStatus.AUTOCRYPT_PEER_MUTUAL));

        KeyIdResult result = extractor.returnKeyIdsFromIntent(intent, false, CALLER_PKG);

        assertEquals(KeyIdResultStatus.OK, result.getStatus());
        assertEquals(AutocryptStatus.AUTOCRYPT_PEER_MUTUAL, result.getAutocryptRecommendation());
    }

    /**
     * Two recipients: one MUTUAL, one AVAILABLE → combined = min = AVAILABLE.
     */
    @Test
    public void returnKeyIdsFromIntent__mixedAutocryptStates__returnsMinimum() throws Exception {
        String[] userIds = new String[] { "alice@example.org", "bob@example.org" };
        Intent intent = intentWithUserIds(userIds);
        mockContentResolver(cursor()
                .addFullRow("alice@example.org",
                        null, 0, 0,
                        100L, KeychainExternalContract.KEY_STATUS_VERIFIED,
                        AutocryptStatus.AUTOCRYPT_PEER_MUTUAL)
                .addFullRow("bob@example.org",
                        null, 0, 0,
                        200L, KeychainExternalContract.KEY_STATUS_VERIFIED,
                        AutocryptStatus.AUTOCRYPT_PEER_AVAILABLE));

        KeyIdResult result = extractor.returnKeyIdsFromIntent(intent, false, CALLER_PKG);

        assertEquals(KeyIdResultStatus.OK, result.getStatus());
        assertEquals(AutocryptStatus.AUTOCRYPT_PEER_AVAILABLE, result.getAutocryptRecommendation());
    }

    /**
     * Two recipients: one GOSSIP, one DISCOURAGED_OLD → combined = min = DISCOURAGED_OLD.
     */
    @Test
    public void returnKeyIdsFromIntent__gossipAndDiscouraged__returnsDiscouraged() throws Exception {
        String[] userIds = new String[] { "alice@example.org", "bob@example.org" };
        Intent intent = intentWithUserIds(userIds);
        mockContentResolver(cursor()
                .addFullRow("alice@example.org",
                        null, 0, 0,
                        100L, KeychainExternalContract.KEY_STATUS_VERIFIED,
                        AutocryptStatus.AUTOCRYPT_PEER_GOSSIP)
                .addFullRow("bob@example.org",
                        null, 0, 0,
                        200L, KeychainExternalContract.KEY_STATUS_VERIFIED,
                        AutocryptStatus.AUTOCRYPT_PEER_DISCOURAGED_OLD));

        KeyIdResult result = extractor.returnKeyIdsFromIntent(intent, false, CALLER_PKG);

        assertEquals(KeyIdResultStatus.OK, result.getStatus());
        assertEquals(AutocryptStatus.AUTOCRYPT_PEER_DISCOURAGED_OLD, result.getAutocryptRecommendation());
    }

    /**
     * UID-key path (no autocrypt) forces combined state to AVAILABLE_EXTERNAL.
     */
    @Test
    public void returnKeyIdsFromIntent__uidKeyOnly__autocryptStateAvailableExternal() throws Exception {
        String[] userIds = new String[] { "alice@example.org" };
        Intent intent = intentWithUserIds(userIds);
        mockContentResolver(cursor()
                .addUidRow("alice@example.org", 42L, KeychainExternalContract.KEY_STATUS_VERIFIED, 1));

        KeyIdResult result = extractor.returnKeyIdsFromIntent(intent, false, CALLER_PKG);

        assertEquals(KeyIdResultStatus.OK, result.getStatus());
        assertEquals(AutocryptStatus.AUTOCRYPT_PEER_AVAILABLE_EXTERNAL, result.getAutocryptRecommendation());
    }

    /**
     * Mixed: one autocrypt recipient + one UID-only recipient →
     * UID-only forces AVAILABLE_EXTERNAL, which is less than AVAILABLE → min wins.
     */
    @Test
    public void returnKeyIdsFromIntent__mixedAutocryptAndUid__stateIsAvailableExternal() throws Exception {
        String[] userIds = new String[] { "alice@example.org", "bob@example.org" };
        Intent intent = intentWithUserIds(userIds);
        mockContentResolver(cursor()
                .addFullRow("alice@example.org",
                        null, 0, 0,
                        100L, KeychainExternalContract.KEY_STATUS_VERIFIED,
                        AutocryptStatus.AUTOCRYPT_PEER_MUTUAL)
                .addUidRow("bob@example.org", 200L, KeychainExternalContract.KEY_STATUS_VERIFIED, 1));

        KeyIdResult result = extractor.returnKeyIdsFromIntent(intent, false, CALLER_PKG);

        assertEquals(KeyIdResultStatus.OK, result.getStatus());
        // AVAILABLE_EXTERNAL(30) < MUTUAL(50), so min = 30
        assertEquals(AutocryptStatus.AUTOCRYPT_PEER_AVAILABLE_EXTERNAL, result.getAutocryptRecommendation());
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 8. Missing keys
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * One user ID has null key (no key available) → MISSING with select-key PendingIntent.
     */
    @Test
    public void returnKeyIdsFromIntent__withUserIds__withMissing() throws Exception {
        Intent intent = intentWithUserIds(USER_IDS);
        mockContentResolver(cursor()
                .addUidRow(USER_IDS[0], null, 0, 0)
                .addUidRow(USER_IDS[1], 234L, KeychainExternalContract.KEY_STATUS_UNVERIFIED, 1));
        PendingIntent pi = mockSelectPubkeyPendingIntent();

        KeyIdResult result = extractor.returnKeyIdsFromIntent(intent, false, CALLER_PKG);

        assertEquals(KeyIdResultStatus.MISSING, result.getStatus());
        assertTrue(result.hasKeySelectionPendingIntent());
        assertSame(pi, result.getKeySelectionPendingIntent());
    }

    /**
     * All user IDs missing → MISSING (not NO_KEYS, since we had addresses to resolve).
     */
    @Test
    public void returnKeyIdsFromIntent__allEmailsMissing__returnsMissing() throws Exception {
        String[] userIds = new String[] { "unknown1@example.org", "unknown2@example.org" };
        Intent intent = intentWithUserIds(userIds);
        mockContentResolver(cursor()
                .addUidRow("unknown1@example.org", null, 0, 0)
                .addUidRow("unknown2@example.org", null, 0, 0));
        PendingIntent pi = mockSelectPubkeyPendingIntent();

        KeyIdResult result = extractor.returnKeyIdsFromIntent(intent, false, CALLER_PKG);

        assertEquals(KeyIdResultStatus.MISSING, result.getStatus());
        assertTrue(result.hasKeySelectionPendingIntent());
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 9. Duplicate keys
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * One user ID has multiple candidates (uid_candidates > 1) → DUPLICATE.
     */
    @Test
    public void returnKeyIdsFromIntent__withUserIds__withDuplicate() throws Exception {
        Intent intent = intentWithUserIds(USER_IDS);
        mockContentResolver(cursor()
                .addUidRow(USER_IDS[0], 123L, KeychainExternalContract.KEY_STATUS_UNVERIFIED, 2)
                .addUidRow(USER_IDS[1], 234L, KeychainExternalContract.KEY_STATUS_UNVERIFIED, 1));
        PendingIntent pi = mockDeduplicatePendingIntent();

        KeyIdResult result = extractor.returnKeyIdsFromIntent(intent, false, CALLER_PKG);

        assertEquals(KeyIdResultStatus.DUPLICATE, result.getStatus());
        assertTrue(result.hasKeySelectionPendingIntent());
        assertSame(pi, result.getKeySelectionPendingIntent());
    }

    /**
     * MISSING takes priority over DUPLICATE: if one email is missing AND another
     * is duplicate, the result is MISSING (not DUPLICATE).
     */
    @Test
    public void returnKeyIdsFromIntent__missingTakesPriorityOverDuplicate() throws Exception {
        Intent intent = intentWithUserIds(USER_IDS);
        mockContentResolver(cursor()
                .addUidRow(USER_IDS[0], null, 0, 0)                // missing
                .addUidRow(USER_IDS[1], 234L, 0, 2));              // duplicate
        PendingIntent pi = mockSelectPubkeyPendingIntent();

        KeyIdResult result = extractor.returnKeyIdsFromIntent(intent, false, CALLER_PKG);

        assertEquals(KeyIdResultStatus.MISSING, result.getStatus());
        assertTrue(result.hasKeySelectionPendingIntent());
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 10. Mixed extras (USER_IDS + KEY_IDS, KEY_IDS_SELECTED + KEY_IDS)
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * USER_IDS resolve to keys AND KEY_IDS are present → both are merged.
     * Status is driven by user ID resolution (OK), with explicit key IDs appended.
     */
    @Test
    public void returnKeyIdsFromIntent__userIdsAndExplicitKeyIds__bothMerged() throws Exception {
        Intent intent = new Intent();
        intent.putExtra(OpenPgpApi.EXTRA_USER_IDS, new String[] { "alice@example.org" });
        intent.putExtra(OpenPgpApi.EXTRA_KEY_IDS, new long[] { 500L });
        mockContentResolver(cursor()
                .addUidRow("alice@example.org", 100L, KeychainExternalContract.KEY_STATUS_VERIFIED, 1));

        KeyIdResult result = extractor.returnKeyIdsFromIntent(intent, false, CALLER_PKG);

        assertEquals(KeyIdResultStatus.OK, result.getStatus());
        assertArrayEqualsSorted(new long[] { 100L, 500L }, result.getKeyIds());
    }

    /**
     * USER_IDS + KEY_IDS where the same ID appears in both → no duplicates in result.
     */
    @Test
    public void returnKeyIdsFromIntent__overlappingUserAndExplicitKeyIds__noDuplicate() throws Exception {
        Intent intent = new Intent();
        intent.putExtra(OpenPgpApi.EXTRA_USER_IDS, new String[] { "alice@example.org" });
        intent.putExtra(OpenPgpApi.EXTRA_KEY_IDS, new long[] { 100L }); // same as resolved
        mockContentResolver(cursor()
                .addUidRow("alice@example.org", 100L, KeychainExternalContract.KEY_STATUS_VERIFIED, 1));

        KeyIdResult result = extractor.returnKeyIdsFromIntent(intent, false, CALLER_PKG);

        assertEquals(KeyIdResultStatus.OK, result.getStatus());
        assertArrayEqualsSorted(new long[] { 100L }, result.getKeyIds());
    }

    /**
     * USER_IDS with MISSING status + KEY_IDS → status is MISSING (explicit IDs
     * are appended to the result but don't override the missing-keys state).
     */
    @Test
    public void returnKeyIdsFromIntent__missingUserIdsAndExplicitKeyIds__stillMissing() throws Exception {
        Intent intent = new Intent();
        intent.putExtra(OpenPgpApi.EXTRA_USER_IDS, new String[] { "missing@example.org" });
        intent.putExtra(OpenPgpApi.EXTRA_KEY_IDS, new long[] { 500L });
        mockContentResolver(cursor()
                .addUidRow("missing@example.org", null, 0, 0));
        PendingIntent pi = mockSelectPubkeyPendingIntent();

        KeyIdResult result = extractor.returnKeyIdsFromIntent(intent, false, CALLER_PKG);

        assertEquals(KeyIdResultStatus.MISSING, result.getStatus());
        assertTrue(result.hasKeySelectionPendingIntent());
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 11. Case-sensitive email matching
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * If the content provider returns a differently-cased address than what was
     * requested, the HashMap lookup fails → IllegalStateException.
     * This documents the case-sensitivity contract: callers and the provider must
     * agree on the exact address string.
     */
    @Test(expected = IllegalStateException.class)
    public void returnKeyIdsFromIntent__caseSensitiveEmailMismatch__throwsIllegalState() throws Exception {
        String[] userIds = new String[] { "Alice@Example.Org" };
        Intent intent = intentWithUserIds(userIds);
        // Provider returns lower-case, which won't match the requested upper-case key
        mockContentResolver(cursor()
                .addUidRow("alice@example.org", 123L, KeychainExternalContract.KEY_STATUS_VERIFIED, 1));
        mockSelectPubkeyPendingIntent();

        extractor.returnKeyIdsFromIntent(intent, false, CALLER_PKG);
    }

    /**
     * Exact case match (all lower-case) → resolves correctly.
     */
    @Test
    public void returnKeyIdsFromIntent__lowerCaseEmailMatches() throws Exception {
        String[] userIds = new String[] { "alice@example.org" };
        Intent intent = intentWithUserIds(userIds);
        mockContentResolver(cursor()
                .addUidRow("alice@example.org", 42L, KeychainExternalContract.KEY_STATUS_VERIFIED, 1));

        KeyIdResult result = extractor.returnKeyIdsFromIntent(intent, false, CALLER_PKG);

        assertEquals(KeyIdResultStatus.OK, result.getStatus());
        assertArrayEqualsSorted(new long[] { 42L }, result.getKeyIds());
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 12. Malformed / boundary user IDs
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Full RFC 2822 display-name format "Name <email>" should be accepted
     * and passed through to the content resolver as-is.
     */
    @Test
    public void returnKeyIdsFromIntent__userIdWithDisplayName__passedThrough() throws Exception {
        String[] userIds = new String[] { "Alice <alice@example.org>" };
        Intent intent = intentWithUserIds(userIds);
        mockContentResolver(cursor()
                .addUidRow("Alice <alice@example.org>", 42L, KeychainExternalContract.KEY_STATUS_VERIFIED, 1));

        KeyIdResult result = extractor.returnKeyIdsFromIntent(intent, false, CALLER_PKG);

        assertEquals(KeyIdResultStatus.OK, result.getStatus());
        assertArrayEqualsSorted(new long[] { 42L }, result.getKeyIds());
    }

    /**
     * User ID containing only whitespace → content resolver likely won't match
     * → IllegalStateException (no matching row in cursor).
     */
    @Test(expected = IllegalStateException.class)
    public void returnKeyIdsFromIntent__blankUserId__throwsIllegalState() throws Exception {
        String[] userIds = new String[] { "   " };
        Intent intent = intentWithUserIds(userIds);
        // Content resolver returns an empty cursor (no rows for blank address)
        mockContentResolver(new MailStatusCursorBuilder().build());
        mockSelectPubkeyPendingIntent();

        extractor.returnKeyIdsFromIntent(intent, false, CALLER_PKG);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 13. Duplicate entries in EXTRA_USER_IDS array
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Same email appears twice in the user IDs array. The HashMap deduplicates
     * addresses, but the iteration loop visits the address twice, potentially
     * adding it to duplicateEmails twice.
     */
    @Test
    public void returnKeyIdsFromIntent__duplicateEmailInArray__resolvesOk() throws Exception {
        String[] userIds = new String[] { "alice@example.org", "alice@example.org" };
        Intent intent = intentWithUserIds(userIds);
        // Provider returns a single row (addresses are unique in DB)
        mockContentResolver(cursor()
                .addUidRow("alice@example.org", 42L, KeychainExternalContract.KEY_STATUS_VERIFIED, 1));

        KeyIdResult result = extractor.returnKeyIdsFromIntent(intent, false, CALLER_PKG);

        // The same key ID is added twice to the HashSet → deduplicated
        assertEquals(KeyIdResultStatus.OK, result.getStatus());
        assertArrayEqualsSorted(new long[] { 42L }, result.getKeyIds());
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 14. Calling package verification
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Calling package name is appended to the content URI. Different callers
     * produce different query URIs (used by the provider for per-app filtering).
     * The extractor correctly forwards whatever package name it receives.
     */
    @Test
    public void returnKeyIdsFromIntent__differentCallingPackage__stillResolvesOk() throws Exception {
        String[] userIds = new String[] { "alice@example.org" };
        Intent intent = intentWithUserIds(userIds);
        mockContentResolver(cursor()
                .addUidRow("alice@example.org", 42L, KeychainExternalContract.KEY_STATUS_VERIFIED, 1));

        // Use a different package name than BuildConfig.APPLICATION_ID
        KeyIdResult result = extractor.returnKeyIdsFromIntent(intent, false, "com.example.otherapp");

        assertEquals(KeyIdResultStatus.OK, result.getStatus());
        assertArrayEqualsSorted(new long[] { 42L }, result.getKeyIds());
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 15. Error handling
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Content resolver returns a non-null cursor that has zero rows for a
     * non-empty user IDs array → IllegalStateException (address not found in map).
     */
    @Test(expected = IllegalStateException.class)
    public void returnKeyIdsFromIntent__withUserIds__withEmptyQueryResult() throws Exception {
        Intent intent = intentWithUserIds(USER_IDS);
        mockContentResolver(new MailStatusCursorBuilder().build());
        mockSelectPubkeyPendingIntent();

        extractor.returnKeyIdsFromIntent(intent, false, CALLER_PKG);
    }

    /**
     * Content resolver returns null → IllegalStateException.
     * The extractor explicitly checks for null cursors and throws.
     */
    @Test(expected = IllegalStateException.class)
    public void returnKeyIdsFromIntent__nullCursor__throwsIllegalState() throws Exception {
        Intent intent = intentWithUserIds(USER_IDS);
        when(contentResolver.query(
                any(Uri.class), any(String[].class),
                nullable(String.class), any(String[].class),
                nullable(String.class)))
                .thenReturn(null);

        extractor.returnKeyIdsFromIntent(intent, false, CALLER_PKG);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 16. KEY_IDS_SELECTED precedence over other resolution paths
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * KEY_IDS_SELECTED is present → email resolution is entirely skipped,
     * even when EXTRA_USER_IDS is also present.
     */
    @Test
    public void returnKeyIdsFromIntent__selectedKeysBypassEmailResolution() throws Exception {
        Intent intent = new Intent();
        intent.putExtra(OpenPgpApi.EXTRA_KEY_IDS_SELECTED, new long[] { 888L });
        intent.putExtra(OpenPgpApi.EXTRA_USER_IDS, new String[] { "alice@example.org" });
        // No content resolver mock → would fail if email resolution were attempted

        KeyIdResult result = extractor.returnKeyIdsFromIntent(intent, false, CALLER_PKG);

        assertEquals(KeyIdResultStatus.OK, result.getStatus());
        assertArrayEqualsSorted(new long[] { 888L }, result.getKeyIds());
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 17. Three or more recipients — autocrypt state combination
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Three recipients with varying autocrypt states:
     * MUTUAL(50), AVAILABLE(40), GOSSIP(20) → min = GOSSIP(20).
     */
    @Test
    public void returnKeyIdsFromIntent__threeRecipients__autocryptMinAcrossAll() throws Exception {
        String[] userIds = new String[] { "a@example.org", "b@example.org", "c@example.org" };
        Intent intent = intentWithUserIds(userIds);
        mockContentResolver(cursor()
                .addFullRow("a@example.org", null, 0, 0,
                        100L, KeychainExternalContract.KEY_STATUS_VERIFIED,
                        AutocryptStatus.AUTOCRYPT_PEER_MUTUAL)
                .addFullRow("b@example.org", null, 0, 0,
                        200L, KeychainExternalContract.KEY_STATUS_VERIFIED,
                        AutocryptStatus.AUTOCRYPT_PEER_AVAILABLE)
                .addFullRow("c@example.org", null, 0, 0,
                        300L, KeychainExternalContract.KEY_STATUS_VERIFIED,
                        AutocryptStatus.AUTOCRYPT_PEER_GOSSIP));

        KeyIdResult result = extractor.returnKeyIdsFromIntent(intent, false, CALLER_PKG);

        assertEquals(KeyIdResultStatus.OK, result.getStatus());
        assertEquals(AutocryptStatus.AUTOCRYPT_PEER_GOSSIP, result.getAutocryptRecommendation());
        assertArrayEqualsSorted(new long[] { 100L, 200L, 300L }, result.getKeyIds());
    }

    // ─────────────────────────────────────────────────────────────────────
    // Intent construction helpers
    // ─────────────────────────────────────────────────────────────────────

    private static Intent intentWithUserIds(String[] userIds) {
        Intent intent = new Intent();
        intent.putExtra(OpenPgpApi.EXTRA_USER_IDS, userIds);
        return intent;
    }

    // ─────────────────────────────────────────────────────────────────────
    // Mock setup helpers
    // ─────────────────────────────────────────────────────────────────────

    private static MailStatusCursorBuilder cursor() {
        return new MailStatusCursorBuilder();
    }

    private void mockContentResolver(MatrixCursor cursor) {
        when(contentResolver.query(
                any(Uri.class), any(String[].class),
                nullable(String.class), any(String[].class),
                nullable(String.class)))
                .thenReturn(cursor);
    }

    private PendingIntent mockSelectPubkeyPendingIntent() {
        PendingIntent pi = mock(PendingIntent.class);
        when(apiPendingIntentFactory.createSelectPublicKeyPendingIntent(
                any(Intent.class), any(long[].class),
                any(ArrayList.class), any(ArrayList.class),
                any(Boolean.class)))
                .thenReturn(pi);
        return pi;
    }

    private PendingIntent mockDeduplicatePendingIntent() {
        PendingIntent pi = mock(PendingIntent.class);
        when(apiPendingIntentFactory.createDeduplicatePendingIntent(
                any(String.class), any(Intent.class), any(ArrayList.class)))
                .thenReturn(pi);
        return pi;
    }

    // ─────────────────────────────────────────────────────────────────────
    // Assertion helpers
    // ─────────────────────────────────────────────────────────────────────

    private static void assertArrayEqualsSorted(long[] a, long[] b) {
        long[] tmpA = Arrays.copyOf(a, a.length);
        long[] tmpB = Arrays.copyOf(b, b.length);
        Arrays.sort(tmpA);
        Arrays.sort(tmpB);
        assertArrayEquals(tmpA, tmpB);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Test-data builder: constructs MatrixCursor rows matching
    // OpenPgpServiceKeyIdExtractor.PROJECTION_MAIL_STATUS
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Fluent builder for {@link MatrixCursor} rows matching
     * {@link OpenPgpServiceKeyIdExtractor#PROJECTION_MAIL_STATUS}:
     * <pre>
     *   [ADDRESS, UID_MASTER_KEY_ID, UID_KEY_STATUS, UID_CANDIDATES,
     *    AUTOCRYPT_MASTER_KEY_ID, AUTOCRYPT_KEY_STATUS, AUTOCRYPT_PEER_STATE]
     * </pre>
     *
     * <p>Use {@link #addUidRow} when only UID-level data is relevant (autocrypt
     * columns will be null/0), or {@link #addFullRow} for complete control.
     */
    private static class MailStatusCursorBuilder {
        private final MatrixCursor cursor =
                new MatrixCursor(OpenPgpServiceKeyIdExtractor.PROJECTION_MAIL_STATUS);

        /**
         * Add a row representing a UID-matched key (no autocrypt data).
         *
         * @param address    email address or user ID string
         * @param uidKeyId   master key ID, or null if no key found
         * @param keyStatus  KEY_STATUS_UNAVAILABLE / UNVERIFIED / VERIFIED
         * @param candidates number of candidate keys (1 = unambiguous, &gt;1 = duplicate)
         */
        MailStatusCursorBuilder addUidRow(String address, Long uidKeyId, int keyStatus, int candidates) {
            cursor.addRow(new Object[] {
                    address, uidKeyId, keyStatus, candidates,
                    null, null, null
            });
            return this;
        }

        /**
         * Add a row with full control over all columns, including autocrypt data.
         *
         * @param address             email address or user ID string
         * @param uidKeyId            UID master key ID, or null
         * @param uidKeyStatus        UID key status
         * @param uidCandidates       UID candidate count
         * @param autocryptKeyId      autocrypt master key ID, or null
         * @param autocryptKeyStatus  autocrypt key status
         * @param autocryptPeerState  autocrypt peer state constant
         */
        MailStatusCursorBuilder addFullRow(String address,
                Long uidKeyId, int uidKeyStatus, int uidCandidates,
                Long autocryptKeyId, int autocryptKeyStatus, int autocryptPeerState) {
            cursor.addRow(new Object[] {
                    address, uidKeyId, uidKeyStatus, uidCandidates,
                    autocryptKeyId, autocryptKeyStatus, autocryptPeerState
            });
            return this;
        }

        MatrixCursor build() {
            return cursor;
        }
    }
}
