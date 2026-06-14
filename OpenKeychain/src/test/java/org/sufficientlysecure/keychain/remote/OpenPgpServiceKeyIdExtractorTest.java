package org.sufficientlysecure.keychain.remote;


import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import android.app.PendingIntent;
import android.content.ContentResolver;
import android.content.Intent;
import android.database.MatrixCursor;
import android.net.Uri;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.openintents.openpgp.util.OpenPgpApi;
import org.sufficientlysecure.keychain.BuildConfig;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.provider.KeychainExternalContract;
import org.sufficientlysecure.keychain.remote.OpenPgpServiceKeyIdExtractor.KeyIdResult;
import org.sufficientlysecure.keychain.remote.OpenPgpServiceKeyIdExtractor.KeyIdResultStatus;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link OpenPgpServiceKeyIdExtractor#returnKeyIdsFromIntent}.
 *
 * <p>The extractor is the boundary that turns the loosely-typed extras an external app puts into an
 * {@link Intent} (explicit key ids, "already selected" key ids, recipient user ids) into a concrete
 * set of key ids to use, or into a {@link KeyIdResultStatus} that asks the user to resolve the
 * ambiguity. Because external apps fully control these extras, the tests below deliberately probe
 * the boundary inputs that could otherwise lead to selecting the wrong key (or silently selecting
 * none).
 *
 * <p>The tests are grouped by the <em>kind of intent input</em>, and every test name states the
 * input and the expected key-selection / rejection outcome. The mapping under test is roughly:
 * <ul>
 *     <li>{@code EXTRA_KEY_IDS_SELECTED} present -&gt; {@link KeyIdResultStatus#OK} with exactly
 *         those keys (recipient user ids are ignored).</li>
 *     <li>{@code EXTRA_USER_IDS} present (or {@code askIfNoUserIdsProvided}) -&gt; addresses are
 *         resolved against the per-caller provider, yielding OK / MISSING / DUPLICATE / NO_KEYS.</li>
 *     <li>no relevant extras and not asked -&gt; {@link KeyIdResultStatus#NO_KEYS_ERROR}.</li>
 *     <li>{@code EXTRA_KEY_IDS}, if present, is merged into whatever the above produced.</li>
 * </ul>
 *
 * <p>Authorization of the calling app is <em>not</em> performed here (that is
 * {@link ApiPermissionHelper} / the content provider). What this class does verify is that the
 * extractor scopes its lookup to the calling package and faithfully propagates a provider rejection
 * rather than falling back to some other key.
 */
@SuppressWarnings("unchecked")
@RunWith(KeychainTestRunner.class)
public class OpenPgpServiceKeyIdExtractorTest {

    private static final long KEY_ID_A = 123L;
    private static final long KEY_ID_B = 234L;
    private static final long KEY_ID_C = 999L;
    private static final String[] USER_IDS =
            new String[] { "user1@example.org", "User 2 <user2@example.org>" };
    private static final String CALLING_PACKAGE = BuildConfig.APPLICATION_ID;

    private OpenPgpServiceKeyIdExtractor openPgpServiceKeyIdExtractor;
    private ContentResolver contentResolver;
    private ApiPendingIntentFactory apiPendingIntentFactory;

    @Before
    public void setUp() throws Exception {
        contentResolver = mock(ContentResolver.class);
        apiPendingIntentFactory = mock(ApiPendingIntentFactory.class);

        openPgpServiceKeyIdExtractor = OpenPgpServiceKeyIdExtractor.getInstance(contentResolver,
                apiPendingIntentFactory);
    }

    // region explicit / pre-selected key ids -------------------------------------------------

    @Test
    public void withExplicitKeyIds__returnsThoseKeys__butNoKeysErrorStatus() throws Exception {
        // EXTRA_KEY_IDS alone is treated as "use exactly these", but without user ids there is
        // nothing to confirm, so the status stays NO_KEYS_ERROR while the keys are still returned.
        Intent intent = anApiIntent().withExplicitKeyIds(KEY_ID_A, KEY_ID_B).build();

        KeyIdResult result = extract(intent);

        assertEquals(KeyIdResultStatus.NO_KEYS_ERROR, result.getStatus());
        assertSelectedKeyIds(result, KEY_ID_A, KEY_ID_B);
    }

    @Test
    public void withSelectedKeyIds__ignoresUserIds__returnsOk() throws Exception {
        // Keys coming back from the select-pubkey activity are authoritative; recipient user ids
        // supplied alongside them must be ignored rather than re-resolved.
        Intent intent = anApiIntent()
                .withSelectedKeyIds(KEY_ID_A, KEY_ID_B)
                .withUserIds(USER_IDS)
                .build();

        KeyIdResult result = extract(intent);

        assertEquals(KeyIdResultStatus.OK, result.getStatus());
        assertSelectedKeyIds(result, KEY_ID_A, KEY_ID_B);
    }

    @Test
    public void withDuplicateExplicitKeyIds__deduplicatesToDistinctKeys() throws Exception {
        Intent intent = anApiIntent().withExplicitKeyIds(KEY_ID_A, KEY_ID_A, KEY_ID_B).build();

        KeyIdResult result = extract(intent);

        assertEquals(KeyIdResultStatus.NO_KEYS_ERROR, result.getStatus());
        assertSelectedKeyIds(result, KEY_ID_A, KEY_ID_B);
    }

    @Test
    public void withDuplicateSelectedKeyIds__deduplicatesToDistinctKeys() throws Exception {
        Intent intent = anApiIntent().withSelectedKeyIds(KEY_ID_A, KEY_ID_A).build();

        KeyIdResult result = extract(intent);

        assertEquals(KeyIdResultStatus.OK, result.getStatus());
        assertSelectedKeyIds(result, KEY_ID_A);
    }

    @Test
    public void withEmptySelectedKeyIds__returnsOkWithNoKeys() throws Exception {
        // An explicit (but empty) selection means "the user chose nothing, proceed anyway"; this is
        // distinct from NO_KEYS, which would prompt a selection.
        Intent intent = anApiIntent().withSelectedKeyIds().build();

        KeyIdResult result = extract(intent);

        assertEquals(KeyIdResultStatus.OK, result.getStatus());
        assertSelectedKeyIds(result);
    }

    // endregion

    // region empty / absent extras ------------------------------------------------------------

    @Test
    public void withNoExtras__notAsked__returnsNoKeysError() throws Exception {
        Intent intent = anApiIntent().build();

        KeyIdResult result = extract(intent, false);

        assertEquals(KeyIdResultStatus.NO_KEYS_ERROR, result.getStatus());
        assertFalse(result.hasKeySelectionPendingIntent());
    }

    @Test
    public void withNoExtras__askIfNoUserIds__promptsKeySelection() throws Exception {
        Intent intent = anApiIntent().build();
        PendingIntent pendingIntent = givenSelectPubkeyPendingIntent();

        KeyIdResult result = extract(intent, true);

        assertEquals(KeyIdResultStatus.NO_KEYS, result.getStatus());
        assertTrue(result.hasKeySelectionPendingIntent());
        assertSame(pendingIntent, result.getKeySelectionPendingIntent());
    }

    @Test
    public void withEmptyUserIdArray__promptsKeySelection() throws Exception {
        Intent intent = anApiIntent().withUserIds(/* empty */).build();
        PendingIntent pendingIntent = givenSelectPubkeyPendingIntent();

        KeyIdResult result = extract(intent, false);

        assertEquals(KeyIdResultStatus.NO_KEYS, result.getStatus());
        assertTrue(result.hasKeySelectionPendingIntent());
        assertSame(pendingIntent, result.getKeySelectionPendingIntent());
    }

    // endregion

    // region user-id (recipient address) resolution ------------------------------------------

    @Test
    public void withUserIds__resolvesEachAddressToItsKey() throws Exception {
        Intent intent = anApiIntent().withUserIds(USER_IDS).build();
        setupUidQueryResult(
                uidRow(USER_IDS[0], KEY_ID_A, KeychainExternalContract.KEY_STATUS_UNAVAILABLE, 1),
                uidRow(USER_IDS[1], KEY_ID_B, KeychainExternalContract.KEY_STATUS_UNAVAILABLE, 1));

        KeyIdResult result = extract(intent);

        assertEquals(KeyIdResultStatus.OK, result.getStatus());
        assertSelectedKeyIds(result, KEY_ID_A, KEY_ID_B);
    }

    @Test
    public void withUserIds__allKeysVerified__reportsAllKeysConfirmed() throws Exception {
        Intent intent = anApiIntent().withUserIds(USER_IDS).build();
        setupUidQueryResult(
                uidRow(USER_IDS[0], KEY_ID_A, KeychainExternalContract.KEY_STATUS_VERIFIED, 1),
                uidRow(USER_IDS[1], KEY_ID_B, KeychainExternalContract.KEY_STATUS_VERIFIED, 1));

        KeyIdResult result = extract(intent);

        assertEquals(KeyIdResultStatus.OK, result.getStatus());
        assertSelectedKeyIds(result, KEY_ID_A, KEY_ID_B);
        assertTrue(result.isAllKeysConfirmed());
    }

    @Test
    public void withUserIds__oneKeyUnverified__reportsNotAllKeysConfirmed() throws Exception {
        // A single unverified recipient must drag the whole result down to "not confirmed", so a
        // caller cannot be misled into believing an unverified key was trusted.
        Intent intent = anApiIntent().withUserIds(USER_IDS).build();
        setupUidQueryResult(
                uidRow(USER_IDS[0], KEY_ID_A, KeychainExternalContract.KEY_STATUS_VERIFIED, 1),
                uidRow(USER_IDS[1], KEY_ID_B, KeychainExternalContract.KEY_STATUS_UNVERIFIED, 1));

        KeyIdResult result = extract(intent);

        assertEquals(KeyIdResultStatus.OK, result.getStatus());
        assertSelectedKeyIds(result, KEY_ID_A, KEY_ID_B);
        assertFalse(result.isAllKeysConfirmed());
    }

    @Test
    public void withUserIds__oneAddressHasNoKey__promptsKeySelection() throws Exception {
        Intent intent = anApiIntent().withUserIds(USER_IDS).build();
        setupUidQueryResult(
                uidRow(USER_IDS[0], null, KeychainExternalContract.KEY_STATUS_UNAVAILABLE, 0),
                uidRow(USER_IDS[1], KEY_ID_B, KeychainExternalContract.KEY_STATUS_UNAVAILABLE, 1));
        PendingIntent pendingIntent = givenSelectPubkeyPendingIntent();

        KeyIdResult result = extract(intent);

        assertEquals(KeyIdResultStatus.MISSING, result.getStatus());
        assertTrue(result.hasKeySelectionPendingIntent());
        assertSame(pendingIntent, result.getKeySelectionPendingIntent());
    }

    @Test
    public void withUserIds__addressWithMultipleCandidates__promptsDeduplication() throws Exception {
        Intent intent = anApiIntent().withUserIds(USER_IDS).build();
        setupUidQueryResult(
                uidRow(USER_IDS[0], KEY_ID_A, KeychainExternalContract.KEY_STATUS_UNAVAILABLE, 2),
                uidRow(USER_IDS[1], KEY_ID_B, KeychainExternalContract.KEY_STATUS_UNAVAILABLE, 1));
        PendingIntent pendingIntent = givenDeduplicatePendingIntent();

        KeyIdResult result = extract(intent);

        assertEquals(KeyIdResultStatus.DUPLICATE, result.getStatus());
        assertTrue(result.hasKeySelectionPendingIntent());
        assertSame(pendingIntent, result.getKeySelectionPendingIntent());
    }

    @Test(expected = IllegalStateException.class)
    public void withUserIds__nullProviderCursor__throws() throws Exception {
        // contentResolver returns null (no query stubbed) -> the extractor must fail loudly rather
        // than treat "no cursor" as "no keys".
        Intent intent = anApiIntent().withUserIds(USER_IDS).build();

        extract(intent);
    }

    @Test(expected = IllegalStateException.class)
    public void withUserIds__providerReturnsNoRowForRequestedAddress__throws() throws Exception {
        // The provider answered, but skipped a requested address entirely. Silently dropping it
        // could change the recipient set, so the extractor refuses instead.
        Intent intent = anApiIntent().withUserIds(USER_IDS).build();
        setupUidQueryResult(
                uidRow(USER_IDS[0], KEY_ID_A, KeychainExternalContract.KEY_STATUS_UNAVAILABLE, 1));

        extract(intent);
    }

    // endregion

    // region mixed user-id + explicit key id inputs ------------------------------------------

    @Test
    public void withUserIdsAndExplicitKeyIds__returnsUnionOfBoth() throws Exception {
        Intent intent = anApiIntent()
                .withUserIds(USER_IDS)
                .withExplicitKeyIds(KEY_ID_C)
                .build();
        setupUidQueryResult(
                uidRow(USER_IDS[0], KEY_ID_A, KeychainExternalContract.KEY_STATUS_UNAVAILABLE, 1),
                uidRow(USER_IDS[1], KEY_ID_B, KeychainExternalContract.KEY_STATUS_UNAVAILABLE, 1));

        KeyIdResult result = extract(intent);

        assertEquals(KeyIdResultStatus.OK, result.getStatus());
        assertSelectedKeyIds(result, KEY_ID_A, KEY_ID_B, KEY_ID_C);
    }

    @Test
    public void withSelectedAndExplicitKeyIds__returnsUnionOfBoth() throws Exception {
        Intent intent = anApiIntent()
                .withSelectedKeyIds(KEY_ID_A)
                .withExplicitKeyIds(KEY_ID_B)
                .build();

        KeyIdResult result = extract(intent);

        assertEquals(KeyIdResultStatus.OK, result.getStatus());
        assertSelectedKeyIds(result, KEY_ID_A, KEY_ID_B);
    }

    @Test
    public void withUserIdsAndOverlappingExplicitKeyId__returnsDeduplicatedUnion() throws Exception {
        // The explicitly-added key id overlaps a resolved recipient key; the overlap must collapse
        // rather than appear twice.
        Intent intent = anApiIntent()
                .withUserIds(USER_IDS)
                .withExplicitKeyIds(KEY_ID_B, KEY_ID_C)
                .build();
        setupUidQueryResult(
                uidRow(USER_IDS[0], KEY_ID_A, KeychainExternalContract.KEY_STATUS_UNAVAILABLE, 1),
                uidRow(USER_IDS[1], KEY_ID_B, KeychainExternalContract.KEY_STATUS_UNAVAILABLE, 1));

        KeyIdResult result = extract(intent);

        assertEquals(KeyIdResultStatus.OK, result.getStatus());
        assertSelectedKeyIds(result, KEY_ID_A, KEY_ID_B, KEY_ID_C);
    }

    // endregion

    // region email case sensitivity ----------------------------------------------------------

    @Test
    public void withMixedCaseUserId__providerEchoesSameCasing__resolves() throws Exception {
        // Addresses are matched by exact string. As long as the provider echoes the address back
        // verbatim, the original (mixed) casing is preserved end to end.
        String mixedCaseAddress = "User@Example.ORG";
        Intent intent = anApiIntent().withUserIds(mixedCaseAddress).build();
        setupUidQueryResult(
                uidRow(mixedCaseAddress, KEY_ID_A, KeychainExternalContract.KEY_STATUS_UNAVAILABLE, 1));

        KeyIdResult result = extract(intent);

        assertEquals(KeyIdResultStatus.OK, result.getStatus());
        assertSelectedKeyIds(result, KEY_ID_A);
    }

    @Test(expected = IllegalStateException.class)
    public void withMixedCaseUserId__providerReturnsDifferentCasing__throws() throws Exception {
        // Documents the exact-match pitfall: if the requested casing and the casing the provider
        // returns differ, the requested address has no map entry and the extractor throws rather
        // than guessing which row belongs to which address.
        Intent intent = anApiIntent().withUserIds("User@Example.ORG").build();
        setupUidQueryResult(
                uidRow("user@example.org", KEY_ID_A, KeychainExternalContract.KEY_STATUS_UNAVAILABLE, 1));

        extract(intent);
    }

    // endregion

    // region query URI is scoped to the calling package --------------------------------------

    @Test
    public void queryUri__isScopedToCallingPackage() throws Exception {
        Intent intent = anApiIntent().withUserIds(USER_IDS[0]).build();
        setupUidQueryResult(
                uidRow(USER_IDS[0], KEY_ID_A, KeychainExternalContract.KEY_STATUS_UNAVAILABLE, 1));

        extract(intent);

        Uri queriedUri = captureQueryUri();
        List<String> pathSegments = queriedUri.getPathSegments();
        assertEquals(2, pathSegments.size());
        assertEquals(KeychainExternalContract.BASE_AUTOCRYPT_STATUS, pathSegments.get(0));
        assertEquals(CALLING_PACKAGE, queriedUri.getLastPathSegment());
    }

    @Test
    public void queryUri__callingPackageWithUriSeparators__keptAsSingleSegment() throws Exception {
        // A package name is appended as one path segment. Even a value containing slashes (which
        // could otherwise look like extra path components, e.g. another app's data) stays a single,
        // encoded segment, so the lookup cannot be redirected away from the stated caller.
        String packageWithSeparators = "com.attacker/" + KeychainExternalContract.BASE_AUTOCRYPT_STATUS + "/evil";
        Intent intent = anApiIntent().withUserIds(USER_IDS[0]).build();
        setupUidQueryResult(
                uidRow(USER_IDS[0], KEY_ID_A, KeychainExternalContract.KEY_STATUS_UNAVAILABLE, 1));

        extractAsPackage(intent, packageWithSeparators);

        Uri queriedUri = captureQueryUri();
        assertEquals(2, queriedUri.getPathSegments().size());
        assertEquals(packageWithSeparators, queriedUri.getLastPathSegment());
    }

    // endregion

    // region provider rejecting the caller ---------------------------------------------------

    @Test(expected = SecurityException.class)
    public void withUserIds__providerRejectsCaller__propagatesException() throws Exception {
        // The exported provider throws an AccessControlException (a SecurityException) for an
        // unregistered / forbidden caller. The extractor must let that surface, never silently
        // resolving to some other key.
        Intent intent = anApiIntent().withUserIds(USER_IDS).build();
        when(contentResolver.query(
                any(Uri.class), any(String[].class), nullable(String.class), any(String[].class),
                nullable(String.class)))
                .thenThrow(new SecurityException("caller not allowed to use this provider"));

        extract(intent);
    }

    // endregion

    // region helpers --------------------------------------------------------------------------

    private KeyIdResult extract(Intent intent) {
        return extract(intent, false);
    }

    private KeyIdResult extract(Intent intent, boolean askIfNoUserIdsProvided) {
        return openPgpServiceKeyIdExtractor.returnKeyIdsFromIntent(
                intent, askIfNoUserIdsProvided, CALLING_PACKAGE);
    }

    private KeyIdResult extractAsPackage(Intent intent, String callingPackage) {
        return openPgpServiceKeyIdExtractor.returnKeyIdsFromIntent(intent, false, callingPackage);
    }

    /** Fluent builder for the API intents external apps send, so each test states only the extras
     * it cares about instead of repeating {@code new Intent()} / {@code putExtra} boilerplate. */
    private static final class ApiIntentBuilder {
        private final Intent intent = new Intent();

        ApiIntentBuilder withUserIds(String... userIds) {
            intent.putExtra(OpenPgpApi.EXTRA_USER_IDS, userIds);
            return this;
        }

        ApiIntentBuilder withExplicitKeyIds(long... keyIds) {
            intent.putExtra(OpenPgpApi.EXTRA_KEY_IDS, keyIds);
            return this;
        }

        ApiIntentBuilder withSelectedKeyIds(long... keyIds) {
            intent.putExtra(OpenPgpApi.EXTRA_KEY_IDS_SELECTED, keyIds);
            return this;
        }

        Intent build() {
            return intent;
        }
    }

    private static ApiIntentBuilder anApiIntent() {
        return new ApiIntentBuilder();
    }

    /** One row of the address-status cursor the provider returns. The autocrypt columns are left
     * empty so resolution falls through to the user-id (uid) key, which is what the intent-driven
     * encryption path uses. */
    private static final class UidRow {
        final String address;
        final Long uidMasterKeyId;
        final int uidKeyStatus;
        final int uidCandidates;

        UidRow(String address, Long uidMasterKeyId, int uidKeyStatus, int uidCandidates) {
            this.address = address;
            this.uidMasterKeyId = uidMasterKeyId;
            this.uidKeyStatus = uidKeyStatus;
            this.uidCandidates = uidCandidates;
        }
    }

    private static UidRow uidRow(String address, Long uidMasterKeyId, int uidKeyStatus, int uidCandidates) {
        return new UidRow(address, uidMasterKeyId, uidKeyStatus, uidCandidates);
    }

    private void setupUidQueryResult(UidRow... rows) {
        MatrixCursor resultCursor = new MatrixCursor(OpenPgpServiceKeyIdExtractor.PROJECTION_MAIL_STATUS);
        for (UidRow row : rows) {
            resultCursor.addRow(new Object[] {
                    row.address, row.uidMasterKeyId, row.uidKeyStatus, row.uidCandidates, null, null, null });
        }

        when(contentResolver.query(
                any(Uri.class), any(String[].class), nullable(String.class), any(String[].class),
                nullable(String.class)))
                .thenReturn(resultCursor);
    }

    private PendingIntent givenSelectPubkeyPendingIntent() {
        PendingIntent pendingIntent = mock(PendingIntent.class);
        when(apiPendingIntentFactory.createSelectPublicKeyPendingIntent(
                any(Intent.class), any(long[].class), any(ArrayList.class), any(ArrayList.class),
                any(Boolean.class)))
                .thenReturn(pendingIntent);
        return pendingIntent;
    }

    private PendingIntent givenDeduplicatePendingIntent() {
        PendingIntent pendingIntent = mock(PendingIntent.class);
        when(apiPendingIntentFactory.createDeduplicatePendingIntent(
                any(String.class), any(Intent.class), any(ArrayList.class)))
                .thenReturn(pendingIntent);
        return pendingIntent;
    }

    private Uri captureQueryUri() {
        ArgumentCaptor<Uri> uriCaptor = ArgumentCaptor.forClass(Uri.class);
        verify(contentResolver).query(
                uriCaptor.capture(), any(String[].class), nullable(String.class), any(String[].class),
                nullable(String.class));
        return uriCaptor.getValue();
    }

    private static void assertSelectedKeyIds(KeyIdResult result, long... expectedKeyIds) {
        assertFalse("expected resolved key ids but result carries a key-selection pending intent",
                result.hasKeySelectionPendingIntent());
        assertArrayEqualsSorted(expectedKeyIds, result.getKeyIds());
    }

    private static void assertArrayEqualsSorted(long[] a, long[] b) {
        long[] tmpA = Arrays.copyOf(a, a.length);
        long[] tmpB = Arrays.copyOf(b, b.length);
        Arrays.sort(tmpA);
        Arrays.sort(tmpB);

        assertArrayEquals(tmpA, tmpB);
    }

    // endregion
}
