package org.sufficientlysecure.keychain.remote;


import android.content.pm.PackageInfo;
import android.content.pm.Signature;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.shadows.ShadowBinder;
import org.robolectric.shadows.ShadowLog;
import org.robolectric.shadows.ShadowPackageManager;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.daos.ApiAppDao;
import org.sufficientlysecure.keychain.remote.ApiPermissionHelper.WrongPackageCertificateException;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.robolectric.Shadows.shadowOf;

/**
 * Tests for {@link ApiPermissionHelper}, the component that decides whether a calling app is allowed
 * to use the remote OpenPGP API.
 *
 * <p>{@link KeychainExternalProviderTest} already exercises this end-to-end through the content
 * provider (which surfaces rejections as {@code AccessControlException}). These tests instead pin the
 * decision itself in isolation, covering the three outcomes an external caller can produce:
 * <ul>
 *     <li><b>not registered</b> -&gt; rejected ({@code false}), no exception;</li>
 *     <li><b>registered, certificate matches</b> -&gt; allowed ({@code true});</li>
 *     <li><b>registered, certificate differs</b> -&gt; {@link WrongPackageCertificateException}, so a
 *         repackaged/forged app reusing a known package name cannot pass as the original.</li>
 * </ul>
 */
@RunWith(KeychainTestRunner.class)
public class ApiPermissionHelperTest {

    private static final String PACKAGE_NAME = "test.package";
    private static final byte[] PACKAGE_SIGNATURE = new byte[] { 1, 2, 3 };
    private static final byte[] DIFFERENT_SIGNATURE = new byte[] { 1, 2, 4 };
    private static final int PACKAGE_UID = 42;

    private ApiAppDao apiAppDao;
    private ApiPermissionHelper apiPermissionHelper;

    @Before
    public void setUp() throws Exception {
        ShadowLog.stream = System.out;

        // The installed app is always signed with PACKAGE_SIGNATURE; only what we record as the
        // *expected* certificate (in the DAO) varies per test.
        ShadowPackageManager packageManager = shadowOf(RuntimeEnvironment.getApplication().getPackageManager());
        packageManager.setPackagesForUid(PACKAGE_UID, PACKAGE_NAME);
        PackageInfo packageInfo = new PackageInfo();
        packageInfo.packageName = PACKAGE_NAME;
        packageInfo.signatures = new Signature[] { new Signature(PACKAGE_SIGNATURE) };
        packageManager.addPackage(packageInfo);

        ShadowBinder.setCallingUid(PACKAGE_UID);

        apiAppDao = ApiAppDao.getInstance(RuntimeEnvironment.getApplication());
        apiPermissionHelper = new ApiPermissionHelper(RuntimeEnvironment.getApplication(), apiAppDao);
    }

    // region isPackageAllowed(packageName) ----------------------------------------------------

    @Test
    public void isPackageAllowed__registeredWithMatchingCertificate__returnsTrue() throws Exception {
        apiAppDao.insertApiApp(PACKAGE_NAME, PACKAGE_SIGNATURE);

        assertTrue(apiPermissionHelper.isPackageAllowed(PACKAGE_NAME));
    }

    @Test
    public void isPackageAllowed__unregisteredPackage__returnsFalse() throws Exception {
        // Nothing recorded for this package -> rejected, and importantly without throwing.
        assertFalse(apiPermissionHelper.isPackageAllowed(PACKAGE_NAME));
    }

    @Test(expected = WrongPackageCertificateException.class)
    public void isPackageAllowed__registeredWithDifferentCertificate__throws() throws Exception {
        apiAppDao.insertApiApp(PACKAGE_NAME, DIFFERENT_SIGNATURE);

        apiPermissionHelper.isPackageAllowed(PACKAGE_NAME);
    }

    // endregion

    // region isAllowedIgnoreErrors() (resolves the caller via the binder uid) -----------------

    @Test
    public void isAllowedIgnoreErrors__callerRegisteredWithMatchingCertificate__returnsTrue() throws Exception {
        apiAppDao.insertApiApp(PACKAGE_NAME, PACKAGE_SIGNATURE);

        assertTrue(apiPermissionHelper.isAllowedIgnoreErrors());
    }

    @Test
    public void isAllowedIgnoreErrors__callerUnregistered__returnsFalse() throws Exception {
        assertFalse(apiPermissionHelper.isAllowedIgnoreErrors());
    }

    @Test
    public void isAllowedIgnoreErrors__callerCertificateMismatch__returnsFalse() throws Exception {
        // A certificate mismatch raises WrongPackageCertificateException internally; the
        // ignore-errors entry point must swallow it and simply report "not allowed".
        apiAppDao.insertApiApp(PACKAGE_NAME, DIFFERENT_SIGNATURE);

        assertFalse(apiPermissionHelper.isAllowedIgnoreErrors());
    }

    // endregion
}
