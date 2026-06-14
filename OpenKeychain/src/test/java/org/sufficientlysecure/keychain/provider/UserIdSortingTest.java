/*
 * Copyright (C) 2024 OpenKeychain contributors
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

package org.sufficientlysecure.keychain.provider;


import java.util.Arrays;
import java.util.List;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.daos.KeyRepository;
import org.sufficientlysecure.keychain.model.UnifiedKeyInfo;
import org.sufficientlysecure.keychain.model.UserId;
import org.sufficientlysecure.keychain.pgp.UncachedKeyRing;
import org.sufficientlysecure.keychain.support.DatabaseTestHelper;

/**
 * Tests covering user ID sorting logic after key import.
 *
 * <p>The {@code UserPacketItem.compareTo()} in KeyWritableRepository defines the sort order:
 * <ol>
 *   <li>Revoked UIDs always come last</li>
 *   <li>User IDs (type=NULL) come before user attributes (type!=NULL)</li>
 *   <li>Trusted-certified UIDs come before uncertified ones</li>
 *   <li>Primary UIDs come before non-primary</li>
 *   <li>Otherwise, original order from the key file is preserved (stable sort)</li>
 * </ol></p>
 *
 * <p>Each test is isolated: keys inserted during a test are deleted in {@link #tearDown()}.</p>
 */
@RunWith(KeychainTestRunner.class)
public class UserIdSortingTest {

    private DatabaseTestHelper helper;

    @Before
    public void setUp() {
        helper = new DatabaseTestHelper();
    }

    @After
    public void tearDown() {
        helper.cleanupInsertedKeys();
    }

    @Test
    public void testSingleUserIdIsAtRankZero() throws Exception {
        UncachedKeyRing ring = helper.generateSimpleKey("Alice <alice@example.com>");
        long masterKeyId = ring.getMasterKeyId();
        Assert.assertTrue("save should succeed", helper.saveAndTrackSecretKeyRing(ring));

        KeyRepository repo = helper.createReadRepository();
        List<UserId> userIds = repo.getUserIds(masterKeyId);

        Assert.assertEquals("should have exactly 1 user ID", 1, userIds.size());
        Assert.assertEquals("single UID should be at rank 0", 0, userIds.get(0).rank());
        Assert.assertTrue("single UID should be primary", userIds.get(0).is_primary());
    }

    @Test
    public void testMultipleUserIdsHaveSequentialRanks() throws Exception {
        List<String> uids = Arrays.asList(
                "Alice <alice@example.com>",
                "Bob <bob@example.com>",
                "Carol <carol@example.com>"
        );
        UncachedKeyRing ring = helper.generateKeyWithMultipleUserIds(uids);
        long masterKeyId = ring.getMasterKeyId();
        Assert.assertTrue("save should succeed", helper.saveAndTrackSecretKeyRing(ring));

        KeyRepository repo = helper.createReadRepository();
        List<UserId> userIds = repo.getUserIds(masterKeyId);

        Assert.assertEquals("should have 3 user IDs", 3, userIds.size());

        // Verify sequential ranks
        for (int i = 0; i < userIds.size(); i++) {
            Assert.assertEquals("rank should be sequential starting at 0",
                    i, userIds.get(i).rank());
        }
    }

    @Test
    public void testPrimaryUserIdComesFirst() throws Exception {
        // The first UID added during key generation is the primary one
        List<String> uids = Arrays.asList(
                "Primary <primary@example.com>",
                "Secondary <secondary@example.com>",
                "Tertiary <tertiary@example.com>"
        );
        UncachedKeyRing ring = helper.generateKeyWithMultipleUserIds(uids);
        long masterKeyId = ring.getMasterKeyId();
        Assert.assertTrue("save should succeed", helper.saveAndTrackSecretKeyRing(ring));

        KeyRepository repo = helper.createReadRepository();
        List<UserId> userIds = repo.getUserIds(masterKeyId);

        Assert.assertTrue("should have at least 2 user IDs", userIds.size() >= 2);

        // The first UID (rank 0) should be primary
        Assert.assertTrue("first UID (rank 0) should be primary", userIds.get(0).is_primary());

        // Other UIDs should not be primary
        for (int i = 1; i < userIds.size(); i++) {
            Assert.assertFalse("non-first UIDs should not be primary",
                    userIds.get(i).is_primary());
        }
    }

    @Test
    public void testRevokedUserIdComesLast() throws Exception {
        List<String> uids = Arrays.asList(
                "Alice <alice@example.com>",
                "Bob <bob@example.com>",
                "Carol <carol@example.com>"
        );
        UncachedKeyRing ring = helper.generateKeyWithRevokedUserId(uids, "Bob <bob@example.com>");
        long masterKeyId = ring.getMasterKeyId();
        Assert.assertTrue("save should succeed", helper.saveAndTrackSecretKeyRing(ring));

        KeyRepository repo = helper.createReadRepository();
        List<UserId> userIds = repo.getUserIds(masterKeyId);

        Assert.assertTrue("should have at least 2 user IDs", userIds.size() >= 2);

        // The last UID should be the revoked one
        UserId lastUid = userIds.get(userIds.size() - 1);
        Assert.assertTrue("last UID should be revoked", lastUid.is_revoked());

        // Non-last UIDs should not be revoked
        for (int i = 0; i < userIds.size() - 1; i++) {
            Assert.assertFalse("non-last UIDs should not be revoked (index " + i + ")",
                    userIds.get(i).is_revoked());
        }
    }

    @Test
    public void testRevokedUserIdPreservesData() throws Exception {
        List<String> uids = Arrays.asList(
                "Active <active@example.com>",
                "Revoked <revoked@example.com>"
        );
        UncachedKeyRing ring = helper.generateKeyWithRevokedUserId(uids, "Revoked <revoked@example.com>");
        long masterKeyId = ring.getMasterKeyId();
        Assert.assertTrue("save should succeed", helper.saveAndTrackSecretKeyRing(ring));

        KeyRepository repo = helper.createReadRepository();
        List<UserId> userIds = repo.getUserIds(masterKeyId);

        // Find the revoked UID
        UserId revokedUid = null;
        for (UserId uid : userIds) {
            if (uid.is_revoked()) {
                revokedUid = uid;
                break;
            }
        }

        Assert.assertNotNull("should find a revoked UID", revokedUid);
        Assert.assertEquals("revoked UID email should match",
                "revoked@example.com", revokedUid.email());
        Assert.assertEquals("revoked UID name should match",
                "Revoked", revokedUid.name());
    }

    @Test
    public void testUserIdFieldsAreCorrectlyParsed() throws Exception {
        String fullUid = "Test User (test comment) <test@example.com>";
        UncachedKeyRing ring = helper.generateSimpleKey(fullUid);
        long masterKeyId = ring.getMasterKeyId();
        Assert.assertTrue("save should succeed", helper.saveAndTrackSecretKeyRing(ring));

        KeyRepository repo = helper.createReadRepository();
        List<UserId> userIds = repo.getUserIds(masterKeyId);

        Assert.assertEquals("should have exactly 1 user ID", 1, userIds.size());
        UserId uid = userIds.get(0);

        Assert.assertEquals("full user_id should match", fullUid, uid.user_id());
        Assert.assertEquals("name should be parsed", "Test User", uid.name());
        Assert.assertEquals("email should be parsed", "test@example.com", uid.email());
        Assert.assertEquals("comment should be parsed", "test comment", uid.comment());
    }

    @Test
    public void testUserIdWithMinimalFormat() throws Exception {
        // User ID with only a name, no email or comment
        UncachedKeyRing ring = helper.generateSimpleKey("Just A Name");
        long masterKeyId = ring.getMasterKeyId();
        Assert.assertTrue("save should succeed", helper.saveAndTrackSecretKeyRing(ring));

        KeyRepository repo = helper.createReadRepository();
        List<UserId> userIds = repo.getUserIds(masterKeyId);

        Assert.assertEquals("should have exactly 1 user ID", 1, userIds.size());
        UserId uid = userIds.get(0);

        Assert.assertEquals("name should match", "Just A Name", uid.name());
        // email and comment may be null or empty depending on parser
    }

    @Test
    public void testUserIdWithEmailOnly() throws Exception {
        UncachedKeyRing ring = helper.generateSimpleKey("<emailonly@example.com>");
        long masterKeyId = ring.getMasterKeyId();
        Assert.assertTrue("save should succeed", helper.saveAndTrackSecretKeyRing(ring));

        KeyRepository repo = helper.createReadRepository();
        List<UserId> userIds = repo.getUserIds(masterKeyId);

        Assert.assertEquals("should have exactly 1 user ID", 1, userIds.size());
        UserId uid = userIds.get(0);
        Assert.assertEquals("email should be parsed from angle-bracket format",
                "emailonly@example.com", uid.email());
    }

    @Test
    public void testUnifiedKeyViewPicksFirstUserId() throws Exception {
        // The unifiedKeyView should use the UID with the minimum rank
        // (which is the primary, non-revoked UID after sorting)
        List<String> uids = Arrays.asList(
                "Primary <primary@example.com>",
                "Secondary <secondary@example.com>"
        );
        UncachedKeyRing ring = helper.generateKeyWithMultipleUserIds(uids);
        long masterKeyId = ring.getMasterKeyId();
        Assert.assertTrue("save should succeed", helper.saveAndTrackSecretKeyRing(ring));

        KeyRepository repo = helper.createReadRepository();
        UnifiedKeyInfo info = repo.getUnifiedKeyInfo(masterKeyId);

        Assert.assertNotNull("UnifiedKeyInfo should not be null", info);
        // The view should pick the primary UID (rank 0)
        Assert.assertEquals("unified view should show primary UID email",
                "primary@example.com", info.email());
        Assert.assertEquals("unified view should show primary UID name",
                "Primary", info.name());
    }

    @Test
    public void testUnifiedKeyViewUserIdListContainsAll() throws Exception {
        List<String> uids = Arrays.asList(
                "Alice <alice@example.com>",
                "Bob <bob@example.com>"
        );
        UncachedKeyRing ring = helper.generateKeyWithMultipleUserIds(uids);
        long masterKeyId = ring.getMasterKeyId();
        Assert.assertTrue("save should succeed", helper.saveAndTrackSecretKeyRing(ring));

        KeyRepository repo = helper.createReadRepository();
        UnifiedKeyInfo info = repo.getUnifiedKeyInfo(masterKeyId);

        Assert.assertNotNull("UnifiedKeyInfo should not be null", info);
        String uidList = info.user_id_list();
        Assert.assertNotNull("user_id_list should not be null", uidList);
        // The user_id_list uses "|||" separator
        Assert.assertTrue("uid list should contain Alice",
                uidList.contains("Alice <alice@example.com>"));
        Assert.assertTrue("uid list should contain Bob",
                uidList.contains("Bob <bob@example.com>"));
    }

    @Test
    public void testConfirmedUserIdsAfterSave() throws Exception {
        // For a secret key, the self-certifications should be VERIFIED_SECRET
        UncachedKeyRing ring = helper.generateSimpleKey("Confirmed <confirmed@example.com>");
        long masterKeyId = ring.getMasterKeyId();
        Assert.assertTrue("save should succeed", helper.saveAndTrackSecretKeyRing(ring));

        KeyRepository repo = helper.createReadRepository();
        List<String> confirmed = repo.getConfirmedUserIds(masterKeyId);

        Assert.assertFalse("should have at least one confirmed user ID", confirmed.isEmpty());
        boolean found = false;
        for (String uid : confirmed) {
            if (uid.contains("confirmed@example.com")) {
                found = true;
                break;
            }
        }
        Assert.assertTrue("confirmed UID list should contain our user ID", found);
    }
}
