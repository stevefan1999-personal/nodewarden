import assert from 'node:assert/strict';
import test from 'node:test';
import { eq } from 'drizzle-orm';

import { getOrm } from '../db/client';
import { auditLogs } from '../db/schema';
import { AuthService } from '../services/auth';
import { markEmailVerified, syncVaultAdminRoles } from '../services/vault-admin-role';
import { createRegisterVerifyToken } from '../utils/jwt';
import { archiveDb, archiveOf, restoreArchive, withArchiveDb } from './support/backup';
import { authedFetch, createTestEnv, portalFetch, seedUser, signInToAdminPortal } from './support/env';
import { userRepo } from '../services/storage-user-repo';

const ENCRYPTED = '2.dGVzdA==|dGVzdA==|dGVzdA==';
const roleSyncAudits = (db: D1Database) => getOrm(db).$count(auditLogs, eq(auditLogs.action, 'admin.vault_role.sync'));

test('enabling the first verified listed account synchronizes roles and revokes cached legacy admin access', async () => {
  const env = await createTestEnv({ ADMIN_EMAILS: 'listed@x.io' });
  const legacy = await seedUser(env, { role: 'admin' });
  const listed = await seedUser(env, { email: 'listed@x.io', emailVerified: true, status: 'banned' });
  await syncVaultAdminRoles(env);
  const token = await new AuthService(env).generateAccessToken(legacy);
  const headers = { Authorization: `Bearer ${token}` };
  assert.equal((await authedFetch(env, { path: '/api/admin/users', headers })).status, 200);

  const portal = await signInToAdminPortal(env, listed.email);
  const enabled = await portalFetch(env, {
    method: 'POST',
    path: `/admin/users/${listed.id}/enable`,
    cookie: portal.cookie,
    form: { csrf: portal.csrf },
  });
  assert.equal(enabled.status, 303);
  assert.equal((await userRepo(env.DB).getUserById(listed.id))?.role, 'admin');
  assert.equal((await userRepo(env.DB).getUserById(legacy.id))?.role, 'user');
  assert.equal((await authedFetch(env, { path: '/api/admin/users', headers })).status, 403);
});

for (const config of ['disabled', 'invalid', 'absent', 'unverified', 'banned', 'enabled']) {
  test(`directory ${config} obeys the verified active-account guard`, async () => {
    const env = await createTestEnv();
    const legacy = await seedUser(env, { role: 'admin' });
    const listed = await seedUser(env, {
      emailVerified: config !== 'unverified',
      status: config === 'banned' ? 'banned' : 'active',
    });
    env.ADMIN_EMAILS =
      config === 'disabled'
        ? undefined
        : config === 'invalid'
          ? 'invalid'
          : config === 'absent'
            ? 'missing@x.io'
            : listed.email;
    await syncVaultAdminRoles(env);
    assert.equal((await userRepo(env.DB).getUserById(legacy.id))?.role, config === 'enabled' ? 'user' : 'admin');
    assert.equal((await userRepo(env.DB).getUserById(listed.id))?.role, config === 'enabled' ? 'admin' : 'user');
    if (config === 'enabled') {
      await userRepo(env.DB).saveUser({ ...legacy, name: 'Stale role' });
      assert.equal((await userRepo(env.DB).getUserById(legacy.id))?.role, 'user');
      const auditCount = await roleSyncAudits(env.DB);
      await syncVaultAdminRoles(env);
      assert.equal(await roleSyncAudits(env.DB), auditCount);
    }
  });
}

test('only validated registration tokens verify an email; listing a claimed address later cannot promote it', async () => {
  const env = await createTestEnv({ ALLOW_OPEN_REGISTRATION: '1' });
  const firstEmail = 'first@x.io';
  const register = (email: string, token?: string) =>
    authedFetch(env, {
      method: 'POST',
      path: '/identity/accounts/register/finish',
      body: {
        email,
        masterPasswordHash: 'password-hash',
        key: ENCRYPTED,
        encryptedPrivateKey: ENCRYPTED,
        publicKey: 'public-key',
        emailVerificationToken: token,
      },
    });
  env.ADMIN_EMAILS = firstEmail;
  assert.equal((await register(firstEmail)).status, 200);
  const first = (await userRepo(env.DB).getUser(firstEmail))!;
  assert.equal(first.emailVerified, false);
  assert.equal(first.role, 'admin'); // First-account bootstrap remains the no-lockout fallback.
  const claimedEmail = 'claimed@x.io';
  assert.equal((await register(claimedEmail)).status, 200);
  const claimed = (await userRepo(env.DB).getUser(claimedEmail))!;
  assert.equal(claimed.emailVerified, false);
  env.ADMIN_EMAILS = claimedEmail;
  await syncVaultAdminRoles(env);
  assert.equal((await userRepo(env.DB).getUserById(claimed.id))?.role, 'user');
  const verifiedEmail = 'verified@x.io';
  env.ADMIN_EMAILS = `${claimedEmail},${verifiedEmail}`;
  const token = await createRegisterVerifyToken(env.JWT_SECRET, verifiedEmail, null);
  assert.equal((await register(verifiedEmail, token)).status, 200);
  assert.equal((await userRepo(env.DB).getUser(verifiedEmail))?.emailVerified, true);
  assert.equal((await userRepo(env.DB).getUser(verifiedEmail))?.role, 'admin');
  assert.equal((await userRepo(env.DB).getUserById(first.id))?.role, 'user');
  assert.equal((await userRepo(env.DB).getUserById(claimed.id))?.role, 'user');
  const invalid = await register('wrong@x.io', token);
  assert.equal(invalid.status, 400);
  assert.equal(await userRepo(env.DB).getUser('wrong@x.io'), null);
  const profile = await authedFetch(env, { path: '/api/accounts/profile', userId: claimed.id });
  assert.equal(((await profile.json()) as { emailVerified: boolean }).emailVerified, true);
});

test('markEmailVerified grants a listed account once and stale saves cannot clear verification', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env, { emailVerified: false });
  env.ADMIN_EMAILS = user.email;
  await markEmailVerified(env, user.id);
  assert.equal((await userRepo(env.DB).getUserById(user.id))?.emailVerified, true);
  assert.equal((await userRepo(env.DB).getUserById(user.id))?.role, 'admin');
  await userRepo(env.DB).saveUser(user);
  assert.equal((await userRepo(env.DB).getUserById(user.id))?.emailVerified, true);
  assert.equal((await userRepo(env.DB).getUserById(user.id))?.role, 'admin');
  await markEmailVerified(env, user.id);
  assert.equal(await roleSyncAudits(env.DB), 1);
});

test('backup restore preserves verified state, defaults legacy rows and corrects imported roles', async () => {
  const source = await createTestEnv();
  const legacy = await seedUser(source, { role: 'admin' });
  const listed = await seedUser(source);
  const unverified = await seedUser(source, { emailVerified: false });
  const { bytes } = await archiveOf(source, false);
  const db = archiveDb(bytes);
  assert.equal(db.users.find((row) => row.id === unverified.id)!.email_verified, 0);
  delete db.users.find((row) => row.id === listed.id)!.email_verified;
  const env = await createTestEnv({ ADMIN_EMAILS: listed.email });
  await restoreArchive(env, withArchiveDb(bytes, db), legacy.id);
  assert.equal((await userRepo(env.DB).getUserById(listed.id))?.role, 'admin');
  assert.equal((await userRepo(env.DB).getUserById(listed.id))?.emailVerified, true);
  assert.equal((await userRepo(env.DB).getUserById(legacy.id))?.role, 'user');
  assert.equal((await userRepo(env.DB).getUserById(unverified.id))?.emailVerified, false);
});
