import assert from 'node:assert/strict';
import test from 'node:test';
import { getOrm } from '../db/client';
import { webauthnCredentials } from '../db/schema';
import { AuthService } from '../services/auth';
import { hashPassword } from '../services/auth-password';
import { ensureTwoFactorRecoveryCode } from '../services/two-factor-providers';
import {
  authedFetch,
  captureEmail,
  createTestEnv,
  drainWaitUntil,
  MAILABLE_DOMAIN,
  portalFetch,
  seedUser,
  signInToAdminPortal,
} from './support/env';
import type { Env, User } from '../types';
import { passkeyRepo } from '../services/storage-account-passkey-repo';
import { deviceRepo } from '../services/storage-device-repo';
import { sessionRepo } from '../services/storage-session-repo';
import { userRepo } from '../services/storage-user-repo';

const PASSWORD = 'recovery-client-password';
const RECOVERY = 'ABCD EFGH IJKL MNOP QRST UVWX YZ23 4567';
const TOTP = 'JBSWY3DPEHPK3PXP';
const recoveryRequest = (env: Env, user: User, login: boolean) =>
  authedFetch(env, {
    method: 'POST',
    path: login ? '/identity/connect/token' : '/identity/accounts/recover-2fa',
    body: login
      ? {
          grant_type: 'password',
          username: user.email,
          password: PASSWORD,
          twoFactorProvider: '8',
          twoFactorToken: RECOVERY,
        }
      : { email: user.email, masterPasswordHash: PASSWORD, recoveryCode: RECOVERY },
  });

for (const login of [false, true]) {
  test(`${login ? 'login' : 'endpoint'} recovery verified before an administrator reset cannot clear current factors or sessions`, async (t) => {
    const env = await createTestEnv({ ADMIN_EMAILS: 'portal@x.io' });
    const user = await seedUser(env, {
      masterPasswordHash: await hashPassword(PASSWORD),
      totpSecret: TOTP,
      totpRecoveryCode: RECOVERY,
    });
    const portal = await signInToAdminPortal(env, 'portal@x.io');
    const repo = userRepo(env.DB);
    const getUser = repo.getUser.bind(repo);
    let interrupted = false;
    let current: User;
    t.mock.method(repo, 'getUser', async (email: string) => {
      const snapshot = await getUser(email);
      if (!interrupted && email === user.email) {
        interrupted = true;
        const reset = await portalFetch(env, {
          method: 'POST',
          path: `/admin/users/${user.id}/remove-2fa`,
          cookie: portal.cookie,
          form: { csrf: portal.csrf, confirmation: user.email },
        });
        assert.equal(reset.status, 303);
        current = (await userRepo(env.DB).getUserById(user.id))!;
        current.totpRecoveryCode = await ensureTwoFactorRecoveryCode(env.DB, user.id, current.securityStamp);
        current.totpSecret = TOTP;
        await userRepo(env.DB).saveUser(current, ['totpSecret']);
        await getOrm(env.DB).insert(webauthnCredentials).values({
          id: 'current-key',
          userId: user.id,
          purpose: 'twoFactor',
          name: 'current',
          publicKey: 'cHVibGlj',
          credentialId: 'current-key',
          createdAt: current.createdAt,
          updatedAt: current.updatedAt,
        });
        await deviceRepo(env.DB).saveTrustedTwoFactorDeviceToken(
          'current-remember',
          user.id,
          'current-device',
          Date.now() + 60000,
        );
        await sessionRepo(env.DB).saveRefreshToken('current-session', user.id);
      }
      return snapshot;
    });
    const response = await recoveryRequest(env, user, login);
    assert.equal(response.status, 400);
    assert.equal(interrupted, true);
    const after = (await userRepo(env.DB).getUserById(user.id))!;
    for (const field of ['securityStamp', 'totpSecret', 'totpRecoveryCode'] as const)
      assert.equal(after[field], current![field], field);
    assert.equal(await passkeyRepo(env.DB).countAccountPasskeyCredentialsByUserId(user.id, 'twoFactor'), 1);
    assert.equal(
      await deviceRepo(env.DB).getTrustedTwoFactorDeviceTokenUserId('current-remember', 'current-device'),
      user.id,
    );
    assert.equal(await sessionRepo(env.DB).getRefreshTokenUserId('current-session'), user.id);
    await drainWaitUntil();
  });
}

test('the same recovery code can complete only one of two concurrent login/endpoint requests', async (t) => {
  const mail = captureEmail();
  const env = await createTestEnv(mail.overrides);
  const user = await seedUser(env, {
    email: `recovery@${MAILABLE_DOMAIN}`,
    masterPasswordHash: await hashPassword(PASSWORD),
    totpSecret: TOTP,
    totpRecoveryCode: RECOVERY,
  });
  const repo = userRepo(env.DB);
  const getUser = repo.getUser.bind(repo);
  let arrivals = 0;
  let release!: () => void;
  const ready = new Promise<void>((resolve) => {
    release = resolve;
  });
  t.mock.method(repo, 'getUser', async (email: string) => {
    const snapshot = await getUser(email);
    if (email === user.email) {
      if (++arrivals === 2) release();
      await ready;
    }
    return snapshot;
  });
  const responses = await Promise.all([recoveryRequest(env, user, false), recoveryRequest(env, user, true)]);
  assert.deepEqual(responses.map((response) => response.status).sort(), [200, 400]);
  await drainWaitUntil();
  assert.equal(mail.sent.filter((message) => message.subject === 'NodeWarden two-step login was recovered').length, 1);
  const loginResponse = (await responses[1].json()) as { access_token?: string };
  if (responses[1].status === 200)
    assert.ok(await new AuthService(env).verifyAccessTokenWithUser(`Bearer ${loginResponse.access_token}`));
  else assert.equal(loginResponse.access_token, undefined);
});
