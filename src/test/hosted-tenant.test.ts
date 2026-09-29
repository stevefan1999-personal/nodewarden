import assert from 'node:assert/strict';
import test from 'node:test';

import { getOrm } from '../db/client';
import { verification } from '../db/schema';
import { userRepo } from '../services/storage-user-repo';
import { createRegisterVerifyToken } from '../utils/jwt';
import {
  authedFetch,
  captureEmail,
  createTestEnv,
  drainWaitUntil,
  interceptStatement,
  MAILABLE_DOMAIN,
  seedUser,
} from './support/env';

const ENCRYPTED = '2.YQ==|Yg==|Yw==';
const OWNER_EMAIL = `owner@${MAILABLE_DOMAIN}`;
const REGISTER_BODY = {
  email: OWNER_EMAIL,
  masterPasswordHash: 'client-master-password-hash',
  key: ENCRYPTED,
  encryptedPrivateKey: ENCRYPTED,
  publicKey: 'YQ==',
};
const PLATFORM_SECRET = 'platform-test-secret-'.repeat(2);

test('both deployment modes reserve bootstrap for the owner verified through the existing email flow', async () => {
  for (const NODEWARDEN_DEPLOYMENT of ['standalone', 'dispatch']) {
    const capture = captureEmail();
    const env = await createTestEnv({
      ...capture.overrides,
      NODEWARDEN_DEPLOYMENT,
      TENANT_OWNER_EMAIL: ` ${OWNER_EMAIL.toUpperCase()} `,
      ADMIN_EMAILS: OWNER_EMAIL,
    });
    let address = 10;
    const post = (path: string, body: object) =>
      authedFetch(env, {
        method: 'POST',
        path,
        body,
        headers: { 'CF-Connecting-IP': `203.0.113.${address++}` },
      });
    const intruder = `other@${MAILABLE_DOMAIN}`;
    const verificationPath = '/identity/accounts/register/send-verification-email';
    assert.equal((await post(verificationPath, { email: intruder })).status, 403);
    for (const path of [
      '/api/accounts/register',
      '/identity/accounts/register',
      '/api/accounts/register/finish',
      '/accounts/register/finish',
      '/identity/accounts/register/finish',
    ]) {
      assert.equal((await post(path, { ...REGISTER_BODY, email: intruder })).status, 403);
    }
    const registerPath = '/identity/accounts/register/finish';
    assert.equal((await post(registerPath, REGISTER_BODY)).status, 400);
    const otherToken = await createRegisterVerifyToken(env.JWT_SECRET, intruder, null);
    assert.equal((await post(registerPath, { ...REGISTER_BODY, token: otherToken })).status, 400);
    assert.equal(await userRepo(env.DB).getUserCount(), 0);
    await drainWaitUntil();
    assert.equal(capture.sent.length, 0);

    const started = await post(verificationPath, { email: OWNER_EMAIL });
    assert.equal(started.status, 200);
    assert.equal(await started.json(), '');
    await drainWaitUntil();
    assert.equal(capture.sent.length, 1);
    assert.equal(capture.sent[0].to, OWNER_EMAIL);
    const link = capture.sent[0].text.match(/https:\/\/\S+\/redirect-connector\.html#finish-signup\?\S+/)?.[0];
    assert.ok(link);
    const token = new URLSearchParams(new URL(link).hash.split('?')[1]).get('token');
    assert.ok(token);
    const clickedPath = '/identity/accounts/register/verification-email-clicked';
    assert.equal((await post(clickedPath, { email: OWNER_EMAIL, emailVerificationToken: otherToken })).status, 400);
    assert.equal((await post(clickedPath, { email: OWNER_EMAIL, emailVerificationToken: token })).status, 204);
    assert.equal(await userRepo(env.DB).getUserCount(), 0);
    assert.equal((await post(registerPath, { ...REGISTER_BODY, token })).status, 200);
    const owner = await userRepo(env.DB).getUser(OWNER_EMAIL);
    assert.ok(owner);
    assert.equal(owner.emailVerified, true);
    assert.equal(owner.role, 'admin');
    assert.equal(owner.key, ENCRYPTED);
    assert.equal(owner.privateKey, ENCRYPTED);
    await drainWaitUntil();

    // Once claimed, the normal invite/open-registration policy remains authoritative.
    assert.equal((await post(verificationPath, { email: intruder })).status, 403);
    env.ALLOW_OPEN_REGISTRATION = '1';
    assert.equal((await post(registerPath, { ...REGISTER_BODY, email: intruder })).status, 200);
    assert.equal((await userRepo(env.DB).getUser(intruder))?.role, 'user');
    await drainWaitUntil();
  }
});

test('invalid owner configuration and a dispatch tenant with no owner cannot be claimed', async () => {
  for (const overrides of [
    { TENANT_OWNER_EMAIL: '' },
    { TENANT_OWNER_EMAIL: 'invalid' },
    { NODEWARDEN_DEPLOYMENT: 'dispatch' },
  ]) {
    const env = await createTestEnv(overrides);
    for (const path of ['/identity/accounts/register/send-verification-email', '/identity/accounts/register/finish']) {
      assert.equal((await authedFetch(env, { method: 'POST', path, body: REGISTER_BODY })).status, 403);
    }
    assert.equal(await userRepo(env.DB).getUserCount(), 0);
  }
  const env = await createTestEnv({ NODEWARDEN_DEPLOYMENT: 'disptach' });
  assert.equal((await authedFetch(env, { path: '/api/config' })).status, 503);
});

test('fleet maintenance requires a strong secret in either deployment mode and runs the same cleanup', async () => {
  for (const NODEWARDEN_DEPLOYMENT of ['standalone', 'dispatch']) {
    const env = await createTestEnv({ NODEWARDEN_DEPLOYMENT });
    await getOrm(env.DB)
      .insert(verification)
      .values({ id: 'expired', identifier: 'otp:expired', value: 'hash', expiresAt: 0 });
    const tick = (token: string) =>
      authedFetch(env, {
        method: 'POST',
        path: '/api/internal/maintenance',
        headers: { Authorization: `Bearer ${token}` },
      });
    assert.equal((await tick(PLATFORM_SECRET)).status, 401);
    env.PLATFORM_INTERNAL_SECRET = 'short';
    assert.equal((await tick('short')).status, 401);
    env.PLATFORM_INTERNAL_SECRET = PLATFORM_SECRET;
    assert.equal((await tick(`${PLATFORM_SECRET}x`)).status, 401);
    assert.equal(await getOrm(env.DB).$count(verification), 1);
    assert.equal((await tick(PLATFORM_SECRET)).status, 204);
    assert.equal(await getOrm(env.DB).$count(verification), 0);
  }
});

test('fleet maintenance reports a failed job while independent cleanup still finishes', async (t) => {
  t.mock.method(console, 'error', () => {});
  const env = await createTestEnv({ PLATFORM_INTERNAL_SECRET: PLATFORM_SECRET });
  await getOrm(env.DB)
    .insert(verification)
    .values({ id: 'expired', identifier: 'otp:expired', value: 'hash', expiresAt: 0 });
  interceptStatement(env, /^delete from "events"/, async () => {
    throw new Error('private database details');
  });
  const response = await authedFetch(env, {
    method: 'POST',
    path: '/api/internal/maintenance',
    headers: { Authorization: `Bearer ${PLATFORM_SECRET}` },
  });
  assert.equal(response.status, 500);
  assert.doesNotMatch(await response.text(), /private database details/);
  assert.equal(await getOrm(env.DB).$count(verification), 0);
});

test('dispatch sync succeeds when the platform forbids even reading caches.default', async (t) => {
  const env = await createTestEnv({ NODEWARDEN_DEPLOYMENT: 'dispatch' });
  const user = await seedUser(env);
  const descriptor = Object.getOwnPropertyDescriptor(caches, 'default')!;
  Object.defineProperty(caches, 'default', {
    configurable: true,
    get() {
      throw new Error('caches.default is disabled for namespaced scripts');
    },
  });
  t.after(() => Object.defineProperty(caches, 'default', descriptor));
  for (let request = 0; request < 2; request++) {
    const response = await authedFetch(env, { path: '/api/sync', userId: user.id });
    assert.equal(response.status, 200);
    assert.equal(((await response.json()) as { profile: { id: string } }).profile.id, user.id);
  }
});

test('subscription suspension blocks direct vault access and assets without deleting the tenant', async () => {
  for (const NODEWARDEN_DEPLOYMENT of ['standalone', 'dispatch']) {
    let assetReads = 0;
    const env = await createTestEnv({
      NODEWARDEN_DEPLOYMENT,
      PLATFORM_SUBSCRIPTION_STATUS: 'suspended',
      PLATFORM_INTERNAL_SECRET: PLATFORM_SECRET,
      ASSETS: { fetch: async () => new Response(String(++assetReads)) },
    });
    const user = await seedUser(env);
    for (const path of ['/', '/api/config', '/api/sync', '/admin', '/notifications/hub']) {
      const response = await authedFetch(env, { path, userId: user.id });
      assert.equal(response.status, 402, path);
    }
    assert.equal(assetReads, 0);
    assert.equal((await authedFetch(env, { method: 'POST', path: '/api/internal/maintenance' })).status, 401);
    assert.equal(
      (
        await authedFetch(env, {
          method: 'POST',
          path: '/api/internal/maintenance',
          headers: { Authorization: `Bearer ${PLATFORM_SECRET}` },
        })
      ).status,
      204,
    );
    assert.equal(await userRepo(env.DB).getUserCount(), 1);
    env.PLATFORM_SUBSCRIPTION_STATUS = 'invalid';
    assert.equal((await authedFetch(env, { path: '/api/sync', userId: user.id })).status, 503);
    env.PLATFORM_SUBSCRIPTION_STATUS = 'active';
    assert.equal((await authedFetch(env, { path: '/api/sync', userId: user.id })).status, 200);
    assert.equal((await userRepo(env.DB).getUserById(user.id))?.key, user.key);
    assert.equal((await authedFetch(env, { path: '/' })).status, 200);
    assert.equal(assetReads, 1);
  }
});

test('managed standalone origins require a gateway secret while preserving the vault bearer token', async () => {
  const env = await createTestEnv({
    PLATFORM_REQUIRE_GATEWAY: '1',
    PLATFORM_INTERNAL_SECRET: PLATFORM_SECRET,
    ASSETS: { fetch: async () => new Response('vault') },
  });
  const user = await seedUser(env);
  for (const path of ['/', '/api/sync']) {
    for (const secret of ['', 'wrong']) {
      const response = await authedFetch(env, {
        path,
        userId: user.id,
        headers: { 'X-CloudWarden-Gateway-Secret': secret },
      });
      assert.equal(response.status, 403);
    }
    const response = await authedFetch(env, {
      path,
      userId: user.id,
      headers: { 'X-CloudWarden-Gateway-Secret': PLATFORM_SECRET },
    });
    assert.equal(response.status, 200);
  }
  assert.equal(
    (
      await authedFetch(env, {
        method: 'POST',
        path: '/api/internal/maintenance',
        headers: { Authorization: `Bearer ${PLATFORM_SECRET}` },
      })
    ).status,
    204,
  );
  for (const secret of [undefined, 'short']) {
    env.PLATFORM_INTERNAL_SECRET = secret;
    assert.equal(
      (await authedFetch(env, { path: '/', headers: { 'X-CloudWarden-Gateway-Secret': secret || '' } })).status,
      403,
    );
  }
  env.PLATFORM_INTERNAL_SECRET = PLATFORM_SECRET;
  env.PLATFORM_REQUIRE_GATEWAY = 'invalid';
  assert.equal(
    (await authedFetch(env, { path: '/', headers: { 'X-CloudWarden-Gateway-Secret': PLATFORM_SECRET } })).status,
    403,
  );
});

test('authenticated gateway origin forwarding preserves customer URLs, passkeys, vault authorization and bodies', async () => {
  const publicOrigin = 'https://vault.customer.test';
  const backendOrigin = 'http://worker.internal:8787';
  const env = await createTestEnv({
    PLATFORM_REQUIRE_GATEWAY: '1',
    PLATFORM_INTERNAL_SECRET: PLATFORM_SECRET,
    WEB_VAULT_ORIGINS: publicOrigin,
    ASSETS: {
      fetch: async (input) => {
        const request = new Request(input);
        assert.equal(request.headers.get('X-CloudWarden-Gateway-Secret'), null);
        assert.equal(request.headers.get('X-CloudWarden-Original-Origin'), null);
        return new Response(request.url);
      },
    },
  });
  const headers = {
    'X-CloudWarden-Gateway-Secret': PLATFORM_SECRET,
    'X-CloudWarden-Original-Origin': 'https://VAULT.CUSTOMER.TEST:443/',
    Origin: publicOrigin,
  };
  const config = await authedFetch(env, { path: `${backendOrigin}/api/config`, headers });
  assert.equal(config.status, 200);
  assert.equal(config.headers.get('Access-Control-Allow-Origin'), publicOrigin);
  const { environment } = (await config.json()) as { environment: { vault: string; api: string; identity: string } };
  assert.equal(environment.vault, publicOrigin);
  assert.equal(environment.api, `${publicOrigin}/api`);
  assert.equal(environment.identity, `${publicOrigin}/identity`);
  const passkey = await authedFetch(env, {
    path: `${backendOrigin}/identity/accounts/webauthn/assertion-options`,
    headers,
  });
  assert.equal(passkey.status, 200);
  assert.equal(((await passkey.json()) as { options: { rpId: string } }).options.rpId, 'vault.customer.test');

  const user = await seedUser(env);
  const folder = await authedFetch(env, {
    method: 'POST',
    path: `${backendOrigin}/api/folders?unchanged=%2Fvault`,
    body: { name: ENCRYPTED },
    userId: user.id,
    headers,
  });
  assert.equal(folder.status, 200);
  assert.equal(((await folder.json()) as { name: string }).name, ENCRYPTED);
  const asset = await authedFetch(env, {
    path: `${backendOrigin}/static/app.js?unchanged=%2Fvault&locale=en`,
    headers,
  });
  assert.equal(asset.status, 200);
  assert.equal(await asset.text(), `${publicOrigin}/static/app.js?unchanged=%2Fvault&locale=en`);
});

test('gateway origin forwarding refuses untrusted origins and is ignored by self-hosts and maintenance', async () => {
  const publicOrigin = 'https://vault.customer.test';
  const env = await createTestEnv({
    PLATFORM_REQUIRE_GATEWAY: '1',
    PLATFORM_INTERNAL_SECRET: PLATFORM_SECRET,
    WEB_VAULT_ORIGINS: publicOrigin,
  });
  for (const origin of [
    '',
    'https://other.customer.test',
    `${publicOrigin}/path`,
    `${publicOrigin}?query`,
    `${publicOrigin}#fragment`,
    'https://user:password@vault.customer.test',
    'https://vault.customer.test\\evil',
    'file://vault.customer.test',
    `${publicOrigin},https://other.customer.test`,
  ]) {
    assert.equal(
      (
        await authedFetch(env, {
          path: '/api/config',
          headers: {
            'X-CloudWarden-Gateway-Secret': PLATFORM_SECRET,
            'X-CloudWarden-Original-Origin': origin,
          },
        })
      ).status,
      403,
      origin,
    );
  }
  assert.equal(
    (
      await authedFetch(env, {
        path: '/api/config',
        headers: {
          'X-CloudWarden-Gateway-Secret': 'wrong',
          'X-CloudWarden-Original-Origin': publicOrigin,
        },
      })
    ).status,
    403,
  );
  env.PLATFORM_REQUIRE_GATEWAY = undefined;
  const untrusted = await authedFetch(env, {
    path: '/api/config',
    headers: { 'X-CloudWarden-Original-Origin': publicOrigin },
  });
  assert.equal(untrusted.status, 200);
  assert.equal(
    ((await untrusted.json()) as { environment: { vault: string } }).environment.vault,
    'https://vault.example.test',
  );

  env.PLATFORM_REQUIRE_GATEWAY = '1';
  env.PLATFORM_SUBSCRIPTION_STATUS = 'suspended';
  for (const [token, status] of [
    [PLATFORM_SECRET, 204],
    ['wrong', 401],
  ] as const) {
    assert.equal(
      (
        await authedFetch(env, {
          method: 'POST',
          path: '/api/internal/maintenance',
          headers: { Authorization: `Bearer ${token}`, 'X-CloudWarden-Original-Origin': 'https://evil.test/path' },
        })
      ).status,
      status,
    );
  }
});
