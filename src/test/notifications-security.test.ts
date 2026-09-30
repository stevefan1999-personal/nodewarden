import assert from 'node:assert/strict';
import test from 'node:test';

import { handleNotificationsHub, handleNotificationsNegotiate } from '../handlers/notifications';
import { AuthService } from '../services/auth';
import { deviceRepo } from '../services/storage-device-repo';
import type { Env } from '../types';
import { createJWT, signHs256Jwt } from '../utils/jwt';
import { authedFetch, contextFor, createTestEnv, seedUser } from './support/env';

const { NotificationsHub } = await import('../durable/notifications-hub');

const secret = 'notification-security-test-secret-32-bytes';
const userId = 'd75020e1-2de4-46e8-b8f1-475d127b51f2';
const securityStamp = 'security-stamp';

async function createNotificationEnv() {
  const env = await createTestEnv({ JWT_SECRET: secret });
  await seedUser(env, { id: userId, email: 'user@example.test', securityStamp });
  const connectionTokens = new Map<string, { userId: string; deviceIdentifier: string | null; expiresAt: number }>();
  const forwardedHubUrls: string[] = [];
  const durableObjectNames: string[] = [];
  let alarm: number | null = null;
  let pendingTransaction: Promise<unknown> = Promise.resolve();
  const storage = {
    get: async (key: string) => connectionTokens.get(key),
    put: async (key: string, value: Parameters<typeof connectionTokens.set>[1]) =>
      void connectionTokens.set(key, value),
    async delete(keys: string | string[]) {
      for (const key of [keys].flat()) connectionTokens.delete(key);
    },
    getAlarm: async () => alarm,
    setAlarm: async (timestamp: number) => void (alarm = timestamp),
    list: async () => connectionTokens,
    transaction<T>(callback: (transaction: DurableObjectTransaction) => Promise<T>): Promise<T> {
      const result = pendingTransaction.then(() => callback(storage as unknown as DurableObjectTransaction));
      pendingTransaction = result.catch(() => {});
      return result;
    },
  };
  const hub = new NotificationsHub({ storage, setWebSocketAutoResponse() {} } as unknown as DurableObjectState, env);
  hub.fetch = async (request: Request) => {
    forwardedHubUrls.push(request.url);
    return new Response(null, { status: 204 });
  };
  env.NOTIFICATIONS_HUB = {
    idFromName(name: string) {
      durableObjectNames.push(name);
      return name;
    },
    get: () => hub,
  } as unknown as Env['NOTIFICATIONS_HUB'];
  return { env, hub, storage, connectionTokens, durableObjectNames, forwardedHubUrls };
}

async function validAccessToken(): Promise<string> {
  return createJWT(
    {
      sub: userId,
      email: 'user@example.test',
      name: 'Test User',
      sstamp: securityStamp,
    },
    secret,
  );
}

test('official browser query token authenticates the Worker websocket route and verified hub owner', async () => {
  const { env, durableObjectNames, forwardedHubUrls } = await createNotificationEnv();
  const user = await seedUser(env);
  const device = { identifier: 'browser-device', sessionStamp: 'browser-device-stamp' };
  await deviceRepo(env.DB).upsertDevice(user.id, device.identifier, 'Browser', 10, device.sessionStamp);
  const token = await new AuthService(env).generateAccessToken(user, device);
  const response = await authedFetch(env, {
    path: `/notifications/hub?access_token=${encodeURIComponent(token)}&nw_uid=forged&nw_did=forged&id=unused`,
    headers: { Upgrade: 'websocket' },
  });

  assert.equal(response.status, 204);
  assert.deepEqual(durableObjectNames, [user.id]);
  const forwardedUrl = new URL(forwardedHubUrls[0]);
  assert.equal(forwardedUrl.searchParams.get('nw_uid'), user.id);
  assert.equal(forwardedUrl.searchParams.get('nw_did'), device.identifier);
  assert.equal(forwardedUrl.searchParams.has('access_token'), false);
  assert.equal(forwardedUrl.searchParams.has('id'), false);
});

test('user tokens without a device claim cannot forward caller-supplied hub metadata', async () => {
  const { env, forwardedHubUrls } = await createNotificationEnv();
  const token = await validAccessToken();
  for (const headers of [
    new Headers({ Upgrade: 'websocket' }),
    new Headers({ Upgrade: 'websocket', Authorization: `Bearer ${token}` }),
  ]) {
    const response = await authedFetch(env, {
      path: `/notifications/hub?access_token=${encodeURIComponent(token)}&nw_uid=forged&nw_did=forged&nw_auth_request_id=forged`,
      headers,
    });
    assert.equal(response.status, 204);
    const forwardedUrl = new URL(forwardedHubUrls.at(-1)!);
    assert.equal(forwardedUrl.searchParams.get('nw_uid'), userId);
    assert.equal(forwardedUrl.searchParams.has('nw_did'), false);
    assert.equal(forwardedUrl.searchParams.has('nw_auth_request_id'), false);
  }
});

test('query tokens cannot authenticate negotiate, REST or non-upgrade hub requests', async () => {
  const { env, durableObjectNames } = await createNotificationEnv();
  const query = `access_token=${encodeURIComponent(await validAccessToken())}`;
  for (const [path, method, status] of [
    ['/notifications/hub', 'GET', 426],
    ['/notifications/hub/negotiate', 'POST', 401],
    ['/api/sync', 'GET', 401],
  ] as const) {
    assert.equal((await authedFetch(env, { path: `${path}?${query}`, method })).status, status);
  }
  assert.deepEqual(durableObjectNames, []);
});

test('invalid Authorization never falls back to a valid browser query token', async () => {
  const { env, durableObjectNames } = await createNotificationEnv();
  const token = await validAccessToken();
  for (const authorization of ['', 'Basic invalid', 'Bearer invalid']) {
    const response = await authedFetch(env, {
      path: `/notifications/hub?access_token=${encodeURIComponent(token)}`,
      headers: { Upgrade: 'websocket', Authorization: authorization },
    });
    assert.equal(response.status, 401);
  }
  assert.deepEqual(durableObjectNames, []);
});

test('browser query tokens retain signature, expiry, user and device authentication gates', async () => {
  const { env, durableObjectNames } = await createNotificationEnv();
  const claims = { sub: userId, email: 'user@example.test', name: 'Test User', sstamp: securityStamp };
  const inactiveUser = await seedUser(env, { status: 'banned' });
  await deviceRepo(env.DB).upsertDevice(userId, 'revoked-device', 'Browser', 10, 'current-device-stamp');
  const tokens = [
    'invalid',
    await createJWT(claims, 'wrong-notification-security-test-secret'),
    await createJWT(claims, secret, -60),
    await createJWT({ ...claims, sstamp: 'revoked-stamp' }, secret),
    await createJWT({ ...claims, sub: 'missing-user' }, secret),
    await new AuthService(env).generateAccessToken(inactiveUser),
    await createJWT({ ...claims, did: 'missing-device', dstamp: 'device-stamp' }, secret),
    await createJWT({ ...claims, did: 'revoked-device', dstamp: 'revoked-device-stamp' }, secret),
    await signHs256Jwt({ ...claims, type: 'ServiceAccount', exp: Math.floor(Date.now() / 1000) + 60 }, secret),
  ];
  for (const token of tokens) {
    const response = await authedFetch(env, {
      path: `/notifications/hub?access_token=${encodeURIComponent(token)}`,
      headers: { Upgrade: 'websocket' },
    });
    assert.equal(response.status, 401);
  }
  assert.deepEqual(durableObjectNames, []);
});

test('Authorization bearer token still authenticates notifications', async () => {
  const { env, forwardedHubUrls } = await createNotificationEnv();
  const token = await validAccessToken();
  const response = await authedFetch(env, {
    path: '/notifications/hub?access_token=invalid',
    headers: { Authorization: `Bearer ${token}`, Upgrade: 'websocket' },
  });

  assert.equal(response.status, 204);
  assert.equal(new URL(forwardedHubUrls[0]).searchParams.get('nw_uid'), userId);
});

test('negotiate issues a short-lived one-time websocket connection token', async () => {
  const { env, connectionTokens, forwardedHubUrls } = await createNotificationEnv();
  const accessToken = await validAccessToken();
  const negotiate = await handleNotificationsNegotiate(
    contextFor(
      env,
      new Request('https://vault.example.test/notifications/hub/negotiate', {
        method: 'POST',
        headers: { Authorization: `Bearer ${accessToken}` },
      }),
    ),
  );
  const body = (await negotiate.json()) as { connectionToken: string };
  const stored = connectionTokens.get(`ws-token:${body.connectionToken}`);

  assert.equal(negotiate.status, 200);
  assert.ok(stored);
  assert.ok(stored.expiresAt > Date.now());
  assert.ok(stored.expiresAt <= Date.now() + 60_000);

  const request = () =>
    new Request(`https://vault.example.test/notifications/hub?id=${encodeURIComponent(body.connectionToken)}`, {
      headers: { Upgrade: 'websocket' },
    });
  assert.equal((await handleNotificationsHub(contextFor(env, request()))).status, 204);
  assert.equal((await handleNotificationsHub(contextFor(env, request()))).status, 401);
  assert.equal(forwardedHubUrls.length, 1);
});

test('a non-upgrade request does not consume a websocket connection token', async () => {
  const { env, connectionTokens } = await createNotificationEnv();
  const accessToken = await validAccessToken();
  const negotiate = await handleNotificationsNegotiate(
    contextFor(
      env,
      new Request('https://vault.example.test/notifications/hub/negotiate', {
        method: 'POST',
        headers: { Authorization: `Bearer ${accessToken}` },
      }),
    ),
  );
  const { connectionToken } = (await negotiate.json()) as { connectionToken: string };
  const url = `https://vault.example.test/notifications/hub?id=${encodeURIComponent(connectionToken)}`;

  assert.equal((await handleNotificationsHub(contextFor(env, new Request(url)))).status, 426);
  assert.ok(connectionTokens.has(`ws-token:${connectionToken}`));
  assert.equal(
    (await handleNotificationsHub(contextFor(env, new Request(url, { headers: { Upgrade: 'websocket' } })))).status,
    204,
  );
});

test('a forged ticket cannot select or activate a Durable Object', async () => {
  const { env, durableObjectNames } = await createNotificationEnv();
  const response = await handleNotificationsHub(
    contextFor(
      env,
      new Request('https://vault.example.test/notifications/hub?id=attacker-controlled.invalid-signature', {
        headers: { Upgrade: 'websocket' },
      }),
    ),
  );

  assert.equal(response.status, 401);
  assert.deepEqual(durableObjectNames, []);
});

test('connection ticket RPC validates expiry, consumes atomically, and prunes abandoned tickets', async (t) => {
  let now = Date.now();
  t.mock.method(Date, 'now', () => now);
  const { hub, storage, connectionTokens } = await createNotificationEnv();
  const ticket = { token: 'ticket', userId, deviceIdentifier: ' device-1 ', expiresAt: now + 5_000 };
  for (const invalid of [
    { token: ' ' },
    { userId: ' ' },
    { expiresAt: NaN },
    { expiresAt: Infinity },
    { expiresAt: now },
    { expiresAt: now + 60_001 },
  ]) {
    assert.equal(await hub.registerConnectionToken({ ...ticket, ...invalid }), false);
  }
  assert.equal(connectionTokens.size, 0);
  assert.equal(await storage.getAlarm(), null);

  assert.equal(await hub.registerConnectionToken(ticket), true);
  await hub.registerConnectionToken({ ...ticket, token: 'later', expiresAt: now + 10_000 });
  assert.equal(await storage.getAlarm(), ticket.expiresAt);
  await hub.registerConnectionToken({ ...ticket, token: 'earlier', expiresAt: now + 1_000 });
  assert.equal(await storage.getAlarm(), now + 1_000);
  assert.deepEqual(await Promise.all([hub.consumeConnectionToken(' ticket '), hub.consumeConnectionToken('ticket')]), [
    { userId, deviceIdentifier: 'device-1', expiresAt: ticket.expiresAt },
    null,
  ]);

  now += 1_000;
  await hub.alarm();
  assert.equal(connectionTokens.has('ws-token:earlier'), false);
  assert.equal(await storage.getAlarm(), now + 9_000);
  now += 9_000;
  assert.equal(await hub.consumeConnectionToken('later'), null);
  assert.equal(await hub.consumeConnectionToken(' '), null);
  assert.equal(connectionTokens.size, 0);
});
