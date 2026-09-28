import assert from 'node:assert/strict';
import test from 'node:test';
import { inspect } from 'node:util';

import { createTestEnv } from '../test/support/env';
import { ensurePushInstallationCredentials, unregisterMobilePushDevice } from './push-relay';

test('push relay failures log Bitwarden status codes, never response bodies', async (t) => {
  const errors = t.mock.method(console, 'error', () => {});
  // Bitwarden's replies in call order: a failed installation, a created one, a refused token, a token, a failed relay.
  const replies = [
    new Response('installation-reply-body', { status: 500 }),
    Response.json({ id: 'installation-id', key: 'installation-key' }),
    new Response('token-reply-body', { status: 400 }),
    Response.json({ access_token: 'relay-access-token', expires_in: 3600 }),
    new Response('relay-reply-body', { status: 503 }),
  ];
  t.mock.method(globalThis, 'fetch', async () => replies.shift()!);
  const env = await createTestEnv();
  assert.equal(await ensurePushInstallationCredentials(env.DB), null);
  assert.equal(await unregisterMobilePushDevice(env, 'push-uuid'), false);
  assert.equal(await unregisterMobilePushDevice(env, 'push-uuid'), false);
  assert.equal(replies.length, 0);
  const logged = inspect(
    errors.mock.calls.map((call) => call.arguments),
    { depth: 5 },
  );
  for (const status of ['500', '400', '503']) assert.match(logged, new RegExp(status));
  assert.doesNotMatch(logged, /reply-body/);
});
