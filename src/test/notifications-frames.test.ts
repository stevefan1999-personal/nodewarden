import assert from 'node:assert/strict';
import test from 'node:test';
import { decode } from '@msgpack/msgpack';

import type { Env } from '../types';
import { createTestEnv, drainWaitUntil } from './support/env';

// The hub imports cloudflare:workers, which support/env resolves to its Node stand-in.
const {
  buildSignalRMessagePackInvocation,
  NotificationsHub,
  getOnlineUserDevices,
  notifyAuthRequestResponse,
  notifyUserLogout,
} = await import('../durable/notifications-hub');

test('a MessagePack SignalR frame is a VarInt length prefix and the invocation array', () => {
  // Long enough that the length needs two VarInt bytes.
  const payload = { UserId: 'user-1', Id: 'x'.repeat(200), RevisionDate: '2026-09-29T03:01:00.000Z' };
  const frame = buildSignalRMessagePackInvocation(1, payload, 'device-1');
  let length = 0;
  let offset = 0;
  for (let byte = 0x80; byte & 0x80; offset++) {
    byte = frame[offset];
    length |= (byte & 0x7f) << (7 * offset);
  }
  assert.equal(offset, 2);
  assert.equal(length, frame.byteLength - offset);
  assert.deepEqual(decode(frame.subarray(offset)), [
    1,
    {},
    null,
    'ReceiveMessage',
    [{ ContextId: 'device-1', Type: 1, Payload: payload }],
    [],
  ]);
});

test('notification RPC targets devices and matching anonymous auth requests', async () => {
  const env = await createTestEnv();
  const attachments = [
    { kind: 'user', deviceIdentifier: 'device-1', handshakeComplete: true, protocol: 'json' },
    { kind: 'user', deviceIdentifier: 'device-2', handshakeComplete: false, protocol: 'json' },
    { kind: 'anonymous-auth-request', authRequestId: 'request-1', handshakeComplete: true, protocol: 'json' },
    { kind: 'anonymous-auth-request', authRequestId: 'request-2', handshakeComplete: true, protocol: 'json' },
  ];
  const frames = attachments.map(() => [] as string[]);
  const sockets = attachments.map((attachment, index) => ({
    deserializeAttachment: () => attachment,
    send: (frame: string) => frames[index].push(frame),
  }));
  const hub = new NotificationsHub(
    {
      setWebSocketAutoResponse() {},
      getWebSockets: (tag?: string) =>
        sockets.filter((_, index) => !tag || tag === `device:${attachments[index].deviceIdentifier}`),
    } as unknown as DurableObjectState,
    env,
  );
  env.NOTIFICATIONS_HUB = {
    idFromName: (name: string) => name,
    get: () => hub,
  } as unknown as Env['NOTIFICATIONS_HUB'];

  assert.deepEqual(await getOnlineUserDevices(env, 'user-1'), ['device-1']);
  notifyUserLogout(env, 'user-1', 'device-1');
  await drainWaitUntil();
  assert.deepEqual(
    frames.map((messages) => messages.length),
    [1, 0, 0, 0],
  );
  const logout = JSON.parse(frames[0][0].slice(0, -1));
  assert.equal(logout.target, 'ReceiveMessage');
  assert.equal(logout.arguments[0].Type, 11);
  assert.equal(logout.arguments[0].Payload.UserId, 'user-1');

  await notifyAuthRequestResponse(env, 'user-1', 'request-1', ' device-1 ');
  assert.deepEqual(
    frames.map((messages) => messages.length),
    [1, 0, 1, 0],
  );
  assert.deepEqual(JSON.parse(frames[2][0].slice(0, -1)), {
    type: 1,
    target: 'AuthRequestResponseRecieved',
    arguments: [{ ContextId: 'device-1', Type: 16, Payload: { UserId: 'user-1', Id: 'request-1' } }],
  });
  assert.throws(() => hub.notifyAuthRequestResponse({ userId: '', authRequestId: 'request-1' }));
  assert.throws(() => hub.notify({ updateType: NaN, payload: {} }));
  assert.deepEqual(
    frames.map((messages) => messages.length),
    [1, 0, 1, 0],
  );
});
