import assert from 'node:assert/strict';
import test from 'node:test';
import { decode } from '@msgpack/msgpack';

import './support/env';

// The hub imports cloudflare:workers, which support/env resolves to its Node stand-in.
const { buildSignalRMessagePackInvocation } = await import('../durable/notifications-hub');

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
