import assert from 'node:assert/strict';
import test from 'node:test';

import { D1_MAX_BOUND_PARAMETERS } from '../db/client';
import { createTestEnv, seedUser } from '../test/support/env';
import { SendAuthType, SendType, type Send } from '../types';
import { sendRepo } from './storage-send-repo';

const DAY_MS = 86_400_000;

function textSend(userId: string, id: string, maxAccessCount: number | null = null): Send {
  const now = new Date().toISOString();
  return {
    id,
    userId,
    type: SendType.Text,
    name: 'name',
    notes: null,
    data: '{}',
    key: 'key',
    passwordHash: null,
    passwordSalt: null,
    passwordIterations: null,
    authType: SendAuthType.None,
    emails: null,
    maxAccessCount,
    accessCount: 0,
    disabled: false,
    hideEmail: null,
    createdAt: now,
    updatedAt: now,
    expirationDate: null,
    deletionDate: new Date(Date.now() + DAY_MS).toISOString(),
  };
}

test('a Send access counts only while the Send is under its maximum access count', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env);
  for (const [id, maxAccessCount, accepted] of [
    ['capped', 2, [true, true, false]],
    ['unlimited', null, [true, true, true]],
  ] as const) {
    await sendRepo(env.DB).saveSend(textSend(user.id, id, maxAccessCount));
    for (const expected of accepted) assert.equal(await sendRepo(env.DB).incrementSendAccessCount(id), expected, id);
    assert.equal((await sendRepo(env.DB).getSend(id))?.accessCount, accepted.filter(Boolean).length, id);
  }
});

test('reading and bulk-deleting Sends by id split long id lists under the bound-parameter cap', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env);
  const other = await seedUser(env);
  const ids = Array.from({ length: 2 * D1_MAX_BOUND_PARAMETERS }, (_, index) => `send-${index}`);
  for (const id of ids) await sendRepo(env.DB).saveSend(textSend(user.id, id));
  await sendRepo(env.DB).saveSend(textSend(other.id, 'foreign'));
  const requested = [...ids, 'foreign', 'missing'];
  assert.deepEqual(
    (await sendRepo(env.DB).getSendsByIds(requested, user.id)).map((send) => send.id).sort(),
    [...ids].sort(),
  );
  assert.ok(await sendRepo(env.DB).bulkDeleteSends(requested, user.id));
  assert.deepEqual(await sendRepo(env.DB).getAllSends(user.id), []);
  assert.deepEqual(
    (await sendRepo(env.DB).getAllSends(other.id)).map((send) => send.id),
    ['foreign'],
  );
});
