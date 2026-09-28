import assert from 'node:assert/strict';
import test from 'node:test';
import { eq } from 'drizzle-orm';

import { getOrm } from '../db/client';
import { attachments, ciphers, sends, userRevisions } from '../db/schema';
import { createTestEnv, memoryKv, seedUser } from '../test/support/env';
import { createOrg, seedMember } from '../test/support/sm';
import { SendType, type Env } from '../types';
import { putBlobObject } from './blob-store';
import { purgeExpiredSends, purgeOldTrash } from './retention';

const DAY_MS = 86_400_000;
const daysAgo = (days: number) => new Date(Date.now() - days * DAY_MS).toISOString();
const STALE_REVISION = '2000-01-01T00:00:00.000Z';

async function staleRevisions(env: Env, userIds: string[]) {
  await getOrm(env.DB)
    .insert(userRevisions)
    .values(userIds.map((userId) => ({ userId, revisionDate: STALE_REVISION })))
    .onConflictDoUpdate({ target: userRevisions.userId, set: { revisionDate: STALE_REVISION } });
}

async function revisionOf(env: Env, userId: string) {
  return (
    await getOrm(env.DB)
      .select({ date: userRevisions.revisionDate })
      .from(userRevisions)
      .where(eq(userRevisions.userId, userId))
      .get()
  )?.date;
}

test('Sends past their deletion date are purged with their files, and their owners resync', async () => {
  const kv = memoryKv();
  const env = await createTestEnv({ ATTACHMENTS_KV: kv.binding });
  const owner = await seedUser(env);
  await staleRevisions(env, [owner.id]);
  const send = (id: string, type: SendType, deletionDate: string, data: object) => ({
    id,
    userId: owner.id,
    type,
    name: 'enc-name',
    data: JSON.stringify(data),
    key: 'enc-key',
    createdAt: 'c',
    updatedAt: 'u',
    deletionDate,
  });
  await getOrm(env.DB)
    .insert(sends)
    .values([
      send('expired-text', SendType.Text, daysAgo(1), { text: 'enc' }),
      send('expired-file', SendType.File, daysAgo(1), { id: 'file-1', size: 4 }),
      send('live-file', SendType.File, daysAgo(-1), { id: 'file-2', size: 4 }),
    ]);
  for (const key of ['sends/expired-file/file-1', 'sends/live-file/file-2'])
    await putBlobObject(env, key, new Uint8Array(4), { size: 4 });

  await purgeExpiredSends(env);
  assert.deepEqual(await getOrm(env.DB).select({ id: sends.id }).from(sends), [{ id: 'live-file' }]);
  assert.deepEqual([...kv.values.keys()], ['sends/live-file/file-2']);
  assert.notEqual(await revisionOf(env, owner.id), STALE_REVISION);
});

test('items in the trash for more than 30 days are purged with their files, and owners and members resync', async () => {
  const kv = memoryKv();
  const env = await createTestEnv({ ATTACHMENTS_KV: kv.binding });
  const owner = await seedUser(env);
  const orgId = await createOrg(env, owner);
  const { user: member } = await seedMember(env, orgId);
  await staleRevisions(env, [owner.id, member.id]);
  const cipher = (id: string, deletedAt: string | null, organizationId: string | null = null) => ({
    id,
    userId: owner.id,
    organizationId,
    type: 1,
    data: '{}',
    createdAt: 'c',
    updatedAt: 'u',
    deletedAt,
  });
  await getOrm(env.DB)
    .insert(ciphers)
    .values([
      cipher('old-trash', daysAgo(31)),
      cipher('recent-trash', daysAgo(29)),
      cipher('live', null),
      cipher('old-org-trash', daysAgo(31), orgId),
    ]);
  await getOrm(env.DB)
    .insert(attachments)
    .values({ id: 'attachment-1', cipherId: 'old-trash', fileName: 'enc', size: 4, sizeName: '4 Bytes', key: 'k' });
  await putBlobObject(env, 'old-trash/attachment-1', new Uint8Array(4), { size: 4 });

  await purgeOldTrash(env);
  assert.deepEqual(
    (await getOrm(env.DB).select({ id: ciphers.id }).from(ciphers).orderBy(ciphers.id)).map((row) => row.id),
    ['live', 'recent-trash'],
  );
  assert.equal(await getOrm(env.DB).$count(attachments), 0);
  assert.deepEqual([...kv.values.keys()], []);
  for (const user of [owner, member]) assert.notEqual(await revisionOf(env, user.id), STALE_REVISION);
});
