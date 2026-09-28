import { and, inArray, lt } from 'drizzle-orm';

import { chunkRows, columnCount, getOrm, statementChunks, type Orm } from '../db/client';
import { attachments, ciphers, sends, userRevisions } from '../db/schema';
import { excluded } from '../db/sql';
import type { Env } from '../types';
import { archivedFiles } from './backup-archive';
import { deleteBlobObjects } from './blob-store';
import { bumpOrgMemberRevisions } from './storage-org-repo';

// Scheduled retention, as upstream Bitwarden's DeleteSendsJob and DeleteCiphersJob: Sends past their deletion
// date and items trashed more than TRASH_RETENTION_DAYS ago go for good, files included. Each delete re-checks
// its condition, so a Send extended or an item restored meanwhile stays, and only the files of rows that
// really left are removed, after the batch commits. A run takes at most PURGE_BATCH_ROWS rows; a backlog
// drains over the following runs.
const PURGE_BATCH_ROWS = 100;
const TRASH_RETENTION_DAYS = 30;
const DAY_MS = 86_400_000;

// Owners whose clients must drop the purged rows on their next sync.
function bumpRevisions(orm: Orm, userIds: string[], now: string) {
  return chunkRows([...new Set(userIds)], columnCount(userRevisions)).map((chunk) =>
    orm
      .insert(userRevisions)
      .values(chunk.map((userId) => ({ userId, revisionDate: now })))
      .onConflictDoUpdate({
        target: userRevisions.userId,
        set: { revisionDate: excluded(userRevisions.revisionDate) },
      }),
  );
}

export async function purgeExpiredSends(env: Env): Promise<void> {
  const orm = getOrm(env.DB);
  const now = new Date().toISOString();
  const expired = await orm
    .select({ id: sends.id, userId: sends.userId })
    .from(sends)
    .where(lt(sends.deletionDate, now))
    .limit(PURGE_BATCH_ROWS);
  if (!expired.length) return;
  const remove = (chunk: string[]) =>
    orm
      .delete(sends)
      .where(and(inArray(sends.id, chunk), lt(sends.deletionDate, now)))
      .returning({ id: sends.id, type: sends.type, data: sends.data });
  const removals = statementChunks(
    expired.map((send) => send.id),
    remove,
  ).map(remove);
  const statements = [
    ...removals,
    ...bumpRevisions(
      orm,
      expired.map((send) => send.userId),
      now,
    ),
  ];
  const results = await orm.batch(statements as [(typeof statements)[0], ...typeof statements]);
  const removed = results.slice(0, removals.length).flat() as Array<{ id: string; type: number; data: string }>;
  await deleteBlobObjects(
    env,
    archivedFiles({ attachments: [], sends: removed }).map((file) => file.key),
  );
}

export async function purgeOldTrash(env: Env): Promise<void> {
  const orm = getOrm(env.DB);
  const now = new Date();
  const cutoff = new Date(now.getTime() - TRASH_RETENTION_DAYS * DAY_MS).toISOString();
  const trashed = await orm
    .select({ id: ciphers.id, userId: ciphers.userId, organizationId: ciphers.organizationId })
    .from(ciphers)
    .where(lt(ciphers.deletedAt, cutoff))
    .limit(PURGE_BATCH_ROWS);
  if (!trashed.length) return;
  const ids = trashed.map((cipher) => cipher.id);
  // Attachment rows are read in the same batch, before the cipher delete cascades them away.
  const readFiles = (chunk: string[]) =>
    orm
      .select({ id: attachments.id, cipher_id: attachments.cipherId, size: attachments.size })
      .from(attachments)
      .where(inArray(attachments.cipherId, chunk));
  const remove = (chunk: string[]) =>
    orm
      .delete(ciphers)
      .where(and(inArray(ciphers.id, chunk), lt(ciphers.deletedAt, cutoff)))
      .returning({ id: ciphers.id });
  const reads = statementChunks(ids, readFiles).map(readFiles);
  const removals = statementChunks(ids, remove).map(remove);
  const statements = [
    ...reads,
    ...removals,
    ...bumpRevisions(
      orm,
      trashed.filter((cipher) => !cipher.organizationId).map((cipher) => cipher.userId),
      now.toISOString(),
    ),
    ...[...new Set(trashed.flatMap((cipher) => cipher.organizationId ?? []))].map((orgId) =>
      bumpOrgMemberRevisions(env.DB, orgId, now.toISOString()),
    ),
  ];
  const results = await orm.batch(statements as [(typeof statements)[0], ...typeof statements]);
  const files = results.slice(0, reads.length).flat() as Array<{ id: string; cipher_id: string; size: number }>;
  const removed = new Set(
    (results.slice(reads.length, reads.length + removals.length).flat() as Array<{ id: string }>).map(
      (cipher) => cipher.id,
    ),
  );
  await deleteBlobObjects(
    env,
    archivedFiles({ attachments: files.filter((file) => removed.has(file.cipher_id)), sends: [] }).map(
      (file) => file.key,
    ),
  );
}
