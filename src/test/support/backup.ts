import { unzipSync, zipSync } from 'fflate';

import { BACKUP_TABLE_NAMES, backupArchiveKey, writeBackupArchive } from '../../services/backup-archive';
import { restoreBackupArchive } from '../../services/backup-import';
import type { Env } from '../../types';

const DB_SLICE = /^db\/\d+\.json$/;
type Rows = Record<string, Record<string, unknown>[]>;

// The archive a backup run writes for env, read back out of its bucket.
export async function archiveOf(env: Env, includeAttachments = true) {
  const key = backupArchiveKey(new Date(), 'UTC');
  const { manifest } = await writeBackupArchive(env, env.BACKUPS!, key, new Date(), includeAttachments);
  const stored = await env.BACKUPS!.get(key);
  return { bytes: new Uint8Array(await stored!.arrayBuffer()), manifest };
}

// Restores archive bytes into env the way an uploaded archive restores: from its backup bucket.
export async function restoreArchive(env: Env, bytes: Uint8Array, actorUserId: string, replaceExisting = false) {
  const key = `uploads/${crypto.randomUUID()}.zip`;
  await env.BACKUPS!.put(key, bytes);
  return restoreBackupArchive(env, env.BACKUPS!, key, actorUserId, replaceExisting);
}

// Every table's rows in an archive, whole database and slices alike.
export function archiveDb(bytes: Uint8Array): Rows {
  const files = unzipSync(bytes);
  const merged: Rows = {};
  for (const name of Object.keys(files)
    .filter((entry) => entry === 'db.json' || DB_SLICE.test(entry))
    .sort())
    for (const [table, rows] of Object.entries(JSON.parse(new TextDecoder().decode(files[name])) as object))
      merged[table] = [...(merged[table] ?? []), ...rows];
  return merged;
}

// The archive with its database replaced by db, as one slice whose manifest counts its rows.
export function withArchiveDb(bytes: Uint8Array, db: Rows): Uint8Array {
  const files = unzipSync(bytes);
  const manifest = JSON.parse(new TextDecoder().decode(files['manifest.json']));
  manifest.tableCounts = Object.fromEntries(BACKUP_TABLE_NAMES.map((name) => [name, db[name]?.length ?? 0]));
  const kept = Object.entries(files).filter(([name]) => name !== 'db.json' && !DB_SLICE.test(name));
  return zipSync({
    ...Object.fromEntries(kept),
    'manifest.json': new TextEncoder().encode(JSON.stringify(manifest)),
    'db/0001.json': new TextEncoder().encode(JSON.stringify(db)),
  });
}
