import { withoutQueryParams } from '../db/client';
import type { Env } from '../types';
import { writeAuditEvent } from './audit-events';
import { MAX_BACKUP_ARCHIVE_BYTES, buildBackupArchive } from './backup-archive';
import { loadBackupSchedule, updateBackupStatus } from './backup-config';
import { importBackupArchiveBytes, type BackupImportResultBody } from './backup-import';

// Archives a run writes, which retention prunes; uploaded archives live under uploads/ and are never pruned.
const RUN_ARCHIVE_KEY = /^nodewarden_backup_\d{8}_\d{6}_[0-9a-f]{5}\.zip$/;
// Every key restore and delete accept: one path segment of safe characters, optionally under uploads/.
const ARCHIVE_KEY = /^(uploads\/)?[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.zip$/;
const ARCHIVE_CONTENT_TYPE = 'application/zip';
const BYTES_PER_MIB = 1024 * 1024;

export interface BackupArchiveInfo {
  key: string;
  sizeBytes: number;
  uploadedAt: string;
}

type AuditMetadata = Record<string, unknown> | null;

export function isBackupArchiveKey(key: string): boolean {
  return ARCHIVE_KEY.test(key);
}

export function backupBucket(env: Env): R2Bucket {
  if (!env.BACKUPS) throw new Error('Backup storage is not configured');
  return env.BACKUPS;
}

// Newest first.
export async function listBackupArchives(env: Env): Promise<BackupArchiveInfo[]> {
  const bucket = backupBucket(env);
  const archives: BackupArchiveInfo[] = [];
  let cursor: string | undefined;
  do {
    const page = await bucket.list({ cursor });
    archives.push(
      ...page.objects.map((object) => ({
        key: object.key,
        sizeBytes: object.size,
        uploadedAt: object.uploaded.toISOString(),
      })),
    );
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);
  return archives.toSorted((a, b) => b.uploadedAt.localeCompare(a.uploadedAt));
}

export async function deleteBackupArchive(env: Env, key: string): Promise<void> {
  if (!isBackupArchiveKey(key)) throw new Error('Backup archive key is invalid');
  await backupBucket(env).delete(key);
}

// Writes one archive of the instance and records the run in the backup status and the audit log. With a retention
// count, the oldest run archives beyond it go; a failed prune only leaves extra archives, so it is logged instead.
export async function runBackup(
  env: Env,
  trigger: 'manual' | 'scheduled',
  actorUserId: string | null,
  auditMetadata: AuditMetadata = null,
): Promise<BackupArchiveInfo> {
  const schedule = await loadBackupSchedule(env.DB);
  const startedAt = new Date();
  await updateBackupStatus(env.DB, { lastAttemptAt: startedAt.toISOString() });
  try {
    const archive = await buildBackupArchive(env, startedAt, {
      includeAttachments: schedule.includeAttachments,
      timeZone: schedule.timezone,
    });
    const stored = await backupBucket(env).put(archive.fileName, archive.bytes, {
      httpMetadata: { contentType: ARCHIVE_CONTENT_TYPE },
    });
    const info = { key: stored.key, sizeBytes: stored.size, uploadedAt: stored.uploaded.toISOString() };
    if (schedule.retentionCount !== null) {
      const expired = (await listBackupArchives(env))
        .filter(({ key }) => RUN_ARCHIVE_KEY.test(key))
        .slice(schedule.retentionCount)
        .map(({ key }) => key);
      if (expired.length)
        await backupBucket(env)
          .delete(expired)
          .catch((error: unknown) => console.error('Backup retention prune failed', withoutQueryParams(error)));
    }
    await updateBackupStatus(env.DB, {
      lastSuccessAt: new Date().toISOString(),
      lastErrorAt: null,
      lastErrorMessage: null,
      lastArchiveKey: info.key,
      lastArchiveBytes: info.sizeBytes,
    });
    await writeAuditEvent(env.DB, {
      actorUserId,
      action: `admin.backup.${trigger}`,
      category: 'data',
      level: 'info',
      targetType: 'backup',
      targetId: info.key,
      metadata: { sizeBytes: info.sizeBytes, tableCounts: archive.manifest.tableCounts, ...auditMetadata },
    });
    return info;
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Backup failed';
    await updateBackupStatus(env.DB, { lastErrorAt: new Date().toISOString(), lastErrorMessage: message });
    await writeAuditEvent(env.DB, {
      actorUserId,
      action: `admin.backup.${trigger}.failed`,
      category: 'data',
      level: 'error',
      targetType: 'backup',
      targetId: null,
      metadata: { error: message, ...auditMetadata },
    });
    throw error;
  }
}

export async function restoreBackup(
  env: Env,
  key: string,
  actorUserId: string,
  replaceExisting: boolean,
  auditMetadata: AuditMetadata = null,
): Promise<BackupImportResultBody> {
  if (!isBackupArchiveKey(key)) throw new Error('Backup archive key is invalid');
  const object = await backupBucket(env).get(key);
  if (!object) throw new Error('Backup archive not found');
  if (object.size > MAX_BACKUP_ARCHIVE_BYTES) {
    await object.body.cancel();
    throw new Error(
      `Backup archive is too large. The current restore limit is ${MAX_BACKUP_ARCHIVE_BYTES / BYTES_PER_MIB} MiB`,
    );
  }
  const imported = await importBackupArchiveBytes(
    new Uint8Array(await object.arrayBuffer()),
    env,
    actorUserId,
    replaceExisting,
  );
  await writeAuditEvent(env.DB, {
    actorUserId: imported.auditActorUserId,
    action: 'admin.backup.import',
    category: 'data',
    level: 'info',
    targetType: 'backup',
    targetId: key,
    metadata: {
      users: imported.result.imported.users,
      ciphers: imported.result.imported.ciphers,
      attachments: imported.result.imported.attachmentFiles,
      skippedAttachments: imported.result.skipped.attachments,
      skippedReason: imported.result.skipped.reason,
      replaceExisting,
      sizeBytes: object.size,
      ...auditMetadata,
    },
  });
  return imported.result;
}
