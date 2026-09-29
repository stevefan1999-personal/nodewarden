import { verifyPassword } from '../services/auth-password';
import type { AppContext } from '../router';
import type { Env, User } from '../types';
import { z } from 'zod';
import { errorResponse, validationErrorResponse, type BodyContext } from '../utils/response';
import {
  BackupScheduleSchema,
  loadBackupSchedule,
  loadBackupStatus,
  saveBackupSchedule,
} from '../services/backup-config';
import { deleteBackupArchive, isBackupArchiveKey, listBackupArchives } from '../services/backup-runs';
import { backupTransfersConfigured, presignBackupTransfer } from '../services/backup-transfers';
import { auditRequestMetadata, writeAuditEvent } from '../services/audit-events';
import { withoutQueryParams } from '../db/client';

function isAdmin(user: User): boolean {
  return user.role === 'admin' && user.status === 'active';
}

async function requireBackupUserVerification(
  c: AppContext,
  actorUser: User,
  masterPasswordHash: string | null | undefined,
): Promise<Response | null> {
  const normalized = (masterPasswordHash ?? '').trim();
  if (!normalized) {
    return errorResponse(c, 'masterPasswordHash is required', 400);
  }
  const valid = await verifyPassword(normalized, actorUser.masterPasswordHash, actorUser.email);
  if (!valid) {
    return errorResponse(c, 'Invalid password', 400);
  }
  return null;
}

async function writeAuditLog(
  db: D1Database,
  actorUserId: string | null,
  action: string,
  targetId: string | null,
  metadata: Record<string, unknown>,
  request: Request,
): Promise<void> {
  await writeAuditEvent(db, {
    actorUserId,
    action,
    targetType: 'backup',
    targetId,
    category: 'data',
    level: 'info',
    metadata: { ...metadata, ...auditRequestMetadata(request) },
  });
}

function backupTransferRunner(env: Env) {
  return env.BACKUP_TRANSFER_RUNNER.get(env.BACKUP_TRANSFER_RUNNER.idFromName('configured-backup-runner'));
}

export async function runScheduledBackupIfDue(env: Env): Promise<void> {
  await backupTransferRunner(env).runScheduledBackups();
}

const optionalString = z.string().nullish();

// A body that is not an object answers the endpoint's payload message.
export const BackupSettingsBody = z.object(
  { schedule: z.record(z.string(), z.unknown()).nullish(), masterPasswordHash: optionalString },
  { error: 'Backup settings payload is invalid' },
);
export const BackupRunBody = z.object(
  { masterPasswordHash: optionalString },
  { error: 'Backup run payload is invalid' },
);
export const BackupUploadBody = z.object(
  { masterPasswordHash: optionalString },
  { error: 'Backup archive upload payload is invalid' },
);

async function backupSettingsResponse(c: AppContext): Promise<Response> {
  return c.json({
    object: 'backup-settings',
    schedule: await loadBackupSchedule(c.env.DB),
    status: await loadBackupStatus(c.env.DB),
    storageConfigured: !!c.env.BACKUPS,
    transfersConfigured: backupTransfersConfigured(c.env),
  });
}

export async function handleGetAdminBackupSettings(c: AppContext): Promise<Response> {
  const { currentUser: actorUser } = c.var;
  if (!isAdmin(actorUser)) return errorResponse(c, 'Forbidden', 403);
  return backupSettingsResponse(c);
}

// A save may send any subset of the schedule; the rest keeps its stored value.
export async function handleUpdateAdminBackupSettings(c: BodyContext<typeof BackupSettingsBody>): Promise<Response> {
  const { currentUser: actorUser } = c.var;
  if (!isAdmin(actorUser)) return errorResponse(c, 'Forbidden', 403);

  const body = c.req.valid('json');

  const verificationError = await requireBackupUserVerification(c, actorUser, body.masterPasswordHash);
  if (verificationError) return verificationError;

  // Parsed under its body key, so each issue names schedule.<field>.
  const next = z
    .object({ schedule: BackupScheduleSchema })
    .safeParse({ schedule: { ...(await loadBackupSchedule(c.env.DB)), ...body.schedule } });
  if (!next.success) return validationErrorResponse(c, next.error);

  await saveBackupSchedule(c.env.DB, next.data.schedule);
  await writeAuditLog(
    c.env.DB,
    actorUser.id,
    'admin.backup.settings.update',
    null,
    { schedule: next.data.schedule },
    c.req.raw,
  );
  return backupSettingsResponse(c);
}

export async function handleRunAdminBackup(c: BodyContext<typeof BackupRunBody>): Promise<Response> {
  const { currentUser: actorUser } = c.var;
  if (!isAdmin(actorUser)) return errorResponse(c, 'Forbidden', 403);

  const body = c.req.valid('json');

  const verificationError = await requireBackupUserVerification(c, actorUser, body.masterPasswordHash);
  if (verificationError) return verificationError;
  if (!c.env.BACKUPS) return errorResponse(c, 'Backup storage is not configured', 409);

  try {
    const archive = await backupTransferRunner(c.env).runBackup({
      actorUserId: actorUser.id,
      auditMetadata: auditRequestMetadata(c.req.raw),
    });
    if (!archive) return errorResponse(c, 'Another backup or restore run is already in progress', 409);
    return c.json({ object: 'backup-run', archive });
  } catch (error) {
    return errorResponse(c, error instanceof Error ? error.message : 'Backup run failed', 500);
  }
}

export async function handleListAdminBackupArchives(c: AppContext): Promise<Response> {
  const { currentUser: actorUser } = c.var;
  if (!isAdmin(actorUser)) return errorResponse(c, 'Forbidden', 403);
  if (!c.env.BACKUPS) return errorResponse(c, 'Backup storage is not configured', 409);
  return c.json({ object: 'list', data: await listBackupArchives(c.env) });
}

const archiveShape = { key: optionalString, masterPasswordHash: optionalString };
export const BackupRestoreBody = z.object(
  { ...archiveShape, replaceExisting: z.boolean().nullish() },
  { error: 'Backup restore payload is invalid' },
);
export const BackupDeleteBody = z.object(archiveShape, { error: 'Backup archive delete payload is invalid' });
export const BackupDownloadBody = z.object(archiveShape, { error: 'Backup archive download payload is invalid' });

export async function handleRestoreAdminBackupArchive(c: BodyContext<typeof BackupRestoreBody>): Promise<Response> {
  const { currentUser: actorUser } = c.var;
  if (!isAdmin(actorUser)) return errorResponse(c, 'Forbidden', 403);

  const body = c.req.valid('json');

  const verificationError = await requireBackupUserVerification(c, actorUser, body.masterPasswordHash);
  if (verificationError) return verificationError;
  const key = (body.key ?? '').trim();
  if (!isBackupArchiveKey(key)) return errorResponse(c, 'Backup archive key is invalid', 400);
  if (!c.env.BACKUPS) return errorResponse(c, 'Backup storage is not configured', 409);

  try {
    const imported = await backupTransferRunner(c.env).restoreBackup({
      actorUserId: actorUser.id,
      auditMetadata: auditRequestMetadata(c.req.raw),
      key,
      replaceExisting: !!body.replaceExisting,
    });
    if (!imported) return errorResponse(c, 'Another backup or restore run is already in progress', 409);
    return c.json(imported);
  } catch (error) {
    // A failed statement's message ends with the values it bound, which stay out of the response.
    const scrubbed = withoutQueryParams(error);
    const message = scrubbed instanceof Error ? scrubbed.message : 'Backup restore failed';
    // What is wrong with the archive is the caller's to fix; an instance that is not fresh or has no storage
    // conflicts with the restore.
    const status =
      message === 'Backup archive not found'
        ? 404
        : /^(Backup archive |Invalid backup archive|Unsupported backup format version)/.test(message)
          ? 400
          : /fresh instance|not configured/.test(message)
            ? 409
            : 500;
    return errorResponse(c, message, status);
  }
}

export async function handleDeleteAdminBackupArchive(c: BodyContext<typeof BackupDeleteBody>): Promise<Response> {
  const { currentUser: actorUser } = c.var;
  if (!isAdmin(actorUser)) return errorResponse(c, 'Forbidden', 403);

  const body = c.req.valid('json');

  const verificationError = await requireBackupUserVerification(c, actorUser, body.masterPasswordHash);
  if (verificationError) return verificationError;
  const key = (body.key ?? '').trim();
  if (!isBackupArchiveKey(key)) return errorResponse(c, 'Backup archive key is invalid', 400);
  if (!c.env.BACKUPS) return errorResponse(c, 'Backup storage is not configured', 409);

  await deleteBackupArchive(c.env, key);
  await writeAuditLog(c.env.DB, actorUser.id, 'admin.backup.archive.delete', key, {}, c.req.raw);
  return c.json({ object: 'backup-archive-delete', deleted: true, key });
}

// Archives move in and out only through presigned URLs, straight between the administrator and the bucket.
export async function handleDownloadAdminBackupArchive(c: BodyContext<typeof BackupDownloadBody>): Promise<Response> {
  const { currentUser: actorUser } = c.var;
  if (!isAdmin(actorUser)) return errorResponse(c, 'Forbidden', 403);

  const body = c.req.valid('json');

  const verificationError = await requireBackupUserVerification(c, actorUser, body.masterPasswordHash);
  if (verificationError) return verificationError;
  const key = (body.key ?? '').trim();
  if (!isBackupArchiveKey(key)) return errorResponse(c, 'Backup archive key is invalid', 400);
  if (!c.env.BACKUPS) return errorResponse(c, 'Backup storage is not configured', 409);
  if (!backupTransfersConfigured(c.env))
    return errorResponse(c, 'Presigned backup transfers need R2 S3 credentials', 409);
  if (!(await c.env.BACKUPS.head(key))) return errorResponse(c, 'Backup archive not found', 404);

  const transfer = await presignBackupTransfer(c.env, 'GET', key);
  await writeAuditLog(c.env.DB, actorUser.id, 'admin.backup.archive.download', key, {}, c.req.raw);
  return c.json({ object: 'backup-transfer', method: 'GET', key, ...transfer });
}

// A fresh key under uploads/, which a restore then names.
export async function handleUploadAdminBackupArchive(c: BodyContext<typeof BackupUploadBody>): Promise<Response> {
  const { currentUser: actorUser } = c.var;
  if (!isAdmin(actorUser)) return errorResponse(c, 'Forbidden', 403);

  const body = c.req.valid('json');

  const verificationError = await requireBackupUserVerification(c, actorUser, body.masterPasswordHash);
  if (verificationError) return verificationError;
  if (!c.env.BACKUPS) return errorResponse(c, 'Backup storage is not configured', 409);
  if (!backupTransfersConfigured(c.env))
    return errorResponse(c, 'Presigned backup transfers need R2 S3 credentials', 409);

  const key = `uploads/${crypto.randomUUID()}.zip`;
  const transfer = await presignBackupTransfer(c.env, 'PUT', key);
  await writeAuditLog(c.env.DB, actorUser.id, 'admin.backup.archive.upload', key, {}, c.req.raw);
  return c.json({ object: 'backup-transfer', method: 'PUT', key, ...transfer });
}
