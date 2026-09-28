import type { Env, User } from '../types';
import { z } from 'zod';
import { bodyIssues, errorResponse, jsonResponse, parseBody } from '../utils/response';
import {
  MAX_BACKUP_ARCHIVE_BYTES,
  buildBackupArchive,
  isSafeBackupBlobName,
  verifyBackupArchiveFileNameChecksum,
} from '../services/backup-archive';
import {
  BackupScheduleSchema,
  loadBackupSchedule,
  loadBackupStatus,
  saveBackupSchedule,
} from '../services/backup-config';
import { importBackupArchiveBytes } from '../services/backup-import';
import { deleteBackupArchive, isBackupArchiveKey, listBackupArchives } from '../services/backup-runs';
import { AuthService } from '../services/auth';
import { auditRequestMetadata, writeAuditEvent } from '../services/audit-events';
import { getBlobObject } from '../services/blob-store';
import { getMultipartRequestMaxBytes } from '../utils/direct-upload';

function isAdmin(user: User): boolean {
  return user.role === 'admin' && user.status === 'active';
}

async function requireBackupUserVerification(
  actorUser: User,
  masterPasswordHash: string | null | undefined,
  env: Env,
): Promise<Response | null> {
  const normalized = (masterPasswordHash ?? '').trim();
  if (!normalized) {
    return errorResponse('masterPasswordHash is required', 400);
  }
  const auth = new AuthService(env);
  const valid = await auth.verifyPassword(normalized, actorUser.masterPasswordHash, actorUser.email);
  if (!valid) {
    return errorResponse('Invalid password', 400);
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

function toImportStatusCode(message: string): number {
  const lower = message.toLowerCase();
  if (lower.includes('checksum')) return 400;
  if (lower.includes('not found')) return 404;
  if (lower.includes('invalid backup') || lower.includes('invalid json') || lower.includes('key is invalid'))
    return 400;
  if (lower.includes('fresh instance')) return 409;
  if (lower.includes('not configured') || lower.includes('kv')) return 409;
  return 500;
}

export async function runScheduledBackupIfDue(env: Env): Promise<void> {
  await backupTransferRunner(env).runScheduledBackups();
}

const optionalString = z.string().nullish();

// Unparseable JSON and a non-object body both answer the endpoint's payload message.
function parseBackupBody<Shape extends z.ZodRawShape>(request: Request, shape: Shape, message: string) {
  return parseBody(request, z.object(shape, { error: message }), message);
}

async function backupSettingsResponse(env: Env): Promise<Response> {
  return jsonResponse({
    object: 'backup-settings',
    schedule: await loadBackupSchedule(env.DB),
    status: await loadBackupStatus(env.DB),
    storageConfigured: !!env.BACKUPS,
  });
}

export async function handleGetAdminBackupSettings(request: Request, env: Env, actorUser: User): Promise<Response> {
  void request;
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);
  return backupSettingsResponse(env);
}

// A save may send any subset of the schedule; the rest keeps its stored value.
export async function handleUpdateAdminBackupSettings(request: Request, env: Env, actorUser: User): Promise<Response> {
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  const body = await parseBackupBody(
    request,
    { schedule: z.record(z.string(), z.unknown()).nullish(), masterPasswordHash: optionalString },
    'Backup settings payload is invalid',
  );
  if (body instanceof Response) return body;

  const verificationError = await requireBackupUserVerification(actorUser, body.masterPasswordHash, env);
  if (verificationError) return verificationError;

  // Parsed under its body key, so each issue names schedule.<field>.
  const next = z
    .object({ schedule: BackupScheduleSchema })
    .safeParse({ schedule: { ...(await loadBackupSchedule(env.DB)), ...body.schedule } });
  if (!next.success) return errorResponse(next.error.issues[0].message, 400, {}, bodyIssues(next.error));

  await saveBackupSchedule(env.DB, next.data.schedule);
  await writeAuditLog(
    env.DB,
    actorUser.id,
    'admin.backup.settings.update',
    null,
    { schedule: next.data.schedule },
    request,
  );
  return backupSettingsResponse(env);
}

export async function handleRunAdminBackup(request: Request, env: Env, actorUser: User): Promise<Response> {
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  const body = await parseBackupBody(request, { masterPasswordHash: optionalString }, 'Backup run payload is invalid');
  if (body instanceof Response) return body;

  const verificationError = await requireBackupUserVerification(actorUser, body.masterPasswordHash, env);
  if (verificationError) return verificationError;
  if (!env.BACKUPS) return errorResponse('Backup storage is not configured', 409);

  try {
    const archive = await backupTransferRunner(env).runBackup({
      actorUserId: actorUser.id,
      auditMetadata: auditRequestMetadata(request),
    });
    if (!archive) return errorResponse('Another backup or restore run is already in progress', 409);
    return jsonResponse({ object: 'backup-run', archive });
  } catch (error) {
    return errorResponse(error instanceof Error ? error.message : 'Backup run failed', 500);
  }
}

export async function handleListAdminBackupArchives(request: Request, env: Env, actorUser: User): Promise<Response> {
  void request;
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);
  if (!env.BACKUPS) return errorResponse('Backup storage is not configured', 409);
  return jsonResponse({ object: 'list', data: await listBackupArchives(env) });
}

const archiveShape = { key: optionalString, masterPasswordHash: optionalString };

export async function handleRestoreAdminBackupArchive(request: Request, env: Env, actorUser: User): Promise<Response> {
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  const body = await parseBackupBody(
    request,
    { ...archiveShape, replaceExisting: z.boolean().nullish() },
    'Backup restore payload is invalid',
  );
  if (body instanceof Response) return body;

  const verificationError = await requireBackupUserVerification(actorUser, body.masterPasswordHash, env);
  if (verificationError) return verificationError;
  const key = (body.key ?? '').trim();
  if (!isBackupArchiveKey(key)) return errorResponse('Backup archive key is invalid', 400);
  if (!env.BACKUPS) return errorResponse('Backup storage is not configured', 409);

  try {
    const imported = await backupTransferRunner(env).restoreBackup({
      actorUserId: actorUser.id,
      auditMetadata: auditRequestMetadata(request),
      key,
      replaceExisting: !!body.replaceExisting,
    });
    if (!imported) return errorResponse('Another backup or restore run is already in progress', 409);
    return jsonResponse(imported);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Backup restore failed';
    return errorResponse(message, toImportStatusCode(message));
  }
}

export async function handleDeleteAdminBackupArchive(request: Request, env: Env, actorUser: User): Promise<Response> {
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  const body = await parseBackupBody(request, archiveShape, 'Backup archive delete payload is invalid');
  if (body instanceof Response) return body;

  const verificationError = await requireBackupUserVerification(actorUser, body.masterPasswordHash, env);
  if (verificationError) return verificationError;
  const key = (body.key ?? '').trim();
  if (!isBackupArchiveKey(key)) return errorResponse('Backup archive key is invalid', 400);
  if (!env.BACKUPS) return errorResponse('Backup storage is not configured', 409);

  await deleteBackupArchive(env, key);
  await writeAuditLog(env.DB, actorUser.id, 'admin.backup.archive.delete', key, {}, request);
  return jsonResponse({ object: 'backup-archive-delete', deleted: true, key });
}

export async function handleAdminExportBackup(request: Request, env: Env, actorUser: User): Promise<Response> {
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  const body = await parseBackupBody(
    request,
    { includeAttachments: z.boolean().nullish(), masterPasswordHash: optionalString },
    'Backup export payload is invalid',
  );
  if (body instanceof Response) return body;
  const verificationError = await requireBackupUserVerification(actorUser, body.masterPasswordHash, env);
  if (verificationError) return verificationError;

  let archive: Awaited<ReturnType<typeof buildBackupArchive>>;
  try {
    archive = await buildBackupArchive(env, new Date(), { includeAttachments: !!body.includeAttachments });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Backup export failed';
    return errorResponse(message, message.includes('blob missing') ? 409 : 500);
  }

  await writeAuditLog(
    env.DB,
    actorUser.id,
    'admin.backup.export',
    null,
    {
      users: archive.manifest.tableCounts.users,
      ciphers: archive.manifest.tableCounts.ciphers,
      attachments: archive.manifest.tableCounts.attachments,
      compressedBytes: archive.bytes.byteLength,
      includesAttachments: archive.manifest.includes.attachments,
    },
    request,
  );

  return new Response(archive.bytes, {
    status: 200,
    headers: {
      'Content-Type': 'application/zip',
      'Content-Disposition': `attachment; filename="${archive.fileName}"`,
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

export async function handleDownloadAdminBackupAttachment(
  request: Request,
  env: Env,
  actorUser: User,
): Promise<Response> {
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  try {
    // Read the request body only. Accepting these fields from the query string
    // would put the master-password authentication hash in the URL, where it is
    // captured by request logs, browser history and Referer headers.
    const body = await parseBackupBody(
      request,
      { blobName: optionalString, masterPasswordHash: optionalString },
      'Backup attachment download payload is invalid',
    );
    if (body instanceof Response) return body;

    const verificationError = await requireBackupUserVerification(actorUser, body.masterPasswordHash, env);
    if (verificationError) return verificationError;

    const blobName = String(body.blobName || '')
      .trim()
      .replace(/\\/g, '/')
      .replace(/^\/+|\/+$/g, '');
    if (!blobName) {
      return errorResponse('Backup attachment blob is required', 400);
    }
    // Only <cipher>/<attachment> names with safe segments reach blob storage.
    if (!isSafeBackupBlobName(blobName)) {
      return errorResponse('Backup attachment blob is invalid', 400);
    }
    const object = await getBlobObject(env, blobName);
    if (!object) {
      return errorResponse('Backup attachment blob not found', 404);
    }
    return new Response(object.body, {
      status: 200,
      headers: {
        'Content-Type': object.contentType || 'application/octet-stream',
        'Content-Length': String(object.size),
        'Cache-Control': 'no-store',
      },
    });
  } catch (error) {
    return errorResponse(error instanceof Error ? error.message : 'Backup attachment download failed', 400);
  }
}

export async function handleAdminImportBackup(request: Request, env: Env, actorUser: User): Promise<Response> {
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  const contentType = request.headers.get('Content-Type') || '';
  if (!contentType.includes('multipart/form-data')) {
    return errorResponse('Content-Type must be multipart/form-data', 400);
  }
  // Refuse an oversized upload before reading it; a missing or malformed Content-Length falls through to the
  // file size check below.
  const declaredSize = Number(request.headers.get('content-length') || Number.NaN);
  if (
    Number.isFinite(declaredSize) &&
    declaredSize >= 0 &&
    Math.floor(declaredSize) > getMultipartRequestMaxBytes(MAX_BACKUP_ARCHIVE_BYTES)
  ) {
    return errorResponse(
      `Backup file too large. Maximum size is ${Math.floor(MAX_BACKUP_ARCHIVE_BYTES / (1024 * 1024))}MB`,
      413,
    );
  }

  let formData: FormData;
  try {
    formData = await request.formData();
  } catch {
    return errorResponse('Content-Type must be multipart/form-data', 400);
  }

  const file = formData.get('file');
  if (!file || typeof file !== 'object' || !('arrayBuffer' in file)) {
    return errorResponse('Backup file is required', 400);
  }
  if ('size' in file && typeof (file as File).size === 'number' && (file as File).size > MAX_BACKUP_ARCHIVE_BYTES) {
    return errorResponse(
      `Backup file too large. Maximum size is ${Math.floor(MAX_BACKUP_ARCHIVE_BYTES / (1024 * 1024))}MB`,
      413,
    );
  }

  const verificationError = await requireBackupUserVerification(
    actorUser,
    String(formData.get('masterPasswordHash') || ''),
    env,
  );
  if (verificationError) return verificationError;

  const replaceExisting = String(formData.get('replaceExisting') || '').trim() === '1';
  const allowChecksumMismatch = String(formData.get('allowChecksumMismatch') || '').trim() === '1';
  let archiveBytes: Uint8Array;
  try {
    archiveBytes = new Uint8Array(await (file as { arrayBuffer(): Promise<ArrayBuffer> }).arrayBuffer());
  } catch {
    return errorResponse('Unable to read backup file', 400);
  }

  try {
    const fileName = 'name' in file ? String((file as File).name || '') : '';
    const checksumOk = await verifyBackupArchiveFileNameChecksum(archiveBytes, fileName);
    if (!checksumOk && !allowChecksumMismatch) {
      return errorResponse('Backup file checksum does not match its filename', 400);
    }
    const imported = await importBackupArchiveBytes(archiveBytes, env, actorUser.id, replaceExisting);
    await writeAuditLog(
      env.DB,
      imported.auditActorUserId,
      'admin.backup.import',
      null,
      {
        users: imported.result.imported.users,
        ciphers: imported.result.imported.ciphers,
        attachments: imported.result.imported.attachmentFiles,
        skippedAttachments: imported.result.skipped.attachments,
        skippedReason: imported.result.skipped.reason,
        replaceExisting,
        trigger: 'local',
        bytes: archiveBytes.byteLength,
        checksumMismatchAccepted: !checksumOk,
      },
      request,
    );
    return jsonResponse(imported.result);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Backup import failed';
    return errorResponse(message, toImportStatusCode(message));
  }
}
