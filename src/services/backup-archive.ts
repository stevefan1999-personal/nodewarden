import { zipSync, unzipSync, type UnzipFileInfo } from 'fflate';
import { sha256 } from 'hono/utils/crypto';
import { z } from 'zod';
import { asc, getColumns } from 'drizzle-orm';
import { getTableConfig, type SQLiteColumn } from 'drizzle-orm/sqlite-core';

import { getOrm } from '../db/client';
import {
  attachments,
  ciphers,
  config,
  domainSettings,
  folders,
  userRevisions,
  users,
  webauthnCredentials,
} from '../db/schema';
import { unmapped } from '../db/sql';
import type { Env } from '../types';
import { APP_VERSION } from '../../shared/app-version';
import { BACKUP_SETTINGS_CONFIG_KEY } from './backup-config';
import { YUBICO_BOOTSTRAP_CLAIM_CONFIG_KEY } from './yubico-config';
import { exportPortableBackupSettingsEnvelope } from './backup-settings-crypto';
import { getAttachmentObjectKey, getBlobStorageKind } from './blob-store';

// CONTRACT:
// This file defines the exported instance-backup archive shape. Keep it in lock
// step with src/services/backup-import.ts.
//
// WHEN CHANGING THIS:
// - Add persistent tables to BACKUP_TABLES, in restore order: export, restore,
//   manifest tableCounts and the db allowlist all follow it. Put cross-row rules
//   the database cannot check in validateBackupPayloadContents().
// - Keep secrets and transient runtime rows sanitized before writing db.json.
// - Runtime authentication state (devices, sessions, auth requests, remembered
//   2FA devices, and one-time tokens) must never enter an instance backup.
// - users.api_key is intentionally not exported.
// - backup.settings.v1 is exported as portable-only; the current server runtime
//   envelope must not leave the instance.
type SqlRow = Record<string, string | number | null>;

const BACKUP_FORMAT_VERSION = 1;
const BACKUP_RUNNER_LOCK_CONFIG_KEY = 'backup.runner.lock.v1';
const BACKUP_FILE_HASH_PREFIX_LENGTH = 5;
// Worker-side backup export must stay well below Cloudflare CPU limits.
// Prefer store-only ZIP entries over heavier compression to keep exports reliable.
const BACKUP_TEXT_COMPRESSION_LEVEL = 0;
const BACKUP_JSON_INDENT = 2;
export const MAX_BACKUP_ARCHIVE_BYTES = 64 * 1024 * 1024;
const MAX_BACKUP_ARCHIVE_ENTRY_COUNT = 10_000;
const MAX_BACKUP_EXTRACTED_BYTES = 64 * 1024 * 1024;
const MAX_BACKUP_DB_JSON_BYTES = 32 * 1024 * 1024;
const MAX_BACKUP_PATH_SEGMENT_LENGTH = 128;

export interface BackupManifest {
  formatVersion: 1;
  exportedAt: string;
  appVersion: string;
  storageKind: 'r2' | 'kv' | null;
  tableCounts: Record<string, number>;
  includes: {
    attachments: boolean;
  };
  blobSummary: {
    attachmentFiles: number;
    totalBytes: number;
    largestObjectBytes: number;
  };
  attachmentBlobs?: BackupManifestAttachmentBlob[];
}

const BackupManifestAttachmentBlobSchema = z.object({
  cipherId: z.string().trim(),
  attachmentId: z.string().trim(),
  blobName: z.string().trim(),
  sizeBytes: z.number(),
});
export type BackupManifestAttachmentBlob = z.infer<typeof BackupManifestAttachmentBlobSchema>;

const sqlRows = z.array(z.record(z.string(), z.union([z.string(), z.number(), z.null()])));
const optionalSqlRows = sqlRows.nullish().transform((rows) => rows ?? []);

// The tables an instance backup carries, in restore order: each follows the tables its rows reference.
// An archived row holds every column of its table except `omit`: the personal API key and the runtime user
// key id never leave an instance, nor does Better Auth's profile image, which Bitwarden clients never set.
// Every archive carries the `required` tables.
export const BACKUP_TABLES = {
  config: { table: config, required: true },
  users: { table: users, required: true, omit: ['api_key', 'user_key_id', 'image'] },
  domain_settings: { table: domainSettings },
  user_revisions: { table: userRevisions, required: true },
  webauthn_credentials: { table: webauthnCredentials },
  folders: { table: folders, required: true },
  ciphers: { table: ciphers, required: true },
  attachments: { table: attachments, required: true },
} as const;
export type BackupTableName = keyof typeof BACKUP_TABLES;
export const BACKUP_TABLE_NAMES = Object.keys(BACKUP_TABLES) as BackupTableName[];

// Each archived column of a table with its drizzle property key, in schema order.
export function backupColumns(name: BackupTableName): Array<[string, SQLiteColumn]> {
  const spec = BACKUP_TABLES[name];
  const omit: readonly string[] = 'omit' in spec ? spec.omit : [];
  return Object.entries(getColumns(spec.table)).filter(([, column]) => !omit.includes(column.name));
}

// Restore reads only the format version and the attachment references from the manifest. The db
// shape is an explicit allowlist: z.object strips extra tables from old or modified archives,
// especially runtime authentication state.
const BackupPayloadSchema = z.object({
  manifest: z.looseObject(
    {
      formatVersion: z.literal(BACKUP_FORMAT_VERSION, { error: 'Unsupported backup format version' }),
      attachmentBlobs: z
        .array(BackupManifestAttachmentBlobSchema)
        .nullish()
        .transform((blobs) => blobs ?? []),
    },
    { error: 'Unsupported backup format version' },
  ),
  db: z.object(
    Object.fromEntries(
      BACKUP_TABLE_NAMES.map((name) => [name, 'required' in BACKUP_TABLES[name] ? sqlRows : optionalSqlRows]),
    ) as Record<BackupTableName, typeof optionalSqlRows>,
    { error: 'Backup archive database payload is invalid' },
  ),
});
export type BackupPayload = z.output<typeof BackupPayloadSchema>;

export interface BackupArchiveBundle {
  bytes: Uint8Array;
  fileName: string;
  manifest: BackupManifest;
}

export interface BackupFileIntegrityCheckResult {
  hasChecksumPrefix: boolean;
  expectedPrefix: string | null;
  actualPrefix: string;
  matches: boolean;
}

export interface BuildBackupArchiveOptions {
  includeAttachments?: boolean;
  progress?: BackupArchiveBuildProgressReporter;
  timeZone?: string;
}

export interface BackupArchiveBuildProgressEvent {
  step: string;
  fileName?: string;
  stageTitle: string;
  stageDetail: string;
  includeAttachments: boolean;
}

export type BackupArchiveBuildProgressReporter = (event: BackupArchiveBuildProgressEvent) => Promise<void>;

export function extractBackupFileChecksumPrefix(fileName: string): string | null {
  const normalized = String(fileName || '').trim();
  const match = normalized.match(/_([0-9a-f]{5})\.zip$/i);
  return match ? match[1].toLowerCase() : null;
}

export async function inspectBackupArchiveFileNameChecksum(
  bytes: Uint8Array,
  fileName: string,
): Promise<BackupFileIntegrityCheckResult> {
  const expectedPrefix = extractBackupFileChecksumPrefix(fileName);
  const actualPrefix = String(await sha256(bytes)).slice(0, BACKUP_FILE_HASH_PREFIX_LENGTH);
  return {
    hasChecksumPrefix: !!expectedPrefix,
    expectedPrefix,
    actualPrefix,
    matches: !expectedPrefix || actualPrefix === expectedPrefix,
  };
}

export async function verifyBackupArchiveFileNameChecksum(bytes: Uint8Array, fileName: string): Promise<boolean> {
  const result = await inspectBackupArchiveFileNameChecksum(bytes, fileName);
  return result.matches;
}

function isSafeBackupPathSegment(value: string): boolean {
  if (!value || value.length > MAX_BACKUP_PATH_SEGMENT_LENGTH) return false;
  if (value === '.' || value === '..') return false;
  return /^[A-Za-z0-9._-]+$/.test(value);
}

export function isSafeBackupAttachmentBlobName(value: unknown): boolean {
  const normalized = String(value ?? '').trim();
  const parts = normalized.split('/');
  return parts.length === 2 && parts.every(isSafeBackupPathSegment);
}

function validateBackupEntryName(name: string): void {
  const normalized = String(name || '').trim();
  if (normalized !== name || !normalized) {
    throw new Error('Backup archive contains an invalid file name');
  }
  if (
    normalized.includes('\\') ||
    normalized.includes('\0') ||
    normalized.startsWith('/') ||
    normalized.includes('//')
  ) {
    throw new Error(`Backup archive contains an unsafe file name: ${normalized}`);
  }
  // Besides the two metadata files, only attachments/<cipher>/<attachment>.bin with safe segments is accepted.
  const attachmentEntry =
    normalized.startsWith('attachments/') &&
    normalized.endsWith('.bin') &&
    isSafeBackupAttachmentBlobName(normalized.slice('attachments/'.length, -'.bin'.length));
  if (normalized !== 'manifest.json' && normalized !== 'db.json' && !attachmentEntry) {
    throw new Error(`Backup archive contains an unsupported file: ${normalized}`);
  }
}

function externalAttachmentPaths(
  manifest: BackupPayload['manifest'],
  allowExternalAttachmentBlobs = false,
): Set<string> {
  return new Set(
    allowExternalAttachmentBlobs
      ? manifest.attachmentBlobs.map(({ cipherId, attachmentId }) => `attachments/${cipherId}/${attachmentId}.bin`)
      : [],
  );
}

export interface ParseBackupArchiveOptions {
  allowExternalAttachmentBlobs?: boolean;
}

export function parseBackupArchive(
  bytes: Uint8Array,
  options: ParseBackupArchiveOptions = {},
): { payload: BackupPayload; files: Record<string, Uint8Array> } {
  if (bytes.byteLength > MAX_BACKUP_ARCHIVE_BYTES) {
    throw new Error(
      `Backup archive is too large. The current restore limit is ${Math.floor(MAX_BACKUP_ARCHIVE_BYTES / (1024 * 1024))} MiB`,
    );
  }
  // The filter vets each entry's name and declared size before fflate inflates it; the loop below
  // re-checks the sizes actually extracted.
  let entryCount = 0;
  let totalOriginalBytes = 0;
  let zipped: Record<string, Uint8Array>;
  try {
    zipped = unzipSync(bytes, {
      filter: (file: UnzipFileInfo): boolean => {
        entryCount += 1;
        if (entryCount > MAX_BACKUP_ARCHIVE_ENTRY_COUNT) {
          throw new Error('Backup archive contains too many files');
        }
        validateBackupEntryName(file.name);
        const originalSize = Number(file.originalSize);
        if (!Number.isFinite(originalSize) || originalSize < 0) {
          throw new Error(`Backup archive contains an invalid file size: ${file.name}`);
        }
        if (file.name === 'db.json' && originalSize > MAX_BACKUP_DB_JSON_BYTES) {
          throw new Error('Backup archive database payload is too large');
        }
        totalOriginalBytes += originalSize;
        if (totalOriginalBytes > MAX_BACKUP_EXTRACTED_BYTES) {
          throw new Error('Backup archive expands beyond the current restore limit');
        }
        return true;
      },
    });
  } catch (error) {
    if (error instanceof Error && error.message.startsWith('Backup archive ')) {
      throw error;
    }
    throw new Error('Invalid backup archive');
  }

  const entryNames = Object.keys(zipped);
  if (entryNames.length > MAX_BACKUP_ARCHIVE_ENTRY_COUNT) {
    throw new Error('Backup archive contains too many files');
  }

  let totalExtractedBytes = 0;
  for (const entry of entryNames) {
    validateBackupEntryName(entry);
    const entryBytes = zipped[entry];
    totalExtractedBytes += entryBytes.byteLength;
    if (entry === 'db.json' && entryBytes.byteLength > MAX_BACKUP_DB_JSON_BYTES) {
      throw new Error('Backup archive database payload is too large');
    }
    if (totalExtractedBytes > MAX_BACKUP_EXTRACTED_BYTES) {
      throw new Error('Backup archive expands beyond the current restore limit');
    }
  }

  const manifestBytes = zipped['manifest.json'];
  const dbBytes = zipped['db.json'];
  if (!manifestBytes || !dbBytes) {
    throw new Error('Backup archive is missing manifest.json or db.json');
  }

  const decoder = new TextDecoder();
  let rawPayload: unknown;
  try {
    rawPayload = { manifest: JSON.parse(decoder.decode(manifestBytes)), db: JSON.parse(decoder.decode(dbBytes)) };
  } catch {
    throw new Error('Backup archive contains invalid JSON metadata');
  }

  const parsed = BackupPayloadSchema.safeParse(rawPayload, {
    error: ({ path = [] }) =>
      path[0] === 'db' ? `Backup archive table ${String(path[1])} is invalid` : 'Backup archive manifest is invalid',
  });
  if (!parsed.success) throw new Error(parsed.error.issues[0].message);
  const payload = parsed.data;

  const externalAttachmentKeys = externalAttachmentPaths(payload.manifest, options.allowExternalAttachmentBlobs);
  for (const row of payload.db.attachments) {
    const cipherId = String(row.cipher_id || '').trim();
    const attachmentId = String(row.id || '').trim();
    if (!cipherId || !attachmentId) continue;
    const entry = `attachments/${cipherId}/${attachmentId}.bin`;
    if (!externalAttachmentKeys.has(entry) && !zipped[entry]) {
      throw new Error(`Backup archive is missing required file: ${entry}`);
    }
  }

  return {
    payload,
    files: zipped,
  };
}

export interface ValidateBackupPayloadOptions {
  allowExternalAttachmentBlobs?: boolean;
}

export function validateBackupPayloadContents(
  payload: BackupPayload,
  files: Record<string, Uint8Array>,
  options: ValidateBackupPayloadOptions = {},
): void {
  const {
    config: configRows,
    users: userRows,
    user_revisions: revisionRows,
    domain_settings: domainSettingsRows,
    folders: folderRows,
    ciphers: cipherRows,
    attachments: attachmentRows,
    webauthn_credentials: accountPasskeyRows,
  } = payload.db;
  const externalAttachmentKeys = externalAttachmentPaths(payload.manifest, options.allowExternalAttachmentBlobs);

  const userIds = new Set<string>();
  for (const row of userRows) {
    const id = String(row.id || '').trim();
    const email = String(row.email || '').trim();
    if (!id || !email) throw new Error('Backup archive contains an invalid user row');
    if (userIds.has(id)) throw new Error(`Backup archive contains duplicate user id: ${id}`);
    userIds.add(id);
  }

  for (const row of configRows) {
    const key = String(row.key || '').trim();
    if (!key) throw new Error('Backup archive contains an invalid config row');
  }

  for (const row of revisionRows) {
    const userId = String(row.user_id || '').trim();
    if (!userId || !userIds.has(userId)) {
      throw new Error(`Backup archive contains a revision for an unknown user: ${userId || '(empty)'}`);
    }
  }

  const domainSettingUserIds = new Set<string>();
  for (const row of domainSettingsRows) {
    const userId = String(row.user_id || '').trim();
    if (!userId || !userIds.has(userId)) {
      throw new Error(`Backup archive contains domain settings for an unknown user: ${userId || '(empty)'}`);
    }
    if (domainSettingUserIds.has(userId)) {
      throw new Error(`Backup archive contains duplicate domain settings for user: ${userId}`);
    }
    domainSettingUserIds.add(userId);
  }

  const folderIds = new Set<string>();
  for (const row of folderRows) {
    const id = String(row.id || '').trim();
    const userId = String(row.user_id || '').trim();
    if (!id || !userIds.has(userId)) throw new Error('Backup archive contains an invalid folder row');
    if (folderIds.has(id)) throw new Error(`Backup archive contains duplicate folder id: ${id}`);
    folderIds.add(id);
  }

  const cipherIds = new Set<string>();
  for (const row of cipherRows) {
    const id = String(row.id || '').trim();
    const userId = String(row.user_id || '').trim();
    const folderId = String(row.folder_id || '').trim();
    if (!id || !userIds.has(userId)) throw new Error('Backup archive contains an invalid cipher row');
    if (folderId && !folderIds.has(folderId)) {
      throw new Error(`Backup archive contains a cipher for an unknown folder: ${folderId}`);
    }
    if (cipherIds.has(id)) throw new Error(`Backup archive contains duplicate cipher id: ${id}`);
    cipherIds.add(id);
  }

  for (const row of attachmentRows) {
    const id = String(row.id || '').trim();
    const cipherId = String(row.cipher_id || '').trim();
    if (
      !id ||
      !cipherId ||
      !isSafeBackupPathSegment(id) ||
      !isSafeBackupPathSegment(cipherId) ||
      !cipherIds.has(cipherId)
    ) {
      throw new Error('Backup archive contains an invalid attachment row');
    }
    const attachmentPath = `attachments/${cipherId}/${id}.bin`;
    if (!files[attachmentPath] && !externalAttachmentKeys.has(attachmentPath)) {
      throw new Error(`Backup archive is missing required file: attachments/${cipherId}/${id}.bin`);
    }
  }

  const accountPasskeyIds = new Set<string>();
  const accountPasskeyCredentialIds = new Set<string>();
  for (const row of accountPasskeyRows) {
    const id = String(row.id || '').trim();
    const userId = String(row.user_id || '').trim();
    const purpose = row.purpose == null ? 'login' : String(row.purpose || '').trim();
    const credentialId = String(row.credential_id || '').trim();
    const publicKey = String(row.public_key || '').trim();
    if (
      !id ||
      !userIds.has(userId) ||
      !credentialId ||
      !publicKey ||
      (purpose !== 'login' && purpose !== 'twoFactor')
    ) {
      throw new Error('Backup archive contains an invalid account passkey row');
    }
    if (accountPasskeyIds.has(id)) throw new Error(`Backup archive contains duplicate account passkey id: ${id}`);
    if (accountPasskeyCredentialIds.has(credentialId))
      throw new Error(`Backup archive contains duplicate account passkey credential id: ${credentialId}`);
    accountPasskeyIds.add(id);
    accountPasskeyCredentialIds.add(credentialId);
  }
}

export async function buildBackupArchive(
  env: Env,
  date: Date = new Date(),
  options: BuildBackupArchiveOptions = {},
): Promise<BackupArchiveBundle> {
  const includeAttachments = options.includeAttachments !== false;
  await options.progress?.({
    step: 'collect_data',
    fileName: '',
    stageTitle: 'txt_backup_archive_progress_collect_title',
    stageDetail: includeAttachments
      ? 'txt_backup_archive_progress_collect_with_attachments_detail'
      : 'txt_backup_archive_progress_collect_detail',
    includeAttachments,
  });
  const encoder = new TextEncoder();
  const orm = getOrm(env.DB);
  const rows = Object.fromEntries(
    await Promise.all(
      BACKUP_TABLE_NAMES.map(async (name) => {
        // Rows keep database column names and raw stored values: every column is selected through
        // unmapped(), so no drizzle value mapping runs. Rows follow the primary key, so repeated exports
        // list them in the same order.
        const { table } = BACKUP_TABLES[name];
        const { primaryKeys, columns } = getTableConfig(table);
        const primaryKey = primaryKeys[0]?.columns ?? columns.filter((column) => column.primary);
        const selected = await orm
          .select(
            Object.fromEntries(
              backupColumns(name).map(([, column]) => [column.name, unmapped<string | number | null>(column)]),
            ),
          )
          .from(table)
          .orderBy(...primaryKey.map((column) => asc(column)));
        return [name, selected];
      }),
    ),
  ) as Record<BackupTableName, SqlRow[]>;
  // Runner locks and the Yubico bootstrap claim stay with this instance; backup settings leave only as
  // their portable envelope.
  const exportedConfigRows = rows.config.flatMap((row): SqlRow[] => {
    const key = String(row.key || '').trim();
    if (!key || key === BACKUP_RUNNER_LOCK_CONFIG_KEY || key === YUBICO_BOOTSTRAP_CLAIM_CONFIG_KEY) return [];
    if (key === BACKUP_SETTINGS_CONFIG_KEY) {
      const portableOnly = exportPortableBackupSettingsEnvelope(typeof row.value === 'string' ? row.value : null);
      return portableOnly ? [{ ...row, value: portableOnly }] : [];
    }
    return [{ ...row }];
  });
  const exportedAttachmentRows = includeAttachments ? rows.attachments : [];
  const attachmentBlobs: BackupManifestAttachmentBlob[] = exportedAttachmentRows.map((row) => {
    const cipherId = String(row.cipher_id || '').trim();
    const attachmentId = String(row.id || '').trim();
    return {
      cipherId,
      attachmentId,
      blobName: getAttachmentObjectKey(cipherId, attachmentId),
      sizeBytes: Number(row.size || 0) || 0,
    };
  });

  const exported: Record<BackupTableName, SqlRow[]> = {
    ...rows,
    config: exportedConfigRows,
    attachments: exportedAttachmentRows,
  };
  const manifestBase = {
    formatVersion: BACKUP_FORMAT_VERSION,
    exportedAt: date.toISOString(),
    appVersion: APP_VERSION,
    storageKind: getBlobStorageKind(env),
    tableCounts: Object.fromEntries(BACKUP_TABLE_NAMES.map((name) => [name, exported[name].length])),
    includes: {
      attachments: includeAttachments,
    },
    blobSummary: {
      attachmentFiles: attachmentBlobs.length,
      totalBytes: attachmentBlobs.reduce((sum, item) => sum + item.sizeBytes, 0),
      largestObjectBytes: attachmentBlobs.reduce((max, item) => Math.max(max, item.sizeBytes), 0),
    },
    attachmentBlobs: includeAttachments ? attachmentBlobs : [],
  } satisfies BackupManifest;

  const files: Record<string, Uint8Array> = {
    'manifest.json': encoder.encode(JSON.stringify(manifestBase, null, BACKUP_JSON_INDENT)),
    'db.json': encoder.encode(JSON.stringify(exported, null, BACKUP_JSON_INDENT)),
  };

  await options.progress?.({
    step: 'package_archive',
    fileName: '',
    stageTitle: 'txt_backup_archive_progress_package_title',
    stageDetail: includeAttachments
      ? 'txt_backup_archive_progress_package_with_attachments_detail'
      : 'txt_backup_archive_progress_package_detail',
    includeAttachments,
  });
  const bytes = zipSync(
    Object.fromEntries(
      Object.entries(files).map(([path, content]): [string, [Uint8Array, { level: 0 | 1 | 6 }]] => [
        path,
        [content, { level: BACKUP_TEXT_COMPRESSION_LEVEL }],
      ]),
    ),
  );
  const fileHashPrefix = String(await sha256(bytes)).slice(0, BACKUP_FILE_HASH_PREFIX_LENGTH);
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: options.timeZone || 'UTC',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23',
  }).formatToParts(date);
  const pick = (type: string): string => parts.find((part) => part.type === type)?.value || '';
  const fileName = `nodewarden_backup_${pick('year')}${pick('month')}${pick('day')}_${pick('hour')}${pick('minute')}${pick('second')}_${fileHashPrefix}.zip`;
  await options.progress?.({
    step: 'archive_ready',
    fileName,
    stageTitle: 'txt_backup_archive_progress_ready_title',
    stageDetail: 'txt_backup_archive_progress_ready_detail',
    includeAttachments,
  });

  return {
    bytes,
    fileName,
    manifest: manifestBase,
  };
}
