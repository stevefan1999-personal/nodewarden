import { zipSync, unzipSync, type UnzipFileInfo } from 'fflate';
import { sha256 } from 'hono/utils/crypto';
import { z } from 'zod';
import { asc, getColumns } from 'drizzle-orm';
import { getTableConfig, type SQLiteColumn } from 'drizzle-orm/sqlite-core';

import { getOrm } from '../db/client';
import {
  attachments,
  cipherCollections,
  ciphers,
  collectionGroups,
  collectionUsers,
  collections,
  config,
  domainSettings,
  emergencyAccess,
  events,
  folders,
  invites,
  orgGroupMembers,
  orgGroups,
  orgPolicies,
  organizationApiKeys,
  organizationMemberships,
  organizationScimTokens,
  organizations,
  pendingCollectionUsers,
  sends,
  smAccessTokens,
  smProjectGroups,
  smProjectMembers,
  smProjects,
  smSecretGroups,
  smSecretMembers,
  smSecretProjects,
  smSecretServiceAccounts,
  smSecrets,
  smServiceAccountGroups,
  smServiceAccountMembers,
  smServiceAccountProjects,
  smServiceAccounts,
  ssoUsers,
  userRevisions,
  users,
  webauthnCredentials,
} from '../db/schema';
import { unmapped } from '../db/sql';
import { SendType, type Env } from '../types';
import { APP_VERSION } from '../../shared/app-version';
import { BACKUP_STATUS_CONFIG_KEY, RETIRED_BACKUP_CONFIG_KEYS } from './backup-config';
import { YUBICO_BOOTSTRAP_CLAIM_CONFIG_KEY } from './yubico-config';
import { getAttachmentObjectKey, getBlobObject, getBlobStorageKind, getSendFileObjectKey } from './blob-store';
import { jsonText } from './org-types';

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
// - Config rows in INSTANCE_LOCAL_CONFIG_KEYS never leave the instance, and
//   restore never writes them.
type SqlRow = Record<string, string | number | null>;

// Format 2 added organizations, Sends, Secrets Manager, emergency access and event history.
const BACKUP_FORMAT_VERSION = 2;
// Config rows that stay with their instance: the Yubico bootstrap claim, the backup status and the rows of the
// WebDAV-era backup destinations.
export const INSTANCE_LOCAL_CONFIG_KEYS: ReadonlySet<string> = new Set([
  YUBICO_BOOTSTRAP_CLAIM_CONFIG_KEY,
  BACKUP_STATUS_CONFIG_KEY,
  ...RETIRED_BACKUP_CONFIG_KEYS,
]);
const BACKUP_FILE_HASH_PREFIX_LENGTH = 5;
// Worker-side backup export must stay well below Cloudflare CPU limits.
// Prefer store-only ZIP entries over heavier compression to keep exports reliable.
const BACKUP_TEXT_COMPRESSION_LEVEL = 0;
const BACKUP_JSON_INDENT = 2;
const BYTES_PER_MIB = 1024 * 1024;
export const MAX_BACKUP_ARCHIVE_BYTES = 64 * BYTES_PER_MIB;
const MAX_BACKUP_ARCHIVE_ENTRY_COUNT = 10_000;
const MAX_BACKUP_EXTRACTED_BYTES = 64 * BYTES_PER_MIB;
const MAX_BACKUP_DB_JSON_BYTES = 32 * BYTES_PER_MIB;
const MAX_BACKUP_PATH_SEGMENT_LENGTH = 128;

export interface BackupManifest {
  formatVersion: typeof BACKUP_FORMAT_VERSION;
  exportedAt: string;
  appVersion: string;
  storageKind: 'r2' | 'kv' | null;
  tableCounts: Record<string, number>;
  includes: {
    attachments: boolean;
  };
  blobSummary: {
    attachmentFiles: number;
    sendFiles: number;
    totalBytes: number;
    largestObjectBytes: number;
  };
  attachmentBlobs?: BackupManifestAttachmentBlob[];
  sendFileBlobs?: BackupManifestSendFileBlob[];
}

const BackupManifestAttachmentBlobSchema = z.object({
  cipherId: z.string().trim(),
  attachmentId: z.string().trim(),
  blobName: z.string().trim(),
  sizeBytes: z.number(),
});
export type BackupManifestAttachmentBlob = z.infer<typeof BackupManifestAttachmentBlobSchema>;

const BackupManifestSendFileBlobSchema = z.object({
  sendId: z.string().trim(),
  fileId: z.string().trim(),
  blobName: z.string().trim(),
  sizeBytes: z.number(),
});
type BackupManifestSendFileBlob = z.infer<typeof BackupManifestSendFileBlobSchema>;

const sqlRows = z.array(z.record(z.string(), z.union([z.string(), z.number(), z.null()])));
const optionalSqlRows = sqlRows.nullish().transform((rows) => rows ?? []);

// The tables an instance backup carries, in restore order: each follows the tables its rows reference.
// Everything else stays with the instance: runtime authentication state (sessions, devices, auth requests,
// remembered two-step devices, one-time tokens and challenges, rate limits), Better Auth's copy of the
// master password hash, which the next password change rebuilds, and the administrator audit log, which a
// restore must not rewrite. backup-archive.test.ts fails until a new schema table is on one side.
// An archived row holds every column of its table except `omit`: the personal API key and the runtime user
// key id never leave an instance, nor does Better Auth's profile image, which Bitwarden clients never set.
// Stored credentials (organization API keys, SCIM tokens, machine access tokens) are hashes, so they travel.
// Every archive carries the `required` tables; older ones lack the rest.
export const BACKUP_TABLES = {
  config: { table: config, required: true },
  users: { table: users, required: true, omit: ['api_key', 'user_key_id', 'image'] },
  domain_settings: { table: domainSettings },
  user_revisions: { table: userRevisions, required: true },
  webauthn_credentials: { table: webauthnCredentials },
  folders: { table: folders, required: true },
  invites: { table: invites },
  sso_users: { table: ssoUsers },
  emergency_access: { table: emergencyAccess },
  sends: { table: sends },
  organizations: { table: organizations },
  organization_memberships: { table: organizationMemberships },
  organization_api_keys: { table: organizationApiKeys },
  organization_scim_tokens: { table: organizationScimTokens },
  org_policies: { table: orgPolicies },
  org_groups: { table: orgGroups },
  org_group_members: { table: orgGroupMembers },
  collections: { table: collections },
  collection_users: { table: collectionUsers },
  pending_collection_users: { table: pendingCollectionUsers },
  collection_groups: { table: collectionGroups },
  ciphers: { table: ciphers, required: true },
  attachments: { table: attachments, required: true },
  cipher_collections: { table: cipherCollections },
  sm_projects: { table: smProjects },
  sm_secrets: { table: smSecrets },
  sm_secret_projects: { table: smSecretProjects },
  sm_service_accounts: { table: smServiceAccounts },
  sm_service_account_projects: { table: smServiceAccountProjects },
  sm_access_tokens: { table: smAccessTokens },
  sm_project_members: { table: smProjectMembers },
  sm_project_groups: { table: smProjectGroups },
  sm_secret_members: { table: smSecretMembers },
  sm_secret_groups: { table: smSecretGroups },
  sm_secret_service_accounts: { table: smSecretServiceAccounts },
  sm_service_account_members: { table: smServiceAccountMembers },
  sm_service_account_groups: { table: smServiceAccountGroups },
  events: { table: events },
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
      formatVersion: z.literal([1, BACKUP_FORMAT_VERSION], { error: 'Unsupported backup format version' }),
      attachmentBlobs: z
        .array(BackupManifestAttachmentBlobSchema)
        .nullish()
        .transform((blobs) => blobs ?? []),
      sendFileBlobs: z
        .array(BackupManifestSendFileBlobSchema)
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

// A blob storage key an archive may carry: <cipher>/<attachment> for an attachment, sends/<send>/<file> for
// a file Send's file.
export function isSafeBackupBlobName(value: unknown): boolean {
  const parts = String(value ?? '')
    .trim()
    .split('/');
  const segments = parts.length === 3 && parts[0] === 'sends' ? parts.slice(1) : parts;
  return segments.length === 2 && segments.every(isSafeBackupPathSegment);
}

// A file an archived row owns: an attachment's, or a file Send's. The archive carries it inline as
// attachments/<key>.bin, or a remote destination keeps it as attachments/<key>, where key is its blob
// storage key.
export type ArchivedFile = { table: 'attachments' | 'sends'; row: SqlRow; key: string; sizeBytes: number };

// The file a file Send's data names. A Send whose data names none owns no file.
const SendFile = jsonText.pipe(z.object({ id: z.string(), size: z.coerce.number().catch(0) }).nullable()).catch(null);

export function archivedFiles(db: Pick<BackupPayload['db'], 'attachments' | 'sends'>): ArchivedFile[] {
  return [
    ...db.attachments.map((row) => ({
      table: 'attachments' as const,
      row,
      key: getAttachmentObjectKey(String(row.cipher_id || '').trim(), String(row.id || '').trim()),
      sizeBytes: Number(row.size || 0) || 0,
    })),
    ...db.sends.flatMap((row) => {
      const file = Number(row.type) === SendType.File ? SendFile.parse(row.data) : null;
      return file
        ? [
            {
              table: 'sends' as const,
              row,
              key: getSendFileObjectKey(String(row.id || '').trim(), file.id),
              sizeBytes: file.size,
            },
          ]
        : [];
    }),
  ];
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
  // Besides the two metadata files, only attachments/<blob storage key>.bin with safe segments is accepted.
  const attachmentEntry =
    normalized.startsWith('attachments/') &&
    normalized.endsWith('.bin') &&
    isSafeBackupBlobName(normalized.slice('attachments/'.length, -'.bin'.length));
  if (normalized !== 'manifest.json' && normalized !== 'db.json' && !attachmentEntry) {
    throw new Error(`Backup archive contains an unsupported file: ${normalized}`);
  }
}

export function parseBackupArchive(bytes: Uint8Array): { payload: BackupPayload; files: Record<string, Uint8Array> } {
  if (bytes.byteLength > MAX_BACKUP_ARCHIVE_BYTES) {
    throw new Error(
      `Backup archive is too large. The current restore limit is ${MAX_BACKUP_ARCHIVE_BYTES / BYTES_PER_MIB} MiB`,
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

  // A file with an unsafe key is reported by validateBackupPayloadContents() as an invalid row.
  for (const { key } of archivedFiles(payload.db)) {
    const entry = `attachments/${key}.bin`;
    if (isSafeBackupBlobName(key) && !zipped[entry]) {
      throw new Error(`Backup archive is missing required file: ${entry}`);
    }
  }

  return {
    payload,
    files: zipped,
  };
}

export function validateBackupPayloadContents(payload: BackupPayload, files: Record<string, Uint8Array>): void {
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
    if (!files[`attachments/${cipherId}/${id}.bin`]) {
      throw new Error(`Backup archive is missing required file: attachments/${cipherId}/${id}.bin`);
    }
  }

  // A file Send's file travels like an attachment's.
  for (const { table, key } of archivedFiles(payload.db)) {
    if (table !== 'sends') continue;
    if (!isSafeBackupBlobName(key)) throw new Error('Backup archive contains an invalid Send file');
    if (!files[`attachments/${key}.bin`]) {
      throw new Error(`Backup archive is missing required file: attachments/${key}.bin`);
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
  const selects = BACKUP_TABLE_NAMES.map((name) => {
    // Rows keep database column names and raw stored values: every column is selected through unmapped(),
    // so no drizzle value mapping runs. Rows follow the primary key, so repeated exports list them in the
    // same order.
    const { table } = BACKUP_TABLES[name];
    const { primaryKeys, columns } = getTableConfig(table);
    const primaryKey = primaryKeys[0]?.columns ?? columns.filter((column) => column.primary);
    return orm
      .select(
        Object.fromEntries(
          backupColumns(name).map(([, column]) => [column.name, unmapped<string | number | null>(column)]),
        ),
      )
      .from(table)
      .orderBy(...primaryKey.map((column) => asc(column)));
  });
  // One batch reads every table inside a single D1 transaction. Separate reads would let a write land
  // between them and export a row whose parent the archive lacks, which restore then rejects.
  const results = await orm.batch(selects as [(typeof selects)[0], ...typeof selects]);
  const rows = Object.fromEntries(BACKUP_TABLE_NAMES.map((name, index) => [name, results[index]])) as Record<
    BackupTableName,
    SqlRow[]
  >;
  const exportedConfigRows = rows.config.filter((row) => {
    const key = String(row.key || '').trim();
    return key && !INSTANCE_LOCAL_CONFIG_KEYS.has(key);
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

  // Without attachments an archive carries no files, and a file Send is useless without its file.
  const exportedSendRows = includeAttachments
    ? rows.sends
    : rows.sends.filter((row) => Number(row.type) !== SendType.File);
  const sendFileBlobs: BackupManifestSendFileBlob[] = archivedFiles({ attachments: [], sends: exportedSendRows }).map(
    ({ row, key, sizeBytes }) => ({
      sendId: String(row.id || '').trim(),
      fileId: key.split('/')[2],
      blobName: key,
      sizeBytes,
    }),
  );
  const fileSizes = [...attachmentBlobs, ...sendFileBlobs].map((blob) => blob.sizeBytes);

  const exported: Record<BackupTableName, SqlRow[]> = {
    ...rows,
    config: exportedConfigRows,
    sends: exportedSendRows,
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
      sendFiles: sendFileBlobs.length,
      totalBytes: fileSizes.reduce((sum, size) => sum + size, 0),
      largestObjectBytes: Math.max(0, ...fileSizes),
    },
    attachmentBlobs: includeAttachments ? attachmentBlobs : [],
    sendFileBlobs,
  } satisfies BackupManifest;

  const dbJson = encoder.encode(JSON.stringify(exported, null, BACKUP_JSON_INDENT));
  // Restore refuses a larger payload, so such an archive could never come back.
  if (dbJson.byteLength > MAX_BACKUP_DB_JSON_BYTES) {
    throw new Error(
      `Backup database payload is ${Math.round(dbJson.byteLength / BYTES_PER_MIB)} MiB; restore accepts at most ${MAX_BACKUP_DB_JSON_BYTES / BYTES_PER_MIB} MiB`,
    );
  }
  // Every archived file travels inline, so the archive restores on its own.
  const fileEntries = await Promise.all(
    archivedFiles(exported).map(async ({ key }) => {
      const object = await getBlobObject(env, key);
      if (!object?.body) throw new Error(`Backup blob missing for ${key}`);
      return [`attachments/${key}.bin`, new Uint8Array(await new Response(object.body).arrayBuffer())] as const;
    }),
  );
  const files: Record<string, Uint8Array> = {
    'manifest.json': encoder.encode(JSON.stringify(manifestBase, null, BACKUP_JSON_INDENT)),
    'db.json': dbJson,
    ...Object.fromEntries(fileEntries),
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
