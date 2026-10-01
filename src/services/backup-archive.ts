import { Zip, ZipPassThrough } from 'fflate';
import { z } from 'zod';
import { asc, getColumns, gt } from 'drizzle-orm';
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
import { MAX_ZIP32_ENTRIES, R2PartWriter } from './backup-zip';
import { jsonText } from './org-types';

// CONTRACT:
// This file defines the instance-backup archive: a store-only zip holding manifest.json, the database as
// db/NNNN.json slices ({ table: rows[] }, tables in restore order, each slice a few MiB), and every attachment and
// Send file inline as attachments/<blob storage key>.bin. Restore reads format 1 and 2 archives too, whose whole
// database is one db.json.
//
// WHEN CHANGING THIS:
// - Add persistent tables to BACKUP_TABLES, in restore order: export, restore,
//   manifest tableCounts and the db allowlist all follow it. Put cross-row rules
//   the database cannot check in BackupRowValidator.
// - Keep secrets and transient runtime rows sanitized before writing a slice.
// - Runtime authentication state (devices, sessions, auth requests, remembered
//   2FA devices, and one-time tokens) must never enter an instance backup.
// - users.api_key is intentionally not exported.
// - Config rows in INSTANCE_LOCAL_CONFIG_KEYS never leave the instance, and
//   restore never writes them.
export type SqlRow = Record<string, string | number | null>;

// Format 3 slices the database; format 2 added organizations, Sends, Secrets Manager, emergency access and event
// history.
export const BACKUP_FORMAT_VERSION = 3;
// Config rows that stay with their instance: the Yubico bootstrap claim, the backup status and the rows of the
// WebDAV-era backup destinations.
export const INSTANCE_LOCAL_CONFIG_KEYS: ReadonlySet<string> = new Set([
  YUBICO_BOOTSTRAP_CLAIM_CONFIG_KEY,
  BACKUP_STATUS_CONFIG_KEY,
  ...RETIRED_BACKUP_CONFIG_KEYS,
]);
const BYTES_PER_MIB = 1024 * 1024;
// Restore parses one database entry at a time; each has to fit the isolate's memory with room to spare.
export const MAX_DB_ENTRY_BYTES = 32 * BYTES_PER_MIB;
const DB_SLICE_TARGET_BYTES = 4 * BYTES_PER_MIB;
export const MAX_MANIFEST_BYTES = BYTES_PER_MIB;
// An end record whose entry count reads 0xFFFF belongs to a ZIP64 archive.
export const MAX_ARCHIVE_ENTRIES = MAX_ZIP32_ENTRIES - 1;
export const DB_SLICE_ENTRY = /^db\/(\d{4,})\.json$/;
const EVENT_PAGE_ROWS = 1000;
const MAX_BACKUP_PATH_SEGMENT_LENGTH = 128;
const ARCHIVE_KEY_SUFFIX_BYTES = 3;
const BACKUP_JSON_INDENT = 2;

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
    // Files whose blob was already gone: their rows travel, and restore leaves them out.
    missingFiles: number;
  };
}

const sqlRows = z.array(z.record(z.string(), z.union([z.string(), z.number(), z.null()])));

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

// Restore reads only the format version and the table counts from the manifest.
const BackupManifestSchema = z.looseObject(
  {
    formatVersion: z.literal([1, 2, BACKUP_FORMAT_VERSION], { error: 'Unsupported backup format version' }),
    tableCounts: z
      .record(z.string(), z.number())
      .nullish()
      .transform((counts) => counts ?? {}),
  },
  { error: 'Unsupported backup format version' },
);
export type ParsedBackupManifest = z.output<typeof BackupManifestSchema>;

function parseArchiveJson(bytes: Uint8Array): unknown {
  try {
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new Error('Backup archive contains invalid JSON metadata');
  }
}

export function parseBackupManifest(bytes: Uint8Array): ParsedBackupManifest {
  const parsed = BackupManifestSchema.safeParse(parseArchiveJson(bytes), {
    error: () => 'Backup archive manifest is invalid',
  });
  if (!parsed.success) throw new Error(parsed.error.issues[0].message);
  return parsed.data;
}

// A database entry is an explicit allowlist: z.object strips tables outside BACKUP_TABLES from old or modified
// archives, especially runtime authentication state. A format 1 or 2 db.json must hold the required tables; a slice
// holds whichever tables it reaches, and the manifest's counts check that none is missing.
export function parseDbEntry(bytes: Uint8Array, wholeDatabase: boolean): Partial<Record<BackupTableName, SqlRow[]>> {
  const parsed = z
    .object(
      Object.fromEntries(
        BACKUP_TABLE_NAMES.map((name) => [
          name,
          wholeDatabase && 'required' in BACKUP_TABLES[name] ? sqlRows : sqlRows.optional(),
        ]),
      ) as Record<BackupTableName, z.ZodOptional<typeof sqlRows>>,
      { error: 'Backup archive database payload is invalid' },
    )
    .safeParse(parseArchiveJson(bytes), {
      error: ({ path = [] }) =>
        path.length
          ? `Backup archive table ${String(path[0])} is invalid`
          : 'Backup archive database payload is invalid',
    });
  if (!parsed.success) throw new Error(parsed.error.issues[0].message);
  return parsed.data;
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

export function archivedFiles(db: { attachments: SqlRow[]; sends: SqlRow[] }): ArchivedFile[] {
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

export function validateBackupEntryName(name: string): void {
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
  // Besides the manifest, the database (db.json, or db/NNNN.json slices) and attachments/<blob storage key>.bin
  // with safe segments, nothing is accepted.
  const attachmentEntry =
    normalized.startsWith('attachments/') &&
    normalized.endsWith('.bin') &&
    isSafeBackupBlobName(normalized.slice('attachments/'.length, -'.bin'.length));
  if (
    normalized !== 'manifest.json' &&
    normalized !== 'db.json' &&
    !DB_SLICE_ENTRY.test(normalized) &&
    !attachmentEntry
  ) {
    throw new Error(`Backup archive contains an unsupported file: ${normalized}`);
  }
}

// The checks the database cannot make, over rows that arrive table by table in restore order, so every parent is
// seen before its children. Only ids are kept.
export class BackupRowValidator {
  private readonly userIds = new Set<string>();
  private readonly domainSettingUserIds = new Set<string>();
  private readonly folderIds = new Set<string>();
  private readonly cipherIds = new Set<string>();
  private readonly passkeyIds = new Set<string>();
  private readonly passkeyCredentialIds = new Set<string>();

  check(table: BackupTableName, rows: SqlRow[]): void {
    const text = (row: SqlRow, column: string) => String(row[column] || '').trim();
    for (const row of rows) {
      if (table === 'users') {
        const id = text(row, 'id');
        if (!id || !text(row, 'email')) throw new Error('Backup archive contains an invalid user row');
        if (this.userIds.has(id)) throw new Error(`Backup archive contains duplicate user id: ${id}`);
        this.userIds.add(id);
      } else if (table === 'config') {
        if (!text(row, 'key')) throw new Error('Backup archive contains an invalid config row');
      } else if (table === 'user_revisions') {
        const userId = text(row, 'user_id');
        if (!this.userIds.has(userId))
          throw new Error(`Backup archive contains a revision for an unknown user: ${userId || '(empty)'}`);
      } else if (table === 'domain_settings') {
        const userId = text(row, 'user_id');
        if (!this.userIds.has(userId))
          throw new Error(`Backup archive contains domain settings for an unknown user: ${userId || '(empty)'}`);
        if (this.domainSettingUserIds.has(userId))
          throw new Error(`Backup archive contains duplicate domain settings for user: ${userId}`);
        this.domainSettingUserIds.add(userId);
      } else if (table === 'folders') {
        const id = text(row, 'id');
        if (!id || !this.userIds.has(text(row, 'user_id')))
          throw new Error('Backup archive contains an invalid folder row');
        if (this.folderIds.has(id)) throw new Error(`Backup archive contains duplicate folder id: ${id}`);
        this.folderIds.add(id);
      } else if (table === 'ciphers') {
        const id = text(row, 'id');
        const folderId = text(row, 'folder_id');
        if (!id || !this.userIds.has(text(row, 'user_id')))
          throw new Error('Backup archive contains an invalid cipher row');
        if (folderId && !this.folderIds.has(folderId))
          throw new Error(`Backup archive contains a cipher for an unknown folder: ${folderId}`);
        if (this.cipherIds.has(id)) throw new Error(`Backup archive contains duplicate cipher id: ${id}`);
        this.cipherIds.add(id);
      } else if (table === 'attachments') {
        const cipherId = text(row, 'cipher_id');
        if (
          !isSafeBackupPathSegment(text(row, 'id')) ||
          !isSafeBackupPathSegment(cipherId) ||
          !this.cipherIds.has(cipherId)
        )
          throw new Error('Backup archive contains an invalid attachment row');
      } else if (table === 'sends') {
        // A file Send's file travels like an attachment's.
        for (const { key } of archivedFiles({ attachments: [], sends: [row] }))
          if (!isSafeBackupBlobName(key)) throw new Error('Backup archive contains an invalid Send file');
      } else if (table === 'webauthn_credentials') {
        const id = text(row, 'id');
        const purpose = row.purpose == null ? 'login' : text(row, 'purpose');
        const credentialId = text(row, 'credential_id');
        if (
          !id ||
          !this.userIds.has(text(row, 'user_id')) ||
          !credentialId ||
          !text(row, 'public_key') ||
          (purpose !== 'login' && purpose !== 'twoFactor')
        )
          throw new Error('Backup archive contains an invalid account passkey row');
        if (this.passkeyIds.has(id)) throw new Error(`Backup archive contains duplicate account passkey id: ${id}`);
        if (this.passkeyCredentialIds.has(credentialId))
          throw new Error(`Backup archive contains duplicate account passkey credential id: ${credentialId}`);
        this.passkeyIds.add(id);
        this.passkeyCredentialIds.add(credentialId);
      }
    }
  }
}

// cloudwarden_backup_<local date>_<local time>_<random>.zip, in the schedule's timezone.
export function backupArchiveKey(date: Date, timeZone: string): string {
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23',
  }).formatToParts(date);
  const pick = (type: string): string => parts.find((part) => part.type === type)?.value || '';
  const suffix = crypto.getRandomValues(new Uint8Array(ARCHIVE_KEY_SUFFIX_BYTES)).toHex().slice(0, 5);
  return `cloudwarden_backup_${pick('year')}${pick('month')}${pick('day')}_${pick('hour')}${pick('minute')}${pick('second')}_${suffix}.zip`;
}

// Streams an archive of the instance into bucket under key. Every table but events is read in one D1 batch, a
// consistent snapshot, so no row can point at a parent the archive lacks. Events follow a page at a time: they
// are append-only history, and a page keeps only events whose organization is in the snapshot. The snapshot's rows
// stay in memory while files stream through a part at a time. ponytail: one R2 read per file, so an archive
// holds a few thousand files within the invocation's 10,000-subrequest budget; raise limits.subrequests for more.
export async function writeBackupArchive(
  env: Env,
  bucket: R2Bucket,
  key: string,
  date: Date,
  includeAttachments: boolean,
): Promise<{ object: R2Object; manifest: BackupManifest }> {
  const orm = getOrm(env.DB);
  const snapshotTables = BACKUP_TABLE_NAMES.filter((name) => name !== 'events');
  const columnsOf = (name: BackupTableName) =>
    Object.fromEntries(
      backupColumns(name).map(([, column]) => [column.name, unmapped<string | number | null>(column)]),
    );
  const selects = snapshotTables.map((name) => {
    // Rows keep database column names and raw stored values, in primary key order, so repeated exports list
    // them the same way.
    const { table } = BACKUP_TABLES[name];
    const { primaryKeys, columns } = getTableConfig(table);
    const primaryKey = primaryKeys[0]?.columns ?? columns.filter((column) => column.primary);
    return orm
      .select(columnsOf(name))
      .from(table)
      .orderBy(...primaryKey.map((column) => asc(column)));
  });
  const results = await orm.batch(selects as [(typeof selects)[0], ...typeof selects]);
  const rows = Object.fromEntries(snapshotTables.map((name, index) => [name, results[index]])) as Record<
    BackupTableName,
    SqlRow[]
  >;
  // Without attachments an archive carries no files, and a file Send is useless without its file.
  const exported: Record<BackupTableName, SqlRow[]> = {
    ...rows,
    config: rows.config.filter((row) => {
      const configKey = String(row.key || '').trim();
      return configKey && !INSTANCE_LOCAL_CONFIG_KEYS.has(configKey);
    }),
    attachments: includeAttachments ? rows.attachments : [],
    sends: includeAttachments ? rows.sends : rows.sends.filter((row) => Number(row.type) !== SendType.File),
  };
  const organizationIds = new Set(exported.organizations.map((row) => String(row.id)));

  const writer = await R2PartWriter.open(bucket, key, 'application/zip');
  // fflate hands its output over synchronously as entries are pushed; each push is followed by uploading the parts
  // it completed.
  const zip = new Zip((error, chunk) => {
    if (error) throw error;
    writer.write(chunk);
  });
  let entries = 0;
  const addEntry = async (name: string, chunks: AsyncIterable<Uint8Array> | Iterable<Uint8Array>) => {
    if (++entries > MAX_ARCHIVE_ENTRIES)
      throw new Error(`Backup archive would hold more than ${MAX_ARCHIVE_ENTRIES} entries`);
    const entry = new ZipPassThrough(name);
    zip.add(entry);
    for await (const chunk of chunks) {
      entry.push(chunk);
      await writer.flush();
    }
    entry.push(new Uint8Array(0), true);
    await writer.flush();
  };
  // Rows are serialized once, into slices of about DB_SLICE_TARGET_BYTES.
  const encoder = new TextEncoder();
  let slice = new Map<BackupTableName, string[]>();
  let sliceBytes = 0;
  let slices = 0;
  const flushSlice = async () => {
    if (!slice.size) return;
    const body = `{${[...slice].map(([name, json]) => `${JSON.stringify(name)}:[${json.join(',')}]`).join(',')}}`;
    slice = new Map();
    sliceBytes = 0;
    await addEntry(`db/${String(++slices).padStart(4, '0')}.json`, [encoder.encode(body)]);
  };
  const addRows = async (name: BackupTableName, tableRows: SqlRow[]) => {
    for (const row of tableRows) {
      const json = JSON.stringify(row);
      if (json.length > MAX_DB_ENTRY_BYTES)
        throw new Error(
          `Backup table ${name} holds a row of ${Math.round(json.length / BYTES_PER_MIB)} MiB; restore accepts at most ${MAX_DB_ENTRY_BYTES / BYTES_PER_MIB} MiB`,
        );
      if (sliceBytes && sliceBytes + json.length > DB_SLICE_TARGET_BYTES) await flushSlice();
      // Appended in place: a slice holds thousands of rows, and copying the list per row would be quadratic.
      const tableRows = slice.get(name);
      if (tableRows) tableRows.push(json);
      else slice.set(name, [json]);
      sliceBytes += json.length;
    }
  };

  try {
    for (const name of snapshotTables) await addRows(name, exported[name]);
    // Events are only counted as their pages go by; none stays in memory past its page.
    let eventRows = 0;
    for (let after: string | null = ''; after !== null;) {
      const page: SqlRow[] = await orm
        .select(columnsOf('events'))
        .from(events)
        .where(gt(events.id, after))
        .orderBy(asc(events.id))
        .limit(EVENT_PAGE_ROWS);
      const kept = page.filter(
        (row) => row.organization_id === null || organizationIds.has(String(row.organization_id)),
      );
      eventRows += kept.length;
      await addRows('events', kept);
      after = page.length === EVENT_PAGE_ROWS ? String(page.at(-1)!.id) : null;
    }
    await flushSlice();

    const files = archivedFiles(exported);
    let missingFiles = 0;
    let totalBytes = 0;
    for (const file of files) {
      const object = await getBlobObject(env, file.key);
      if (!object?.body) {
        missingFiles++;
        continue;
      }
      await addEntry(`attachments/${file.key}.bin`, object.body);
      totalBytes += object.size;
    }
    const manifest: BackupManifest = {
      formatVersion: BACKUP_FORMAT_VERSION,
      exportedAt: date.toISOString(),
      appVersion: APP_VERSION,
      storageKind: getBlobStorageKind(env),
      tableCounts: Object.fromEntries(
        BACKUP_TABLE_NAMES.map((name) => [name, name === 'events' ? eventRows : exported[name].length]),
      ),
      includes: { attachments: includeAttachments },
      blobSummary: {
        attachmentFiles: files.filter((file) => file.table === 'attachments').length,
        sendFiles: files.filter((file) => file.table === 'sends').length,
        totalBytes,
        missingFiles,
      },
    };
    await addEntry('manifest.json', [encoder.encode(JSON.stringify(manifest, null, BACKUP_JSON_INDENT))]);
    zip.end();
    return { object: await writer.close(), manifest };
  } catch (error) {
    // The run fails either way; an upload left open is aborted by R2 after seven days.
    await writer.abort().catch(() => undefined);
    throw error;
  }
}
