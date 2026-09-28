import { syncVaultAdminRoles } from './vault-admin-role';
import { and, count, eq, getTableName, TableAliasProxyHandler } from 'drizzle-orm';
import type { SQLiteTable } from 'drizzle-orm/sqlite-core';

import { chunkRows, columnCount, getOrm } from '../db/client';
import { sqliteMaster } from '../db/migrate';
import { attachments, ciphers, folders, organizations, sends } from '../db/schema';
import type { Env, User } from '../types';
import { KV_MAX_OBJECT_BYTES, deleteBlobObject, getBlobStorageKind, putBlobObject } from './blob-store';
import { BACKUP_SETTINGS_CONFIG_KEY, normalizeImportedBackupSettingsValue } from './backup-config';
import { YUBICO_BOOTSTRAP_CLAIM_CONFIG_KEY } from './yubico-config';
import {
  BACKUP_TABLE_NAMES,
  BACKUP_TABLES,
  archivedFiles,
  backupColumns,
  externalFiles,
  type ArchivedFile,
  type BackupPayload,
  type BackupTableName,
  parseBackupArchive,
  validateBackupPayloadContents,
} from './backup-archive';

// CONTRACT:
// Restore is intentionally whitelist-based. Old backups may contain retired
// fields, but only the tables and columns BACKUP_TABLES (backup-archive.ts)
// archives are imported.
//
// WHEN CHANGING THIS:
// - Give rows from older archives a value for every column a table gains in
//   the prepared payload, as users, passkeys and ciphers do.
// - Do not import users.api_key, even if an older backup contains it.
// - Do not import, clear, or replace runtime authentication state such as
//   devices, sessions, auth requests, or remembered 2FA device tokens.
type SqlRow = Record<string, string | number | null>;

function shadowTableName(table: string): string {
  return `${table}__restore`;
}

// A shadow copy has its live table's columns under the __restore name. Drizzle's alias proxy with
// replaceOriginalName renders that name in every position (FROM, INSERT INTO, DELETE FROM, column
// references), so the query builder addresses the copy although it has no schema entry of its own.
function shadowTable<T extends SQLiteTable>(table: T): T {
  return new Proxy(table, new TableAliasProxyHandler(shadowTableName(getTableName(table)), true));
}

export interface BackupImportResultBody {
  object: 'instance-backup-import';
  imported: {
    config: number;
    users: number;
    domainSettings: number;
    userRevisions: number;
    webauthnCredentials: number;
    folders: number;
    ciphers: number;
    attachments: number;
    attachmentFiles: number;
    sends: number;
    sendFiles: number;
  };
  skipped: {
    reason: string | null;
    attachments: number;
    sendFiles: number;
    items: SkippedFile[];
  };
}

type SkippedFile = { kind: 'attachment' | 'send'; path: string; sizeBytes: number };

export interface BackupImportExecutionResult {
  result: BackupImportResultBody;
  auditActorUserId: string | null;
}

async function resetRestoreArtifacts(db: D1Database): Promise<void> {
  /* eslint-disable nodewarden/no-raw-sql -- shadow tables are DDL copies made at runtime, outside the drizzle schema */
  await db.batch(
    BACKUP_TABLE_NAMES.slice()
      .reverse()
      .map((table) => db.prepare(`DROP TABLE IF EXISTS ${shadowTableName(table)}`)),
  );
  /* eslint-enable nodewarden/no-raw-sql */
}

async function validateShadowTableCounts(
  db: D1Database,
  expectedCounts: Partial<Record<BackupTableName, number>>,
): Promise<void> {
  const orm = getOrm(db);
  await Promise.all(
    BACKUP_TABLE_NAMES.map(async (table) => {
      const expected = expectedCounts[table] ?? 0;
      const actual = await orm.$count(shadowTable(BACKUP_TABLES[table].table));
      if (actual !== expected) {
        throw new Error(`Restore shadow validation failed for ${table}: expected ${expected}, received ${actual}`);
      }
    }),
  );
}

// Every blob the instance's attachments and file Sends own.
async function collectCurrentBlobKeys(db: D1Database): Promise<Set<string>> {
  const orm = getOrm(db);
  const [attachmentRows, sendRows] = await Promise.all([
    orm
      .select({ id: attachments.id, cipher_id: attachments.cipherId, size: attachments.size })
      .from(attachments)
      .innerJoin(ciphers, eq(ciphers.id, attachments.cipherId)),
    orm.select({ id: sends.id, type: sends.type, data: sends.data }).from(sends),
  ]);
  return new Set(archivedFiles({ attachments: attachmentRows, sends: sendRows }).map(({ key }) => key));
}

const KV_BLOB_SKIP_REASON = 'Cloudflare KV object size limit (25 MB)';
const BLOB_STORAGE_UNAVAILABLE_SKIP_REASON = 'Attachment storage is not configured';
const REMOTE_FILES_UNAVAILABLE_REASON = 'Some remote attachments were unavailable and were skipped';
const FILE_RESTORE_FAILED_REASON = 'Some attachments could not be restored and were skipped';

interface RemoteAttachmentSource {
  loadAttachment(blobName: string): Promise<Uint8Array | null>;
}

export interface BackupRestoreProgressEvent {
  source: 'local' | 'remote';
  step: string;
  fileName: string;
  stageTitle: string;
  stageDetail: string;
  replaceExisting: boolean;
  done?: boolean;
  ok?: boolean;
  error?: string | null;
}

export type BackupRestoreProgressReporter = (event: BackupRestoreProgressEvent) => Promise<void> | void;

function upsertConfigRow(rows: SqlRow[], key: string, value: string): SqlRow[] {
  let replaced = false;
  const nextRows = rows.map((row) => {
    if (String(row.key || '').trim() !== key) return { ...row };
    replaced = true;
    return { ...row, key, value };
  });
  if (!replaced) {
    nextRows.push({ key, value });
  }
  return nextRows;
}

export async function importBackupArchiveBytes(
  archiveBytes: Uint8Array,
  env: Env,
  actorUserId: string,
  replaceExisting: boolean,
  source: RemoteAttachmentSource | null = null,
  progress?: BackupRestoreProgressReporter,
  fileName: string = 'nodewarden_backup.zip',
): Promise<BackupImportExecutionResult> {
  // A local archive carries every file inline and validates as-is. A remote one keeps its files at the
  // destination, so its file-owning rows are fitted to what that source supplies before validation.
  const restoreSource = source ? 'remote' : 'local';
  const parsed = parseBackupArchive(archiveBytes, { allowExternalAttachmentBlobs: !!source });
  if (!source) validateBackupPayloadContents(parsed.payload, parsed.files);
  const external = source
    ? externalFiles(parsed.payload.manifest)
    : new Map<string, { blobName: string; sizeBytes: number }>();
  const storageKind = getBlobStorageKind(env);
  const describe = (file: ArchivedFile) => {
    const inline = parsed.files[`attachments/${file.key}.bin`];
    const ref = external.get(file.key);
    const item: SkippedFile = {
      kind: file.table === 'sends' ? 'send' : 'attachment',
      path: ref ? `attachments/${ref.blobName}` : `attachments/${file.key}.bin`,
      sizeBytes: inline?.byteLength ?? ref?.sizeBytes ?? file.sizeBytes,
    };
    return { inline, ref, item };
  };
  // Fit the files to this instance's blob storage: R2 takes every file, KV only files within its object
  // size limit, and without storage no file-owning row restores. A row whose file does not fit is left out.
  const unfit = archivedFiles(parsed.payload.db).filter((file) => {
    const { inline, ref, item } = describe(file);
    return !(inline || ref) || !storageKind || (storageKind === 'kv' && item.sizeBytes > KV_MAX_OBJECT_BYTES);
  });
  const unfitRows = new Set(unfit.map(({ row }) => row));
  const prepared = {
    payload: {
      ...parsed.payload,
      db: {
        ...parsed.payload.db,
        attachments: parsed.payload.db.attachments.filter((row) => !unfitRows.has(row)),
        sends: parsed.payload.db.sends.filter((row) => !unfitRows.has(row)),
      },
    },
    skipped: unfit.map((file) => describe(file).item),
    reason: !unfit.length
      ? null
      : source
        ? REMOTE_FILES_UNAVAILABLE_REASON
        : storageKind
          ? KV_BLOB_SKIP_REASON
          : BLOB_STORAGE_UNAVAILABLE_SKIP_REASON,
  };
  if (source) validateBackupPayloadContents(prepared.payload, parsed.files, { allowExternalAttachmentBlobs: true });
  const report = (
    step: string,
    stage: string,
    outcome: Pick<BackupRestoreProgressEvent, 'done' | 'ok' | 'error'> = {},
  ) =>
    progress?.({
      source: restoreSource,
      step: `${restoreSource}_${step}`,
      fileName,
      stageTitle: `txt_backup_restore_progress_${restoreSource}_${stage}_title`,
      stageDetail: `txt_backup_restore_progress_${restoreSource}_${stage}_detail`,
      replaceExisting,
      ...outcome,
    });
  const orm = getOrm(env.DB);

  try {
    const counts = await Promise.all([
      orm.select({ count: count() }).from(ciphers),
      orm.select({ count: count() }).from(folders),
      orm.select({ count: count() }).from(attachments),
      orm.select({ count: count() }).from(sends),
      orm.select({ count: count() }).from(organizations),
    ]);
    const total = counts.reduce((sum, rows) => sum + Number(rows[0]?.count || 0), 0);
    if (total > 0) {
      throw new Error('Backup import requires a fresh instance with no vault or send data');
    }
  } catch (error) {
    if (!replaceExisting) {
      throw error instanceof Error ? error : new Error('Backup import requires a fresh instance');
    }
  }

  await resetRestoreArtifacts(env.DB);
  const previousBlobKeys = replaceExisting ? await collectCurrentBlobKeys(env.DB) : new Set<string>();
  try {
    await report('create_shadow', 'shadow');
    const createStatements: string[] = [];
    for (const table of BACKUP_TABLE_NAMES) {
      const [row] = await orm
        .select({ sql: sqliteMaster.sql })
        .from(sqliteMaster)
        .where(and(eq(sqliteMaster.type, 'table'), eq(sqliteMaster.name, table)))
        .limit(1);
      const createSql = String(row?.sql || '').trim();
      if (!createSql) {
        throw new Error(`Restore shadow schema is missing table definition for ${table}`);
      }
      // Rename the copy and point its foreign keys at the other shadow tables.
      const tablePattern = new RegExp(
        `^CREATE TABLE(?:\\s+IF NOT EXISTS)?\\s+(?:\"${table}\"|\`${table}\`|${table})(?=\\s*\\()`,
        'i',
      );
      let shadowSql = createSql.replace(tablePattern, `CREATE TABLE "${shadowTableName(table)}"`);
      if (shadowSql === createSql) {
        throw new Error(`Restore shadow schema could not rewrite CREATE TABLE statement for ${table}`);
      }
      for (const currentTable of BACKUP_TABLE_NAMES) {
        const referencePattern = new RegExp(
          `\\bREFERENCES\\s+(?:\"${currentTable}\"|\`${currentTable}\`|${currentTable})(?=\\s*\\()`,
          'gi',
        );
        shadowSql = shadowSql.replace(referencePattern, `REFERENCES "${shadowTableName(currentTable)}"`);
      }
      createStatements.push(shadowSql);
    }
    // eslint-disable-next-line nodewarden/no-raw-sql -- shadow DDL is rewritten at runtime from the live tables' sqlite_master text
    await env.DB.batch(createStatements.map((statement) => env.DB.prepare(statement)));
    await report('import_data', 'data');
    let configRows = prepared.payload.db.config.filter(
      (row) => String(row.key || '').trim() !== YUBICO_BOOTSTRAP_CLAIM_CONFIG_KEY,
    );
    const rawBackupSettings = configRows.find((row) => String(row.key || '').trim() === BACKUP_SETTINGS_CONFIG_KEY);
    const normalizedBackupSettings = await normalizeImportedBackupSettingsValue(
      typeof rawBackupSettings?.value === 'string' ? rawBackupSettings.value : null,
      env,
      prepared.payload.db.users.map((row) => ({
        id: String(row.id || '').trim(),
        publicKey: typeof row.public_key === 'string' ? row.public_key : null,
        role: String(row.role || '').trim() as User['role'],
        status: String(row.status || '').trim() as User['status'],
      })),
      'UTC',
    );
    if (normalizedBackupSettings !== null) {
      configRows = upsertConfigRow(configRows, BACKUP_SETTINGS_CONFIG_KEY, normalizedBackupSettings);
    }
    configRows = upsertConfigRow(configRows, 'registered', 'true');
    // Imported preferences must survive a later baseline replay, including archives without this marker.
    configRows = upsertConfigRow(configRows, 'migration.verify-devices-on', '1');
    const db: BackupPayload['db'] = {
      ...prepared.payload.db,
      config: configRows,
      users: prepared.payload.db.users.map((row) => ({
        ...row,
        email_verified: row.email_verified ?? 1,
        verify_devices: row.verify_devices ?? 0,
        yubikey_nfc: row.yubikey_nfc ?? 0,
      })),
      // Archives from before passkey purposes hold login passkeys only.
      webauthn_credentials: prepared.payload.db.webauthn_credentials.map((row) => ({
        ...row,
        purpose: row.purpose == null ? 'login' : String(row.purpose).trim() === 'twoFactor' ? 'twoFactor' : 'login',
      })),
      ciphers: prepared.payload.db.ciphers.map((row) => ({
        ...row,
        archived_at: row.archived_at ?? null,
      })),
    };
    // Config, revisions and domain settings keep the INSERT OR REPLACE semantics they always had. REPLACE
    // turns a NULL in a NOT NULL column into the column default, which drizzle binds for undefined. The
    // shadow copy starts empty, so only a key the archive repeats can conflict; skipping it leaves the
    // count check to reject the archive, as it did after REPLACE deduplicated the rows.
    const replaced = new Set<BackupTableName>(['config', 'user_revisions', 'domain_settings']);
    for (const name of BACKUP_TABLE_NAMES) {
      if (!db[name].length) continue;
      // Multi-row inserts into the table's shadow copy, one batch per table. Only the archived columns come
      // from the row; every other column keeps its default. Each row binds at most one parameter per
      // schema column, so chunks by column count stay within D1's parameter limit.
      const target: SQLiteTable = shadowTable(BACKUP_TABLES[name].table);
      const replace = replaced.has(name);
      const values = db[name].map((row) =>
        Object.fromEntries(
          backupColumns(name).map(([key, column]) => [
            key,
            row[column.name] ?? (replace && column.notNull ? undefined : null),
          ]),
        ),
      );
      const statements = chunkRows(values, columnCount(target)).map((chunk) => {
        const insert = orm.insert(target).values(chunk);
        return replace ? insert.onConflictDoNothing() : insert;
      });
      try {
        await orm.batch(statements as [(typeof statements)[0], ...typeof statements]);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        throw new Error(`Restore insert failed for ${shadowTableName(name)}: ${message}`);
      }
    }
    const stagedCounts = Object.fromEntries(BACKUP_TABLE_NAMES.map((name) => [name, db[name].length]));
    await validateShadowTableCounts(env.DB, stagedCounts);

    await report('restore_files', 'files');
    // Store each file under its blob key. A row whose file is missing or cannot be stored leaves its shadow
    // table and is reported as skipped; a failed drop is left to the count validation below.
    const files = archivedFiles(db);
    const failedRows = new Set<SqlRow>();
    for (const file of files) {
      const { inline, ref } = describe(file);
      try {
        const bytes = inline ?? (ref && source ? await source.loadAttachment(ref.blobName) : null);
        if (!bytes) throw new Error('Backup file is unavailable');
        await putBlobObject(env, file.key, bytes, { size: bytes.byteLength, contentType: 'application/octet-stream' });
      } catch {
        failedRows.add(file.row);
      }
    }
    const failed = files.filter(({ row }) => failedRows.has(row));
    const stagedAttachments = shadowTable(attachments);
    const stagedSends = shadowTable(sends);
    const drops = failed.map(({ table, row }) =>
      table === 'sends'
        ? orm.delete(stagedSends).where(eq(stagedSends.id, String(row.id || '').trim()))
        : orm
            .delete(stagedAttachments)
            .where(
              and(
                eq(stagedAttachments.id, String(row.id || '').trim()),
                eq(stagedAttachments.cipherId, String(row.cipher_id || '').trim()),
              ),
            ),
    );
    if (drops.length) await orm.batch(drops as [(typeof drops)[0], ...typeof drops]).catch(() => undefined);
    // What each file-owning table restored: its rows, and the files among them.
    const restored = (table: ArchivedFile['table']) => ({
      rows: db[table].filter((row) => !failedRows.has(row)).length,
      files: files.filter((file) => file.table === table && !failedRows.has(file.row)).length,
    });
    await validateShadowTableCounts(env.DB, {
      ...stagedCounts,
      attachments: restored('attachments').rows,
      sends: restored('sends').rows,
    });
    await report('finalize', 'finalize');
    // Commit by replacing live table contents from validated shadow tables.
    // This avoids D1 schema-rename edge cases while keeping current data intact
    // until the final batch succeeds.
    const swap = [
      ...BACKUP_TABLE_NAMES.toReversed().map((name) => orm.delete(BACKUP_TABLES[name].table)),
      // Copies by column name, not SELECT *: a live table's physical column order can differ from its
      // schema order (users does), so a positional copy under drizzle's column list would misplace values.
      ...BACKUP_TABLE_NAMES.map((name) => BACKUP_TABLES[name].table).map(<T extends SQLiteTable>(live: T) =>
        orm.insert(live).select(orm.select().from(shadowTable(live))),
      ),
    ];
    await orm.batch(swap as [(typeof swap)[0], ...typeof swap]);
    await syncVaultAdminRoles(env);
    await resetRestoreArtifacts(env.DB).catch(() => undefined);
    if (replaceExisting && previousBlobKeys.size) {
      const nextBlobKeys = await collectCurrentBlobKeys(env.DB).catch(() => null);
      if (nextBlobKeys) {
        // Deleting orphaned blobs is best effort: the restore has already committed.
        try {
          for (const key of Array.from(previousBlobKeys).filter((blobKey) => !nextBlobKeys.has(blobKey))) {
            await deleteBlobObject(env, key);
          }
        } catch {
          // An orphaned blob only costs storage.
        }
      }
    }

    await report('complete', 'finalize', { done: true, ok: true });
    const skippedItems = [...prepared.skipped, ...failed.map((file) => describe(file).item)];
    return {
      auditActorUserId: db.users.some((row) => String(row.id || '').trim() === actorUserId) ? actorUserId : null,
      result: {
        object: 'instance-backup-import',
        imported: {
          config: db.config.length,
          users: db.users.length,
          domainSettings: db.domain_settings.length,
          userRevisions: db.user_revisions.length,
          webauthnCredentials: db.webauthn_credentials.length,
          folders: db.folders.length,
          ciphers: db.ciphers.length,
          attachments: restored('attachments').rows,
          attachmentFiles: restored('attachments').files,
          sends: restored('sends').rows,
          sendFiles: restored('sends').files,
        },
        skipped: {
          reason: failed.length ? FILE_RESTORE_FAILED_REASON : prepared.reason,
          attachments: skippedItems.filter((item) => item.kind === 'attachment').length,
          sendFiles: skippedItems.filter((item) => item.kind === 'send').length,
          items: skippedItems,
        },
      },
    };
  } catch (error) {
    await report('failed', 'finalize', {
      done: true,
      ok: false,
      error: error instanceof Error ? error.message : String(error),
    });
    await resetRestoreArtifacts(env.DB).catch(() => undefined);
    throw error;
  }
}
