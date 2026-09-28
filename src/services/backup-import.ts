import { syncVaultAdminRoles } from './vault-admin-role';
import { and, count, eq } from 'drizzle-orm';

import { chunkRows, columnCount, getOrm } from '../db/client';
import { attachments, backupRestoreRows, ciphers, folders, organizations, sends } from '../db/schema';
import { bound, coalesce, jsonExtract } from '../db/sql';
import type { Env } from '../types';
import { KV_MAX_OBJECT_BYTES, deleteBlobObject, getBlobStorageKind, putBlobObject } from './blob-store';
import {
  BACKUP_TABLE_NAMES,
  BACKUP_TABLES,
  INSTANCE_LOCAL_CONFIG_KEYS,
  archivedFiles,
  backupColumns,
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

// Staged rows per table must match what the restore meant to stage; a mismatch rejects it before the swap.
async function validateStagedCounts(db: D1Database, expected: Record<string, number>): Promise<void> {
  const staged = new Map(
    (
      await getOrm(db)
        .select({ tableName: backupRestoreRows.tableName, rows: count() })
        .from(backupRestoreRows)
        .groupBy(backupRestoreRows.tableName)
    ).map((row) => [row.tableName, row.rows]),
  );
  for (const name of BACKUP_TABLE_NAMES) {
    const wanted = expected[name] ?? 0;
    const actual = staged.get(name) ?? 0;
    if (actual !== wanted) {
      throw new Error(`Restore staging validation failed for ${name}: expected ${wanted}, received ${actual}`);
    }
  }
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
const FILE_RESTORE_FAILED_REASON = 'Some attachments could not be restored and were skipped';

export async function importBackupArchiveBytes(
  archiveBytes: Uint8Array,
  env: Env,
  actorUserId: string,
  replaceExisting: boolean,
): Promise<BackupImportExecutionResult> {
  const parsed = parseBackupArchive(archiveBytes);
  validateBackupPayloadContents(parsed.payload, parsed.files);
  const storageKind = getBlobStorageKind(env);
  const describe = (file: ArchivedFile) => {
    const inline = parsed.files[`attachments/${file.key}.bin`];
    const item: SkippedFile = {
      kind: file.table === 'sends' ? 'send' : 'attachment',
      path: `attachments/${file.key}.bin`,
      sizeBytes: inline?.byteLength ?? file.sizeBytes,
    };
    return { inline, item };
  };
  // Fit the files to this instance's blob storage: R2 takes every file, KV only files within its object
  // size limit, and without storage no file-owning row restores. A row whose file does not fit is left out.
  const unfit = archivedFiles(parsed.payload.db).filter((file) => {
    const { inline, item } = describe(file);
    return !inline || !storageKind || (storageKind === 'kv' && item.sizeBytes > KV_MAX_OBJECT_BYTES);
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
    reason: !unfit.length ? null : storageKind ? KV_BLOB_SKIP_REASON : BLOB_STORAGE_UNAVAILABLE_SKIP_REASON,
  };
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

  await orm.delete(backupRestoreRows);
  const previousBlobKeys = replaceExisting ? await collectCurrentBlobKeys(env.DB) : new Set<string>();
  try {
    // A restored instance counts as registered, whatever the archive says.
    const configRows: SqlRow[] = [
      ...prepared.payload.db.config.filter((row) => {
        const key = String(row.key || '').trim();
        return key !== 'registered' && !INSTANCE_LOCAL_CONFIG_KEYS.has(key);
      }),
      { key: 'registered', value: 'true' },
    ];
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
    // Each archived row is staged as JSON under its table and position, one batch per table: three parameters
    // a row, and only the archived columns. The live tables stay intact until the swap below.
    for (const name of BACKUP_TABLE_NAMES) {
      const rows = db[name].map((row, position) => ({
        tableName: name,
        position,
        row: JSON.stringify(
          Object.fromEntries(backupColumns(name).map(([, column]) => [column.name, row[column.name] ?? null])),
        ),
      }));
      const statements = chunkRows(rows, columnCount(backupRestoreRows)).map((chunk) =>
        orm.insert(backupRestoreRows).values(chunk),
      );
      if (statements.length) await orm.batch(statements as [(typeof statements)[0], ...typeof statements]);
    }
    const stagedCounts = Object.fromEntries(BACKUP_TABLE_NAMES.map((name) => [name, db[name].length]));
    await validateStagedCounts(env.DB, stagedCounts);

    // Store each file under its blob key. A row whose file is missing or cannot be stored leaves the staging
    // table and is reported as skipped; a failed drop is left to the count validation below.
    const files = archivedFiles(db);
    const failedRows = new Set<SqlRow>();
    for (const file of files) {
      const { inline } = describe(file);
      try {
        const bytes = inline;
        if (!bytes) throw new Error('Backup file is unavailable');
        await putBlobObject(env, file.key, bytes, { size: bytes.byteLength, contentType: 'application/octet-stream' });
      } catch {
        failedRows.add(file.row);
      }
    }
    const failed = files.filter(({ row }) => failedRows.has(row));
    const drops = failed.map(({ table, row }) =>
      orm
        .delete(backupRestoreRows)
        .where(and(eq(backupRestoreRows.tableName, table), eq(backupRestoreRows.position, db[table].indexOf(row)))),
    );
    if (drops.length) await orm.batch(drops as [(typeof drops)[0], ...typeof drops]).catch(() => undefined);
    // What each file-owning table restored: its rows, and the files among them.
    const restored = (table: ArchivedFile['table']) => ({
      rows: db[table].filter((row) => !failedRows.has(row)).length,
      files: files.filter((file) => file.table === table && !failedRows.has(file.row)).length,
    });
    await validateStagedCounts(env.DB, {
      ...stagedCounts,
      attachments: restored('attachments').rows,
      sends: restored('sends').rows,
    });
    // Commit by replacing every live table from the staged rows in one batch, so the live data changes only if
    // all of it applies. Live constraints check the archive here: a missing required value, a duplicate key or a
    // dangling reference rolls the batch back. Columns are copied by name, as a live table's physical column
    // order can differ from its schema order (users does). Config, revisions and domain settings keep the
    // INSERT OR REPLACE semantics they always had: a missing or NULL value in a NOT NULL column takes the
    // column default.
    const replaced = new Set<BackupTableName>(['config', 'user_revisions', 'domain_settings']);
    const swap = [
      ...BACKUP_TABLE_NAMES.toReversed().map((name) => orm.delete(BACKUP_TABLES[name].table)),
      // Each staged column is selected under the live column's key, so drizzle names the columns in its INSERT.
      // A selection built per table has no static keys to type-check; drizzle checks at runtime that every key
      // is a column of the live table.
      ...BACKUP_TABLE_NAMES.map((name) =>
        orm.insert(BACKUP_TABLES[name].table).select(
          orm
            .select(
              Object.fromEntries(
                backupColumns(name).map(([key, column]) => {
                  const value = jsonExtract<unknown>(backupRestoreRows.row, `$.${column.name}`);
                  const fallback = replaced.has(name) && column.notNull ? column.default : undefined;
                  return [key, (fallback === undefined ? value : coalesce(value, bound(fallback))).as(key)];
                }),
              ),
            )
            .from(backupRestoreRows)
            .where(eq(backupRestoreRows.tableName, name))
            .orderBy(backupRestoreRows.position) as never,
        ),
      ),
      orm.delete(backupRestoreRows),
    ];
    await orm.batch(swap as [(typeof swap)[0], ...typeof swap]);
    await syncVaultAdminRoles(env);
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
    await orm.delete(backupRestoreRows).catch(() => undefined);
    throw error;
  }
}
