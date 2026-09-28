import { and, count, eq } from 'drizzle-orm';

import { chunkRows, columnCount, getOrm, withoutQueryParams } from '../db/client';
import { attachments, backupRestoreRows, ciphers, folders, organizations, sends } from '../db/schema';
import { bound, coalesce, jsonExtract } from '../db/sql';
import type { Env } from '../types';
import {
  BACKUP_FORMAT_VERSION,
  BACKUP_TABLE_NAMES,
  BACKUP_TABLES,
  BackupRowValidator,
  DB_SLICE_ENTRY,
  INSTANCE_LOCAL_CONFIG_KEYS,
  MAX_ARCHIVE_ENTRIES,
  MAX_DB_ENTRY_BYTES,
  MAX_MANIFEST_BYTES,
  archivedFiles,
  backupColumns,
  parseBackupManifest,
  parseDbEntry,
  validateBackupEntryName,
  type BackupTableName,
  type SqlRow,
} from './backup-archive';
import { R2ZipReader, type ZipEntry } from './backup-zip';
import { KV_MAX_OBJECT_BYTES, deleteBlobObject, getBlobStorageKind, putBlobObject } from './blob-store';
import { syncVaultAdminRoles } from './vault-admin-role';

// CONTRACT:
// Restore is intentionally whitelist-based. Old backups may contain retired
// fields, but only the tables and columns BACKUP_TABLES (backup-archive.ts)
// archives are imported.
//
// WHEN CHANGING THIS:
// - Give rows from older archives a value for every column a table gains when
//   their slice is prepared, as users, passkeys and ciphers do.
// - Do not import users.api_key, even if an older backup contains it.
// - Do not import, clear, or replace runtime authentication state such as
//   devices, sessions, auth requests, or remembered 2FA device tokens.

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

// A staged row whose file streams to blob storage once every slice is staged.
interface StagedFile {
  table: 'attachments' | 'sends';
  position: number;
  key: string;
  entry: ZipEntry;
  item: SkippedFile;
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
const MISSING_FILE_SKIP_REASON = 'Some files were missing from the archive and were skipped';
const FILE_RESTORE_FAILED_REASON = 'Some attachments could not be restored and were skipped';

// Restores the archive at key in bucket. The archive is read through range requests and each database entry is
// parsed alone, so memory holds one entry, the id sets the validator keeps and the staged files' entries. Rows are
// staged in backup_restore_rows as they arrive; the live tables change only in the final swap. ponytail: two
// subrequests per file (its range read and its store), so a restore stays within the invocation's 10,000 with a
// few thousand files; raise limits.subrequests for more.
export async function restoreBackupArchive(
  env: Env,
  bucket: R2Bucket,
  key: string,
  actorUserId: string,
  replaceExisting: boolean,
): Promise<BackupImportExecutionResult> {
  const zip = await R2ZipReader.open(bucket, key);
  if (!zip) throw new Error('Backup archive not found');
  if (zip.entries.length > MAX_ARCHIVE_ENTRIES) throw new Error('Backup archive contains too many files');
  const entries = new Map<string, ZipEntry>();
  for (const entry of zip.entries) {
    validateBackupEntryName(entry.name);
    if (entries.has(entry.name)) throw new Error(`Backup archive contains a duplicate file: ${entry.name}`);
    entries.set(entry.name, entry);
  }
  const manifestEntry = entries.get('manifest.json');
  if (!manifestEntry) throw new Error('Backup archive is missing manifest.json or db.json');
  const manifest = parseBackupManifest(
    await zip.bytes(manifestEntry, MAX_MANIFEST_BYTES, 'Backup archive manifest is too large'),
  );
  // Format 3 slices the database in restore order; older archives hold it whole in db.json.
  const sliced = manifest.formatVersion === BACKUP_FORMAT_VERSION;
  const sliceNumber = (entry: ZipEntry) => Number(DB_SLICE_ENTRY.exec(entry.name)?.[1]);
  const dbEntries = sliced
    ? zip.entries.filter((entry) => DB_SLICE_ENTRY.test(entry.name)).toSorted((a, b) => sliceNumber(a) - sliceNumber(b))
    : [entries.get('db.json')].filter((entry) => entry !== undefined);
  if (!dbEntries.length) throw new Error('Backup archive is missing manifest.json or db.json');

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

  const storageKind = getBlobStorageKind(env);
  await orm.delete(backupRestoreRows);
  const previousBlobKeys = replaceExisting ? await collectCurrentBlobKeys(env.DB) : new Set<string>();
  try {
    const validator = new BackupRowValidator();
    const read = new Map<BackupTableName, number>();
    const staged = new Map<BackupTableName, number>();
    const stagedFiles: StagedFile[] = [];
    const skipped: Array<{ item: SkippedFile; reason: string }> = [];
    let actorRestored = false;
    // Stages rows at the table's next positions, three parameters a row and only the archived columns, and
    // returns the first position.
    const stage = async (name: BackupTableName, rows: SqlRow[]) => {
      const first = staged.get(name) ?? 0;
      staged.set(name, first + rows.length);
      const values = rows.map((row, index) => ({
        tableName: name,
        position: first + index,
        row: JSON.stringify(
          Object.fromEntries(backupColumns(name).map(([, column]) => [column.name, row[column.name] ?? null])),
        ),
      }));
      const statements = chunkRows(values, columnCount(backupRestoreRows)).map((chunk) =>
        orm.insert(backupRestoreRows).values(chunk),
      );
      if (statements.length) await orm.batch(statements as [(typeof statements)[0], ...typeof statements]);
      return first;
    };

    for (const dbEntry of dbEntries) {
      const slice = parseDbEntry(
        await zip.bytes(dbEntry, MAX_DB_ENTRY_BYTES, 'Backup archive database payload is too large'),
        !sliced,
      );
      for (const name of BACKUP_TABLE_NAMES) {
        const rows = slice[name];
        if (!rows?.length) continue;
        read.set(name, (read.get(name) ?? 0) + rows.length);
        validator.check(name, rows);
        if (name === 'users') actorRestored ||= rows.some((row) => String(row.id || '').trim() === actorUserId);
        // Rows from older archives get a value for every column the table gained since. The instance's own
        // config rows, and the registered flag staged below, are not taken from the archive.
        const prepared =
          name === 'config'
            ? rows.filter((row) => {
                const configKey = String(row.key || '').trim();
                return configKey !== 'registered' && !INSTANCE_LOCAL_CONFIG_KEYS.has(configKey);
              })
            : name === 'users'
              ? rows.map((row) => ({
                  ...row,
                  email_verified: row.email_verified ?? 1,
                  verify_devices: row.verify_devices ?? 0,
                  yubikey_nfc: row.yubikey_nfc ?? 0,
                }))
              : // Archives from before passkey purposes hold login passkeys only.
                name === 'webauthn_credentials'
                ? rows.map((row) => ({
                    ...row,
                    purpose:
                      row.purpose == null
                        ? 'login'
                        : String(row.purpose).trim() === 'twoFactor'
                          ? 'twoFactor'
                          : 'login',
                  }))
                : name === 'ciphers'
                  ? rows.map((row) => ({ ...row, archived_at: row.archived_at ?? null }))
                  : rows;
        // A file-owning row restores only with a file in the archive that this instance can store; the rest are
        // left out and reported.
        const described = prepared.map((row) => {
          const [file] = archivedFiles({
            attachments: name === 'attachments' ? [row] : [],
            sends: name === 'sends' ? [row] : [],
          });
          if (!file) return { row };
          const path = `attachments/${file.key}.bin`;
          const entry = entries.get(path);
          const item: SkippedFile = {
            kind: file.table === 'sends' ? 'send' : 'attachment',
            path,
            sizeBytes: entry?.size ?? file.sizeBytes,
          };
          const reason = !entry
            ? MISSING_FILE_SKIP_REASON
            : !storageKind
              ? BLOB_STORAGE_UNAVAILABLE_SKIP_REASON
              : storageKind === 'kv' && entry.size > KV_MAX_OBJECT_BYTES
                ? KV_BLOB_SKIP_REASON
                : null;
          return { row, file: { table: file.table, key: file.key, entry, item }, reason };
        });
        skipped.push(...described.flatMap(({ file, reason }) => (file && reason ? [{ item: file.item, reason }] : [])));
        const kept = described.filter(({ reason }) => !reason);
        const first = await stage(
          name,
          kept.map(({ row }) => row),
        );
        stagedFiles.push(
          ...kept.flatMap(({ file }, index) =>
            file?.entry ? [{ ...file, entry: file.entry, position: first + index }] : [],
          ),
        );
      }
    }
    // A format 3 manifest counts every table's rows, so a lost slice cannot pass for a smaller table.
    if (sliced)
      for (const name of BACKUP_TABLE_NAMES) {
        const expected = manifest.tableCounts[name] ?? 0;
        const found = read.get(name) ?? 0;
        if (found !== expected)
          throw new Error(`Backup archive is incomplete: ${name} holds ${found} rows, its manifest counts ${expected}`);
      }
    // A restored instance counts as registered, whatever the archive says.
    await stage('config', [{ key: 'registered', value: 'true' }]);
    await validateStagedCounts(env.DB, Object.fromEntries(staged));

    // Each file streams from its entry to its blob key. One that cannot be stored takes its row out of the staging
    // table and is reported as skipped; a failed drop is left to the count check below.
    const failed: StagedFile[] = [];
    for (const file of stagedFiles) {
      // A store that fails before reading its stream would leave the entry's range read open; the abort closes it.
      const abort = new AbortController();
      try {
        const { readable, writable } = new FixedLengthStream(file.entry.size);
        await Promise.all([
          (await zip.stream(file.entry)).pipeTo(writable, { signal: abort.signal }),
          putBlobObject(env, file.key, readable, { size: file.entry.size, contentType: 'application/octet-stream' }),
        ]);
      } catch (error) {
        abort.abort();
        console.error('Backup file restore failed', file.key, withoutQueryParams(error));
        failed.push(file);
      }
    }
    const drops = failed.map(({ table, position }) =>
      orm
        .delete(backupRestoreRows)
        .where(and(eq(backupRestoreRows.tableName, table), eq(backupRestoreRows.position, position))),
    );
    if (drops.length) await orm.batch(drops as [(typeof drops)[0], ...typeof drops]).catch(() => undefined);
    const failedIn = (table: StagedFile['table']) => failed.filter((file) => file.table === table).length;
    const restoredRows = (table: StagedFile['table']) => (staged.get(table) ?? 0) - failedIn(table);
    const restoredFiles = (table: StagedFile['table']) =>
      stagedFiles.filter((file) => file.table === table).length - failedIn(table);
    await validateStagedCounts(env.DB, {
      ...Object.fromEntries(staged),
      attachments: restoredRows('attachments'),
      sends: restoredRows('sends'),
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

    const imported = (name: BackupTableName) => staged.get(name) ?? 0;
    const skippedItems = [...skipped, ...failed.map(({ item }) => ({ item, reason: FILE_RESTORE_FAILED_REASON }))];
    return {
      auditActorUserId: actorRestored ? actorUserId : null,
      result: {
        object: 'instance-backup-import',
        imported: {
          config: imported('config'),
          users: imported('users'),
          domainSettings: imported('domain_settings'),
          userRevisions: imported('user_revisions'),
          webauthnCredentials: imported('webauthn_credentials'),
          folders: imported('folders'),
          ciphers: imported('ciphers'),
          attachments: restoredRows('attachments'),
          attachmentFiles: restoredFiles('attachments'),
          sends: restoredRows('sends'),
          sendFiles: restoredFiles('sends'),
        },
        skipped: {
          reason: failed.length ? FILE_RESTORE_FAILED_REASON : (skipped[0]?.reason ?? null),
          attachments: skippedItems.filter(({ item }) => item.kind === 'attachment').length,
          sendFiles: skippedItems.filter(({ item }) => item.kind === 'send').length,
          items: skippedItems.map(({ item }) => item),
        },
      },
    };
  } catch (error) {
    await orm.delete(backupRestoreRows).catch(() => undefined);
    throw error;
  }
}
