import assert from 'node:assert/strict';
import test from 'node:test';
import { eq, getColumns, getTableName } from 'drizzle-orm';
import { getTableConfig, type SQLiteColumn, type SQLiteTable } from 'drizzle-orm/sqlite-core';
import { unzipSync, zipSync } from 'fflate';

import { columnCount, D1_MAX_BOUND_PARAMETERS, getOrm } from '../db/client';
import {
  attachments,
  backupRestoreRows,
  ciphers,
  config,
  domainSettings,
  folders,
  organizations,
  sends,
  userRevisions,
  users,
  webauthnCredentials,
} from '../db/schema';
import { unmapped } from '../db/sql';
import { BACKUP_TABLE_NAMES, BACKUP_TABLES, backupColumns, type BackupTableName } from '../services/backup-archive';
import { SendType, type Env } from '../types';
import { archiveDb, archiveOf, restoreArchive, withArchiveDb } from './support/backup';
import { createTestEnv, interceptStatement, memoryKv, seedUser } from './support/env';

type Row = Record<string, unknown>;

// Restored tables with the key that orders their rows, for a stable row-by-row comparison.
const RESTORED_TABLES = [
  [users, users.id],
  [domainSettings, domainSettings.userId],
  [userRevisions, userRevisions.userId],
  [webauthnCredentials, webauthnCredentials.id],
  [folders, folders.id],
  [ciphers, ciphers.id],
  [attachments, attachments.id],
] as const;

// Stored values keyed by SQL column name, the shape of the archive's rows.
const rowsOf = (db: D1Database, table: SQLiteTable, orderBy: SQLiteColumn) =>
  getOrm(db)
    .select(Object.fromEntries(Object.values(getColumns(table)).map((column) => [column.name, unmapped(column)])))
    .from(table)
    .orderBy(orderBy);
// Code-unit order, as SQLite's default BINARY collation sorts.
const byKey = (key: string) => (left: Row, right: Row) => (String(left[key]) < String(right[key]) ? -1 : 1);

test('backup restore brings back every archived value, fills legacy defaults and keeps runtime-only columns empty', async () => {
  const blobs = memoryKv();
  const source = await createTestEnv({ ATTACHMENTS_KV: blobs.binding });
  const owner = await seedUser(source, {
    apiKey: 'runtime-api-key',
    kdfMemory: 64,
    kdfParallelism: 4,
    totpSecret: 'totp',
    yubikeyKey1: 'yubikey',
    privateKey: 'private',
    publicKey: 'public',
  });
  const other = await seedUser(source, {
    emailVerified: false,
    verifyDevices: true,
    name: null,
    masterPasswordHint: 'hint',
  });
  const orm = getOrm(source.DB);
  await orm.update(users).set({ userKeyId: 'runtime-key-id' }).where(eq(users.id, owner.id));
  await orm.insert(config).values({ key: 'custom.setting', value: 'kept' });
  await orm
    .insert(folders)
    .values({ id: 'folder-1', userId: owner.id, name: 'enc-folder', createdAt: 'c1', updatedAt: 'u1' });
  await orm.insert(ciphers).values({
    id: 'cipher-1',
    userId: owner.id,
    type: 1,
    folderId: 'folder-1',
    name: 'enc-name',
    notes: null,
    favorite: 1,
    data: '{"login":{}}',
    reprompt: 1,
    key: 'cipher-key',
    createdAt: 'c2',
    updatedAt: 'u2',
    archivedAt: 'a2',
    deletedAt: null,
  });
  await orm.insert(ciphers).values({
    id: 'cipher-2',
    userId: other.id,
    type: 2,
    data: '{}',
    createdAt: 'c3',
    updatedAt: 'u3',
    deletedAt: 'd3',
    organizationId: 'org-1',
  });
  await orm.insert(attachments).values([
    { id: 'att-1', cipherId: 'cipher-1', fileName: 'enc-file', size: 10, sizeName: '10 Bytes', key: 'file-key' },
    { id: 'att-2', cipherId: 'cipher-1', fileName: 'enc-lost', size: 20, sizeName: '20 Bytes', key: null },
  ]);
  await orm.insert(domainSettings).values([
    {
      userId: owner.id,
      equivalentDomains: '[["a.com","b.com"]]',
      customEquivalentDomains: '[["c.com"]]',
      excludedGlobalEquivalentDomains: '[1,2]',
      updatedAt: 'u4',
    },
    {
      userId: other.id,
      equivalentDomains: '[]',
      customEquivalentDomains: '[]',
      excludedGlobalEquivalentDomains: '[]',
      updatedAt: 'u5',
    },
  ]);
  await orm.insert(userRevisions).values([
    { userId: owner.id, revisionDate: 'r1' },
    { userId: other.id, revisionDate: 'r2' },
  ]);
  await orm.insert(webauthnCredentials).values({
    id: 'passkey-1',
    userId: owner.id,
    purpose: 'twoFactor',
    name: 'Key',
    publicKey: 'pk',
    credentialId: 'credential-1',
    counter: 5,
    type: 'public-key',
    aaGuid: 'guid',
    transports: '["usb"]',
    encryptedUserKey: 'euk',
    encryptedPublicKey: 'epk',
    encryptedPrivateKey: 'eprk',
    supportsPrf: 1,
    createdAt: 'c6',
    updatedAt: 'u6',
  });
  await orm.insert(webauthnCredentials).values({
    id: 'passkey-2',
    userId: other.id,
    name: 'Login',
    publicKey: 'pk2',
    credentialId: 'credential-2',
    createdAt: 'c7',
    updatedAt: 'u7',
  });

  await blobs.binding.put('cipher-1/att-1', 'blob-1');
  await blobs.binding.put('cipher-1/att-2', 'blob-2');
  const archive = await archiveOf(source);
  const archived = archiveDb(archive.bytes);
  // An archive from before custom equivalent domains existed lacks the column; restore falls back to its
  // default. Older archives may also still carry runtime-only columns, which restore must ignore.
  const legacy = structuredClone(archived);
  delete legacy.domain_settings.find((row) => row.user_id === owner.id)!.custom_equivalent_domains;
  Object.assign(legacy.users[0], { api_key: 'archived-api-key', user_key_id: 'archived-key-id' });

  const kv = memoryKv();
  const restored = await createTestEnv({ ATTACHMENTS_KV: kv.binding });
  const outcome = await restoreArchive(restored, withArchiveDb(archive.bytes, legacy), owner.id);
  assert.equal(outcome.result.imported.attachments, 2);
  assert.equal(outcome.result.skipped.attachments, 0);
  assert.deepEqual([...kv.values.keys()], ['cipher-1/att-1', 'cipher-1/att-2']);

  const expected: Record<string, Row[]> = {
    ...archived,
    domain_settings: archived.domain_settings.map((row) =>
      row.user_id === owner.id ? { ...row, custom_equivalent_domains: '[]' } : row,
    ),
  };
  for (const [table, orderBy] of RESTORED_TABLES) {
    const name = getTableName(table);
    const rows = await rowsOf(restored.DB, table, orderBy);
    const wanted = expected[name].toSorted(byKey(orderBy.name));
    assert.deepEqual(
      rows.map((row, index) =>
        Object.fromEntries(Object.keys(wanted[index] ?? row).map((column) => [column, row[column]])),
      ),
      wanted,
      name,
    );
  }
  const userRows = await rowsOf(restored.DB, users, users.id);
  assert.ok(userRows.every((row) => row.api_key === null && row.user_key_id === null));
  // An organization item stays one: without its link it would land in its creator's personal vault,
  // encrypted with a key that vault cannot open.
  assert.deepEqual(
    (await rowsOf(restored.DB, ciphers, ciphers.id)).map((row) => [row.id, row.organization_id]),
    [
      ['cipher-1', null],
      ['cipher-2', 'org-1'],
    ],
  );
  const settings = new Map((await rowsOf(restored.DB, config, config.key)).map((row) => [row.key, row.value]));
  assert.equal(settings.get('custom.setting'), 'kept');
  assert.equal(settings.get('registered'), 'true');
});

test('backup restore rejects a row missing a required value outside the replace tables instead of defaulting it', async () => {
  const source = await createTestEnv();
  const owner = await seedUser(source);
  await getOrm(source.DB)
    .insert(ciphers)
    .values({ id: 'cipher-1', userId: owner.id, type: 1, favorite: 1, data: '{}', createdAt: 'c', updatedAt: 'u' });
  const { bytes } = await archiveOf(source, false);
  const archived = archiveDb(bytes);
  delete archived.ciphers[0].favorite;

  const restored = await createTestEnv();
  await assert.rejects(
    restoreArchive(restored, withArchiveDb(bytes, archived), owner.id),
    /NOT NULL constraint failed: ciphers\.favorite/,
  );
  assert.deepEqual(await rowsOf(restored.DB, users, users.id), []);
});

test('backup restore writes tables with more rows than one D1 statement can bind', async () => {
  const source = await createTestEnv();
  const owner = await seedUser(source);
  // Staging binds every column of backup_restore_rows for each row, so one folder more than a statement holds
  // takes a second statement.
  const folderIds = Array.from(
    { length: Math.floor(D1_MAX_BOUND_PARAMETERS / columnCount(backupRestoreRows)) + 1 },
    (_, index) => `folder-${index}`,
  );
  for (const id of folderIds)
    await getOrm(source.DB)
      .insert(folders)
      .values({ id, userId: owner.id, name: 'enc', createdAt: 'c', updatedAt: 'u' });
  const restored = await createTestEnv();
  await restoreArchive(restored, (await archiveOf(source, false)).bytes, owner.id);
  assert.deepEqual(
    (await getOrm(restored.DB).select({ id: folders.id }).from(folders)).map((row) => row.id).toSorted(),
    folderIds.toSorted(),
  );
});

test('backup export reads every table in one snapshot, so a concurrent write cannot split parent from child', async () => {
  const source = await createTestEnv();
  const owner = await seedUser(source);
  const orm = getOrm(source.DB);
  // Lands between the folder and cipher reads if they run separately, exporting a cipher whose folder the
  // archive lacks, which restore then rejects.
  interceptStatement(source, /^select .* from "ciphers" order by/, async () => {
    await orm
      .insert(folders)
      .values({ id: 'late-folder', userId: owner.id, name: 'enc', createdAt: 'c', updatedAt: 'u' });
    await orm.insert(ciphers).values({
      id: 'late-cipher',
      userId: owner.id,
      type: 1,
      folderId: 'late-folder',
      data: '{}',
      createdAt: 'c',
      updatedAt: 'u',
    });
  });
  const archive = await archiveOf(source, false);
  await restoreArchive(await createTestEnv(), archive.bytes, owner.id);
});

// Columns that point at another table without a foreign key; restore checks that the folder exists.
const UNLINKED: Partial<Record<BackupTableName, Record<string, BackupTableName>>> = {
  ciphers: { folder_id: 'folders', organization_id: 'organizations' },
};
// Values restore validates or normalizes.
const VALID: Partial<Record<BackupTableName, Row>> = {
  webauthn_credentials: { purpose: 'twoFactor' },
  sends: { type: SendType.Text },
};
// Tables whose rows the generic seed leaves out: config goes through its own sanitizer and attachments need
// their files, so the first test covers those two.
const SEEDED_TABLES = BACKUP_TABLE_NAMES.filter((name) => name !== 'config' && name !== 'attachments');

// One synthetic row per archived table, in restore order: each column holds its own name and the tag
// (integers hold 1), and each foreign key the value of the row it references.
async function seedEveryArchivedTable(env: Env, tag: string): Promise<Map<BackupTableName, Row>> {
  const seeded = new Map<BackupTableName, Row>();
  for (const name of SEEDED_TABLES) {
    const table: SQLiteTable = BACKUP_TABLES[name].table;
    const { columns, foreignKeys } = getTableConfig(table);
    const row: Row = Object.fromEntries(
      columns.map((column) => [column.name, column.getSQLType() === 'integer' ? 1 : `${name}.${column.name}.${tag}`]),
    );
    for (const foreignKey of foreignKeys) {
      const reference = foreignKey.reference();
      const parent = seeded.get(getTableName(reference.foreignTable) as BackupTableName)!;
      reference.columns.forEach((column, index) => (row[column.name] = parent[reference.foreignColumns[index].name]));
    }
    for (const [column, parent] of Object.entries(UNLINKED[name] ?? {})) row[column] = seeded.get(parent)!.id;
    Object.assign(row, VALID[name]);
    seeded.set(name, row);
    await getOrm(env.DB)
      .insert(table)
      .values(Object.fromEntries(Object.entries(getColumns(table)).map(([key, column]) => [key, row[column.name]])));
  }
  return seeded;
}

// Every archived table's rows as the archive holds them.
const archivedTables = (db: D1Database) =>
  Promise.all(
    SEEDED_TABLES.map(async (name) => [
      name,
      await getOrm(db)
        .select(Object.fromEntries(backupColumns(name).map(([, column]) => [column.name, unmapped(column)])))
        .from(BACKUP_TABLES[name].table),
    ]),
  );

test('backup restore brings back every row of every archived table', async () => {
  const source = await createTestEnv();
  const seeded = await seedEveryArchivedTable(source, 'source');
  const restored = await createTestEnv();
  const archive = await archiveOf(source);
  await restoreArchive(restored, archive.bytes, String(seeded.get('users')!.id));
  assert.deepEqual(await archivedTables(restored.DB), await archivedTables(source.DB));
});

test('a replacing restore swaps every archived table of a populated instance for the archive', async () => {
  const source = await createTestEnv();
  const seeded = await seedEveryArchivedTable(source, 'source');
  const target = await createTestEnv();
  await seedEveryArchivedTable(target, 'target');
  const archive = await archiveOf(source);
  await restoreArchive(target, archive.bytes, String(seeded.get('users')!.id), true);
  assert.deepEqual(await archivedTables(target.DB), await archivedTables(source.DB));
});

test('backup restore without replace refuses an instance that already has an organization', async () => {
  const source = await createTestEnv();
  const owner = await seedUser(source);
  const archive = await archiveOf(source, false);
  const target = await createTestEnv();
  await getOrm(target.DB)
    .insert(organizations)
    .values({ id: 'org', name: 'enc', billingEmail: 'owner@example.test', createdAt: 'c', updatedAt: 'u' });
  await assert.rejects(restoreArchive(target, archive.bytes, owner.id), {
    message: 'Backup import requires a fresh instance with no vault or send data',
  });
});

test('file Sends travel with their files the way attachments do', async () => {
  const blobs = memoryKv();
  const source = await createTestEnv({ ATTACHMENTS_KV: blobs.binding });
  const owner = await seedUser(source);
  await blobs.binding.put('sends/file-send/file-1', 'file');
  const send = (id: string, type: SendType, data: object) => ({
    id,
    userId: owner.id,
    type,
    name: 'enc-name',
    data: JSON.stringify(data),
    key: 'enc-key',
    createdAt: 'c',
    updatedAt: 'u',
    deletionDate: 'd',
  });
  await getOrm(source.DB)
    .insert(sends)
    .values([
      send('text-send', SendType.Text, { text: 'enc' }),
      send('file-send', SendType.File, { id: 'file-1', fileName: 'enc', size: 4 }),
    ]);

  // Without attachments an archive carries no files, so the file Send stays behind.
  const bare = await archiveOf(source, false);
  assert.equal(bare.manifest.tableCounts.sends, 1);
  assert.equal(bare.manifest.blobSummary.sendFiles, 0);
  const archive = await archiveOf(source);
  assert.deepEqual(archive.manifest.blobSummary, { attachmentFiles: 0, sendFiles: 1, totalBytes: 4, missingFiles: 0 });
  assert.equal(new TextDecoder().decode(unzipSync(archive.bytes)['attachments/sends/file-send/file-1.bin']), 'file');

  // The archive carries the file inline; restore stores it under the Send's blob key.
  const local = memoryKv();
  const restored = await restoreArchive(
    await createTestEnv({ ATTACHMENTS_KV: local.binding }),
    archive.bytes,
    owner.id,
  );
  assert.deepEqual([restored.result.imported.sends, restored.result.imported.sendFiles], [2, 1]);
  assert.deepEqual([...local.values.keys()], ['sends/file-send/file-1']);

  // Without blob storage the file Send cannot restore; it is left out and reported.
  const noStorage = await createTestEnv();
  const skipped = await restoreArchive(noStorage, archive.bytes, owner.id);
  assert.deepEqual(skipped.result.skipped.items, [
    { kind: 'send', path: 'attachments/sends/file-send/file-1.bin', sizeBytes: 4 },
  ]);
  assert.deepEqual(await getOrm(noStorage.DB).select({ id: sends.id }).from(sends), [{ id: 'text-send' }]);
});

test('backup export refuses a row that restore would reject for its size', async () => {
  const source = await createTestEnv();
  await seedUser(source);
  await getOrm(source.DB)
    .insert(config)
    .values({ key: 'oversized', value: 'x'.repeat(33 * 1024 * 1024) });
  await assert.rejects(archiveOf(source, false), {
    message: 'Backup table config holds a row of 33 MiB; restore accepts at most 32 MiB',
  });
});

test('a file the archive lacks leaves its row out and is reported, while the rest restores', async () => {
  const blobs = memoryKv();
  const source = await createTestEnv({ ATTACHMENTS_KV: blobs.binding });
  const owner = await seedUser(source);
  const orm = getOrm(source.DB);
  await orm
    .insert(ciphers)
    .values({ id: 'cipher-1', userId: owner.id, type: 1, data: '{}', createdAt: 'c', updatedAt: 'u' });
  await orm.insert(attachments).values(
    ['kept', 'lost'].map((id) => ({
      id,
      cipherId: 'cipher-1',
      fileName: 'enc',
      size: 4,
      sizeName: '4 Bytes',
      key: 'k',
    })),
  );
  // The lost attachment's blob is already gone, so the archive carries its row without a file.
  await blobs.binding.put('cipher-1/kept', 'kept');
  const archive = await archiveOf(source);
  assert.equal(archive.manifest.blobSummary.missingFiles, 1);

  const restoredBlobs = memoryKv();
  const restored = await createTestEnv({ ATTACHMENTS_KV: restoredBlobs.binding });
  const outcome = await restoreArchive(restored, archive.bytes, owner.id);
  assert.deepEqual(outcome.result.skipped, {
    reason: 'Some files were missing from the archive and were skipped',
    attachments: 1,
    sendFiles: 0,
    items: [{ kind: 'attachment', path: 'attachments/cipher-1/lost.bin', sizeBytes: 4 }],
  });
  assert.deepEqual([...restoredBlobs.values.keys()], ['cipher-1/kept']);
  assert.deepEqual(await getOrm(restored.DB).select({ id: attachments.id }).from(attachments), [{ id: 'kept' }]);
});

test('a database split over several slices restores, and a lost slice fails the manifest count', async () => {
  const source = await createTestEnv();
  const owner = await seedUser(source);
  await getOrm(source.DB)
    .insert(folders)
    .values({ id: 'folder-1', userId: owner.id, name: 'enc', createdAt: 'c', updatedAt: 'u' });
  const { bytes } = await archiveOf(source, false);
  const { folders: folderRows, ...rest } = archiveDb(bytes);
  const encode = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
  const { 'db/0001.json': whole, ...entries } = unzipSync(withArchiveDb(bytes, { ...rest, folders: folderRows }));
  assert.ok(whole);
  const split = { ...entries, 'db/0001.json': encode(rest), 'db/0002.json': encode({ folders: folderRows }) };

  const restored = await createTestEnv();
  await restoreArchive(restored, zipSync(split), owner.id);
  assert.deepEqual(await getOrm(restored.DB).select({ id: folders.id }).from(folders), [{ id: 'folder-1' }]);

  const { 'db/0002.json': lost, ...truncated } = split;
  assert.ok(lost);
  await assert.rejects(restoreArchive(await createTestEnv(), zipSync(truncated), owner.id), {
    message: 'Backup archive is incomplete: folders holds 0 rows, its manifest counts 1',
  });
});

test('a format 2 archive, with the whole database in db.json, still restores', async () => {
  const source = await createTestEnv();
  const owner = await seedUser(source);
  await getOrm(source.DB)
    .insert(folders)
    .values({ id: 'folder-1', userId: owner.id, name: 'enc', createdAt: 'c', updatedAt: 'u' });
  const encode = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
  const legacy = zipSync({
    'manifest.json': encode({ formatVersion: 2 }),
    // A whole database lists every table, empty ones included.
    'db.json': encode({
      ...Object.fromEntries(BACKUP_TABLE_NAMES.map((name) => [name, []])),
      ...archiveDb((await archiveOf(source, false)).bytes),
    }),
  });
  const restored = await createTestEnv();
  await restoreArchive(restored, legacy, owner.id);
  assert.deepEqual(await getOrm(restored.DB).select({ id: folders.id }).from(folders), [{ id: 'folder-1' }]);
});
