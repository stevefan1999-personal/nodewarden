import assert from 'node:assert/strict';
import test from 'node:test';
import { eq, getColumns, getTableName } from 'drizzle-orm';
import { getTableConfig, type SQLiteColumn, type SQLiteTable } from 'drizzle-orm/sqlite-core';
import { unzipSync, zipSync } from 'fflate';

import { getOrm } from '../db/client';
import {
  attachments,
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
import {
  BACKUP_TABLE_NAMES,
  BACKUP_TABLES,
  backupColumns,
  buildBackupArchive,
  type BackupTableName,
} from '../services/backup-archive';
import { importBackupArchiveBytes } from '../services/backup-import';
import { SendType, type Env } from '../types';
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
  const source = await createTestEnv();
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

  const archive = await buildBackupArchive(source, new Date(), { includeAttachments: true });
  const files = unzipSync(archive.bytes);
  const archived = JSON.parse(new TextDecoder().decode(files['db.json'])) as Record<string, Row[]>;
  // An archive from before custom equivalent domains existed lacks the column; restore falls back to its
  // default. Older archives may also still carry runtime-only columns, which restore must ignore.
  const legacy = structuredClone(archived);
  delete legacy.domain_settings.find((row) => row.user_id === owner.id)!.custom_equivalent_domains;
  Object.assign(legacy.users[0], { api_key: 'archived-api-key', user_key_id: 'archived-key-id' });
  files['db.json'] = Buffer.from(JSON.stringify(legacy));

  const kv = memoryKv();
  const restored = await createTestEnv({ ATTACHMENTS_KV: kv.binding });
  // The remote source can still supply only one of the two attachment blobs.
  const outcome = await importBackupArchiveBytes(zipSync(files), restored, owner.id, false, {
    loadAttachment: async (blobName) => (blobName === 'cipher-1/att-1' ? new TextEncoder().encode('blob') : null),
  });
  assert.equal(outcome.result.imported.attachments, 1);
  assert.equal(outcome.result.skipped.attachments, 1);
  assert.deepEqual([...kv.values.keys()], ['cipher-1/att-1']);

  const expected: Record<string, Row[]> = {
    ...archived,
    domain_settings: archived.domain_settings.map((row) =>
      row.user_id === owner.id ? { ...row, custom_equivalent_domains: '[]' } : row,
    ),
    attachments: archived.attachments.filter((row) => row.id === 'att-1'),
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
  const files = unzipSync((await buildBackupArchive(source, new Date(), { includeAttachments: false })).bytes);
  const archived = JSON.parse(new TextDecoder().decode(files['db.json'])) as Record<string, Row[]>;
  delete archived.ciphers[0].favorite;
  files['db.json'] = Buffer.from(JSON.stringify(archived));

  const restored = await createTestEnv();
  await assert.rejects(
    importBackupArchiveBytes(zipSync(files), restored, owner.id, false),
    /NOT NULL constraint failed: ciphers__restore\.favorite/,
  );
  assert.deepEqual(await rowsOf(restored.DB, users, users.id), []);
});

test('backup restore writes tables with more rows than one D1 statement can bind', async () => {
  const source = await createTestEnv();
  // users has 31 columns, so each insert statement carries at most three rows under the 100-parameter cap.
  const seeded = [];
  for (let index = 0; index < 7; index++) seeded.push(await seedUser(source));
  const restored = await createTestEnv();
  await importBackupArchiveBytes(
    (await buildBackupArchive(source, new Date(), { includeAttachments: false })).bytes,
    restored,
    seeded[0].id,
    false,
  );
  assert.deepEqual(
    (await getOrm(restored.DB).select({ id: users.id }).from(users)).map((row) => row.id).toSorted(),
    seeded.map((user) => user.id).toSorted(),
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
  const archive = await buildBackupArchive(source, new Date(), { includeAttachments: false });
  await importBackupArchiveBytes(archive.bytes, await createTestEnv(), owner.id, false);
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
  const archive = await buildBackupArchive(source, new Date(), { includeAttachments: true });
  await importBackupArchiveBytes(archive.bytes, restored, String(seeded.get('users')!.id), false);
  assert.deepEqual(await archivedTables(restored.DB), await archivedTables(source.DB));
});

test('a replacing restore swaps every archived table of a populated instance for the archive', async () => {
  const source = await createTestEnv();
  const seeded = await seedEveryArchivedTable(source, 'source');
  const target = await createTestEnv();
  await seedEveryArchivedTable(target, 'target');
  const archive = await buildBackupArchive(source, new Date(), { includeAttachments: true });
  await importBackupArchiveBytes(archive.bytes, target, String(seeded.get('users')!.id), true);
  assert.deepEqual(await archivedTables(target.DB), await archivedTables(source.DB));
});

test('backup restore without replace refuses an instance that already has an organization', async () => {
  const source = await createTestEnv();
  const owner = await seedUser(source);
  const archive = await buildBackupArchive(source, new Date(), { includeAttachments: false });
  const target = await createTestEnv();
  await getOrm(target.DB)
    .insert(organizations)
    .values({ id: 'org', name: 'enc', billingEmail: 'owner@example.test', createdAt: 'c', updatedAt: 'u' });
  await assert.rejects(importBackupArchiveBytes(archive.bytes, target, owner.id, false), {
    message: 'Backup import requires a fresh instance with no vault or send data',
  });
});

test('file Sends travel with their files the way attachments do', async () => {
  const source = await createTestEnv();
  const owner = await seedUser(source);
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
  const bare = await buildBackupArchive(source, new Date(), { includeAttachments: false });
  assert.equal(bare.manifest.tableCounts.sends, 1);
  assert.deepEqual(bare.manifest.sendFileBlobs, []);
  const archive = await buildBackupArchive(source, new Date(), { includeAttachments: true });
  assert.deepEqual(archive.manifest.sendFileBlobs, [
    { sendId: 'file-send', fileId: 'file-1', blobName: 'sends/file-send/file-1', sizeBytes: 4 },
  ]);
  const files = unzipSync(archive.bytes);
  files['attachments/sends/file-send/file-1.bin'] = Buffer.from('file');

  // A local archive carries the file inline; restore stores it under the Send's blob key.
  const local = memoryKv();
  const restored = await importBackupArchiveBytes(
    zipSync(files),
    await createTestEnv({ ATTACHMENTS_KV: local.binding }),
    owner.id,
    false,
  );
  assert.deepEqual([restored.result.imported.sends, restored.result.imported.sendFiles], [2, 1]);
  assert.deepEqual([...local.values.keys()], ['sends/file-send/file-1']);

  // A remote destination supplies it by blob name instead.
  const remote = memoryKv();
  const requested: string[] = [];
  await importBackupArchiveBytes(
    archive.bytes,
    await createTestEnv({ ATTACHMENTS_KV: remote.binding }),
    owner.id,
    false,
    {
      loadAttachment: async (blobName) => (requested.push(blobName), Buffer.from('file')),
    },
  );
  assert.deepEqual(requested, ['sends/file-send/file-1']);
  assert.deepEqual([...remote.values.keys()], ['sends/file-send/file-1']);

  // Without blob storage the file Send cannot restore; it is left out and reported.
  const noStorage = await createTestEnv();
  const skipped = await importBackupArchiveBytes(zipSync(files), noStorage, owner.id, false);
  assert.deepEqual(skipped.result.skipped.items, [
    { kind: 'send', path: 'attachments/sends/file-send/file-1.bin', sizeBytes: 4 },
  ]);
  assert.deepEqual(await getOrm(noStorage.DB).select({ id: sends.id }).from(sends), [{ id: 'text-send' }]);
});
