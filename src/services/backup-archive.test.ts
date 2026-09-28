import assert from 'node:assert/strict';
import { test } from 'node:test';
import { getTableName, is } from 'drizzle-orm';
import { getTableConfig, SQLiteTable } from 'drizzle-orm/sqlite-core';

import * as schema from '../db/schema';
import {
  BACKUP_TABLE_NAMES,
  BACKUP_TABLES,
  isSafeBackupBlobName,
  parseBackupManifest,
  parseDbEntry,
} from './backup-archive';

// Tables that stay with their instance, and why. Every other table must be archived.
const INSTANCE_LOCAL_TABLES: Record<string, string> = {
  session: 'runtime authentication',
  account: "Better Auth's copy of the master password hash, rebuilt by the next password change",
  verification: 'one-time tokens',
  devices: 'runtime authentication',
  auth_requests: 'runtime authentication',
  trusted_two_factor_device_tokens: 'remembered two-step devices',
  totp_login_replays: 'one-time replay guard',
  webauthn_challenges: 'one-time challenges',
  login_attempts_ip: 'rate limiting',
  rate_limit_buckets: 'rate limiting',
  used_attachment_download_tokens: 'one-time tokens',
  sso_auth: 'one-time SSO state',
  audit_logs: 'administrator log, which a restore must not rewrite',
  backup_restore_rows: 'restore staging',
};

const tables = { config: [], users: [], user_revisions: [], folders: [], ciphers: [], attachments: [] };
const json = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));

test('a database entry keeps only allowlisted tables, and a whole database must list the required ones', () => {
  assert.deepEqual(parseDbEntry(json({ ...tables, devices: [{ id: 'd1' }] }), true), tables);
  // A slice holds whichever tables it reaches.
  assert.deepEqual(parseDbEntry(json({ folders: [] }), false), { folders: [] });
  const required = BACKUP_TABLE_NAMES.find((name) => 'required' in BACKUP_TABLES[name]);
  assert.throws(() => parseDbEntry(json({}), true), { message: `Backup archive table ${required} is invalid` });
});

test('manifests and database entries name the first malformed field', () => {
  const manifests: Array<[unknown, string]> = [
    [{ formatVersion: 4 }, 'Unsupported backup format version'],
    [null, 'Unsupported backup format version'],
    [{ formatVersion: 3, tableCounts: { users: 'many' } }, 'Backup archive manifest is invalid'],
  ];
  for (const [manifest, message] of manifests) assert.throws(() => parseBackupManifest(json(manifest)), { message });
  assert.throws(() => parseBackupManifest(new TextEncoder().encode('{not json')), {
    message: 'Backup archive contains invalid JSON metadata',
  });
  const entries: Array<[unknown, string]> = [
    [[], 'Backup archive database payload is invalid'],
    [{ ...tables, users: {} }, 'Backup archive table users is invalid'],
    [{ ...tables, ciphers: [{ data: { nested: true } }] }, 'Backup archive table ciphers is invalid'],
  ];
  for (const [db, message] of entries) assert.throws(() => parseDbEntry(json(db), true), { message });
});

test('every schema table is either archived or kept with its instance', () => {
  const tables = Object.values(schema)
    .filter((value) => is(value, SQLiteTable))
    .map((table) => getTableName(table));
  assert.deepEqual(
    tables.filter((name) => !(name in BACKUP_TABLES) && !(name in INSTANCE_LOCAL_TABLES)),
    [],
  );
  assert.deepEqual(
    BACKUP_TABLE_NAMES.filter((name) => name in INSTANCE_LOCAL_TABLES),
    [],
  );
});

test('archived tables come after every table their rows reference', () => {
  for (const [index, name] of BACKUP_TABLE_NAMES.entries())
    for (const foreignKey of getTableConfig(BACKUP_TABLES[name].table).foreignKeys) {
      const parent = getTableName(foreignKey.reference().foreignTable);
      assert.ok(
        BACKUP_TABLE_NAMES.slice(0, index).some((earlier) => earlier === parent),
        `${name} references ${parent}`,
      );
    }
});

test('archives accept only attachment and Send file blob keys', () => {
  for (const name of ['cipher-1/attachment-1', 'sends/send-1/file-1'])
    assert.equal(isSafeBackupBlobName(name), true, name);
  for (const name of [
    'attachment-1',
    'cipher-1/attachment-1/extra',
    'sends/send-1/file-1/extra',
    'cipher-1/..',
    'sends/../file-1',
    '../etc/passwd',
    'cipher 1/attachment-1',
    '',
  ])
    assert.equal(isSafeBackupBlobName(name), false, name);
});
