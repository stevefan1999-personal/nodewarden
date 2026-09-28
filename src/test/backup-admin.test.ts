import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import test from 'node:test';

import { getOrm } from '../db/client';
import { folders } from '../db/schema';
import { hashPassword } from '../services/auth-password';
import { DEFAULT_BACKUP_SCHEDULE } from '../services/backup-config';
import type { Env } from '../types';
import { authedFetch, createTestEnv, memoryR2, seedUser } from './support/env';

const PASSWORD = 'client-derived-password-hash';
// 03:01 UTC on a day the default 03:00 UTC slot is due.
const DUE = new Date('2026-09-29T03:01:00Z');
// The settings of an R2 API token for the BACKUPS bucket, which presigned URLs are signed with.
const TRANSFER_SETTINGS = {
  R2_ACCOUNT_ID: 'account-id',
  R2_ACCESS_KEY_ID: 'key-id',
  R2_SECRET_ACCESS_KEY: 'secret-key',
  BACKUPS_BUCKET_NAME: 'nodewarden-backups',
};

// An instance whose administrator knows PASSWORD, with calls made as that administrator.
async function adminInstance(overrides: Partial<Env> = {}) {
  const env = await createTestEnv(overrides);
  const admin = await seedUser(env, { role: 'admin', masterPasswordHash: await hashPassword(PASSWORD) });
  const call = (method: string, path: string, body?: unknown) =>
    authedFetch(env, { method, path, userId: admin.id, body });
  return { env, admin, call };
}

test('backup settings start from the defaults, merge a partial save and name each broken field', async () => {
  const { env, call } = await adminInstance();
  const settings = await call('GET', '/api/admin/backup/settings');
  assert.equal(settings.status, 200);
  assert.deepEqual(await settings.json(), {
    object: 'backup-settings',
    schedule: DEFAULT_BACKUP_SCHEDULE,
    status: {
      lastAttemptAt: null,
      lastSuccessAt: null,
      lastErrorAt: null,
      lastErrorMessage: null,
      lastArchiveKey: null,
      lastArchiveBytes: null,
    },
    storageConfigured: true,
    transfersConfigured: false,
  });

  for (const [body, message] of [
    [[], 'Backup settings payload is invalid'],
    [{ schedule: { enabled: true } }, 'masterPasswordHash is required'],
    [{ schedule: { enabled: true }, masterPasswordHash: 'wrong' }, 'Invalid password'],
  ] as const) {
    const refused = await call('PUT', '/api/admin/backup/settings', body);
    assert.equal(refused.status, 400);
    assert.equal(((await refused.json()) as { message: string }).message, message);
  }

  const saved = await call('PUT', '/api/admin/backup/settings', {
    masterPasswordHash: PASSWORD,
    schedule: { enabled: true, intervalHours: 12 },
  });
  assert.equal(saved.status, 200);
  assert.deepEqual(((await saved.json()) as { schedule: unknown }).schedule, {
    ...DEFAULT_BACKUP_SCHEDULE,
    enabled: true,
    intervalHours: 12,
  });

  const invalid = await call('PUT', '/api/admin/backup/settings', {
    masterPasswordHash: PASSWORD,
    schedule: { intervalHours: 0, startTime: '25:00' },
  });
  assert.equal(invalid.status, 400);
  assert.deepEqual(((await invalid.json()) as { validationErrors: unknown }).validationErrors, {
    'schedule.intervalHours': ['Backup interval hours must be between 1 and 99'],
    'schedule.startTime': ['Backup start time must be in HH:mm format'],
  });

  const member = await seedUser(env);
  const forbidden = await authedFetch(env, { path: '/api/admin/backup/settings', userId: member.id });
  assert.equal(forbidden.status, 403);
});

test('a backup run stores an archive, records it and prunes run archives beyond the retention count', async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: DUE });
  const bucket = memoryR2();
  const { call } = await adminInstance({ BACKUPS: bucket.binding });
  await bucket.binding.put('uploads/kept.zip', 'uploaded archive');
  await call('PUT', '/api/admin/backup/settings', { masterPasswordHash: PASSWORD, schedule: { retentionCount: 2 } });

  const keys: string[] = [];
  for (let run = 0; run < 3; run++) {
    t.mock.timers.tick(1000);
    const response = await call('POST', '/api/admin/backup/run', { masterPasswordHash: PASSWORD });
    assert.equal(response.status, 200);
    keys.push(((await response.json()) as { archive: { key: string } }).archive.key);
  }
  assert.equal(new Set(keys).size, 3);

  const listed = (await (await call('GET', '/api/admin/backup/archives')).json()) as { data: { key: string }[] };
  assert.deepEqual(
    listed.data.map(({ key }) => key),
    [keys[2], keys[1], 'uploads/kept.zip'],
  );
  const { status } = (await (await call('GET', '/api/admin/backup/settings')).json()) as {
    status: { lastSuccessAt: string; lastArchiveKey: string };
  };
  assert.deepEqual([status.lastSuccessAt, status.lastArchiveKey], [new Date().toISOString(), keys[2]]);
});

test('a restore by key rebuilds a fresh instance from an archive in the bucket', async () => {
  const bucket = memoryR2();
  const source = await adminInstance({ BACKUPS: bucket.binding });
  await getOrm(source.env.DB)
    .insert(folders)
    .values({ id: 'folder-1', userId: source.admin.id, name: 'enc', createdAt: 'c', updatedAt: 'u' });
  const run = await source.call('POST', '/api/admin/backup/run', { masterPasswordHash: PASSWORD });
  const { key } = ((await run.json()) as { archive: { key: string } }).archive;

  const target = await adminInstance({ BACKUPS: bucket.binding });
  const restored = await target.call('POST', '/api/admin/backup/archives/restore', {
    key,
    masterPasswordHash: PASSWORD,
  });
  assert.equal(restored.status, 200);
  assert.deepEqual(await getOrm(target.env.DB).select({ id: folders.id }).from(folders), [{ id: 'folder-1' }]);
});

test('archive keys outside the bucket layout are refused, and a delete removes the archive', async () => {
  const bucket = memoryR2();
  const { call } = await adminInstance({ BACKUPS: bucket.binding });
  await bucket.binding.put('uploads/archive.zip', 'uploaded archive');
  for (const key of ['../escape.zip', 'nested/dir/archive.zip', 'archive.txt', '']) {
    for (const [method, path] of [
      ['POST', '/api/admin/backup/archives/restore'],
      ['DELETE', '/api/admin/backup/archives'],
    ]) {
      const refused = await call(method, path, { key, masterPasswordHash: PASSWORD });
      assert.equal(refused.status, 400, `${method} ${key}`);
      assert.equal(((await refused.json()) as { message: string }).message, 'Backup archive key is invalid');
    }
  }
  const deleted = await call('DELETE', '/api/admin/backup/archives', {
    key: 'uploads/archive.zip',
    masterPasswordHash: PASSWORD,
  });
  assert.equal(deleted.status, 200);
  assert.deepEqual([...bucket.objects.keys()], []);
});

test('without a backup bucket the settings say so and every archive route answers 409', async () => {
  const { call } = await adminInstance({ BACKUPS: undefined });
  const settings = (await (await call('GET', '/api/admin/backup/settings')).json()) as { storageConfigured: boolean };
  assert.equal(settings.storageConfigured, false);
  for (const [method, path] of [
    ['POST', '/api/admin/backup/run'],
    ['GET', '/api/admin/backup/archives'],
    ['POST', '/api/admin/backup/archives/restore'],
    ['DELETE', '/api/admin/backup/archives'],
  ]) {
    const response = await call(
      method,
      path,
      method === 'GET' ? undefined : { key: 'a.zip', masterPasswordHash: PASSWORD },
    );
    assert.equal(response.status, 409, `${method} ${path}`);
    assert.equal(((await response.json()) as { message: string }).message, 'Backup storage is not configured');
  }
});

test('the scheduled runner backs up once for a due slot', async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: DUE });
  const bucket = memoryR2();
  const { env, call } = await adminInstance({ BACKUPS: bucket.binding });
  await call('PUT', '/api/admin/backup/settings', { masterPasswordHash: PASSWORD, schedule: { enabled: true } });
  const runner = env.BACKUP_TRANSFER_RUNNER.get(env.BACKUP_TRANSFER_RUNNER.idFromName('configured-backup-runner'));
  await runner.runScheduledBackups();
  t.mock.timers.tick(60_000);
  await runner.runScheduledBackups();
  assert.equal(bucket.objects.size, 1);
});

test('archive transfers are refused until the R2 S3 credentials are set', async () => {
  const { call } = await adminInstance();
  for (const path of ['/api/admin/backup/archives/download', '/api/admin/backup/archives/upload']) {
    const refused = await call('POST', path, { key: 'uploads/a.zip', masterPasswordHash: PASSWORD });
    assert.equal(refused.status, 409, path);
    assert.equal(
      ((await refused.json()) as { message: string }).message,
      'Presigned backup transfers need R2 S3 credentials',
    );
  }
});

test('an archive downloads and uploads through presigned R2 URLs that expire in 15 minutes', async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: DUE });
  const bucket = memoryR2();
  const { call } = await adminInstance({ BACKUPS: bucket.binding, ...TRANSFER_SETTINGS });
  const key = 'nodewarden_backup_20260929_030000_abcde.zip';
  await bucket.binding.put(key, 'archive');
  const signing = {
    'X-Amz-Expires': '900',
    'X-Amz-Date': '20260929T030100Z',
    'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
    'X-Amz-Credential': 'key-id/20260929/auto/s3/aws4_request',
    'X-Amz-SignedHeaders': 'host',
  };
  type Transfer = { method: string; key: string; url: string; expiresAt: string };
  const unsigned = (url: URL) =>
    Object.fromEntries([...url.searchParams].filter(([name]) => name !== 'X-Amz-Signature'));

  const missing = await call('POST', '/api/admin/backup/archives/download', {
    key: 'uploads/absent.zip',
    masterPasswordHash: PASSWORD,
  });
  assert.equal(missing.status, 404);

  const download = (await (
    await call('POST', '/api/admin/backup/archives/download', { key, masterPasswordHash: PASSWORD })
  ).json()) as Transfer;
  const downloadUrl = new URL(download.url);
  assert.deepEqual([download.method, download.key, download.expiresAt], ['GET', key, '2026-09-29T03:16:00.000Z']);
  assert.equal(
    downloadUrl.origin + downloadUrl.pathname,
    `https://account-id.r2.cloudflarestorage.com/nodewarden-backups/${key}`,
  );
  assert.deepEqual(unsigned(downloadUrl), {
    ...signing,
    'response-content-disposition': `attachment; filename="${key}"`,
  });
  assert.match(downloadUrl.searchParams.get('X-Amz-Signature')!, /^[0-9a-f]{64}$/);

  const upload = (await (
    await call('POST', '/api/admin/backup/archives/upload', { masterPasswordHash: PASSWORD })
  ).json()) as Transfer;
  const uploadUrl = new URL(upload.url);
  assert.equal(upload.method, 'PUT');
  assert.match(upload.key, /^uploads\/[0-9a-f-]{36}\.zip$/);
  assert.equal(uploadUrl.pathname, `/nodewarden-backups/${upload.key}`);
  assert.deepEqual(unsigned(uploadUrl), signing);
});

test('each wrangler config names the BACKUPS bucket that presigned URLs address', () => {
  for (const file of ['wrangler.toml', 'wrangler.kv.toml']) {
    const toml = readFileSync(resolve(import.meta.dirname, '../..', file), 'utf8');
    const bucket = /\[\[r2_buckets\]\]\s*binding = "BACKUPS"\s*bucket_name = "([^"]+)"/.exec(toml)?.[1];
    assert.ok(bucket, file);
    assert.equal(/^BACKUPS_BUCKET_NAME = "([^"]+)"/m.exec(toml)?.[1], bucket, file);
  }
});
