import assert from 'node:assert/strict';
import test from 'node:test';
import { tenantDeployMetadata } from '../../scripts/build-tenant-artifact.mjs';

test('tenant artifacts preserve resource bindings and force the billing gate before assets without copying tenant values', () => {
  const metadata = tenantDeployMetadata(
    {
      compatibility_date: '2024-09-23',
      compatibility_flags: ['nodejs_compat'],
      assets: {
        binding: 'ASSETS',
        run_worker_first: ['/api/*'],
        html_handling: 'none',
        not_found_handling: 'single-page-application',
      },
      durable_objects: {
        bindings: [
          { name: 'NOTIFICATIONS_HUB', class_name: 'NotificationsHub' },
          { name: 'BACKUP_TRANSFER_RUNNER', class_name: 'BackupTransferRunner' },
        ],
      },
      ratelimits: [{ name: 'RATE_LIMIT_30_PER_MINUTE', namespace_id: '7301', simple: { limit: 30, period: 60 } }],
      vars: { JWT_SECRET: 'must-not-copy', WEB_VAULT_ORIGINS: 'https://original.example' },
      triggers: { crons: ['*/5 * * * *'] },
      d1_databases: [{ binding: 'DB', database_id: 'original-account-resource' }],
    },
    '/*\n  X-Frame-Options: DENY\n',
  );
  assert.deepEqual(metadata.assetConfig, {
    html_handling: 'none',
    not_found_handling: 'single-page-application',
    run_worker_first: true,
    _headers: '/*\n  X-Frame-Options: DENY\n',
  });
  assert.deepEqual(metadata.staticBindings, [
    { type: 'assets', name: 'ASSETS' },
    { type: 'durable_object_namespace', name: 'NOTIFICATIONS_HUB', class_name: 'NotificationsHub' },
    { type: 'durable_object_namespace', name: 'BACKUP_TRANSFER_RUNNER', class_name: 'BackupTransferRunner' },
    { type: 'ratelimit', name: 'RATE_LIMIT_30_PER_MINUTE', namespace_id: '7301', simple: { limit: 30, period: 60 } },
  ]);
  assert.deepEqual(metadata.exports, {
    NotificationsHub: { type: 'durable-object', storage: 'sqlite' },
    BackupTransferRunner: { type: 'durable-object', storage: 'sqlite' },
  });
  assert.equal(metadata.observability.enabled, false);
  assert.doesNotMatch(JSON.stringify(metadata), /must-not-copy|original|crons/);
});
