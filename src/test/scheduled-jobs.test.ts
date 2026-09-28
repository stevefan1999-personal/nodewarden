import assert from 'node:assert/strict';
import test from 'node:test';
import { eq } from 'drizzle-orm';

import { getOrm } from '../db/client';
import { verification } from '../db/schema';
import type { Env } from '../types';
import { createTestEnv, interceptStatement } from './support/env';

const { default: worker } = await import('../index');

const controller = { cron: '*/5 * * * *', scheduledTime: Date.now(), noRetry() {} } as ScheduledController;

test('a failed scheduled job fails the cron invocation by name while the other jobs still run', async (t) => {
  t.mock.method(console, 'error', () => {});
  const env = await createTestEnv({
    // A runner with no destinations configured, as a real one finds on an instance without backups.
    BACKUP_TRANSFER_RUNNER: {
      idFromName: (name: string) => name,
      get: () => ({ runScheduledBackups: async () => {} }),
    } as unknown as Env['BACKUP_TRANSFER_RUNNER'],
  });
  await worker.scheduled(controller, env);
  // An expired one-time code, which the email code cleanup removes even though event pruning fails.
  await getOrm(env.DB)
    .insert(verification)
    .values({ id: 'expired-code', identifier: 'otp:expired', value: 'hash', expiresAt: 0 });
  interceptStatement(env, /^delete from "events"/, async () => {
    throw new Error('events table unavailable');
  });
  await assert.rejects(worker.scheduled(controller, env), { message: 'Scheduled jobs failed: event cleanup' });
  assert.equal(await getOrm(env.DB).$count(verification, eq(verification.id, 'expired-code')), 0);
});
