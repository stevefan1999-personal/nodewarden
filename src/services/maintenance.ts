import { pruneEvents } from './events';
import { purgeExpiredEmailOtps } from './email-otp';
import { smRepo } from './storage-secret-repo';
import { purgeExpiredSends, purgeOldTrash } from './retention';
import { runScheduledBackupIfDue } from '../handlers/backup';
import { approveExpiredEmergencyAccess, remindPendingEmergencyAccess } from '../handlers/emergency-access';
import { withoutQueryParams } from '../db/client';
import type { Env } from '../types';

// Shared by standalone cron and the platform's authenticated fleet tick. Every job runs even
// when another fails; failures reach the caller so a platform tick cannot silently lose work.
export async function runMaintenance(env: Env): Promise<void> {
  const jobs = {
    'event cleanup': () => pruneEvents(env.DB),
    'email code cleanup': () => purgeExpiredEmailOtps(env.DB),
    'scheduled backup': () => runScheduledBackupIfDue(env),
    'Secrets Manager trash purge': () => smRepo(env.DB).purgeSecretsTrash(),
    'emergency access timeouts': () => approveExpiredEmergencyAccess(env),
    'emergency access reminders': () => remindPendingEmergencyAccess(env),
    'expired Send purge': () => purgeExpiredSends(env),
    'trash purge': () => purgeOldTrash(env),
  };
  const outcomes = await Promise.allSettled(Object.values(jobs).map((job) => job()));
  const failed = Object.keys(jobs).filter((name, index) => {
    const outcome = outcomes[index];
    if (outcome.status === 'rejected')
      console.error(`Scheduled job failed: ${name}`, withoutQueryParams(outcome.reason));
    return outcome.status === 'rejected';
  });
  if (failed.length) throw new Error(`Scheduled jobs failed: ${failed.join(', ')}`);
}
