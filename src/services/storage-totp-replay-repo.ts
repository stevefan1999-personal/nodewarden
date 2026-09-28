import { lt } from 'drizzle-orm';

import { Repository, repository } from '../db/client';
import { totpLoginReplays } from '../db/schema';
import { shouldRunPeriodicCleanup } from './periodic-cleanup';

const CLEANUP_INTERVAL_MS = 10 * 60 * 1000;
const MARKER_TTL_MS = 5 * 60 * 1000;
let lastCleanupAt = 0;

export class TotpReplayRepository extends Repository {
  // Records a TOTP time step as used for the user; false when that step was already consumed.
  async consumeTotpLoginCounter(userId: string, timeCounter: number, consumedAtMs = Date.now()): Promise<boolean> {
    if (!Number.isSafeInteger(timeCounter) || timeCounter < 0) return false;
    if (shouldRunPeriodicCleanup(lastCleanupAt, CLEANUP_INTERVAL_MS)) {
      await this.orm.delete(totpLoginReplays).where(lt(totpLoginReplays.consumedAt, consumedAtMs - MARKER_TTL_MS));
      lastCleanupAt = consumedAtMs;
    }
    const result = await this.orm
      .insert(totpLoginReplays)
      .values({ userId, timeCounter, consumedAt: consumedAtMs })
      .onConflictDoNothing({ target: [totpLoginReplays.userId, totpLoginReplays.timeCounter] })
      .run();
    return (result.meta.changes ?? 0) > 0;
  }
}

export const totpReplayRepo = repository(TotpReplayRepository);
