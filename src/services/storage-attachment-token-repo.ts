import { lt } from 'drizzle-orm';

import { LIMITS } from '../config/limits';
import { Repository, repository } from '../db/client';
import { usedAttachmentDownloadTokens } from '../db/schema';
import { shouldRunPeriodicCleanup } from './periodic-cleanup';

let lastCleanupAt = 0;

export class AttachmentTokenRepository extends Repository {
  // Marks a download token JTI as used; true only on first use.
  async consumeAttachmentDownloadToken(jti: string, expUnixSeconds: number): Promise<boolean> {
    const nowMs = Date.now();
    if (shouldRunPeriodicCleanup(lastCleanupAt, LIMITS.cleanup.attachmentTokenCleanupIntervalMs)) {
      await this.orm.delete(usedAttachmentDownloadTokens).where(lt(usedAttachmentDownloadTokens.expiresAt, nowMs));
      lastCleanupAt = nowMs;
    }
    const result = await this.orm
      .insert(usedAttachmentDownloadTokens)
      .values({ jti, expiresAt: expUnixSeconds * 1000 })
      .onConflictDoNothing({ target: usedAttachmentDownloadTokens.jti })
      .run();
    return (result.meta.changes ?? 0) > 0;
  }
}

export const attachmentTokenRepo = repository(AttachmentTokenRepository);
