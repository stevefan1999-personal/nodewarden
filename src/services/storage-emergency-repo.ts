import { and, desc, eq, isNotNull } from 'drizzle-orm';

import { Repository, repository } from '../db/client';
import { emergencyAccess } from '../db/schema';
import { bound, lower } from '../db/sql';

export const EmergencyAccessType = {
  View: 0,
  Takeover: 1,
} as const;

export const EmergencyAccessStatus = {
  Invited: 0,
  Accepted: 1,
  Confirmed: 2,
  RecoveryInitiated: 3,
  RecoveryApproved: 4,
} as const;

export type EmergencyAccessRecord = typeof emergencyAccess.$inferSelect;

export class EmergencyRepository extends Repository {
  async saveEmergencyAccess(record: EmergencyAccessRecord): Promise<void> {
    await this.orm
      .insert(emergencyAccess)
      .values(record)
      .onConflictDoUpdate({
        target: emergencyAccess.id,
        set: {
          grantorId: record.grantorId,
          granteeId: record.granteeId,
          email: record.email,
          keyEncrypted: record.keyEncrypted,
          type: record.type,
          status: record.status,
          waitTimeDays: record.waitTimeDays,
          recoveryInitiatedAt: record.recoveryInitiatedAt,
          lastNotificationAt: record.lastNotificationAt,
          updatedAt: record.updatedAt,
        },
      });
  }

  async getEmergencyAccess(id: string): Promise<EmergencyAccessRecord | null> {
    const [row] = await this.orm.select().from(emergencyAccess).where(eq(emergencyAccess.id, id)).limit(1);
    return row ?? null;
  }

  async listByGrantor(grantorId: string): Promise<EmergencyAccessRecord[]> {
    const rows = await this.orm
      .select()
      .from(emergencyAccess)
      .where(eq(emergencyAccess.grantorId, grantorId))
      .orderBy(desc(emergencyAccess.createdAt));
    return rows;
  }

  async listByGrantee(granteeId: string): Promise<EmergencyAccessRecord[]> {
    const rows = await this.orm
      .select()
      .from(emergencyAccess)
      .where(eq(emergencyAccess.granteeId, granteeId))
      .orderBy(desc(emergencyAccess.createdAt));
    return rows;
  }

  async findInvite(grantorId: string, email: string): Promise<EmergencyAccessRecord | null> {
    const [row] = await this.orm
      .select()
      .from(emergencyAccess)
      .where(and(eq(emergencyAccess.grantorId, grantorId), eq(lower(emergencyAccess.email), lower(email))))
      .limit(1);
    return row ?? null;
  }

  async deleteEmergencyAccess(id: string): Promise<void> {
    await this.orm.delete(emergencyAccess).where(eq(emergencyAccess.id, id));
  }

  async listRecoveryReady(nowIso: string): Promise<EmergencyAccessRecord[]> {
    const rows = await this.orm
      .select()
      .from(emergencyAccess)
      .where(
        and(
          eq(emergencyAccess.status, EmergencyAccessStatus.RecoveryInitiated),
          isNotNull(emergencyAccess.recoveryInitiatedAt),
        ),
      );
    return rows.filter((record) => {
      if (!record.recoveryInitiatedAt) return false;
      const started = Date.parse(record.recoveryInitiatedAt);
      if (!Number.isFinite(started)) return false;
      return Date.parse(nowIso) - started >= record.waitTimeDays * 24 * 60 * 60 * 1000;
    });
  }

  async listRecoveryToNotify(nowIso: string): Promise<EmergencyAccessRecord[]> {
    const rows = await this.orm
      .select()
      .from(emergencyAccess)
      .where(eq(emergencyAccess.status, EmergencyAccessStatus.RecoveryInitiated));
    const now = Date.parse(nowIso);
    const day = 86_400_000;
    return rows.filter((record) => {
      if (!record.recoveryInitiatedAt || !record.lastNotificationAt) return false;
      const deadline = Date.parse(record.recoveryInitiatedAt) + record.waitTimeDays * day;
      return now >= deadline - day && now < deadline && now >= Date.parse(record.lastNotificationAt) + day;
    });
  }

  async claimRecoveryNotification(record: EmergencyAccessRecord, nowIso: string): Promise<boolean> {
    const rows = await this.orm
      .update(emergencyAccess)
      .set({ lastNotificationAt: nowIso })
      .where(
        and(
          eq(emergencyAccess.id, record.id),
          eq(emergencyAccess.status, EmergencyAccessStatus.RecoveryInitiated),
          // Compare-and-swap on the listed snapshot; a NULL date binds NULL and never matches.
          eq(emergencyAccess.lastNotificationAt, bound(record.lastNotificationAt)),
          eq(emergencyAccess.recoveryInitiatedAt, bound(record.recoveryInitiatedAt)),
          eq(emergencyAccess.waitTimeDays, record.waitTimeDays),
        ),
      )
      .returning({ id: emergencyAccess.id });
    return rows.length > 0;
  }
}

export const emergencyRepo = repository(EmergencyRepository);
