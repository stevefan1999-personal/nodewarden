import { and, eq, gte, isNotNull, isNull, lt, or } from 'drizzle-orm';
import { sha256 } from 'hono/utils/crypto';

import { Repository, repository } from '../db/client';
import { session } from '../db/schema';
import { caseWhen } from '../db/sql';
import type { RefreshTokenRecord } from '../types';
import { LIMITS } from '../config/limits';
import { shouldRunPeriodicCleanup } from './periodic-cleanup';

let lastCleanupAt = 0;

// Tokens are stored as their SHA-256, so a database read never yields a usable credential.
export async function hashedTokenKey(token: string): Promise<string> {
  return `sha256:${await sha256(token)}`;
}

export class SessionRepository extends Repository {
  private async maybeCleanupExpiredRefreshTokens(nowMs: number): Promise<void> {
    if (!shouldRunPeriodicCleanup(lastCleanupAt, LIMITS.cleanup.refreshTokenCleanupIntervalMs)) return;
    await this.deleteExpiredRefreshTokens(nowMs);
    lastCleanupAt = nowMs;
  }

  async saveRefreshToken(
    token: string,
    userId: string,
    expiresAtMs?: number,
    deviceIdentifier?: string | null,
    deviceSessionStamp?: string | null,
    securityStamp?: string | null,
    clientType?: string | null,
    absoluteExpiresAtMs?: number | null,
  ): Promise<void> {
    const now = Date.now();
    await this.maybeCleanupExpiredRefreshTokens(now);
    const tokenKey = await hashedTokenKey(token);
    const expiresAt = expiresAtMs ?? now + LIMITS.auth.refreshTokenDefaultSlidingTtlMs;
    const absoluteExpiresAt = absoluteExpiresAtMs ?? now + LIMITS.auth.refreshTokenAbsoluteTtlMs;
    await this.orm
      .insert(session)
      .values({
        id: crypto.randomUUID(),
        token: tokenKey,
        userId,
        expiresAt,
        createdAt: now,
        updatedAt: now,
        deviceIdentifier: deviceIdentifier ?? null,
        deviceSessionStamp: deviceSessionStamp ?? null,
        securityStamp: securityStamp ?? null,
        clientType: clientType ?? null,
        absoluteExpiresAt,
        lastUsedAt: now,
      })
      .onConflictDoUpdate({
        target: session.token,
        set: {
          userId,
          expiresAt,
          updatedAt: now,
          deviceIdentifier: deviceIdentifier ?? null,
          deviceSessionStamp: deviceSessionStamp ?? null,
          securityStamp: securityStamp ?? null,
          clientType: clientType ?? null,
          lastUsedAt: now,
          absoluteExpiresAt,
        },
      });
  }

  async getRefreshTokenRecord(token: string): Promise<RefreshTokenRecord | null> {
    const now = Date.now();
    await this.maybeCleanupExpiredRefreshTokens(now);
    const tokenKey = await hashedTokenKey(token);
    const [row] = await this.orm.select().from(session).where(eq(session.token, tokenKey)).limit(1);
    if (!row) return null;
    if ((row.expiresAt && row.expiresAt < now) || (row.absoluteExpiresAt && row.absoluteExpiresAt < now)) {
      await this.deleteRefreshToken(token);
      return null;
    }
    return row;
  }

  async getRefreshTokenUserId(token: string): Promise<string | null> {
    return (await this.getRefreshTokenRecord(token))?.userId ?? null;
  }

  async extendRefreshTokenExpiry(token: string, requestedExpiresAtMs: number, nowMs = Date.now()): Promise<boolean> {
    const tokenKey = await hashedTokenKey(token);
    const result = await this.orm
      .update(session)
      .set({
        expiresAt: caseWhen(
          and(isNotNull(session.absoluteExpiresAt), lt(session.absoluteExpiresAt, requestedExpiresAtMs)),
          session.absoluteExpiresAt,
          requestedExpiresAtMs,
        ),
        lastUsedAt: nowMs,
        updatedAt: nowMs,
      })
      .where(
        and(
          eq(session.token, tokenKey),
          gte(session.expiresAt, nowMs),
          or(isNull(session.absoluteExpiresAt), gte(session.absoluteExpiresAt, nowMs)),
        ),
      )
      .run();
    return Number(result.meta.changes ?? 0) > 0;
  }

  async bindRefreshTokenSecurityStamp(token: string, securityStamp: string): Promise<void> {
    const tokenKey = await hashedTokenKey(token);
    await this.orm
      .update(session)
      .set({ securityStamp, updatedAt: Date.now() })
      .where(and(eq(session.token, tokenKey), or(isNull(session.securityStamp), eq(session.securityStamp, ''))));
  }

  async bindRefreshTokenDeviceStamp(token: string, deviceSessionStamp: string): Promise<void> {
    const tokenKey = await hashedTokenKey(token);
    await this.orm
      .update(session)
      .set({ deviceSessionStamp, updatedAt: Date.now() })
      .where(
        and(eq(session.token, tokenKey), or(isNull(session.deviceSessionStamp), eq(session.deviceSessionStamp, ''))),
      );
  }

  async deleteRefreshToken(token: string): Promise<void> {
    const tokenKey = await hashedTokenKey(token);
    await this.orm.delete(session).where(eq(session.token, token));
    await this.orm.delete(session).where(eq(session.token, tokenKey));
  }

  async deleteRefreshTokensByUserId(userId: string): Promise<number> {
    const result = await this.orm.delete(session).where(eq(session.userId, userId)).run();
    return Number(result.meta.changes ?? 0);
  }

  async deleteRefreshTokensByDevice(userId: string, deviceIdentifier: string): Promise<number> {
    const result = await this.orm
      .delete(session)
      .where(and(eq(session.userId, userId), eq(session.deviceIdentifier, deviceIdentifier)))
      .run();
    return Number(result.meta.changes ?? 0);
  }

  async deleteExpiredRefreshTokens(nowMs: number): Promise<void> {
    await this.orm
      .delete(session)
      .where(
        or(
          lt(session.expiresAt, nowMs),
          and(isNotNull(session.absoluteExpiresAt), lt(session.absoluteExpiresAt, nowMs)),
        ),
      );
  }
}

export const sessionRepo = repository(SessionRepository);
