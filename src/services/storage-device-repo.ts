import { and, count, desc, eq, gte, inArray, isNotNull, isNull, lt, max, ne, or } from 'drizzle-orm';

import { Repository, repository, statementChunks } from '../db/client';
import { devices, trustedTwoFactorDeviceTokens } from '../db/schema';
import { caseWhen, coalesce, excluded } from '../db/sql';
import type { Device, TrustedDeviceTokenSummary } from '../types';
import { hashedTokenKey } from './storage-session-repo';
import { userRepo } from './storage-user-repo';

const TWO_FACTOR_REMEMBER_TTL_MS = 30 * 24 * 60 * 60 * 1000;

// Rows predating device session stamps carry null; callers compare the stamp as a string.
function mapDeviceRow(row: typeof devices.$inferSelect): Device {
  return { ...row, sessionStamp: row.sessionStamp ?? '' };
}

function deviceKey(userId: string, deviceIdentifier: string) {
  return and(eq(devices.userId, userId), eq(devices.deviceIdentifier, deviceIdentifier));
}

export class DeviceRepository extends Repository {
  async upsertDevice(
    userId: string,
    deviceIdentifier: string,
    name: string,
    type: number,
    sessionStamp?: string,
    keys?: {
      encryptedUserKey?: string | null;
      encryptedPublicKey?: string | null;
      encryptedPrivateKey?: string | null;
    },
  ): Promise<void> {
    const now = new Date().toISOString();
    const existingDevice = await this.getDevice(userId, deviceIdentifier);
    const effectiveSessionStamp = String(sessionStamp || '').trim() || existingDevice?.sessionStamp || '';
    const effectiveName = String(name || '').trim() || String(existingDevice?.name || '').trim();
    const effectivePushUuid = String(existingDevice?.pushUuid || '').trim() || crypto.randomUUID();
    await this.orm
      .insert(devices)
      .values({
        userId,
        deviceIdentifier,
        name: effectiveName,
        type,
        sessionStamp: effectiveSessionStamp,
        encryptedUserKey: keys?.encryptedUserKey ?? null,
        encryptedPublicKey: keys?.encryptedPublicKey ?? null,
        encryptedPrivateKey: keys?.encryptedPrivateKey ?? null,
        pushUuid: effectivePushUuid,
        banned: 0,
        bannedAt: null,
        deviceNote: existingDevice?.deviceNote ?? null,
        lastSeenAt: now,
        createdAt: now,
        updatedAt: now,
      })
      .onConflictDoUpdate({
        target: [devices.userId, devices.deviceIdentifier],
        set: {
          name: effectiveName,
          type,
          sessionStamp: caseWhen(
            or(isNull(devices.sessionStamp), eq(devices.sessionStamp, '')),
            excluded(devices.sessionStamp),
            devices.sessionStamp,
          ),
          encryptedUserKey: coalesce(excluded(devices.encryptedUserKey), devices.encryptedUserKey),
          encryptedPublicKey: coalesce(excluded(devices.encryptedPublicKey), devices.encryptedPublicKey),
          encryptedPrivateKey: coalesce(excluded(devices.encryptedPrivateKey), devices.encryptedPrivateKey),
          pushUuid: coalesce(devices.pushUuid, excluded(devices.pushUuid)),
          lastSeenAt: now,
          updatedAt: now,
        },
      });
  }

  async updateDeviceName(userId: string, deviceIdentifier: string, name: string): Promise<boolean> {
    const result = await this.orm
      .update(devices)
      .set({ deviceNote: String(name || '').trim() })
      .where(deviceKey(userId, deviceIdentifier))
      .run();
    return Number(result.meta.changes ?? 0) > 0;
  }

  async touchDeviceLastSeen(userId: string, deviceIdentifier: string): Promise<boolean> {
    const result = await this.orm
      .update(devices)
      .set({ lastSeenAt: new Date().toISOString() })
      .where(deviceKey(userId, deviceIdentifier))
      .run();
    return Number(result.meta.changes ?? 0) > 0;
  }

  async updateDeviceKeys(
    userId: string,
    deviceIdentifier: string,
    keys: {
      encryptedUserKey?: string | null;
      encryptedPublicKey?: string | null;
      encryptedPrivateKey?: string | null;
    },
  ): Promise<boolean> {
    const result = await this.orm
      .update(devices)
      .set({
        encryptedUserKey: keys.encryptedUserKey ?? null,
        encryptedPublicKey: keys.encryptedPublicKey ?? null,
        encryptedPrivateKey: keys.encryptedPrivateKey ?? null,
        updatedAt: new Date().toISOString(),
      })
      .where(deviceKey(userId, deviceIdentifier))
      .run();
    return Number(result.meta.changes ?? 0) > 0;
  }

  async clearDeviceKeys(userId: string, deviceIdentifiers: string[]): Promise<number> {
    const uniqueIds = Array.from(new Set(deviceIdentifiers.map((id) => String(id || '').trim()).filter(Boolean)));
    if (!uniqueIds.length) return 0;
    const updatedAt = new Date().toISOString();
    const clear = (chunk: string[]) =>
      this.orm
        .update(devices)
        .set({ encryptedUserKey: null, encryptedPublicKey: null, encryptedPrivateKey: null, updatedAt })
        .where(and(eq(devices.userId, userId), inArray(devices.deviceIdentifier, chunk)));
    const statements = statementChunks(uniqueIds, clear).map(clear);
    const results = await this.orm.batch(statements as [(typeof statements)[0], ...typeof statements]);
    return results.reduce((total, result) => total + Number(result.meta.changes ?? 0), 0);
  }

  async isKnownDevice(userId: string, deviceIdentifier: string): Promise<boolean> {
    const [row] = await this.orm
      .select({ userId: devices.userId })
      .from(devices)
      .where(deviceKey(userId, deviceIdentifier))
      .limit(1);
    return !!row;
  }

  async isKnownDeviceByEmail(email: string, deviceIdentifier: string): Promise<boolean> {
    const user = await userRepo(this.db).getUser(email);
    if (!user) return false;
    return this.isKnownDevice(user.id, deviceIdentifier);
  }

  async getDevicesByUserId(userId: string): Promise<Device[]> {
    const rows = await this.orm
      .select()
      .from(devices)
      .where(eq(devices.userId, userId))
      .orderBy(desc(coalesce(devices.lastSeenAt, devices.createdAt)), desc(devices.updatedAt));
    return rows.map(mapDeviceRow);
  }

  async getDevice(userId: string, deviceIdentifier: string): Promise<Device | null> {
    const [row] = await this.orm.select().from(devices).where(deviceKey(userId, deviceIdentifier)).limit(1);
    return row ? mapDeviceRow(row) : null;
  }

  async updateDevicePushToken(
    userId: string,
    deviceIdentifier: string,
    pushUuid: string,
    pushToken: string,
  ): Promise<boolean> {
    const result = await this.orm
      .update(devices)
      .set({ pushUuid, pushToken, updatedAt: new Date().toISOString() })
      .where(deviceKey(userId, deviceIdentifier))
      .run();
    return Number(result.meta.changes ?? 0) > 0;
  }

  async getDevicePushUuid(userId: string, deviceIdentifier: string): Promise<string | null> {
    const [row] = await this.orm
      .select({ pushUuid: devices.pushUuid })
      .from(devices)
      .where(deviceKey(userId, deviceIdentifier))
      .limit(1);
    return row?.pushUuid ?? null;
  }

  async userHasPushDevice(userId: string): Promise<boolean> {
    const [row] = await this.orm
      .select({ userId: devices.userId })
      .from(devices)
      .where(and(eq(devices.userId, userId), isNotNull(devices.pushToken), ne(devices.pushToken, '')))
      .limit(1);
    return !!row;
  }

  async deleteDevice(userId: string, deviceIdentifier: string): Promise<boolean> {
    const result = await this.orm.delete(devices).where(deviceKey(userId, deviceIdentifier)).run();
    return Number(result.meta.changes ?? 0) > 0;
  }

  async deleteDevicesByUserId(userId: string): Promise<number> {
    const result = await this.orm.delete(devices).where(eq(devices.userId, userId)).run();
    return Number(result.meta.changes ?? 0);
  }

  private async deleteExpiredTrustedTokens(nowMs: number): Promise<void> {
    await this.orm.delete(trustedTwoFactorDeviceTokens).where(lt(trustedTwoFactorDeviceTokens.expiresAt, nowMs));
  }

  async getTrustedDeviceTokenSummariesByUserId(userId: string): Promise<TrustedDeviceTokenSummary[]> {
    const now = Date.now();
    await this.deleteExpiredTrustedTokens(now);
    const rows = await this.orm
      .select({
        deviceIdentifier: trustedTwoFactorDeviceTokens.deviceIdentifier,
        expiresAt: max(trustedTwoFactorDeviceTokens.expiresAt),
        tokenCount: count(),
      })
      .from(trustedTwoFactorDeviceTokens)
      .where(eq(trustedTwoFactorDeviceTokens.userId, userId))
      .groupBy(trustedTwoFactorDeviceTokens.deviceIdentifier)
      .orderBy(desc(max(trustedTwoFactorDeviceTokens.expiresAt)));

    return rows.map((row) => ({
      deviceIdentifier: row.deviceIdentifier,
      expiresAt: Number(row.expiresAt || 0),
      tokenCount: Number(row.tokenCount || 0),
    }));
  }

  async deleteTrustedTwoFactorTokensByDevice(userId: string, deviceIdentifier: string): Promise<number> {
    const result = await this.orm
      .delete(trustedTwoFactorDeviceTokens)
      .where(
        and(
          eq(trustedTwoFactorDeviceTokens.userId, userId),
          eq(trustedTwoFactorDeviceTokens.deviceIdentifier, deviceIdentifier),
        ),
      )
      .run();
    return Number(result.meta.changes ?? 0);
  }

  async deleteTrustedTwoFactorTokensByUserId(userId: string): Promise<number> {
    const result = await this.orm
      .delete(trustedTwoFactorDeviceTokens)
      .where(eq(trustedTwoFactorDeviceTokens.userId, userId))
      .run();
    return Number(result.meta.changes ?? 0);
  }

  async updateTrustedTwoFactorTokensExpiryByDevice(
    userId: string,
    deviceIdentifier: string,
    expiresAtMs: number,
  ): Promise<number> {
    const now = Date.now();
    await this.deleteExpiredTrustedTokens(now);
    const result = await this.orm
      .update(trustedTwoFactorDeviceTokens)
      .set({ expiresAt: expiresAtMs })
      .where(
        and(
          eq(trustedTwoFactorDeviceTokens.userId, userId),
          eq(trustedTwoFactorDeviceTokens.deviceIdentifier, deviceIdentifier),
          gte(trustedTwoFactorDeviceTokens.expiresAt, now),
        ),
      )
      .run();
    return Number(result.meta.changes ?? 0);
  }

  async saveTrustedTwoFactorDeviceToken(
    token: string,
    userId: string,
    deviceIdentifier: string,
    expiresAtMs = Date.now() + TWO_FACTOR_REMEMBER_TTL_MS,
  ): Promise<void> {
    const tokenKey = await hashedTokenKey(token);
    await this.deleteExpiredTrustedTokens(Date.now());
    await this.orm
      .insert(trustedTwoFactorDeviceTokens)
      .values({ token: tokenKey, userId, deviceIdentifier, expiresAt: expiresAtMs })
      .onConflictDoUpdate({
        target: trustedTwoFactorDeviceTokens.token,
        set: { userId, deviceIdentifier, expiresAt: expiresAtMs },
      });
  }

  async getTrustedTwoFactorDeviceTokenUserId(token: string, deviceIdentifier: string): Promise<string | null> {
    const now = Date.now();
    const tokenKey = await hashedTokenKey(token);
    const [row] = await this.orm
      .select({
        userId: trustedTwoFactorDeviceTokens.userId,
        expiresAt: trustedTwoFactorDeviceTokens.expiresAt,
      })
      .from(trustedTwoFactorDeviceTokens)
      .where(
        and(
          eq(trustedTwoFactorDeviceTokens.token, tokenKey),
          eq(trustedTwoFactorDeviceTokens.deviceIdentifier, deviceIdentifier),
        ),
      )
      .limit(1);

    if (!row) return null;
    if (row.expiresAt && row.expiresAt < now) {
      await this.orm.delete(trustedTwoFactorDeviceTokens).where(eq(trustedTwoFactorDeviceTokens.token, tokenKey));
      return null;
    }
    return row.userId;
  }
}

export const deviceRepo = repository(DeviceRepository);
