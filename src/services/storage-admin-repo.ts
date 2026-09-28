import { and, desc, eq, gt, gte, isNull, like, lt, lte, ne, notInArray, or } from 'drizzle-orm';
import { alias } from 'drizzle-orm/sqlite-core';

import { Repository, repository } from '../db/client';
import { auditLogs, invites, users } from '../db/schema';
import { coalesce, likeEscaped, lower } from '../db/sql';
import type { AuditLog, Invite } from '../types';

export interface AuditLogListOptions {
  limit: number;
  offset: number;
  actionPrefix?: string;
  category?: string | null;
  level?: string | null;
  q?: string | null;
  from?: string | null;
  to?: string | null;
}

export interface AuditLogListResult {
  logs: AuditLog[];
  total: number;
  hasMore: boolean;
}

function mapInvite(row: typeof invites.$inferSelect): Invite {
  return {
    code: row.code,
    createdBy: row.createdBy,
    usedBy: row.usedBy ?? null,
    expiresAt: row.expiresAt,
    status: row.status === 'used' || row.status === 'revoked' || row.status === 'expired' ? row.status : 'active',
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

export class AdminRepository extends Repository {
  async createInvite(invite: Invite): Promise<void> {
    await this.orm.insert(invites).values({
      code: invite.code,
      createdBy: invite.createdBy,
      usedBy: invite.usedBy,
      expiresAt: invite.expiresAt,
      status: invite.status,
      createdAt: invite.createdAt,
      updatedAt: invite.updatedAt,
    });
  }

  async getInvite(code: string): Promise<Invite | null> {
    const [row] = await this.orm.select().from(invites).where(eq(invites.code, code)).limit(1);
    return row ? mapInvite(row) : null;
  }

  async listInvites(includeInactive: boolean = false): Promise<Invite[]> {
    const now = new Date().toISOString();
    const rows = includeInactive
      ? await this.orm.select().from(invites).orderBy(desc(invites.createdAt))
      : await this.orm
          .select()
          .from(invites)
          .where(and(eq(invites.status, 'active'), gt(invites.expiresAt, now)))
          .orderBy(desc(invites.createdAt));
    return rows.map(mapInvite);
  }

  async markInviteUsed(code: string, userId: string): Promise<boolean> {
    void userId;
    const now = new Date().toISOString();
    const result = await this.orm
      .update(invites)
      .set({ status: 'used', usedBy: null, updatedAt: now })
      .where(and(eq(invites.code, code), eq(invites.status, 'active'), gt(invites.expiresAt, now)))
      .run();
    return (result.meta.changes ?? 0) > 0;
  }

  async assignInviteUsedBy(code: string, userId: string): Promise<boolean> {
    const now = new Date().toISOString();
    const result = await this.orm
      .update(invites)
      .set({ usedBy: userId, updatedAt: now })
      .where(and(eq(invites.code, code), eq(invites.status, 'used'), isNull(invites.usedBy)))
      .run();
    return (result.meta.changes ?? 0) > 0;
  }

  async revertInviteUsed(code: string, userId: string): Promise<boolean> {
    void userId;
    const now = new Date().toISOString();
    const result = await this.orm
      .update(invites)
      .set({ status: 'active', usedBy: null, updatedAt: now })
      .where(and(eq(invites.code, code), eq(invites.status, 'used'), isNull(invites.usedBy)))
      .run();
    return (result.meta.changes ?? 0) > 0;
  }

  async deleteInvite(code: string): Promise<boolean> {
    const result = await this.orm.delete(invites).where(eq(invites.code, code)).run();
    return (result.meta.changes ?? 0) > 0;
  }

  async deleteInvalidInvites(): Promise<number> {
    const now = new Date().toISOString();
    const result = await this.orm
      .delete(invites)
      .where(or(ne(invites.status, 'active'), lte(invites.expiresAt, now)))
      .run();
    return Number(result.meta.changes ?? 0);
  }

  async deleteAllInvites(): Promise<number> {
    const result = await this.orm.delete(invites).run();
    return Number(result.meta.changes ?? 0);
  }

  async createAuditLog(log: AuditLog): Promise<void> {
    await this.orm.insert(auditLogs).values({
      id: log.id,
      actorUserId: log.actorUserId,
      action: log.action,
      category: log.category,
      level: log.level,
      targetType: log.targetType,
      targetId: log.targetId,
      metadata: log.metadata,
      createdAt: log.createdAt,
    });
  }

  async pruneAuditLogs(beforeIso: string): Promise<number> {
    const result = await this.orm.delete(auditLogs).where(lt(auditLogs.createdAt, beforeIso)).run();
    return Number(result.meta.changes ?? 0);
  }

  async pruneAuditLogsToMax(maxEntries: number): Promise<number> {
    const newest = this.orm
      .select({ id: auditLogs.id })
      .from(auditLogs)
      .orderBy(desc(auditLogs.createdAt))
      .limit(Math.max(1, Math.floor(maxEntries)));
    const result = await this.orm.delete(auditLogs).where(notInArray(auditLogs.id, newest)).run();
    return Number(result.meta.changes ?? 0);
  }

  async clearAuditLogs(): Promise<number> {
    const result = await this.orm.delete(auditLogs).run();
    return Number(result.meta.changes ?? 0);
  }

  async listAuditLogs(options: AuditLogListOptions): Promise<AuditLogListResult> {
    const limit = Math.max(1, Math.min(200, Math.floor(options.limit || 50)));
    const offset = Math.max(0, Math.floor(options.offset || 0));
    const actor = alias(users, 'actor');
    const target = alias(users, 'target');
    const filters = [];
    if (options.actionPrefix)
      filters.push(
        likeEscaped(auditLogs.action, options.actionPrefix.replace(/[\\%_]/g, (value) => `\\${value}`) + '%'),
      );
    if (options.from) filters.push(gte(auditLogs.createdAt, options.from));
    if (options.to) filters.push(lte(auditLogs.createdAt, options.to));
    if (options.category) filters.push(eq(auditLogs.category, options.category));
    if (options.level) filters.push(eq(auditLogs.level, options.level));
    if (options.q) {
      const likePattern = `%${options.q.toLowerCase().slice(0, 48)}%`;
      filters.push(
        or(
          like(lower(auditLogs.action), likePattern),
          like(lower(coalesce(auditLogs.actorUserId, '')), likePattern),
          like(lower(coalesce(auditLogs.targetType, '')), likePattern),
          like(lower(coalesce(auditLogs.targetId, '')), likePattern),
          like(lower(coalesce(actor.email, '')), likePattern),
          like(lower(coalesce(target.email, '')), likePattern),
        ),
      );
    }

    const rows = await this.orm
      .select({
        id: auditLogs.id,
        actorUserId: auditLogs.actorUserId,
        actorEmail: actor.email,
        action: auditLogs.action,
        category: auditLogs.category,
        level: auditLogs.level,
        targetType: auditLogs.targetType,
        targetId: auditLogs.targetId,
        targetUserEmail: target.email,
        metadata: auditLogs.metadata,
        createdAt: auditLogs.createdAt,
      })
      .from(auditLogs)
      .leftJoin(actor, eq(actor.id, auditLogs.actorUserId))
      .leftJoin(target, and(eq(auditLogs.targetType, 'user'), eq(target.id, auditLogs.targetId)))
      .where(filters.length ? and(...filters) : undefined)
      .orderBy(desc(auditLogs.createdAt))
      .limit(limit + 1)
      .offset(offset);

    const logs = rows.slice(0, limit).map((row): AuditLog => ({
      id: row.id,
      actorUserId: row.actorUserId ?? null,
      actorEmail: row.actorEmail ?? null,
      action: row.action,
      category:
        row.category === 'auth' || row.category === 'security' || row.category === 'device' || row.category === 'data'
          ? row.category
          : 'system',
      level: row.level === 'warn' || row.level === 'error' || row.level === 'security' ? row.level : 'info',
      targetType: row.targetType ?? null,
      targetId: row.targetId ?? null,
      targetUserEmail: row.targetUserEmail ?? null,
      metadata: row.metadata ?? null,
      createdAt: row.createdAt,
    }));

    return {
      logs,
      total: offset + logs.length + (rows.length > limit ? 1 : 0),
      hasMore: rows.length > limit,
    };
  }
}

export const adminRepo = repository(AdminRepository);
