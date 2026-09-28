import { and, desc, eq, gt, inArray, isNull, lt, or } from 'drizzle-orm';

import { Repository, repository, statementChunks } from '../db/client';
import { sends } from '../db/schema';
import { plus } from '../db/sql';
import type { Send } from '../types';
import { revisionRepo } from './storage-revision-repo';

function mapSendRow(row: typeof sends.$inferSelect): Send {
  return {
    id: row.id,
    userId: row.userId,
    type: row.type,
    name: row.name,
    notes: row.notes,
    data: row.data,
    key: row.key,
    passwordHash: row.passwordHash,
    passwordSalt: row.passwordSalt,
    passwordIterations: row.passwordIterations,
    authType: row.authType ?? 0,
    emails: row.emails ?? null,
    maxAccessCount: row.maxAccessCount,
    accessCount: row.accessCount,
    disabled: !!row.disabled,
    hideEmail: row.hideEmail === null || row.hideEmail === undefined ? null : !!row.hideEmail,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    expirationDate: row.expirationDate,
    deletionDate: row.deletionDate,
  };
}

export class SendRepository extends Repository {
  async getSend(id: string): Promise<Send | null> {
    const [row] = await this.orm.select().from(sends).where(eq(sends.id, id)).limit(1);
    return row ? mapSendRow(row) : null;
  }

  async getSendForUser(id: string, userId: string): Promise<Send | null> {
    const [row] = await this.orm
      .select()
      .from(sends)
      .where(and(eq(sends.id, id), eq(sends.userId, userId)))
      .limit(1);
    return row ? mapSendRow(row) : null;
  }

  async saveSend(send: Send): Promise<void> {
    const values = {
      id: send.id,
      userId: send.userId,
      type: Number(send.type) || 0,
      name: send.name,
      notes: send.notes,
      data: send.data,
      key: send.key,
      passwordHash: send.passwordHash,
      passwordSalt: send.passwordSalt,
      passwordIterations: send.passwordIterations,
      authType: send.authType,
      emails: send.emails,
      maxAccessCount: send.maxAccessCount,
      accessCount: send.accessCount,
      disabled: send.disabled ? 1 : 0,
      hideEmail: send.hideEmail === null || send.hideEmail === undefined ? null : send.hideEmail ? 1 : 0,
      createdAt: send.createdAt,
      updatedAt: send.updatedAt,
      expirationDate: send.expirationDate,
      deletionDate: send.deletionDate,
    };
    await this.orm
      .insert(sends)
      .values(values)
      .onConflictDoUpdate({
        target: sends.id,
        set: {
          type: values.type,
          name: values.name,
          notes: values.notes,
          data: values.data,
          key: values.key,
          passwordHash: values.passwordHash,
          passwordSalt: values.passwordSalt,
          passwordIterations: values.passwordIterations,
          authType: values.authType,
          emails: values.emails,
          maxAccessCount: values.maxAccessCount,
          accessCount: values.accessCount,
          disabled: values.disabled,
          hideEmail: values.hideEmail,
          updatedAt: values.updatedAt,
          expirationDate: values.expirationDate,
          deletionDate: values.deletionDate,
        },
        where: eq(sends.userId, send.userId),
      });
  }

  async incrementSendAccessCount(sendId: string): Promise<boolean> {
    const now = new Date().toISOString();
    const result = await this.orm
      .update(sends)
      .set({
        accessCount: plus(sends.accessCount, 1),
        updatedAt: now,
      })
      .where(
        and(
          eq(sends.id, sendId),
          eq(sends.disabled, 0),
          or(isNull(sends.maxAccessCount), lt(sends.accessCount, sends.maxAccessCount)),
          or(isNull(sends.expirationDate), gt(sends.expirationDate, now)),
          gt(sends.deletionDate, now),
        ),
      )
      .run();
    return (result.meta.changes ?? 0) > 0;
  }

  async deleteSend(id: string, userId: string): Promise<void> {
    await this.orm.delete(sends).where(and(eq(sends.id, id), eq(sends.userId, userId)));
  }

  async getSendsByIds(ids: string[], userId: string): Promise<Send[]> {
    const uniqueIds = Array.from(new Set(ids.map((id) => String(id || '').trim()).filter(Boolean)));
    if (!uniqueIds.length) return [];
    const read = (chunk: string[]) =>
      this.orm
        .select()
        .from(sends)
        .where(and(eq(sends.userId, userId), inArray(sends.id, chunk)));
    const out: Send[] = [];

    for (const chunk of statementChunks(uniqueIds, read)) {
      out.push(...(await read(chunk)).map(mapSendRow));
    }

    return out;
  }

  async bulkDeleteSends(ids: string[], userId: string): Promise<string | null> {
    const uniqueIds = Array.from(new Set(ids.map((id) => String(id || '').trim()).filter(Boolean)));
    if (!uniqueIds.length) return null;
    const remove = (chunk: string[]) =>
      this.orm.delete(sends).where(and(eq(sends.userId, userId), inArray(sends.id, chunk)));
    for (const chunk of statementChunks(uniqueIds, remove)) {
      await remove(chunk);
    }

    return revisionRepo(this.db).updateRevisionDate(userId);
  }

  async getAllSends(userId: string): Promise<Send[]> {
    const rows = await this.orm.select().from(sends).where(eq(sends.userId, userId)).orderBy(desc(sends.updatedAt));
    return rows.map(mapSendRow);
  }

  async getSendsPage(userId: string, limit: number, offset: number): Promise<Send[]> {
    const rows = await this.orm
      .select()
      .from(sends)
      .where(eq(sends.userId, userId))
      .orderBy(desc(sends.updatedAt))
      .limit(limit)
      .offset(offset);
    return rows.map(mapSendRow);
  }
}

export const sendRepo = repository(SendRepository);
