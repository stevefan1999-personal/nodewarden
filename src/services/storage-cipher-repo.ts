import { and, asc, desc, eq, inArray, isNotNull, isNull, ne, or, type SQL } from 'drizzle-orm';
import { alias } from 'drizzle-orm/sqlite-core';

import { Repository, repository, statementChunks } from '../db/client';
import { ciphers, organizationMemberships } from '../db/schema';
import { bound, jsonExtract, jsonRemove, scalar } from '../db/sql';
import type { Cipher } from '../types';
import { MembershipStatus, MembershipType } from './org-types';
import { revisionRepo } from './storage-revision-repo';

function normalizeOptionalId(value: unknown): string | null {
  if (value == null) return null;
  const normalized = String(value).trim();
  return normalized ? normalized : null;
}

const CIPHER_SCALAR_DATA_KEYS = new Set([
  'id',
  'userId',
  'user_id',
  'type',
  'folderId',
  'folder_id',
  'name',
  'notes',
  'favorite',
  'reprompt',
  'key',
  'attachments',
  'Attachments',
  'attachments2',
  'Attachments2',
  'createdAt',
  'created_at',
  'creationDate',
  'updatedAt',
  'updated_at',
  'revisionDate',
  'archivedAt',
  'archived_at',
  'archivedDate',
  'deletedAt',
  'deleted_at',
  'deletedDate',
]);

// Older clients stored archivedDate / deletedDate inside the cipher blob; only string values are dates.
const legacyDate = (value: unknown): string | null => (typeof value === 'string' ? value : null);

function parseCipherRow(row: typeof ciphers.$inferSelect | null | undefined): Cipher | null {
  if (!row?.data) return null;
  try {
    const parsed = JSON.parse(row.data) as Cipher;
    const folderId = normalizeOptionalId(row.folderId ?? parsed.folderId ?? null);
    return {
      ...parsed,
      id: row.id,
      userId: row.userId,
      organizationId: normalizeOptionalId(row.organizationId ?? parsed.organizationId ?? null),
      type: Number(row.type) || Number(parsed.type) || 1,
      folderId,
      name: row.name ?? parsed.name ?? null,
      notes: row.notes ?? parsed.notes ?? null,
      favorite: row.favorite != null ? !!row.favorite : !!parsed.favorite,
      reprompt: row.reprompt ?? parsed.reprompt ?? 0,
      key: row.key ?? parsed.key ?? null,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
      archivedAt: row.archivedAt ?? parsed.archivedAt ?? legacyDate(parsed.archivedDate),
      deletedAt: row.deletedAt ?? parsed.deletedAt ?? legacyDate(parsed.deletedDate),
    };
  } catch {
    console.error('Corrupted cipher data, id:', row.id);
    return null;
  }
}

function sanitizeIds(ids: string[]): string[] {
  return Array.from(new Set(ids.map((id) => String(id || '').trim()).filter(Boolean)));
}

function personalVault(userId: string) {
  return and(eq(ciphers.userId, userId), isNull(ciphers.organizationId));
}

export class CipherRepository extends Repository {
  async getCipher(id: string): Promise<Cipher | null> {
    const [row] = await this.orm.select().from(ciphers).where(eq(ciphers.id, id)).limit(1);
    return parseCipherRow(row);
  }

  async getCipherForUser(id: string, userId: string): Promise<Cipher | null> {
    const [row] = await this.orm
      .select()
      .from(ciphers)
      .where(and(eq(ciphers.id, id), personalVault(userId)))
      .limit(1);
    return parseCipherRow(row);
  }

  // The upsert as an unexecuted statement, so callers can batch it with related writes.
  cipherUpsert(cipher: Cipher) {
    const folderId = normalizeOptionalId(cipher.folderId);
    const data = JSON.stringify(
      Object.fromEntries(Object.entries(cipher).filter(([key]) => !CIPHER_SCALAR_DATA_KEYS.has(key))),
    );
    const organizationId = normalizeOptionalId(cipher.organizationId ?? null);
    const values = {
      id: cipher.id,
      userId: cipher.userId,
      organizationId,
      type: Number(cipher.type) || 1,
      folderId,
      name: cipher.name,
      notes: cipher.notes,
      favorite: cipher.favorite ? 1 : 0,
      data,
      reprompt: cipher.reprompt ?? 0,
      key: cipher.key,
      createdAt: cipher.createdAt,
      updatedAt: cipher.updatedAt,
      archivedAt: cipher.archivedAt ?? null,
      deletedAt: cipher.deletedAt,
    };
    return this.orm
      .insert(ciphers)
      .values(values)
      .onConflictDoUpdate({
        target: ciphers.id,
        set: {
          organizationId: values.organizationId,
          type: values.type,
          folderId: values.folderId,
          name: values.name,
          notes: values.notes,
          favorite: values.favorite,
          data: values.data,
          reprompt: values.reprompt,
          key: values.key,
          updatedAt: values.updatedAt,
          archivedAt: values.archivedAt,
          deletedAt: values.deletedAt,
        },
        // An org overwrite is only legitimate when the stored row already belongs
        // to that same org; a NULL organization_id must never match an incoming org cipher.
        // An incoming personal cipher binds NULL, which equals nothing either.
        where: or(
          eq(ciphers.userId, cipher.userId),
          and(isNotNull(ciphers.organizationId), eq(ciphers.organizationId, bound(organizationId))),
        ),
      });
  }

  async saveCipher(cipher: Cipher): Promise<void> {
    await this.cipherUpsert(cipher);
  }

  async deleteCipher(id: string, userId: string): Promise<void> {
    await this.orm.delete(ciphers).where(and(eq(ciphers.id, id), personalVault(userId)));
  }

  async deleteCipherById(id: string): Promise<void> {
    await this.orm.delete(ciphers).where(eq(ciphers.id, id));
  }

  deleteCiphersByOrganization(organizationId: string) {
    return this.orm.delete(ciphers).where(eq(ciphers.organizationId, organizationId));
  }

  // Each org item passes to the oldest other confirmed Owner of its org, else to its oldest other confirmed member.
  reassignOrganizationCiphers(userId: string, guard: SQL) {
    const successor = alias(organizationMemberships, 'successor');
    return this.orm
      .update(ciphers)
      .set({
        userId: scalar<string>(
          this.orm
            .select({ userId: successor.userId })
            .from(successor)
            .where(
              and(
                eq(successor.orgId, ciphers.organizationId),
                ne(successor.userId, userId),
                eq(successor.status, MembershipStatus.Confirmed),
              ),
            )
            .orderBy(desc(eq(successor.type, MembershipType.Owner)), asc(successor.createdAt), asc(successor.id))
            .limit(1),
        ),
      })
      .where(and(eq(ciphers.userId, userId), isNotNull(ciphers.organizationId), guard));
  }

  private async chunkedUpdate(
    ids: string[],
    userId: string,
    set: Record<string, unknown>,
    extraWhere: ReturnType<typeof and> | undefined,
  ): Promise<string | null> {
    const uniqueIds = sanitizeIds(ids);
    if (!uniqueIds.length) return null;
    const update = (chunk: string[]) =>
      this.orm
        .update(ciphers)
        .set(set)
        .where(and(personalVault(userId), inArray(ciphers.id, chunk), extraWhere));
    for (const chunk of statementChunks(uniqueIds, update)) {
      await update(chunk);
    }
    return revisionRepo(this.db).updateRevisionDate(userId);
  }

  async bulkSoftDeleteCiphers(ids: string[], userId: string): Promise<string | null> {
    const now = new Date().toISOString();
    return this.chunkedUpdate(
      ids,
      userId,
      {
        deletedAt: now,
        updatedAt: now,
        data: jsonRemove(ciphers.data, '$.deletedAt', '$.deletedDate', '$.updatedAt', '$.revisionDate'),
      },
      undefined,
    );
  }

  async bulkRestoreCiphers(ids: string[], userId: string): Promise<string | null> {
    const now = new Date().toISOString();
    return this.chunkedUpdate(
      ids,
      userId,
      {
        deletedAt: null,
        updatedAt: now,
        data: jsonRemove(ciphers.data, '$.deletedAt', '$.deletedDate', '$.updatedAt', '$.revisionDate'),
      },
      undefined,
    );
  }

  async bulkDeleteCiphers(ids: string[], userId: string): Promise<string | null> {
    const uniqueIds = sanitizeIds(ids);
    if (!uniqueIds.length) return null;
    const remove = (chunk: string[]) =>
      this.orm.delete(ciphers).where(and(personalVault(userId), inArray(ciphers.id, chunk)));
    for (const chunk of statementChunks(uniqueIds, remove)) {
      await remove(chunk);
    }
    return revisionRepo(this.db).updateRevisionDate(userId);
  }

  async getAllCiphers(userId: string): Promise<Cipher[]> {
    const rows = await this.orm.select().from(ciphers).where(personalVault(userId)).orderBy(desc(ciphers.updatedAt));
    return rows.flatMap((row) => {
      const cipher = parseCipherRow(row);
      return cipher ? [cipher] : [];
    });
  }

  async getCiphersPage(userId: string, includeDeleted: boolean, limit: number, offset: number): Promise<Cipher[]> {
    const deletedFilter = includeDeleted
      ? undefined
      : and(
          isNull(ciphers.deletedAt),
          isNull(jsonExtract(ciphers.data, '$.deletedAt')),
          isNull(jsonExtract(ciphers.data, '$.deletedDate')),
        );
    const rows = await this.orm
      .select()
      .from(ciphers)
      .where(and(personalVault(userId), deletedFilter))
      .orderBy(desc(ciphers.updatedAt))
      .limit(limit)
      .offset(offset);
    return rows.flatMap((row) => {
      const cipher = parseCipherRow(row);
      return cipher ? [cipher] : [];
    });
  }

  async getCiphersByIds(ids: string[], userId: string): Promise<Cipher[]> {
    const uniqueIds = sanitizeIds(ids);
    if (!uniqueIds.length) return [];
    const out: Cipher[] = [];
    const read = (chunk: string[]) =>
      this.orm
        .select()
        .from(ciphers)
        .where(and(personalVault(userId), inArray(ciphers.id, chunk)));
    for (const chunk of statementChunks(uniqueIds, read)) {
      const rows = await read(chunk);
      out.push(
        ...rows.flatMap((row) => {
          const cipher = parseCipherRow(row);
          return cipher ? [cipher] : [];
        }),
      );
    }
    return out;
  }

  async bulkMoveCiphers(ids: string[], folderId: string | null, userId: string): Promise<string | null> {
    const now = new Date().toISOString();
    return this.chunkedUpdate(
      ids,
      userId,
      {
        folderId: normalizeOptionalId(folderId),
        updatedAt: now,
        data: jsonRemove(ciphers.data, '$.folderId', '$.folder_id', '$.updatedAt', '$.revisionDate'),
      },
      undefined,
    );
  }

  async bulkArchiveCiphers(ids: string[], userId: string): Promise<string | null> {
    const now = new Date().toISOString();
    return this.chunkedUpdate(
      ids,
      userId,
      {
        archivedAt: now,
        updatedAt: now,
        data: jsonRemove(ciphers.data, '$.archivedAt', '$.archivedDate', '$.updatedAt', '$.revisionDate'),
      },
      and(
        isNull(ciphers.deletedAt),
        isNull(jsonExtract(ciphers.data, '$.deletedAt')),
        isNull(jsonExtract(ciphers.data, '$.deletedDate')),
      ),
    );
  }

  async bulkUnarchiveCiphers(ids: string[], userId: string): Promise<string | null> {
    const now = new Date().toISOString();
    return this.chunkedUpdate(
      ids,
      userId,
      {
        archivedAt: null,
        updatedAt: now,
        data: jsonRemove(ciphers.data, '$.archivedAt', '$.archivedDate', '$.updatedAt', '$.revisionDate'),
      },
      undefined,
    );
  }

  async countPersonalCiphers(userId: string): Promise<number> {
    return this.orm.$count(ciphers, and(eq(ciphers.userId, userId), isNull(ciphers.organizationId)));
  }
}

export const cipherRepo = repository(CipherRepository);
