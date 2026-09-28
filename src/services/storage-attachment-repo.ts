import { and, eq, exists, inArray, isNull, type SQLWrapper } from 'drizzle-orm';
import { alias } from 'drizzle-orm/sqlite-core';

import { Repository, repository, statementChunks, type Orm } from '../db/client';
import { attachments, ciphers } from '../db/schema';
import { excluded } from '../db/sql';
import type { Attachment } from '../types';
import { cipherRepo } from './storage-cipher-repo';
import { revisionRepo } from './storage-revision-repo';

// EXISTS the user's personal (non-organization) cipher with this id: a bound value or a column of the enclosing statement.
function ownsPersonalCipher(orm: Orm, userId: string, cipherId: SQLWrapper | string) {
  const cipher = alias(ciphers, 'owned_cipher');
  return exists(
    orm
      .select({ id: cipher.id })
      .from(cipher)
      .where(and(eq(cipher.id, cipherId), eq(cipher.userId, userId), isNull(cipher.organizationId))),
  );
}

export class AttachmentRepository extends Repository {
  async getAttachment(id: string): Promise<Attachment | null> {
    const [row] = await this.orm.select().from(attachments).where(eq(attachments.id, id)).limit(1);
    return row ?? null;
  }

  async getAttachmentForUser(id: string, userId: string): Promise<Attachment | null> {
    const [row] = await this.orm
      .select({
        id: attachments.id,
        cipherId: attachments.cipherId,
        fileName: attachments.fileName,
        size: attachments.size,
        sizeName: attachments.sizeName,
        key: attachments.key,
      })
      .from(attachments)
      .innerJoin(ciphers, eq(ciphers.id, attachments.cipherId))
      .where(and(eq(attachments.id, id), eq(ciphers.userId, userId), isNull(ciphers.organizationId)))
      .limit(1);
    return row ?? null;
  }

  // The upsert as an unexecuted statement, so callers can batch it with related writes.
  attachmentUpsert(attachment: Attachment) {
    const currentCipher = alias(ciphers, 'current_cipher');
    const nextCipher = alias(ciphers, 'next_cipher');
    return this.orm
      .insert(attachments)
      .values({
        id: attachment.id,
        cipherId: attachment.cipherId,
        fileName: attachment.fileName,
        size: attachment.size,
        sizeName: attachment.sizeName,
        key: attachment.key,
      })
      .onConflictDoUpdate({
        target: attachments.id,
        set: {
          cipherId: attachment.cipherId,
          fileName: attachment.fileName,
          size: attachment.size,
          sizeName: attachment.sizeName,
          key: attachment.key,
        },
        // Re-saving an existing id never moves the attachment onto another owner's cipher.
        where: exists(
          this.orm
            .select({ id: currentCipher.id })
            .from(currentCipher)
            .innerJoin(nextCipher, eq(nextCipher.id, excluded(attachments.cipherId)))
            .where(and(eq(currentCipher.id, attachments.cipherId), eq(currentCipher.userId, nextCipher.userId))),
        ),
      });
  }

  async saveAttachment(attachment: Attachment): Promise<void> {
    await this.attachmentUpsert(attachment);
  }

  async deleteAttachment(id: string): Promise<void> {
    await this.orm.delete(attachments).where(eq(attachments.id, id));
  }

  async deleteAttachmentForUser(id: string, userId: string): Promise<void> {
    await this.orm
      .delete(attachments)
      .where(and(eq(attachments.id, id), ownsPersonalCipher(this.orm, userId, attachments.cipherId)));
  }

  async bulkDeleteAttachmentsByIds(attachmentIds: string[]): Promise<void> {
    const uniqueIds = [...new Set(attachmentIds.map((id) => String(id || '').trim()).filter(Boolean))];
    if (!uniqueIds.length) return;
    const remove = (chunk: string[]) => this.orm.delete(attachments).where(inArray(attachments.id, chunk));
    for (const chunk of statementChunks(uniqueIds, remove)) {
      await remove(chunk);
    }
  }

  async getAttachmentsByCipher(cipherId: string): Promise<Attachment[]> {
    const rows = await this.orm.select().from(attachments).where(eq(attachments.cipherId, cipherId));
    return rows;
  }

  async getAttachmentsByCipherIds(cipherIds: string[]): Promise<Map<string, Attachment[]>> {
    const grouped = new Map<string, Attachment[]>();
    const uniqueCipherIds = [...new Set(cipherIds)];
    if (!uniqueCipherIds.length) return grouped;
    const read = (chunk: string[]) => this.orm.select().from(attachments).where(inArray(attachments.cipherId, chunk));
    for (const chunk of statementChunks(uniqueCipherIds, read)) {
      const rows = await read(chunk);
      for (const item of rows) {
        const list = grouped.get(item.cipherId);
        if (list) list.push(item);
        else grouped.set(item.cipherId, [item]);
      }
    }

    return grouped;
  }

  async getAttachmentsByUserId(userId: string): Promise<Map<string, Attachment[]>> {
    const grouped = new Map<string, Attachment[]>();
    const rows = await this.orm
      .select({
        id: attachments.id,
        cipherId: attachments.cipherId,
        fileName: attachments.fileName,
        size: attachments.size,
        sizeName: attachments.sizeName,
        key: attachments.key,
      })
      .from(attachments)
      .innerJoin(ciphers, eq(ciphers.id, attachments.cipherId))
      .where(and(eq(ciphers.userId, userId), isNull(ciphers.organizationId)));

    for (const item of rows) {
      const list = grouped.get(item.cipherId);
      if (list) list.push(item);
      else grouped.set(item.cipherId, [item]);
    }

    return grouped;
  }

  async addAttachmentToCipher(cipherId: string, attachmentId: string): Promise<void> {
    await this.orm.update(attachments).set({ cipherId }).where(eq(attachments.id, attachmentId));
  }

  async addAttachmentToCipherForUser(cipherId: string, attachmentId: string, userId: string): Promise<void> {
    await this.orm
      .update(attachments)
      .set({ cipherId })
      .where(
        and(
          eq(attachments.id, attachmentId),
          ownsPersonalCipher(this.orm, userId, cipherId),
          ownsPersonalCipher(this.orm, userId, attachments.cipherId),
        ),
      );
  }

  async deleteAllAttachmentsByCipher(cipherId: string): Promise<void> {
    await this.orm.delete(attachments).where(eq(attachments.cipherId, cipherId));
  }

  async updateCipherRevisionDate(cipherId: string): Promise<{ userId: string; revisionDate: string } | null> {
    const cipher = await cipherRepo(this.db).getCipher(cipherId);
    if (!cipher) return null;
    cipher.updatedAt = new Date().toISOString();
    await cipherRepo(this.db).saveCipher(cipher);
    const revisionDate = await revisionRepo(this.db).updateRevisionDate(cipher.userId);
    return { userId: cipher.userId, revisionDate };
  }
}

export const attachmentRepo = repository(AttachmentRepository);
