import { and, desc, eq, inArray, isNull, or } from 'drizzle-orm';

import { Repository, repository, statementChunks } from '../db/client';
import { ciphers, folders } from '../db/schema';
import { jsonExtract, jsonRemove } from '../db/sql';
import type { Folder } from '../types';
import { revisionRepo } from './storage-revision-repo';

function folderClearedData() {
  return jsonRemove(ciphers.data, '$.folderId', '$.folder_id', '$.updatedAt', '$.revisionDate');
}

export class FolderRepository extends Repository {
  async getFolder(id: string): Promise<Folder | null> {
    const [row] = await this.orm.select().from(folders).where(eq(folders.id, id)).limit(1);
    return row ?? null;
  }

  async getFolderForUser(id: string, userId: string): Promise<Folder | null> {
    const [row] = await this.orm
      .select()
      .from(folders)
      .where(and(eq(folders.id, id), eq(folders.userId, userId)))
      .limit(1);
    return row ?? null;
  }

  async saveFolder(folder: Folder): Promise<void> {
    await this.orm
      .insert(folders)
      .values({
        id: folder.id,
        userId: folder.userId,
        name: folder.name,
        createdAt: folder.createdAt,
        updatedAt: folder.updatedAt,
      })
      .onConflictDoUpdate({
        target: folders.id,
        set: { name: folder.name, updatedAt: folder.updatedAt },
        where: eq(folders.userId, folder.userId),
      });
  }

  async deleteFolder(id: string, userId: string): Promise<void> {
    await this.orm.delete(folders).where(and(eq(folders.id, id), eq(folders.userId, userId)));
  }

  async clearFolderFromCiphers(userId: string, folderId: string): Promise<void> {
    const now = new Date().toISOString();
    await this.orm
      .update(ciphers)
      .set({ folderId: null, updatedAt: now, data: folderClearedData() })
      .where(
        and(
          eq(ciphers.userId, userId),
          isNull(ciphers.organizationId),
          or(
            eq(ciphers.folderId, folderId),
            eq(jsonExtract(ciphers.data, '$.folderId'), folderId),
            eq(jsonExtract(ciphers.data, '$.folder_id'), folderId),
          ),
        ),
      );
  }

  async bulkDeleteFolders(ids: string[], userId: string): Promise<string | null> {
    const uniqueIds = Array.from(new Set(ids.map((id) => String(id || '').trim()).filter(Boolean)));
    if (!uniqueIds.length) return null;
    const now = new Date().toISOString();
    const unfile = (chunk: string[]) =>
      this.orm
        .update(ciphers)
        .set({ folderId: null, updatedAt: now, data: folderClearedData() })
        .where(
          and(
            eq(ciphers.userId, userId),
            isNull(ciphers.organizationId),
            or(
              inArray(ciphers.folderId, chunk),
              inArray(jsonExtract(ciphers.data, '$.folderId'), chunk),
              inArray(jsonExtract(ciphers.data, '$.folder_id'), chunk),
            ),
          ),
        );
    // Chunks are sized for the unfile, which binds more than the folder delete.
    const statements = statementChunks(uniqueIds, unfile).flatMap((chunk) => [
      unfile(chunk),
      this.orm.delete(folders).where(and(eq(folders.userId, userId), inArray(folders.id, chunk))),
    ]);

    await this.orm.batch(statements as [(typeof statements)[0], ...typeof statements]);
    return revisionRepo(this.db).updateRevisionDate(userId);
  }

  async getAllFolders(userId: string): Promise<Folder[]> {
    const rows = await this.orm
      .select()
      .from(folders)
      .where(eq(folders.userId, userId))
      .orderBy(desc(folders.updatedAt));
    return rows;
  }

  async getFoldersPage(userId: string, limit: number, offset: number): Promise<Folder[]> {
    const rows = await this.orm
      .select()
      .from(folders)
      .where(eq(folders.userId, userId))
      .orderBy(desc(folders.updatedAt))
      .limit(limit)
      .offset(offset);
    return rows;
  }
}

export const folderRepo = repository(FolderRepository);
