import type { AppContext } from '../router';
import { z } from 'zod';
import { Folder, FolderResponse } from '../types';
import {
  notifyUserFolderCreate,
  notifyUserFolderDelete,
  notifyUserFolderUpdate,
  notifyUserVaultSync,
} from '../durable/notifications-hub';
import { errorResponse, jsonResponse, type BodyContext } from '../utils/response';
import { readActingDeviceIdentifier } from '../utils/device';
import { generateUUID } from '../utils/uuid';
import { parsePagination, encodeContinuationToken } from '../utils/pagination';
import { writeDataAudit } from '../services/audit-events';
import { nonEmptyIdList } from './ciphers';
import { folderRepo } from '../services/storage-folder-repo';
import { revisionRepo } from '../services/storage-revision-repo';

// Convert internal folder to API response format
function folderToResponse(folder: Folder): FolderResponse {
  return {
    id: folder.id,
    name: folder.name,
    revisionDate: folder.updatedAt,
    creationDate: folder.createdAt,
    object: 'folder',
  };
}

// GET /api/folders
export async function handleGetFolders(c: AppContext): Promise<Response> {
  const { userId } = c.var;
  const url = new URL(c.req.raw.url);
  const pagination = parsePagination(url);

  let folders: Folder[];
  let continuationToken: string | null = null;
  if (pagination) {
    const pageRows = await folderRepo(c.env.DB).getFoldersPage(userId, pagination.limit + 1, pagination.offset);
    const hasNext = pageRows.length > pagination.limit;
    folders = hasNext ? pageRows.slice(0, pagination.limit) : pageRows;
    continuationToken = hasNext ? encodeContinuationToken(pagination.offset + folders.length) : null;
  } else {
    folders = await folderRepo(c.env.DB).getAllFolders(userId);
  }

  return jsonResponse({
    data: folders.map(folderToResponse),
    object: 'list',
    continuationToken: continuationToken,
  });
}

// GET /api/folders/:id
export async function handleGetFolder(c: AppContext, id: string): Promise<Response> {
  const { userId } = c.var;
  const folder = await folderRepo(c.env.DB).getFolderForUser(id, userId);

  if (!folder || folder.userId !== userId) {
    return errorResponse('Folder not found', 404);
  }

  return jsonResponse(folderToResponse(folder));
}

export const CreateFolderBody = z.object({
  name: z.string({ error: 'Name is required' }).min(1, { error: 'Name is required' }),
});

// POST /api/folders
export async function handleCreateFolder(c: BodyContext<typeof CreateFolderBody>): Promise<Response> {
  const { userId } = c.var;
  const body = c.req.valid('json');

  const now = new Date().toISOString();
  const folder: Folder = {
    id: generateUUID(),
    userId: userId,
    name: body.name,
    createdAt: now,
    updatedAt: now,
  };

  await folderRepo(c.env.DB).saveFolder(folder);
  const revisionDate = await revisionRepo(c.env.DB).updateRevisionDate(userId);
  notifyUserVaultSync(c.env, userId, revisionDate, readActingDeviceIdentifier(c.req.raw));
  notifyUserFolderCreate(c.env, {
    userId,
    folderId: folder.id,
    revisionDate,
    contextId: readActingDeviceIdentifier(c.req.raw),
  });

  return jsonResponse(folderToResponse(folder), 200);
}

export const UpdateFolderBody = z.object({ name: z.string().nullish() });

// PUT /api/folders/:id
export async function handleUpdateFolder(c: BodyContext<typeof UpdateFolderBody>, id: string): Promise<Response> {
  const { userId } = c.var;
  const folder = await folderRepo(c.env.DB).getFolderForUser(id, userId);

  if (!folder || folder.userId !== userId) {
    return errorResponse('Folder not found', 404);
  }

  const body = c.req.valid('json');

  if (body.name) {
    folder.name = body.name;
  }
  folder.updatedAt = new Date().toISOString();

  await folderRepo(c.env.DB).saveFolder(folder);
  const revisionDate = await revisionRepo(c.env.DB).updateRevisionDate(userId);
  notifyUserVaultSync(c.env, userId, revisionDate, readActingDeviceIdentifier(c.req.raw));
  notifyUserFolderUpdate(c.env, {
    userId,
    folderId: folder.id,
    revisionDate,
    contextId: readActingDeviceIdentifier(c.req.raw),
  });

  return jsonResponse(folderToResponse(folder));
}

// DELETE /api/folders/:id
export async function handleDeleteFolder(c: AppContext, id: string): Promise<Response> {
  const { userId } = c.var;
  const folder = await folderRepo(c.env.DB).getFolderForUser(id, userId);

  if (!folder || folder.userId !== userId) {
    return errorResponse('Folder not found', 404);
  }

  await folderRepo(c.env.DB).clearFolderFromCiphers(userId, id);
  await folderRepo(c.env.DB).deleteFolder(id, userId);
  const revisionDate = await revisionRepo(c.env.DB).updateRevisionDate(userId);
  notifyUserVaultSync(c.env, userId, revisionDate, readActingDeviceIdentifier(c.req.raw));
  notifyUserFolderDelete(c.env, {
    userId,
    folderId: id,
    revisionDate,
    contextId: readActingDeviceIdentifier(c.req.raw),
  });
  await writeDataAudit(c.env.DB, c.req.raw, userId, 'folder', 'folder.delete', {
    id,
  });

  return new Response(null, { status: 204 });
}

export const BulkDeleteFoldersBody = z.object({ ids: nonEmptyIdList('Folder ids are required') });

// POST /api/folders/delete
export async function handleBulkDeleteFolders(c: BodyContext<typeof BulkDeleteFoldersBody>): Promise<Response> {
  const { userId } = c.var;
  const body = c.req.valid('json');
  const { ids } = body;

  const folders = (
    await Promise.all(
      ids.map(async (id) => {
        const folder = await folderRepo(c.env.DB).getFolderForUser(id, userId);
        return folder;
      }),
    )
  ).filter((folder): folder is Folder => !!folder);
  const revisionDate = await folderRepo(c.env.DB).bulkDeleteFolders(ids, userId);
  if (revisionDate) {
    notifyUserVaultSync(c.env, userId, revisionDate, readActingDeviceIdentifier(c.req.raw));
    for (const folder of folders) {
      notifyUserFolderDelete(c.env, {
        userId,
        folderId: folder.id,
        revisionDate,
        contextId: readActingDeviceIdentifier(c.req.raw),
      });
    }
    await writeDataAudit(c.env.DB, c.req.raw, userId, 'folder', 'folder.delete.bulk', {
      count: ids.length,
    });
  }

  return new Response(null, { status: 204 });
}
