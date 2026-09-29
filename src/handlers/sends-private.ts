import type { AppContext } from '../router';
import { z } from 'zod';
import { Env, Send, SendAuthType, SendType } from '../types';
import { recordSendEvent, recordSendEvents } from '../services/events';
import { errorResponse, type BodyContext } from '../utils/response';
import { buildDirectUploadUrl, parseDirectUploadPayload } from '../utils/direct-upload';
import { generateUUID } from '../utils/uuid';
import { parsePagination, encodeContinuationToken } from '../utils/pagination';
import { LIMITS } from '../config/limits';
import {
  getBlobStorageMaxBytes,
  getSendFileObjectKey,
  getBlobObject,
  putBlobObject,
  deleteBlobObject,
} from '../services/blob-store';
import { createSendFileUploadToken, verifySendFileUploadToken } from '../utils/jwt';
import { readActingDeviceIdentifier } from '../utils/device';
import {
  notifyUserSendCreate,
  notifyUserSendDelete,
  notifyUserSendUpdate,
  notifyUserVaultSync,
} from '../durable/notifications-hub';
import {
  formatSize,
  parseDate,
  parseStoredSendData,
  sendFileIdMatches,
  sendToResponse,
  setSendPassword,
  toInteger,
} from './sends-shared';
import { writeDataAudit } from '../services/audit-events';
import { revisionRepo } from '../services/storage-revision-repo';
import { sendRepo } from '../services/storage-send-repo';

const SEND_EMAIL_AUTH_UNSUPPORTED_MESSAGE = 'Send email verification is not supported by this server.';
const DAY_MS = 24 * 60 * 60 * 1000;

const nonBlank = (error: string) => z.string({ error }).regex(/\S/, { error });
const sendDate = (error: string) => z.string({ error }).transform(parseDate).pipe(z.date({ error }));
const sendType = z.preprocess(toInteger, z.enum(SendType, { error: 'Invalid Send type' }));
const sendName = nonBlank('Name is required').trim();
const sendKey = nonBlank('Key is required');
const deletionDate = sendDate('Invalid deletionDate')
  .refine((date) => date.getTime() <= Date.now() + LIMITS.send.maxDeletionDays * DAY_MS, {
    error:
      'You cannot have a Send with a deletion date that far into the future. Adjust the Deletion Date to a value less than 31 days from now and try again.',
  })
  .transform((date) => date.toISOString());
// The text or file object is stored as sent so new client fields round-trip; only the server's own
// response echo is dropped.
const sendData = z.looseObject({}, { error: 'Send data not provided' }).transform(({ response, ...data }) => data);
const emailsError = 'Invalid emails';

// Every field an edit may carry; absent fields stay untouched. Official clients send the unused
// content object as null.
export const SendEdit = z.object({
  type: sendType.optional(),
  name: sendName.optional(),
  key: sendKey.optional(),
  deletionDate: deletionDate.optional(),
  text: sendData.nullable().optional(),
  maxAccessCount: z
    .preprocess(
      (raw) => (raw === '' ? null : toInteger(raw)),
      z.int({ error: 'Invalid maxAccessCount' }).min(0, { error: 'Invalid maxAccessCount' }).nullable(),
    )
    .optional(),
  expirationDate: z
    .preprocess(
      (raw) => (raw === '' ? null : raw),
      sendDate('Invalid expirationDate')
        .transform((date) => date.toISOString())
        .nullable(),
    )
    .optional(),
  authType: z.preprocess(toInteger, z.enum(SendAuthType, { error: 'Invalid authType' })).optional(),
  emails: z
    .union([z.string().min(1, { error: emailsError }), z.array(z.string()).min(1, { error: emailsError })], {
      error: emailsError,
    })
    .nullable()
    .optional(),
  notes: z.string().nullable().catch(null).optional(),
  disabled: z.boolean({ error: 'Invalid disabled' }).optional(),
  hideEmail: z.boolean({ error: 'Invalid hideEmail' }).nullable().optional(),
  password: z.string().optional().catch(undefined),
});

const newSendFields = { name: sendName, key: sendKey, deletionDate };

export const TextSendCreate = SendEdit.extend({
  type: sendType.refine((type) => type === SendType.Text, { error: 'File sends should use /api/sends/file/v2' }),
  ...newSendFields,
  text: sendData,
});

export const FileSendCreate = SendEdit.extend({
  type: z.preprocess(toInteger, z.literal(SendType.File, { error: 'Send content is not a file' })),
  ...newSendFields,
  fileLength: z.preprocess(
    toInteger,
    z.int({ error: 'Invalid send length' }).min(0, { error: "Send size can't be negative" }),
  ),
  file: sendData,
});

export const SendIds = z.object({ ids: z.array(z.string(), { error: 'ids array is required' }) });

async function processSendFileUpload(c: AppContext, send: Send, fileId: string): Promise<Response> {
  const maxFileSize = getBlobStorageMaxBytes(c.env, LIMITS.send.maxFileSizeBytes);
  const { id, fileName, size } = parseStoredSendData(send);
  if (id !== fileId) {
    return errorResponse(c, 'Send file does not match send data.', 400);
  }

  const upload = await parseDirectUploadPayload(c, {
    expectedSize: size === undefined ? null : Number(size),
    expectedFileName: fileName ?? null,
    maxFileSize,
    tooLargeMessage: 'Send storage limit exceeded with this file',
    sizeMismatchMessage: 'Send file size does not match.',
    fileNameMismatchMessage: 'Send file name does not match.',
  });
  if (upload instanceof Response) {
    return upload;
  }

  const path = getSendFileObjectKey(send.id, fileId);
  if (await getBlobObject(c.env, path)) {
    return errorResponse(c, 'Send file has already been uploaded', 409);
  }

  try {
    await putBlobObject(c.env, path, upload.body, {
      size: upload.size,
      contentType: upload.contentType,
      customMetadata: {
        sendId: send.id,
        fileId,
      },
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (message.includes('KV object too large')) {
      return errorResponse(c, 'Send storage limit exceeded with this file', 413);
    }
    return errorResponse(c, 'Attachment storage is not configured', 500);
  }

  const revisionDate = await revisionRepo(c.env.DB).updateRevisionDate(send.userId);
  notifyUserVaultSync(c.env, send.userId, revisionDate, readActingDeviceIdentifier(c.req.raw));
  notifyUserSendUpdate(c.env, {
    userId: send.userId,
    sendId: send.id,
    revisionDate,
    contextId: readActingDeviceIdentifier(c.req.raw),
  });

  return new Response(null, { status: 201 });
}

export async function handleGetSends(c: AppContext): Promise<Response> {
  const { userId } = c.var;
  const url = new URL(c.req.raw.url);
  const pagination = parsePagination(url);

  let sends: Send[];
  let continuationToken: string | null = null;
  if (pagination) {
    const pageRows = await sendRepo(c.env.DB).getSendsPage(userId, pagination.limit + 1, pagination.offset);
    const hasNext = pageRows.length > pagination.limit;
    sends = hasNext ? pageRows.slice(0, pagination.limit) : pageRows;
    continuationToken = hasNext ? encodeContinuationToken(pagination.offset + sends.length) : null;
  } else {
    sends = await sendRepo(c.env.DB).getAllSends(userId);
  }

  const sendResponses = sends.map(sendToResponse);
  return c.json({
    data: sendResponses,
    object: 'list',
    continuationToken,
  });
}

export async function handleGetSend(c: AppContext, sendId: string): Promise<Response> {
  const { userId } = c.var;
  void c.req.raw;
  const send = await sendRepo(c.env.DB).getSendForUser(sendId, userId);

  if (!send || send.userId !== userId) {
    return errorResponse(c, 'Send not found', 404);
  }

  return c.json(sendToResponse(send));
}

// Text and file Sends share every field but the content object; the file handler adds the upload
// metadata it owns so the stored blob names the object the client is about to upload.
async function parseNewSend(
  c: AppContext,
  body: z.output<typeof TextSendCreate> | z.output<typeof FileSendCreate>,
  userId: string,
  type: SendType,
  data: Record<string, unknown>,
): Promise<Send | Response> {
  if (body.authType === SendAuthType.Email || body.emails)
    return errorResponse(c, SEND_EMAIL_AUTH_UNSUPPORTED_MESSAGE, 501);

  const now = new Date().toISOString();
  const send: Send = {
    id: generateUUID(),
    userId,
    type,
    name: body.name,
    notes: body.notes ?? null,
    data: JSON.stringify(data),
    key: body.key,
    passwordHash: null,
    passwordSalt: null,
    passwordIterations: null,
    authType: body.authType ?? SendAuthType.None,
    // Email verification was refused above, so no address list survives creation.
    emails: null,
    maxAccessCount: body.maxAccessCount ?? null,
    accessCount: 0,
    disabled: body.disabled ?? false,
    hideEmail: body.hideEmail ?? null,
    createdAt: now,
    updatedAt: now,
    expirationDate: body.expirationDate ?? null,
    deletionDate: body.deletionDate,
  };

  if (body.password) {
    await setSendPassword(send, body.password);
  } else if (send.authType === SendAuthType.Password) {
    return errorResponse(c, 'Password is required for password auth', 400);
  }
  return send;
}

// Creating or editing a Send persists it, bumps the owner's revision, signals their devices and
// records the matching event.
async function saveSendAndNotify(request: Request, env: Env, send: Send, action: 'created' | 'edited'): Promise<void> {
  await sendRepo(env.DB).saveSend(send);
  const revisionDate = await revisionRepo(env.DB).updateRevisionDate(send.userId);
  notifyUserVaultSync(env, send.userId, revisionDate, readActingDeviceIdentifier(request));
  (action === 'created' ? notifyUserSendCreate : notifyUserSendUpdate)(env, {
    userId: send.userId,
    sendId: send.id,
    revisionDate,
    contextId: readActingDeviceIdentifier(request),
  });
  await recordSendEvent(env, request, send, action);
}

// The file arrives in a second request authorised by a short-lived upload token bound to this Send.
async function sendFileUploadResponse(c: AppContext, send: Send, fileId: string): Promise<Response> {
  const uploadToken = await createSendFileUploadToken(send.userId, send.id, fileId, c.env.JWT_SECRET);
  return c.json({
    fileUploadType: 1,
    object: 'send-fileUpload',
    url: buildDirectUploadUrl(c.req.raw, `/api/sends/${send.id}/file/${fileId}`, uploadToken),
    sendResponse: sendToResponse(send),
  });
}

export async function handleCreateSend(c: BodyContext<typeof TextSendCreate>): Promise<Response> {
  const { userId } = c.var;
  const body = c.req.valid('json');

  const send = await parseNewSend(c, body, userId, SendType.Text, body.text);
  if (send instanceof Response) return send;
  await saveSendAndNotify(c.req.raw, c.env, send, 'created');
  return c.json(sendToResponse(send));
}

export async function handleCreateFileSendV2(c: BodyContext<typeof FileSendCreate>): Promise<Response> {
  const { userId } = c.var;
  const maxFileSize = getBlobStorageMaxBytes(c.env, LIMITS.send.maxFileSizeBytes);
  const body = c.req.valid('json');
  if (body.fileLength > maxFileSize) return errorResponse(c, 'Send storage limit exceeded with this file', 400);

  const fileId = generateUUID();
  const send = await parseNewSend(c, body, userId, SendType.File, {
    ...body.file,
    id: fileId,
    size: body.fileLength,
    sizeName: formatSize(body.fileLength),
  });
  if (send instanceof Response) return send;
  await saveSendAndNotify(c.req.raw, c.env, send, 'created');
  return sendFileUploadResponse(c, send, fileId);
}

export async function handleGetSendFileUpload(c: AppContext, sendId: string, fileId: string): Promise<Response> {
  const { userId } = c.var;
  const send = await sendRepo(c.env.DB).getSendForUser(sendId, userId);
  if (!send || send.userId !== userId) return errorResponse(c, 'Send not found', 404);
  if (send.type !== SendType.File) return errorResponse(c, 'Send is not a file type send.', 400);
  if (!sendFileIdMatches(send, fileId)) return errorResponse(c, 'Send file does not match send data.', 400);
  return sendFileUploadResponse(c, send, fileId);
}

export async function handleUploadSendFile(c: AppContext, sendId: string, fileId: string): Promise<Response> {
  const { userId } = c.var;
  const send = await sendRepo(c.env.DB).getSendForUser(sendId, userId);
  if (!send || send.userId !== userId) {
    return errorResponse(c, 'Send not found. Unable to save the file.', 404);
  }
  if (send.type !== SendType.File) {
    return errorResponse(c, 'Send is not a file type send.', 400);
  }

  return processSendFileUpload(c, send, fileId);
}

export async function handlePublicUploadSendFile(c: AppContext, sendId: string, fileId: string): Promise<Response> {
  const token = new URL(c.req.raw.url).searchParams.get('token');
  if (!token) {
    return errorResponse(c, 'Token required', 401);
  }

  const claims = await verifySendFileUploadToken(token, c.env.JWT_SECRET);
  if (!claims) {
    return errorResponse(c, 'Invalid or expired token', 401);
  }
  if (claims.sendId !== sendId || claims.fileId !== fileId) {
    return errorResponse(c, 'Token mismatch', 401);
  }

  const send = await sendRepo(c.env.DB).getSendForUser(sendId, claims.userId);
  if (!send || send.userId !== claims.userId) {
    return errorResponse(c, 'Send not found. Unable to save the file.', 404);
  }
  if (send.type !== SendType.File) {
    return errorResponse(c, 'Send is not a file type send.', 400);
  }

  return processSendFileUpload(c, send, fileId);
}

export async function handleUpdateSend(c: BodyContext<typeof SendEdit>, sendId: string): Promise<Response> {
  const { userId } = c.var;
  const send = await sendRepo(c.env.DB).getSendForUser(sendId, userId);
  if (!send || send.userId !== userId) {
    return errorResponse(c, 'Send not found', 404);
  }

  const body = c.req.valid('json');
  if (body.type !== undefined && body.type !== send.type) return errorResponse(c, "Sends can't change type", 400);
  if (body.authType === SendAuthType.Email || body.emails)
    return errorResponse(c, SEND_EMAIL_AUTH_UNSUPPORTED_MESSAGE, 501);
  if (send.type === SendType.Text && body.text === null) return errorResponse(c, 'Send data not provided', 400);

  const { type, text, emails, password, ...edits } = body;
  Object.assign(send, edits satisfies Partial<Send>);
  // A new auth type replaces any address list; clearing the list drops email auth with it.
  if (edits.authType !== undefined || emails === null) send.emails = null;
  if (emails === null && Number(send.authType) === SendAuthType.Email) send.authType = SendAuthType.None;
  if (send.type === SendType.Text && text) send.data = JSON.stringify(text);
  if (password !== undefined) await setSendPassword(send, password);

  if (send.authType === SendAuthType.Password && !send.passwordHash) {
    return errorResponse(c, 'Password is required for password auth', 400);
  }

  send.updatedAt = new Date().toISOString();
  await saveSendAndNotify(c.req.raw, c.env, send, 'edited');

  return c.json(sendToResponse(send));
}

export async function handleDeleteSend(c: AppContext, sendId: string): Promise<Response> {
  const { userId } = c.var;
  const send = await sendRepo(c.env.DB).getSendForUser(sendId, userId);
  if (!send || send.userId !== userId) {
    return errorResponse(c, 'Send not found', 404);
  }

  const fileId = send.type === SendType.File ? parseStoredSendData(send).id : undefined;
  if (fileId) await deleteBlobObject(c.env, getSendFileObjectKey(send.id, fileId));

  await sendRepo(c.env.DB).deleteSend(sendId, userId);
  const revisionDate = await revisionRepo(c.env.DB).updateRevisionDate(userId);
  notifyUserVaultSync(c.env, userId, revisionDate, readActingDeviceIdentifier(c.req.raw));
  notifyUserSendDelete(c.env, { userId, sendId, revisionDate, contextId: readActingDeviceIdentifier(c.req.raw) });
  await recordSendEvent(c.env, c.req.raw, send, 'deleted');
  await writeDataAudit(c.env.DB, c.req.raw, userId, 'send', 'send.delete', {
    id: sendId,
    type: send.type,
  });

  return new Response(null, { status: 200 });
}

export async function handleBulkDeleteSends(c: BodyContext<typeof SendIds>): Promise<Response> {
  const { userId } = c.var;
  const body = c.req.valid('json');

  const sends = await sendRepo(c.env.DB).getSendsByIds(body.ids, userId);
  for (const send of sends) {
    const fileId = send.type === SendType.File ? parseStoredSendData(send).id : undefined;
    if (fileId) await deleteBlobObject(c.env, getSendFileObjectKey(send.id, fileId));
  }

  const revisionDate = await sendRepo(c.env.DB).bulkDeleteSends(body.ids, userId);
  if (revisionDate) {
    notifyUserVaultSync(c.env, userId, revisionDate, readActingDeviceIdentifier(c.req.raw));
    for (const send of sends) {
      notifyUserSendDelete(c.env, {
        userId,
        sendId: send.id,
        revisionDate,
        contextId: readActingDeviceIdentifier(c.req.raw),
      });
    }
    await recordSendEvents(c.env, c.req.raw, userId, sends, 'deleted');
    await writeDataAudit(c.env.DB, c.req.raw, userId, 'send', 'send.delete.bulk', {
      count: sends.length,
      requestedCount: body.ids.length,
    });
  }

  return new Response(null, { status: 200 });
}

export async function handleRemoveSendPassword(c: AppContext, sendId: string): Promise<Response> {
  const { userId } = c.var;
  const send = await sendRepo(c.env.DB).getSendForUser(sendId, userId);
  if (!send || send.userId !== userId) {
    return errorResponse(c, 'Send not found', 404);
  }

  await setSendPassword(send, null);
  send.updatedAt = new Date().toISOString();
  await saveSendAndNotify(c.req.raw, c.env, send, 'edited');
  await writeDataAudit(c.env.DB, c.req.raw, userId, 'send', 'send.password.remove', {
    id: send.id,
    type: send.type,
  });

  return c.json(sendToResponse(send));
}

export async function handleRemoveSendAuth(c: AppContext, sendId: string): Promise<Response> {
  const { userId } = c.var;
  const send = await sendRepo(c.env.DB).getSendForUser(sendId, userId);
  if (!send || send.userId !== userId) {
    return errorResponse(c, 'Send not found', 404);
  }

  send.authType = SendAuthType.None;
  send.emails = null;
  send.updatedAt = new Date().toISOString();
  await saveSendAndNotify(c.req.raw, c.env, send, 'edited');
  await writeDataAudit(c.env.DB, c.req.raw, userId, 'send', 'send.auth.remove', {
    id: send.id,
    type: send.type,
  });

  return c.json(sendToResponse(send));
}
