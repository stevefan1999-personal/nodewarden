import { formatSize } from './sends-shared';
import type { AppContext } from '../router';
import { z } from 'zod';
import { Env, Attachment, Cipher } from '../types';
import { notifyUserCipherUpdate, notifyUserVaultSync } from '../durable/notifications-hub';
import { errorResponse, type BodyContext } from '../utils/response';
import { buildDirectUploadUrl, parseDirectUploadPayload } from '../utils/direct-upload';
import { contentDispositionAttachment, sanitizeDownloadContentType } from '../utils/content-type';
import {
  createAttachmentUploadToken,
  createFileDownloadToken,
  verifyAttachmentUploadToken,
  verifyFileDownloadToken,
} from '../utils/jwt';
import { applyCipherEmbeddedAttachmentMetadata, cipherToResponse, recordCipherEvents } from './ciphers';
import { LIMITS } from '../config/limits';
import { cipherNotifyPayload, readActingDeviceIdentifier } from '../utils/device';
import {
  deleteBlobObject,
  getAttachmentObjectKey,
  getBlobObject,
  getBlobStorageMaxBytes,
  putBlobObject,
} from '../services/blob-store';
import { writeDataAudit } from '../services/audit-events';
import { loadAccessibleCipher } from './cipher-access';
import { EventType } from '../services/events';
import { attachmentRepo } from '../services/storage-attachment-repo';
import { attachmentTokenRepo } from '../services/storage-attachment-token-repo';
import { cipherRepo } from '../services/storage-cipher-repo';

const ATTACHMENT_FIELD_REQUIRED = 'fileName and key are required';
const requiredAttachmentField = z
  .string({ error: ATTACHMENT_FIELD_REQUIRED })
  .min(1, { error: ATTACHMENT_FIELD_REQUIRED });

export const CreateAttachmentBody = z.object({
  fileName: requiredAttachmentField,
  key: requiredAttachmentField,
  // Android sends fileSize as a numeric string.
  fileSize: z.coerce.number().optional(),
});

// Only the sent fields change; a present fileName must not be blank, and a blank key clears it.
export const AttachmentMetadataBody = z
  .object({
    fileName: z
      .unknown()
      .transform((value) => String(value || '').trim())
      .pipe(z.string().min(1, { error: 'fileName is required' }))
      .optional(),
    key: z
      .unknown()
      .transform((value) => String(value || '').trim() || null)
      .optional(),
  })
  .refine((body) => 'fileName' in body || 'key' in body, { error: 'No metadata fields supplied' });

// An attachment change is a change to its cipher: the cipher's owner gets a new revision and their
// devices the cipher update signal. Returns null when the cipher row is gone.
async function afterAttachmentChange(
  request: Request,
  env: Env,
  cipher: Cipher,
  cipherId: string,
): Promise<{ userId: string; revisionDate: string } | null> {
  const revisionInfo = await attachmentRepo(env.DB).updateCipherRevisionDate(cipherId);
  if (revisionInfo) {
    notifyUserVaultSync(env, revisionInfo.userId, revisionInfo.revisionDate, readActingDeviceIdentifier(request));
    notifyUserCipherUpdate(env, cipherNotifyPayload(cipher, revisionInfo.revisionDate, request));
  }
  return revisionInfo;
}

async function processAttachmentUpload(
  c: AppContext,
  cipher: Cipher,
  attachment: Attachment,
  cipherId: string,
): Promise<Response> {
  const maxFileSize = getBlobStorageMaxBytes(c.env, LIMITS.attachment.maxFileSizeBytes);
  const upload = await parseDirectUploadPayload(c, {
    expectedSize: Number(attachment.size) || 0,
    maxFileSize,
    tooLargeMessage: `File too large. Maximum size is ${Math.floor(maxFileSize / (1024 * 1024))}MB`,
  });
  if (upload instanceof Response) {
    return upload;
  }

  const path = getAttachmentObjectKey(cipherId, attachment.id);
  if (await getBlobObject(c.env, path)) {
    return errorResponse(c, 'Attachment file has already been uploaded', 409);
  }

  try {
    await putBlobObject(c.env, path, upload.body, {
      size: upload.size,
      contentType: upload.contentType,
      customMetadata: {
        cipherId,
        attachmentId: attachment.id,
      },
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (message.includes('KV object too large')) {
      return errorResponse(c, `File too large. Maximum size is ${Math.floor(maxFileSize / (1024 * 1024))}MB`, 413);
    }
    return errorResponse(c, 'Attachment storage is not configured', 500);
  }

  if (upload.size !== attachment.size) {
    attachment.size = upload.size;
    attachment.sizeName = formatSize(upload.size);
    await attachmentRepo(c.env.DB).saveAttachment(attachment);
  }

  await afterAttachmentChange(c.req.raw, c.env, cipher, cipherId);

  return new Response(null, { status: 201 });
}

// POST /api/ciphers/{cipherId}/attachment/v2
// Creates attachment metadata and returns upload URL
export async function handleCreateAttachment(
  c: BodyContext<typeof CreateAttachmentBody>,
  cipherId: string,
): Promise<Response> {
  const { userId } = c.var;
  const cipher = await loadAccessibleCipher(c.env.DB, userId, cipherId, 'edit');
  if (!cipher) return errorResponse(c, 'Cipher not found', 404);
  const body = c.req.valid('json');

  const fileSize = body.fileSize || 0;
  const attachmentId = crypto.randomUUID();

  // Create attachment metadata
  const attachment: Attachment = {
    id: attachmentId,
    cipherId: cipherId,
    fileName: body.fileName,
    size: fileSize,
    sizeName: formatSize(fileSize),
    key: body.key,
  };

  // Save attachment metadata
  await attachmentRepo(c.env.DB).saveAttachment(attachment);

  // Add attachment to cipher
  if (cipher.organizationId) {
    await attachmentRepo(c.env.DB).addAttachmentToCipher(cipherId, attachmentId);
  } else {
    await attachmentRepo(c.env.DB).addAttachmentToCipherForUser(cipherId, attachmentId, userId);
  }

  await afterAttachmentChange(c.req.raw, c.env, cipher, cipherId);

  // Get updated cipher for response
  const updatedCipher = cipher.organizationId
    ? await cipherRepo(c.env.DB).getCipher(cipherId)
    : await cipherRepo(c.env.DB).getCipherForUser(cipherId, userId);
  const attachments = await attachmentRepo(c.env.DB).getAttachmentsByCipher(cipherId);
  const uploadToken = await createAttachmentUploadToken(userId, cipherId, attachmentId, c.env.JWT_SECRET);
  // Official clients PUT the file to this Worker URL the way they upload to Azure blob storage (fileUploadType 1);
  // for the Direct type they ignore any URL and post to the server instead.
  const url = buildDirectUploadUrl(c.req.raw, `/api/ciphers/${cipherId}/attachment/${attachmentId}`, uploadToken);

  await recordCipherEvents(c.env, c.req.raw, userId, EventType.CipherAttachmentCreated, [cipher]);
  return c.json({
    object: 'attachment-fileUpload',
    attachmentId: attachmentId,
    url,
    urlType: 'direct',
    fileUploadType: 1,
    cipherResponse: cipherToResponse(updatedCipher || cipher, attachments),
  });
}

// POST /api/ciphers/{cipherId}/attachment/{attachmentId}
// Upload attachment file content
export async function handleUploadAttachment(c: AppContext, cipherId: string, attachmentId: string): Promise<Response> {
  const { userId } = c.var;
  const cipher = await loadAccessibleCipher(c.env.DB, userId, cipherId, 'edit');
  if (!cipher) return errorResponse(c, 'Cipher not found', 404);

  const attachment = await attachmentRepo(c.env.DB).getAttachment(attachmentId);
  if (!attachment || attachment.cipherId !== cipherId) {
    return errorResponse(c, 'Attachment not found', 404);
  }

  return processAttachmentUpload(c, cipher, attachment, cipherId);
}

export async function handlePublicUploadAttachment(
  c: AppContext,
  cipherId: string,
  attachmentId: string,
): Promise<Response> {
  const token = new URL(c.req.raw.url).searchParams.get('token');
  if (!token) {
    return errorResponse(c, 'Token required', 401);
  }

  const claims = await verifyAttachmentUploadToken(token, c.env.JWT_SECRET);
  if (!claims) {
    return errorResponse(c, 'Invalid or expired token', 401);
  }
  if (claims.cipherId !== cipherId || claims.attachmentId !== attachmentId) {
    return errorResponse(c, 'Token mismatch', 401);
  }

  const cipher = await cipherRepo(c.env.DB).getCipher(cipherId);
  if (!cipher) return errorResponse(c, 'Cipher not found', 404);

  const attachment = await attachmentRepo(c.env.DB).getAttachment(attachmentId);
  if (!attachment || attachment.cipherId !== cipherId) {
    return errorResponse(c, 'Attachment not found', 404);
  }

  return processAttachmentUpload(c, cipher, attachment, cipherId);
}

// GET /api/ciphers/{cipherId}/attachment/{attachmentId}
// Get attachment download info
export async function handleGetAttachment(c: AppContext, cipherId: string, attachmentId: string): Promise<Response> {
  const { userId } = c.var;
  const cipher = await loadAccessibleCipher(c.env.DB, userId, cipherId, 'read');
  if (!cipher) return errorResponse(c, 'Cipher not found', 404);

  const attachment = await attachmentRepo(c.env.DB).getAttachment(attachmentId);
  if (!attachment || attachment.cipherId !== cipherId) {
    return errorResponse(c, 'Attachment not found', 404);
  }
  const responseAttachment = applyCipherEmbeddedAttachmentMetadata(cipher, [attachment])[0] || attachment;

  // Generate short-lived download token
  const token = await createFileDownloadToken(cipherId, attachmentId, c.env.JWT_SECRET);

  // Generate download URL with token
  const url = new URL(c.req.raw.url);
  const downloadUrl = `${url.origin}/api/attachments/${cipherId}/${attachmentId}?token=${token}`;

  return c.json({
    object: 'attachment',
    id: responseAttachment.id,
    url: downloadUrl,
    fileName: responseAttachment.fileName,
    key: responseAttachment.key,
    size: String(Number(responseAttachment.size) || 0),
    sizeName: responseAttachment.sizeName,
  });
}

// PUT /api/ciphers/{cipherId}/attachment/{attachmentId}/metadata
// 修正旧附件的加密元数据，供官方客户端按当前 Bitwarden 契约解密。
export async function handleUpdateAttachmentMetadata(
  c: BodyContext<typeof AttachmentMetadataBody>,
  cipherId: string,
  attachmentId: string,
): Promise<Response> {
  const { userId } = c.var;
  const cipher = await loadAccessibleCipher(c.env.DB, userId, cipherId, 'edit');
  if (!cipher) return errorResponse(c, 'Cipher not found', 404);

  const attachment = await attachmentRepo(c.env.DB).getAttachment(attachmentId);
  if (!attachment || attachment.cipherId !== cipherId) {
    return errorResponse(c, 'Attachment not found', 404);
  }
  const body = c.req.valid('json');

  if (body.fileName !== undefined) attachment.fileName = body.fileName;
  if (body.key !== undefined) attachment.key = body.key;

  await attachmentRepo(c.env.DB).saveAttachment(attachment);
  await afterAttachmentChange(c.req.raw, c.env, cipher, cipherId);

  return c.json({
    object: 'attachment',
    id: attachment.id,
    fileName: attachment.fileName,
    key: attachment.key,
    size: String(Number(attachment.size) || 0),
    sizeName: attachment.sizeName,
  });
}

// GET /api/attachments/{cipherId}/{attachmentId}?token=xxx
// Public download endpoint (uses token for auth instead of header)
export async function handlePublicDownloadAttachment(
  c: AppContext,
  cipherId: string,
  attachmentId: string,
): Promise<Response> {
  const url = new URL(c.req.raw.url);
  const token = url.searchParams.get('token');

  if (!token) {
    return errorResponse(c, 'Token required', 401);
  }

  // Verify token
  const claims = await verifyFileDownloadToken(token, c.env.JWT_SECRET);
  if (!claims) {
    return errorResponse(c, 'Invalid or expired token', 401);
  }

  // Verify token matches request
  if (claims.cipherId !== cipherId || claims.attachmentId !== attachmentId) {
    return errorResponse(c, 'Token mismatch', 401);
  }

  // Verify attachment exists
  const attachment = await attachmentRepo(c.env.DB).getAttachment(attachmentId);
  if (!attachment || attachment.cipherId !== cipherId) {
    return errorResponse(c, 'Attachment not found', 404);
  }

  const path = getAttachmentObjectKey(cipherId, attachmentId);
  const firstUse = await attachmentTokenRepo(c.env.DB).consumeAttachmentDownloadToken(claims.jti, claims.exp);
  if (!firstUse) {
    return errorResponse(c, 'Invalid or expired token', 401);
  }

  const object = await getBlobObject(c.env, path);
  if (!object) {
    return errorResponse(c, 'Attachment file not found', 404);
  }

  return new Response(object.body, {
    headers: {
      'Content-Type': sanitizeDownloadContentType(object.contentType),
      'Content-Length': String(object.size),
      'Content-Disposition': contentDispositionAttachment(attachment.fileName, 'attachment'),
      'Cache-Control': 'private, no-cache',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

// DELETE /api/ciphers/{cipherId}/attachment/{attachmentId}
// Delete attachment
export async function handleDeleteAttachment(c: AppContext, cipherId: string, attachmentId: string): Promise<Response> {
  const { userId } = c.var;
  const cipher = await loadAccessibleCipher(c.env.DB, userId, cipherId, 'edit');
  if (!cipher) return errorResponse(c, 'Cipher not found', 404);

  const attachment = await attachmentRepo(c.env.DB).getAttachment(attachmentId);
  if (!attachment || attachment.cipherId !== cipherId) {
    return errorResponse(c, 'Attachment not found', 404);
  }

  const path = getAttachmentObjectKey(cipherId, attachmentId);
  await deleteBlobObject(c.env, path);

  if (cipher.organizationId) {
    await attachmentRepo(c.env.DB).deleteAttachment(attachmentId);
  } else {
    await attachmentRepo(c.env.DB).deleteAttachmentForUser(attachmentId, userId);
  }

  const revisionInfo = await afterAttachmentChange(c.req.raw, c.env, cipher, cipherId);
  if (revisionInfo) {
    await writeDataAudit(c.env.DB, c.req.raw, revisionInfo.userId, 'attachment', 'attachment.delete', {
      id: attachmentId,
      cipherId,
      size: attachment.size,
    });
  }

  const updatedCipher = cipher.organizationId
    ? await cipherRepo(c.env.DB).getCipher(cipherId)
    : await cipherRepo(c.env.DB).getCipherForUser(cipherId, userId);
  const attachments = await attachmentRepo(c.env.DB).getAttachmentsByCipher(cipherId);
  const cipherResponse = cipherToResponse(updatedCipher || cipher, attachments);
  await recordCipherEvents(c.env, c.req.raw, userId, EventType.CipherAttachmentDeleted, [cipher]);

  return c.json({
    Cipher: cipherResponse,
    cipher: cipherResponse,
    Object: 'deleteAttachment',
    object: 'deleteAttachment',
  });
}

// Delete all attachments for a cipher (used when deleting cipher)

export async function deleteAllAttachmentsForCiphers(env: Env, cipherIds: string[]): Promise<void> {
  const attachmentsByCipher = await attachmentRepo(env.DB).getAttachmentsByCipherIds(cipherIds);
  const attachments = Array.from(attachmentsByCipher.entries()).flatMap(([ownedCipherId, items]) =>
    items.map((attachment) => ({ attachment, cipherId: ownedCipherId })),
  );
  if (!attachments.length) return;

  // Delete the stored files in batches, so at most `concurrency` deletions run at once.
  const concurrency = Math.max(1, LIMITS.performance.attachmentDeleteConcurrency);
  for (let index = 0; index < attachments.length; index += concurrency) {
    await Promise.all(
      attachments.slice(index, index + concurrency).map(async ({ attachment, cipherId }) => {
        const path = getAttachmentObjectKey(cipherId, attachment.id);
        await deleteBlobObject(env, path);
      }),
    );
  }

  await attachmentRepo(env.DB).bulkDeleteAttachmentsByIds(attachments.map(({ attachment }) => attachment.id));
}
