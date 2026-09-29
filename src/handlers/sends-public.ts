import type { AppContext } from '../router';
import { Send, SendType } from '../types';
import { recordSendEvent } from '../services/events';
import { RateLimitService, getClientIdentifier } from '../services/ratelimit';
import { errorResponse } from '../utils/response';
import { contentDispositionAttachment, sanitizeDownloadContentType } from '../utils/content-type';
import { readActingDeviceIdentifier } from '../utils/device';
import { notifyUserSendUpdate, notifyUserVaultSync } from '../durable/notifications-hub';
import {
  createSendAccessToken,
  createSendFileDownloadToken,
  verifySendAccessToken,
  verifySendFileDownloadToken,
} from '../utils/jwt';
import { getBlobObject, getSendFileObjectKey } from '../services/blob-store';
import {
  SEND_INACCESSIBLE_MSG,
  extractBearerToken,
  fromAccessId,
  getCreatorIdentifier,
  hasEmailAuth,
  isSendAvailable,
  parseStoredSendData,
  resolveSendFromIdOrAccessId,
  sendFileIdMatches,
  sendPasswordLimitKey,
  sendPasswordLockedErrorResponse,
  sendPasswordLockedOAuthResponse,
  sendToAccessResponse,
  validatePublicSendAccess,
  verifySendPassword,
  verifySendPasswordHashB64,
} from './sends-shared';
import { attachmentTokenRepo } from '../services/storage-attachment-token-repo';
import { revisionRepo } from '../services/storage-revision-repo';
import { sendRepo } from '../services/storage-send-repo';

// Reads the optional JSON body and checks the Send password inside the per-client attempt limit,
// so a guessed password costs the guesser lockouts rather than the owner's Send. Resolves to the
// rejection to answer with, or null once the caller may proceed.
async function authorizeSendByPassword(c: AppContext, send: Send): Promise<Response | null> {
  const body: unknown = await c.req.raw.json().catch(() => ({}));

  const clientIdentifier = send.passwordHash ? getClientIdentifier(c.req.raw) : null;
  if (send.passwordHash && !clientIdentifier) return errorResponse(c, 'Client IP is required', 403);
  const limitKey = clientIdentifier ? sendPasswordLimitKey(clientIdentifier, send.id) : null;
  const rateLimit = new RateLimitService(c.env);
  if (limitKey) {
    const check = await rateLimit.checkLoginAttempt(limitKey);
    if (!check.allowed) return sendPasswordLockedErrorResponse(c, check.retryAfterSeconds || 60);
  }

  const validation = await validatePublicSendAccess(c, send, body);
  if (!validation.ok) {
    if (validation.reason === 'invalid_password' && limitKey) {
      const failed = await rateLimit.recordFailedLogin(limitKey);
      if (failed.locked) return sendPasswordLockedErrorResponse(c, failed.retryAfterSeconds || 60);
    }
    return validation.response;
  }
  if (limitKey) await rateLimit.clearLoginAttempts(limitKey);
  return null;
}

// Resolves the available Send named by the bearer send-access token, or the rejection to answer with.
async function authorizeSendByToken(c: AppContext): Promise<{ secret: string; send: Send } | Response> {
  const token = extractBearerToken(c.req.raw);
  const claims = token ? await verifySendAccessToken(token, c.env.JWT_SECRET) : null;
  if (!claims) return errorResponse(c, 'Unauthorized', 401);
  const send = await sendRepo(c.env.DB).getSend(claims.sub);
  if (!send || !isSendAvailable(send)) return errorResponse(c, SEND_INACCESSIBLE_MSG, 404);
  return { secret: c.env.JWT_SECRET, send };
}

// Counts one access against the Send's limit, then tells the owner's devices and the event log.
async function touchSendAccess(c: AppContext, send: Send): Promise<Response | null> {
  if (!(await sendRepo(c.env.DB).incrementSendAccessCount(send.id)))
    return errorResponse(c, SEND_INACCESSIBLE_MSG, 404);
  send.accessCount += 1;
  const revisionDate = await revisionRepo(c.env.DB).updateRevisionDate(send.userId);
  notifyUserVaultSync(c.env, send.userId, revisionDate, readActingDeviceIdentifier(c.req.raw));
  notifyUserSendUpdate(c.env, {
    userId: send.userId,
    sendId: send.id,
    revisionDate,
    contextId: readActingDeviceIdentifier(c.req.raw),
  });
  await recordSendEvent(c.env, c.req.raw, send, 'accessed');
  return null;
}

// The file itself is fetched through a short-lived signed URL rather than a bearer header.
async function sendFileDownloadResponse(c: AppContext, send: Send, fileId: string, secret: string): Promise<Response> {
  const token = await createSendFileDownloadToken(send.id, fileId, secret);
  return c.json({
    object: 'send-fileDownload',
    id: fileId,
    url: `${new URL(c.req.raw.url).origin}/api/sends/${send.id}/${fileId}?t=${token}`,
  });
}

export async function handleAccessSend(c: AppContext, accessId: string): Promise<Response> {
  const sendId = fromAccessId(accessId);
  const send = sendId ? await sendRepo(c.env.DB).getSend(sendId) : null;
  if (!send || !isSendAvailable(send)) return errorResponse(c, SEND_INACCESSIBLE_MSG, 404);

  const rejected = await authorizeSendByPassword(c, send);
  if (rejected) return rejected;

  if (send.type === SendType.Text) {
    const touched = await touchSendAccess(c, send);
    if (touched) return touched;
  }

  return c.json(sendToAccessResponse(send, await getCreatorIdentifier(c.env.DB, send)));
}

export async function handleAccessSendFile(c: AppContext, idOrAccessId: string, fileId: string): Promise<Response> {
  const send = await resolveSendFromIdOrAccessId(c.env.DB, idOrAccessId);
  if (!send || !isSendAvailable(send) || send.type !== SendType.File || !sendFileIdMatches(send, fileId)) {
    return errorResponse(c, SEND_INACCESSIBLE_MSG, 404);
  }

  const rejected = await authorizeSendByPassword(c, send);
  if (rejected) return rejected;

  const touched = await touchSendAccess(c, send);
  if (touched) return touched;

  return sendFileDownloadResponse(c, send, fileId, c.env.JWT_SECRET);
}

export async function handleAccessSendV2(c: AppContext): Promise<Response> {
  const auth = await authorizeSendByToken(c);
  if (auth instanceof Response) return auth;
  const { send } = auth;

  if (send.type === SendType.Text) {
    const touched = await touchSendAccess(c, send);
    if (touched) return touched;
  }

  return c.json(sendToAccessResponse(send, await getCreatorIdentifier(c.env.DB, send)));
}

export async function handleAccessSendFileV2(c: AppContext, fileId: string): Promise<Response> {
  const auth = await authorizeSendByToken(c);
  if (auth instanceof Response) return auth;
  const { send, secret } = auth;
  if (send.type !== SendType.File || !sendFileIdMatches(send, fileId)) {
    return errorResponse(c, SEND_INACCESSIBLE_MSG, 404);
  }

  const touched = await touchSendAccess(c, send);
  if (touched) return touched;

  return sendFileDownloadResponse(c, send, fileId, secret);
}

export async function handleDownloadSendFile(c: AppContext, sendId: string, fileId: string): Promise<Response> {
  const url = new URL(c.req.raw.url);
  const token = url.searchParams.get('t') || url.searchParams.get('token');
  if (!token) {
    return errorResponse(c, 'Token required', 401);
  }

  const claims = await verifySendFileDownloadToken(token, c.env.JWT_SECRET);
  if (!claims) {
    return errorResponse(c, 'Invalid or expired token', 401);
  }
  if (claims.sendId !== sendId || claims.fileId !== fileId) {
    return errorResponse(c, 'Token mismatch', 401);
  }

  const send = await sendRepo(c.env.DB).getSend(sendId);
  if (!send || !isSendAvailable(send) || send.type !== SendType.File) {
    return errorResponse(c, SEND_INACCESSIBLE_MSG, 404);
  }
  const data = parseStoredSendData(send);
  if (data.id !== fileId) {
    return errorResponse(c, SEND_INACCESSIBLE_MSG, 404);
  }

  const firstUse = await attachmentTokenRepo(c.env.DB).consumeAttachmentDownloadToken(`send:${claims.jti}`, claims.exp);
  if (!firstUse) {
    return errorResponse(c, 'Invalid or expired token', 401);
  }

  const object = await getBlobObject(c.env, getSendFileObjectKey(sendId, fileId));
  if (!object) {
    return errorResponse(c, 'Send file not found', 404);
  }
  const fileName = data.fileName ?? fileId;

  return new Response(object.body, {
    headers: {
      'Content-Type': sanitizeDownloadContentType(object.contentType),
      'Content-Length': String(object.size),
      'Content-Disposition': contentDispositionAttachment(fileName, 'send-file'),
      'Cache-Control': 'private, no-cache',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

export async function issueSendAccessToken(
  c: AppContext,
  sendIdOrAccessId: string,
  passwordHashB64?: string | null,
  password?: string | null,
  rateLimit?: RateLimitService,
  clientIdentifier?: string,
): Promise<{ token: string } | { error: Response }> {
  const send = await resolveSendFromIdOrAccessId(c.env.DB, sendIdOrAccessId);

  if (!send || !isSendAvailable(send)) {
    return {
      error: c.json(
        {
          error: 'invalid_grant',
          error_description: SEND_INACCESSIBLE_MSG,
          send_access_error_type: 'send_not_available',
          ErrorModel: {
            Message: SEND_INACCESSIBLE_MSG,
            Object: 'error',
          },
        },
        400,
      ),
    };
  }

  if (hasEmailAuth(send)) {
    const message = 'Email verification for this Send is not supported by this server.';
    return {
      error: c.json(
        {
          error: 'invalid_grant',
          error_description: message,
          send_access_error_type: 'email_verification_not_supported',
          ErrorModel: {
            Message: message,
            Object: 'error',
          },
        },
        501,
      ),
    };
  }

  const sendPasswordLimitIpKey = rateLimit && clientIdentifier ? sendPasswordLimitKey(clientIdentifier, send.id) : null;

  if (send.passwordHash) {
    if (rateLimit && sendPasswordLimitIpKey) {
      const sendPasswordCheck = await rateLimit.checkLoginAttempt(sendPasswordLimitIpKey);
      if (!sendPasswordCheck.allowed) {
        return {
          error: sendPasswordLockedOAuthResponse(c, sendPasswordCheck.retryAfterSeconds || 60),
        };
      }
    }

    let ok = false;
    if (passwordHashB64) {
      ok = verifySendPasswordHashB64(send, passwordHashB64);
    } else if (password) {
      ok = await verifySendPassword(send, password);
    }

    if (!ok) {
      if (rateLimit && sendPasswordLimitIpKey) {
        const failed = await rateLimit.recordFailedLogin(sendPasswordLimitIpKey);
        if (failed.locked) {
          return {
            error: sendPasswordLockedOAuthResponse(c, failed.retryAfterSeconds || 60),
          };
        }
      }
      return {
        error: c.json(
          {
            error: 'invalid_grant',
            error_description: 'Invalid password.',
            send_access_error_type: 'invalid_password',
            ErrorModel: {
              Message: 'Invalid password.',
              Object: 'error',
            },
          },
          400,
        ),
      };
    }

    if (rateLimit && sendPasswordLimitIpKey) {
      await rateLimit.clearLoginAttempts(sendPasswordLimitIpKey);
    }
  }

  const token = await createSendAccessToken(send.id, c.env.JWT_SECRET);
  return { token };
}
