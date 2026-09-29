import { encode } from '@msgpack/msgpack';
import { z } from 'zod';
import { DurableObject, waitUntil } from 'cloudflare:workers';
import type { Env } from '../types';
import { withoutQueryParams } from '../db/client';
import { notifyMobilePush } from '../services/push-relay';

const SIGNALR_RECORD_SEPARATOR = 0x1e;
const SIGNALR_HANDSHAKE_ACK = new Uint8Array([0x7b, 0x7d, SIGNALR_RECORD_SEPARATOR]);
// A SignalR handshake request is {"protocol":"json"|"messagepack","version":1}; a frame that is not an
// object waits for the next one, and any protocol other than json falls back to MessagePack.
const HandshakeFrame = z.object({ protocol: z.string().optional() });
const SIGNALR_UPDATE_TYPE_SYNC_CIPHER_UPDATE = 0;
const SIGNALR_UPDATE_TYPE_SYNC_CIPHER_CREATE = 1;
const SIGNALR_UPDATE_TYPE_SYNC_FOLDER_DELETE = 3;
const SIGNALR_UPDATE_TYPE_SYNC_CIPHERS = 4;
const SIGNALR_UPDATE_TYPE_SYNC_VAULT = 5;
const SIGNALR_UPDATE_TYPE_SYNC_FOLDER_CREATE = 7;
const SIGNALR_UPDATE_TYPE_SYNC_FOLDER_UPDATE = 8;
const SIGNALR_UPDATE_TYPE_SYNC_CIPHER_DELETE = 9;
const SIGNALR_UPDATE_TYPE_LOG_OUT = 11;
const SIGNALR_UPDATE_TYPE_SYNC_SEND_CREATE = 12;
const SIGNALR_UPDATE_TYPE_SYNC_SEND_UPDATE = 13;
const SIGNALR_UPDATE_TYPE_SYNC_SEND_DELETE = 14;
const SIGNALR_UPDATE_TYPE_AUTH_REQUEST = 15;
const SIGNALR_UPDATE_TYPE_AUTH_REQUEST_RESPONSE = 16;
const WEBSOCKET_CONNECTION_TOKEN_PREFIX = 'ws-token:';
const WEBSOCKET_CONNECTION_TOKEN_TTL_MS = 60 * 1000;

type HubProtocol = 'json' | 'messagepack';
type HubKind = 'user' | 'anonymous-auth-request';

interface WsAttachment {
  kind: HubKind;
  userId: string | null;
  authRequestId: string | null;
  handshakeComplete: boolean;
  protocol: HubProtocol;
  deviceIdentifier: string | null;
}

const optionalIdentifier = z
  .string()
  .trim()
  .nullish()
  .transform((value) => value || null);
const ConnectionTicket = z.object({
  token: z.string().trim().min(1),
  userId: z.string().trim().min(1),
  deviceIdentifier: optionalIdentifier,
  expiresAt: z.number(),
});
type WebSocketConnectionToken = Omit<z.output<typeof ConnectionTicket>, 'token'>;
const Notification = z.object({
  updateType: z.number(),
  payload: z.record(z.string(), z.unknown()),
  contextId: optionalIdentifier,
  targetDeviceIdentifier: optionalIdentifier,
});
const AuthRequestNotification = z.object({
  userId: z.string().trim().min(1),
  authRequestId: z.string().trim().min(1),
  contextId: optionalIdentifier,
});

function buildSignalRJsonInvocation(
  updateType: number,
  payload: Record<string, unknown>,
  contextId: string | null,
  target: string = 'ReceiveMessage',
): string {
  return (
    JSON.stringify({
      type: 1,
      target,
      arguments: [
        {
          ContextId: contextId,
          Type: updateType,
          Payload: payload,
        },
      ],
    }) + String.fromCharCode(SIGNALR_RECORD_SEPARATOR)
  );
}

export function buildSignalRMessagePackInvocation(
  updateType: number,
  messagePayload: Record<string, unknown>,
  contextId: string | null,
  target: string = 'ReceiveMessage',
): Uint8Array {
  // SignalR MessagePack hub protocol uses an array-based invocation shape:
  // [type, headers, invocationId, target, arguments, streamIds]
  const encodedPayload = encode([
    1,
    {},
    null,
    target,
    [
      {
        ContextId: contextId,
        Type: updateType,
        Payload: messagePayload,
      },
    ],
    [],
  ]);
  // Binary SignalR frames carry a VarInt length prefix: 7 bits per byte, low bits first.
  const prefix: number[] = [];
  let value = encodedPayload.length;
  do {
    let current = value & 0x7f;
    value >>>= 7;
    if (value > 0) current |= 0x80;
    prefix.push(current);
  } while (value > 0);
  const frame = new Uint8Array(prefix.length + encodedPayload.length);
  frame.set(prefix);
  frame.set(encodedPayload, prefix.length);
  return frame;
}

export class NotificationsHub extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ctx.setWebSocketAutoResponse(
      new WebSocketRequestResponsePair(
        JSON.stringify({ type: 6 }) + String.fromCharCode(SIGNALR_RECORD_SEPARATOR),
        JSON.stringify({ type: 6 }) + String.fromCharCode(SIGNALR_RECORD_SEPARATOR),
      ),
    );
  }

  async registerConnectionToken(input: z.input<typeof ConnectionTicket>): Promise<boolean> {
    const parsed = ConnectionTicket.safeParse(input);
    if (!parsed.success) return false;
    const { token, ...connection } = parsed.data;
    const now = Date.now();
    if (connection.expiresAt <= now || connection.expiresAt > now + WEBSOCKET_CONNECTION_TOKEN_TTL_MS) return false;
    await this.ctx.storage.put(`${WEBSOCKET_CONNECTION_TOKEN_PREFIX}${token}`, connection);
    const currentAlarm = await this.ctx.storage.getAlarm();
    if (currentAlarm === null || connection.expiresAt < currentAlarm)
      await this.ctx.storage.setAlarm(connection.expiresAt);
    return true;
  }

  async consumeConnectionToken(token: string): Promise<WebSocketConnectionToken | null> {
    const parsed = ConnectionTicket.shape.token.safeParse(token);
    if (!parsed.success) return null;
    // Delete inside a transaction so a connection ticket cannot win two concurrent upgrades.
    const connection = await this.ctx.storage.transaction(async (txn) => {
      const key = `${WEBSOCKET_CONNECTION_TOKEN_PREFIX}${parsed.data}`;
      const stored = await txn.get<WebSocketConnectionToken>(key);
      if (stored) await txn.delete(key);
      return stored || null;
    });
    return connection && connection.expiresAt > Date.now() ? connection : null;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname !== '/notifications/hub' && url.pathname !== '/notifications/anonymous-hub') {
      return new Response('Not found', { status: 404 });
    }

    if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') {
      return new Response('Expected websocket', { status: 426 });
    }

    const requestUserId = String(url.searchParams.get('nw_uid') || '').trim();
    const requestDeviceIdentifier = String(url.searchParams.get('nw_did') || '').trim() || null;
    const requestAuthRequestId = String(url.searchParams.get('nw_auth_request_id') || '').trim() || null;
    const isAnonymousAuthRequestHub = url.pathname === '/notifications/anonymous-hub';

    if (!isAnonymousAuthRequestHub && !requestUserId) {
      return new Response('Unauthorized', { status: 401 });
    }
    if (isAnonymousAuthRequestHub && !requestAuthRequestId) {
      return new Response('Unauthorized', { status: 401 });
    }

    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];

    const tags: string[] = [];
    if (requestDeviceIdentifier) {
      tags.push(`device:${requestDeviceIdentifier}`);
    }
    this.ctx.acceptWebSocket(server, tags);

    server.serializeAttachment({
      kind: isAnonymousAuthRequestHub ? 'anonymous-auth-request' : 'user',
      userId: isAnonymousAuthRequestHub ? null : requestUserId,
      authRequestId: requestAuthRequestId,
      handshakeComplete: false,
      protocol: 'messagepack',
      deviceIdentifier: requestDeviceIdentifier,
    } satisfies WsAttachment);

    return new Response(null, {
      status: 101,
      webSocket: client,
    });
  }

  async alarm(): Promise<void> {
    const now = Date.now();
    const tokens = await this.ctx.storage.list<WebSocketConnectionToken>({
      prefix: WEBSOCKET_CONNECTION_TOKEN_PREFIX,
    });
    const expiredKeys: string[] = [];
    let nextExpiration: number | null = null;

    for (const [key, token] of tokens) {
      if (token.expiresAt <= now) {
        expiredKeys.push(key);
      } else if (nextExpiration === null || token.expiresAt < nextExpiration) {
        nextExpiration = token.expiresAt;
      }
    }

    // Negotiated tickets that never reach an upgrade must not remain in DO storage indefinitely.
    if (expiredKeys.length > 0) await this.ctx.storage.delete(expiredKeys);
    if (nextExpiration !== null) await this.ctx.storage.setAlarm(nextExpiration);
  }

  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer | ArrayBufferView): Promise<void> {
    const attachment = ws.deserializeAttachment() as WsAttachment | null;
    if (!attachment) return;

    if (!attachment.handshakeComplete) {
      const text =
        typeof message === 'string'
          ? message
          : new TextDecoder().decode(
              message instanceof ArrayBuffer
                ? new Uint8Array(message)
                : new Uint8Array(message.buffer, message.byteOffset, message.byteLength),
            );
      const frames = text.split(String.fromCharCode(SIGNALR_RECORD_SEPARATOR)).filter(Boolean);
      for (const frame of frames) {
        try {
          const { protocol } = HandshakeFrame.parse(JSON.parse(frame));
          attachment.protocol = protocol === 'json' ? 'json' : 'messagepack';
          attachment.handshakeComplete = true;
          ws.serializeAttachment(attachment);
          ws.send(SIGNALR_HANDSHAKE_ACK);
          return;
        } catch {
          // Ignore malformed pre-handshake payloads.
        }
      }
      return;
    }

    if (typeof message !== 'string') {
      try {
        ws.send(message);
      } catch {
        // ignore send errors on echo
      }
    }
  }

  async webSocketClose(ws: WebSocket, code: number, reason: string, wasClean: boolean): Promise<void> {
    void ws;
    void code;
    void reason;
    void wasClean;
  }

  async webSocketError(ws: WebSocket, error: unknown): Promise<void> {
    void ws;
    void error;
  }

  getOnlineDeviceIdentifiers(): string[] {
    const out = new Set<string>();
    for (const ws of this.ctx.getWebSockets()) {
      const attachment = ws.deserializeAttachment() as WsAttachment | null;
      if (!attachment?.handshakeComplete || attachment.kind !== 'user' || !attachment.deviceIdentifier) continue;
      out.add(attachment.deviceIdentifier);
    }
    return Array.from(out);
  }

  notify(input: z.input<typeof Notification>): void {
    const { updateType, payload, contextId, targetDeviceIdentifier } = Notification.parse(input);
    const sockets = targetDeviceIdentifier
      ? this.ctx.getWebSockets(`device:${targetDeviceIdentifier}`)
      : this.ctx.getWebSockets();

    if (sockets.length === 0) return;

    for (const ws of sockets) {
      const attachment = ws.deserializeAttachment() as WsAttachment | null;
      if (!attachment?.handshakeComplete) continue;
      try {
        if (attachment.protocol === 'json') {
          ws.send(buildSignalRJsonInvocation(updateType, payload, contextId));
        } else {
          ws.send(buildSignalRMessagePackInvocation(updateType, payload, contextId));
        }
      } catch {
        try {
          ws.close(1011, 'Notification send failed');
        } catch {
          // ignore close races
        }
      }
    }
  }

  notifyAuthRequestResponse(input: z.input<typeof AuthRequestNotification>): void {
    const { userId, authRequestId, contextId } = AuthRequestNotification.parse(input);
    for (const ws of this.ctx.getWebSockets()) {
      const attachment = ws.deserializeAttachment() as WsAttachment | null;
      if (
        !attachment?.handshakeComplete ||
        attachment.kind !== 'anonymous-auth-request' ||
        attachment.authRequestId !== authRequestId
      ) {
        continue;
      }

      const payload = {
        UserId: userId,
        Id: authRequestId,
      };
      try {
        if (attachment.protocol === 'json') {
          ws.send(
            buildSignalRJsonInvocation(
              SIGNALR_UPDATE_TYPE_AUTH_REQUEST_RESPONSE,
              payload,
              contextId,
              'AuthRequestResponseRecieved',
            ),
          );
        } else {
          ws.send(
            buildSignalRMessagePackInvocation(
              SIGNALR_UPDATE_TYPE_AUTH_REQUEST_RESPONSE,
              payload,
              contextId,
              'AuthRequestResponseRecieved',
            ),
          );
        }
      } catch {
        try {
          ws.close(1011, 'Notification send failed');
        } catch {
          // ignore close races
        }
      }
    }
  }
}

export function notifyUserVaultSync(env: Env, userId: string, revisionDate: string, contextId?: string | null): void {
  waitUntil(notifyUserUpdate(env, userId, SIGNALR_UPDATE_TYPE_SYNC_VAULT, revisionDate, contextId ?? null, null));
}

export function notifyUserCiphersSync(env: Env, userId: string, revisionDate: string, contextId?: string | null): void {
  waitUntil(notifyUserUpdate(env, userId, SIGNALR_UPDATE_TYPE_SYNC_CIPHERS, revisionDate, contextId ?? null, null));
}

// Cipher, folder and Send changes notify { UserId, Id, ..., RevisionDate } under their own update types, and cipher
// changes also carry the organization and collections.
interface ItemChange {
  userId: string;
  revisionDate: string;
  contextId?: string | null;
}

const notifyChange =
  <Change extends ItemChange>(updateType: number, fields: (change: Change) => Record<string, unknown>) =>
  (env: Env, change: Change): void =>
    waitUntil(
      notifyUserUpdate(env, change.userId, updateType, change.revisionDate, change.contextId ?? null, null, {
        UserId: change.userId,
        ...fields(change),
        RevisionDate: change.revisionDate,
      }),
    );

const cipherFields = (
  change: ItemChange & { cipherId: string; organizationId?: string | null; collectionIds?: string[] | null },
) => ({
  Id: change.cipherId,
  OrganizationId: change.organizationId ?? null,
  CollectionIds: Array.isArray(change.collectionIds) ? change.collectionIds : null,
});
const folderFields = (change: ItemChange & { folderId: string }) => ({ Id: change.folderId });
const sendFields = (change: ItemChange & { sendId: string }) => ({ Id: change.sendId });

export const notifyUserCipherCreate = notifyChange(SIGNALR_UPDATE_TYPE_SYNC_CIPHER_CREATE, cipherFields);
export const notifyUserCipherUpdate = notifyChange(SIGNALR_UPDATE_TYPE_SYNC_CIPHER_UPDATE, cipherFields);
export const notifyUserCipherDelete = notifyChange(SIGNALR_UPDATE_TYPE_SYNC_CIPHER_DELETE, cipherFields);
export const notifyUserFolderCreate = notifyChange(SIGNALR_UPDATE_TYPE_SYNC_FOLDER_CREATE, folderFields);
export const notifyUserFolderUpdate = notifyChange(SIGNALR_UPDATE_TYPE_SYNC_FOLDER_UPDATE, folderFields);
export const notifyUserFolderDelete = notifyChange(SIGNALR_UPDATE_TYPE_SYNC_FOLDER_DELETE, folderFields);
export const notifyUserSendCreate = notifyChange(SIGNALR_UPDATE_TYPE_SYNC_SEND_CREATE, sendFields);
export const notifyUserSendUpdate = notifyChange(SIGNALR_UPDATE_TYPE_SYNC_SEND_UPDATE, sendFields);
export const notifyUserSendDelete = notifyChange(SIGNALR_UPDATE_TYPE_SYNC_SEND_DELETE, sendFields);

export function notifyUserLogout(env: Env, userId: string, targetDeviceIdentifier?: string | null): void {
  waitUntil(
    notifyUserUpdate(
      env,
      userId,
      SIGNALR_UPDATE_TYPE_LOG_OUT,
      new Date().toISOString(),
      null,
      targetDeviceIdentifier ?? null,
    ),
  );
}

export async function getOnlineUserDevices(env: Env, userId: string): Promise<string[]> {
  try {
    const id = env.NOTIFICATIONS_HUB.idFromName(userId);
    const stub = env.NOTIFICATIONS_HUB.get(id);
    return await stub.getOnlineDeviceIdentifiers();
  } catch {
    return [];
  }
}

export async function notifyAuthRequestResponse(
  env: Env,
  userId: string,
  authRequestId: string,
  contextId?: string | null,
): Promise<void> {
  try {
    const id = env.NOTIFICATIONS_HUB.idFromName(authRequestId);
    const stub = env.NOTIFICATIONS_HUB.get(id);
    await stub.notifyAuthRequestResponse({ userId, authRequestId, contextId });
  } catch (error) {
    console.error('Failed to broadcast auth request response notification:', withoutQueryParams(error));
  }
}

export function notifyUserAuthRequest(
  env: Env,
  userId: string,
  authRequestId: string,
  contextId?: string | null,
): void {
  waitUntil(
    notifyUserUpdate(env, userId, SIGNALR_UPDATE_TYPE_AUTH_REQUEST, new Date().toISOString(), contextId ?? null, null, {
      UserId: userId,
      Id: authRequestId,
    }),
  );
}

async function notifyUserUpdate(
  env: Env,
  userId: string,
  updateType: number,
  revisionDate: string,
  contextId: string | null,
  targetDeviceIdentifier: string | null,
  payloadOverride?: Record<string, unknown> | null,
): Promise<void> {
  try {
    const id = env.NOTIFICATIONS_HUB.idFromName(userId);
    const stub = env.NOTIFICATIONS_HUB.get(id);
    await stub.notify({
      contextId,
      updateType,
      targetDeviceIdentifier,
      payload: payloadOverride || {
        UserId: userId,
        Date: revisionDate,
      },
    });
    await notifyMobilePush(env, {
      userId,
      updateType,
      revisionDate,
      contextId,
      payload: payloadOverride || {
        UserId: userId,
        Date: revisionDate,
      },
    });
  } catch (error) {
    console.error('Failed to broadcast realtime notification:', withoutQueryParams(error));
  }
}
