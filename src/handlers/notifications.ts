import type { AppContext } from '../router';
import { AuthService } from '../services/auth';
import { isAuthRequestExpired, authRequestRepo } from '../services/storage-auth-request-repo';
import type { Env, JWTPayload } from '../types';
import { errorResponse } from '../utils/response';
import { createWebSocketConnectionToken, verifyWebSocketConnectionToken } from '../utils/websocket-connection-token';

const WEBSOCKET_CONNECTION_TOKEN_TTL_MS = 60 * 1000;

async function authenticateAccessToken(authHeader: string | null, env: Env): Promise<JWTPayload | null> {
  const accessToken = authHeader
    ?.trim()
    .match(/^Bearer\s+(.+)$/i)?.[1]
    ?.trim();
  if (!accessToken) return null;

  const auth = new AuthService(env);
  return auth.verifyAccessToken(`Bearer ${accessToken}`);
}

export async function handleNotificationsNegotiate(c: AppContext): Promise<Response> {
  const payload = await authenticateAccessToken(c.req.raw.headers.get('Authorization'), c.env);
  if (!payload?.sub) return errorResponse(c, 'Unauthorized', 401);

  // Issue the single-use connection token the WebSocket upgrade presents instead of the access JWT.
  const expiresAt = Date.now() + WEBSOCKET_CONNECTION_TOKEN_TTL_MS;
  const connectionToken = await createWebSocketConnectionToken(payload.sub, expiresAt, c.env.JWT_SECRET);
  const id = c.env.NOTIFICATIONS_HUB.idFromName(payload.sub);
  const stub = c.env.NOTIFICATIONS_HUB.get(id);
  const registered = await stub.registerConnectionToken({
    token: connectionToken,
    userId: payload.sub,
    deviceIdentifier: payload.did || null,
    expiresAt,
  });
  if (!registered) throw new Error('Failed to issue websocket connection token');
  return c.json(
    {
      connectionId: crypto.randomUUID(),
      connectionToken,
      negotiateVersion: 1,
      availableTransports: [
        {
          transport: 'WebSockets',
          transferFormats: ['Text', 'Binary'],
        },
      ],
    },
    200,
    { 'Cache-Control': 'no-store' },
  );
}

export async function handleNotificationsHub(c: AppContext): Promise<Response> {
  if (c.req.raw.headers.get('Upgrade')?.toLowerCase() !== 'websocket') {
    return errorResponse(c, 'Expected websocket', 426);
  }
  const url = new URL(c.req.raw.url);
  let payload: JWTPayload | null;
  if (c.req.raw.headers.has('Authorization')) {
    payload = await authenticateAccessToken(c.req.raw.headers.get('Authorization'), c.env);
  } else if (url.searchParams.has('access_token')) {
    // Official browsers skip negotiation and SignalR uses the query because WebSocket cannot set headers.
    // Invocation logs and tracing must stay off or scrub query strings before retaining request URLs.
    payload = await authenticateAccessToken(`Bearer ${url.searchParams.get('access_token') || ''}`, c.env);
  } else {
    // Without the header, consume the single-use connection token from negotiate (SignalR sends it as id).
    const token = String(url.searchParams.get('id') || '').trim();
    const claims = await verifyWebSocketConnectionToken(token, c.env.JWT_SECRET);
    if (!claims) return errorResponse(c, 'Unauthorized', 401);

    // Verify the signed routing claim before selecting a Durable Object. Otherwise an
    // attacker could activate arbitrary object names with forged token prefixes.
    const tokenHub = c.env.NOTIFICATIONS_HUB.get(c.env.NOTIFICATIONS_HUB.idFromName(claims.userId));
    const connection = await tokenHub.consumeConnectionToken(token);
    if (connection?.userId !== claims.userId) return errorResponse(c, 'Unauthorized', 401);

    payload = {
      sub: claims.userId,
      did: String(connection.deviceIdentifier || '').trim() || undefined,
    } as JWTPayload;
  }
  if (!payload?.sub) return errorResponse(c, 'Unauthorized', 401);

  const userId = payload.sub;
  const id = c.env.NOTIFICATIONS_HUB.idFromName(userId);
  const stub = c.env.NOTIFICATIONS_HUB.get(id);
  url.searchParams.delete('access_token');
  url.searchParams.delete('id');
  url.searchParams.delete('nw_did');
  url.searchParams.delete('nw_auth_request_id');
  url.searchParams.set('nw_uid', userId);
  if (payload.did) {
    url.searchParams.set('nw_did', payload.did);
  }
  return stub.fetch(new Request(url.toString(), c.req.raw));
}

export async function handleAnonymousNotificationsHub(c: AppContext): Promise<Response> {
  const url = new URL(c.req.raw.url);
  const authRequestId = String(url.searchParams.get('Token') || url.searchParams.get('token') || '').trim();
  if (!authRequestId) return errorResponse(c, 'Token is required', 400);
  if (c.req.raw.headers.get('Upgrade')?.toLowerCase() !== 'websocket') {
    return errorResponse(c, 'Expected websocket', 426);
  }

  const authRequest = await authRequestRepo(c.env.DB).getAuthRequestById(authRequestId);
  if (!authRequest || isAuthRequestExpired(authRequest)) {
    return errorResponse(c, 'Not found', 404);
  }

  const id = c.env.NOTIFICATIONS_HUB.idFromName(authRequestId);
  const stub = c.env.NOTIFICATIONS_HUB.get(id);
  const forwardedUrl = new URL(c.req.raw.url);
  forwardedUrl.searchParams.set('nw_auth_request_id', authRequestId);
  return stub.fetch(new Request(forwardedUrl.toString(), c.req.raw));
}
