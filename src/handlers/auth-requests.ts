import type { AppContext } from '../router';
import type { AuthRequestRecord } from '../types';
import { generateUUID } from '../utils/uuid';
import { z } from 'zod';
import { deviceTypeName, readAuthRequestDeviceInfo, readActingDeviceIdentifier } from '../utils/device';
import { isSerializedEncString } from '../utils/account-passkeys';
import { errorResponse, type BodyContext } from '../utils/response';
import { isAuthRequestExpired, authRequestRepo } from '../services/storage-auth-request-repo';
import { notifyAuthRequestResponse, notifyUserAuthRequest } from '../durable/notifications-hub';
import { RateLimitService, getClientIdentifier } from '../services/ratelimit';
import { LIMITS } from '../config/limits';
import { deviceRepo } from '../services/storage-device-repo';
import { userRepo } from '../services/storage-user-repo';

const AUTH_REQUEST_TYPE_AUTHENTICATE_AND_UNLOCK = 0;
const AUTH_REQUEST_TYPE_UNLOCK = 1;
const AUTH_REQUEST_TYPE_ADMIN_APPROVAL = 2;

// Fields are clipped to their column widths; a value of the wrong type reads as empty.
const clippedText = (maxLength: number) =>
  z
    .string()
    .trim()
    .transform((text) => text.slice(0, maxLength))
    .catch('');

export const AuthRequestCreateSchema = z.looseObject({
  email: clippedText(320).transform((email) => email.toLowerCase()),
  publicKey: clippedText(8192),
  accessCode: clippedText(25),
  type: z.coerce.number().catch(AUTH_REQUEST_TYPE_AUTHENTICATE_AND_UNLOCK),
});

export const AuthRequestUpdateSchema = z.object({
  requestApproved: z.coerce.boolean(),
  key: clippedText(20000),
  deviceIdentifier: clippedText(128),
});

function getClientIp(request: Request): string | null {
  return (
    request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() || null
  );
}

function getCountryName(request: Request): string | null {
  return request.headers.get('CF-IPCountry') || null;
}

function buildOrigin(request: Request): string {
  return new URL(request.url).host;
}

function toAuthRequestResponse(request: Request, authRequest: AuthRequestRecord, requestDeviceId?: string | null) {
  return {
    id: authRequest.id,
    Id: authRequest.id,
    publicKey: authRequest.publicKey,
    PublicKey: authRequest.publicKey,
    requestDeviceIdentifier: authRequest.requestDeviceIdentifier,
    RequestDeviceIdentifier: authRequest.requestDeviceIdentifier,
    requestDeviceTypeValue: authRequest.requestDeviceType,
    RequestDeviceTypeValue: authRequest.requestDeviceType,
    requestDeviceType: deviceTypeName(authRequest.requestDeviceType),
    RequestDeviceType: deviceTypeName(authRequest.requestDeviceType),
    requestIpAddress: authRequest.requestIpAddress,
    RequestIpAddress: authRequest.requestIpAddress,
    requestCountryName: authRequest.requestCountryName,
    RequestCountryName: authRequest.requestCountryName,
    key: authRequest.key,
    Key: authRequest.key,
    masterPasswordHash: null,
    MasterPasswordHash: null,
    creationDate: authRequest.creationDate,
    CreationDate: authRequest.creationDate,
    responseDate: authRequest.responseDate,
    ResponseDate: authRequest.responseDate,
    requestApproved: authRequest.approved ?? false,
    RequestApproved: authRequest.approved ?? false,
    requestDeviceId: requestDeviceId ?? null,
    RequestDeviceId: requestDeviceId ?? null,
    origin: buildOrigin(request),
    Origin: buildOrigin(request),
    object: 'auth-request',
    Object: 'auth-request',
  };
}

function listResponse<T>(data: T[]) {
  return {
    data,
    Data: data,
    object: 'list',
    Object: 'list',
    continuationToken: null,
    ContinuationToken: null,
  };
}

async function enforceAuthRequestCreateRateLimit(
  c: AppContext,
  email: string,
  deviceIdentifier: string,
): Promise<Response | null> {
  const clientIdentifier = getClientIdentifier(c.req.raw);
  if (!clientIdentifier) return errorResponse(c, 'Client IP is required', 403);

  const rateLimit = new RateLimitService(c.env);
  const limit = LIMITS.rateLimit.authRequestRequestsPerMinute;
  const encodedEmail = encodeURIComponent(email || 'missing');
  const encodedDevice = encodeURIComponent(deviceIdentifier || 'missing');
  const budgets = await Promise.all([
    rateLimit.consumeStrictBudget(`auth-request:ip:${clientIdentifier}`, limit),
    rateLimit.consumeStrictBudget(`auth-request:email:${encodedEmail}`, limit),
    rateLimit.consumeStrictBudget(`auth-request:device:${encodedDevice}`, limit),
  ]);
  const blocked = budgets.find((budget) => !budget.allowed);
  if (!blocked) return null;

  return errorResponse(c, 'Too many authentication requests. Try again later.', 429);
}

export async function handleCreateAuthRequest(c: BodyContext<typeof AuthRequestCreateSchema>): Promise<Response> {
  const body = c.req.valid('json');
  const { email, publicKey, accessCode, type } = body;
  const deviceInfo = readAuthRequestDeviceInfo(body, c.req.raw);

  if (!email || !publicKey || !accessCode || !deviceInfo.deviceIdentifier) {
    return errorResponse(c, 'Email, public key, device identifier, and access code are required.', 400);
  }
  const rateLimitResponse = await enforceAuthRequestCreateRateLimit(c, email, deviceInfo.deviceIdentifier);
  if (rateLimitResponse) return rateLimitResponse;
  // Admin approval requests are created through their own authenticated endpoint.
  if (type !== AUTH_REQUEST_TYPE_AUTHENTICATE_AND_UNLOCK && type !== AUTH_REQUEST_TYPE_UNLOCK) {
    return errorResponse(c, 'Invalid auth request type.', 400);
  }

  const user = await userRepo(c.env.DB).getUser(email);
  if (!user || user.status !== 'active') {
    return errorResponse(c, 'User or known device not found.', 400);
  }

  await authRequestRepo(c.env.DB).pruneExpiredAuthRequests();
  const now = new Date().toISOString();
  const authRequest: AuthRequestRecord = {
    id: generateUUID(),
    userId: user.id,
    organizationId: null,
    type,
    requestDeviceIdentifier: deviceInfo.deviceIdentifier,
    requestDeviceType: deviceInfo.deviceType,
    requestIpAddress: getClientIp(c.req.raw),
    requestCountryName: getCountryName(c.req.raw),
    responseDeviceIdentifier: null,
    accessCode,
    publicKey,
    key: null,
    masterPasswordHash: null,
    approved: null,
    creationDate: now,
    responseDate: null,
    authenticationDate: null,
  };
  await authRequestRepo(c.env.DB).createAuthRequest(authRequest);
  notifyUserAuthRequest(c.env, user.id, authRequest.id, deviceInfo.deviceIdentifier);
  return c.json(toAuthRequestResponse(c.req.raw, authRequest));
}

export async function handleCreateAdminAuthRequest(c: BodyContext<typeof AuthRequestCreateSchema>): Promise<Response> {
  const { userId, currentUser } = c.var;
  const body = c.req.valid('json');
  const { publicKey, accessCode, type: requestedType } = body;
  const email = body.email || currentUser.email.toLowerCase();
  const deviceInfo = readAuthRequestDeviceInfo(body, c.req.raw);

  if (requestedType !== AUTH_REQUEST_TYPE_ADMIN_APPROVAL) {
    return errorResponse(c, 'Invalid AuthRequestType. Expected AdminApproval.', 400);
  }
  if (email !== currentUser.email.toLowerCase()) {
    return errorResponse(c, 'Email does not match authenticated user.', 400);
  }
  if (!publicKey || !accessCode || !deviceInfo.deviceIdentifier) {
    return errorResponse(c, 'Public key, device identifier, and access code are required.', 400);
  }
  const rateLimitResponse = await enforceAuthRequestCreateRateLimit(c, email, deviceInfo.deviceIdentifier);
  if (rateLimitResponse) return rateLimitResponse;

  const user = await userRepo(c.env.DB).getUserById(userId);
  if (!user || user.status !== 'active') {
    return errorResponse(c, 'User not found.', 404);
  }

  await authRequestRepo(c.env.DB).pruneExpiredAuthRequests();
  const now = new Date().toISOString();
  const authRequest: AuthRequestRecord = {
    id: generateUUID(),
    userId: user.id,
    organizationId: null,
    type: AUTH_REQUEST_TYPE_ADMIN_APPROVAL,
    requestDeviceIdentifier: deviceInfo.deviceIdentifier,
    requestDeviceType: deviceInfo.deviceType,
    requestIpAddress: getClientIp(c.req.raw),
    requestCountryName: getCountryName(c.req.raw),
    responseDeviceIdentifier: null,
    accessCode,
    publicKey,
    key: null,
    masterPasswordHash: null,
    approved: null,
    creationDate: now,
    responseDate: null,
    authenticationDate: null,
  };
  await authRequestRepo(c.env.DB).createAuthRequest(authRequest);
  notifyUserAuthRequest(c.env, user.id, authRequest.id, deviceInfo.deviceIdentifier);
  return c.json(toAuthRequestResponse(c.req.raw, authRequest));
}

export async function handleGetAuthRequest(c: AppContext, id: string): Promise<Response> {
  const { userId } = c.var;
  const authRequest = await authRequestRepo(c.env.DB).getAuthRequestByIdForUser(id, userId);
  if (!authRequest || authRequest.userId !== userId) return errorResponse(c, 'Not found', 404);
  return c.json(toAuthRequestResponse(c.req.raw, authRequest));
}

export async function handleGetAuthRequestResponse(c: AppContext, id: string): Promise<Response> {
  const url = new URL(c.req.raw.url);
  const accessCode = clippedText(25).parse(url.searchParams.get('code'));
  const authRequest = await authRequestRepo(c.env.DB).getAuthRequestById(id);
  if (!authRequest || authRequest.accessCode !== accessCode || isAuthRequestExpired(authRequest)) {
    return errorResponse(c, 'Not found', 404);
  }
  return c.json(toAuthRequestResponse(c.req.raw, authRequest));
}

export async function handleListAuthRequests(c: AppContext): Promise<Response> {
  const { userId } = c.var;
  const authRequests = await authRequestRepo(c.env.DB).listAuthRequestsByUserId(userId);
  return c.json(listResponse(authRequests.map((authRequest) => toAuthRequestResponse(c.req.raw, authRequest))));
}

export async function handleListPendingAuthRequests(c: AppContext): Promise<Response> {
  const { userId } = c.var;
  await authRequestRepo(c.env.DB).pruneExpiredAuthRequests();
  const authRequests = await authRequestRepo(c.env.DB).listPendingAuthRequestsByUserId(userId);
  const rows = await Promise.all(
    authRequests.map(async (authRequest) => {
      const device = await deviceRepo(c.env.DB).getDevice(userId, authRequest.requestDeviceIdentifier);
      return toAuthRequestResponse(
        c.req.raw,
        authRequest,
        device?.deviceIdentifier ?? authRequest.requestDeviceIdentifier,
      );
    }),
  );
  return c.json(listResponse(rows));
}

export async function handleUpdateAuthRequest(
  c: BodyContext<typeof AuthRequestUpdateSchema>,
  id: string,
): Promise<Response> {
  const { userId } = c.var;
  const body = c.req.valid('json');

  const authRequest = await authRequestRepo(c.env.DB).getAuthRequestByIdForUser(id, userId);
  if (!authRequest || authRequest.userId !== userId || isAuthRequestExpired(authRequest)) {
    return errorResponse(c, 'Not found', 404);
  }
  if (authRequest.approved !== null || authRequest.responseDate || authRequest.authenticationDate) {
    return errorResponse(c, 'Auth request has already been answered.', 409);
  }

  const latestForUser = await authRequestRepo(c.env.DB).listPendingAuthRequestsByUserId(userId);
  const latestForDevice = latestForUser.find(
    (item) => item.requestDeviceIdentifier === authRequest.requestDeviceIdentifier,
  );
  if (latestForDevice?.id !== authRequest.id) {
    return errorResponse(c, 'This request is no longer valid. Make sure to approve the most recent request.', 400);
  }

  const { requestApproved: approved, key } = body;
  const responseDeviceIdentifier = body.deviceIdentifier || readActingDeviceIdentifier(c.req.raw) || 'web';

  if (approved && !key) {
    return errorResponse(c, 'Encrypted key is required to approve the request.', 400);
  }
  if (approved && !isSerializedEncString(key)) {
    return errorResponse(c, 'Encrypted key is not a valid encrypted string.', 400);
  }

  const updated = await authRequestRepo(c.env.DB).updateAuthRequestResponse(id, userId, {
    approved,
    responseDeviceIdentifier,
    key,
    masterPasswordHash: null,
  });
  if (!updated) return errorResponse(c, 'Auth request has already been answered.', 409);
  const updatedRequest = await authRequestRepo(c.env.DB).getAuthRequestByIdForUser(id, userId);
  // Match Bitwarden upstream behavior: only approval wakes the originating anonymous
  // client. Denials are not pushed to avoid leaking that a login attempt was rejected.
  if (approved) {
    await notifyAuthRequestResponse(c.env, userId, id);
  }
  return c.json(toAuthRequestResponse(c.req.raw, updatedRequest || authRequest));
}
