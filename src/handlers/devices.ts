import type { AppContext } from '../router';
import type {
  Device,
  DevicePendingAuthRequest,
  DeviceResponse,
  ProtectedDeviceResponse as ProtectedDeviceWireResponse,
} from '../types';
import { getOnlineUserDevices, notifyUserLogout } from '../durable/notifications-hub';
import { AuthService } from '../services/auth';
import { auditRequestMetadata, writeAuditEvent } from '../services/audit-events';
import { registerMobilePushDevice, unregisterMobilePushDevice } from '../services/push-relay';
import { z } from 'zod';
import { errorResponse, type BodyContext } from '../utils/response';
import { DeviceInfoSchema, deviceText, readAuthRequestDeviceInfo, readKnownDeviceProbe } from '../utils/device';
import { generateUUID } from '../utils/uuid';
import { deviceRepo } from '../services/storage-device-repo';
import { sessionRepo } from '../services/storage-session-repo';
import { userRepo } from '../services/storage-user-repo';

const PERMANENT_TRUST_EXPIRES_AT_MS = Date.UTC(2099, 11, 31, 23, 59, 59);

function normalizeIdentifier(value: string | null | undefined): string {
  return String(value || '').trim();
}

function buildDevicePendingAuthRequest(
  value?: { id?: string | null; creationDate?: string | null } | null,
): DevicePendingAuthRequest | null {
  if (!value?.id || !value.creationDate) return null;
  return {
    id: String(value.id),
    creationDate: String(value.creationDate),
  };
}

function isTrustedDevice(device: Pick<Device, 'encryptedUserKey' | 'encryptedPublicKey'>): boolean {
  return !!(device.encryptedUserKey && device.encryptedPublicKey);
}

function buildDeviceResponse(device: Device): DeviceResponse {
  const displayName = String(device.deviceNote || '').trim() || device.name;
  const response = {
    Id: device.deviceIdentifier,
    id: device.deviceIdentifier,
    UserId: device.userId,
    userId: device.userId,
    Name: displayName,
    name: displayName,
    SystemName: device.name,
    systemName: device.name,
    DeviceNote: device.deviceNote,
    deviceNote: device.deviceNote,
    Identifier: device.deviceIdentifier,
    identifier: device.deviceIdentifier,
    Type: device.type,
    type: device.type,
    CreationDate: device.createdAt,
    creationDate: device.createdAt,
    RevisionDate: device.updatedAt,
    revisionDate: device.updatedAt,
    LastActivityDate: device.lastSeenAt,
    lastActivityDate: device.lastSeenAt,
    LastSeenAt: device.lastSeenAt,
    lastSeenAt: device.lastSeenAt,
    HasStoredDevice: true,
    hasStoredDevice: true,
    IsTrusted: isTrustedDevice(device),
    isTrusted: isTrustedDevice(device),
    EncryptedUserKey: device.encryptedUserKey,
    encryptedUserKey: device.encryptedUserKey,
    EncryptedPublicKey: device.encryptedPublicKey,
    encryptedPublicKey: device.encryptedPublicKey,
    DevicePendingAuthRequest: buildDevicePendingAuthRequest(device.devicePendingAuthRequest),
    devicePendingAuthRequest: buildDevicePendingAuthRequest(device.devicePendingAuthRequest),
    object: 'device',
  };
  return response as DeviceResponse;
}

const storedKey = z.string().nullable().optional();
export const DeviceKeysSchema = z.object({
  encryptedUserKey: storedKey,
  encryptedPublicKey: storedKey,
  encryptedPrivateKey: storedKey,
});

// A key the body leaves out keeps the stored value; an explicit null clears it.
function withStoredKeys(keys: z.output<typeof DeviceKeysSchema>, stored?: Device) {
  return {
    encryptedUserKey: stored?.encryptedUserKey ?? null,
    encryptedPublicKey: stored?.encryptedPublicKey ?? null,
    encryptedPrivateKey: stored?.encryptedPrivateKey ?? null,
    ...keys,
  };
}

// Official clients name the device fields identifier/name/type; NodeWarden's own callers use the device* spelling.
const DeviceFieldsSchema = z.looseObject({}).transform((body) => ({
  ...body,
  deviceIdentifier: body.identifier ?? body.deviceIdentifier,
  deviceName: body.name ?? body.deviceName,
  deviceType: body.type ?? body.deviceType,
}));

const DEVICE_REQUIRED = { error: 'Device identifier and type are required' };
export const RegisterDeviceSchema = DeviceFieldsSchema.pipe(
  DeviceKeysSchema.extend({
    deviceIdentifier: z.string(DEVICE_REQUIRED).trim().min(1, DEVICE_REQUIRED),
    deviceName: DeviceInfoSchema.shape.deviceName,
    deviceType: z.coerce.number(DEVICE_REQUIRED).int(DEVICE_REQUIRED).min(0, DEVICE_REQUIRED),
    pushToken: z.string().trim().catch(''),
  }),
);

const NAME_REQUIRED = { error: 'Device name is required' };
export const DeviceNameSchema = z.object({
  name: z.string(NAME_REQUIRED).trim().min(1, NAME_REQUIRED).pipe(deviceText),
});

export const UpdateTrustSchema = z.object({
  currentDevice: DeviceKeysSchema.nullish(),
  otherDevices: z.array(DeviceKeysSchema.extend({ deviceId: z.string().trim().catch('') })).optional(),
});

const PASSWORD_REQUIRED = { error: 'masterPasswordHash is required' };
export const MasterPasswordSchema = z.object({
  masterPasswordHash: z.string(PASSWORD_REQUIRED).trim().min(1, PASSWORD_REQUIRED),
});

const PUSH_TOKEN_INVALID = { error: 'Invalid push token' };
export const PushTokenSchema = z.object({ pushToken: z.string(PUSH_TOKEN_INVALID).trim().min(1, PUSH_TOKEN_INVALID) });

// POST /api/devices
export async function handleRegisterDevice(c: BodyContext<typeof RegisterDeviceSchema>): Promise<Response> {
  const { userId } = c.var;
  const body = c.req.valid('json');
  const { deviceIdentifier: identifier, deviceName: name, deviceType: type, pushToken, ...keys } = body;

  await deviceRepo(c.env.DB).upsertDevice(userId, identifier, name, type, undefined, keys);

  if (pushToken) {
    const device = await deviceRepo(c.env.DB).getDevice(userId, identifier);
    const pushUuid = device?.pushUuid || generateUUID();
    const updated = await deviceRepo(c.env.DB).updateDevicePushToken(userId, identifier, pushUuid, pushToken);
    if (updated) {
      await registerMobilePushDevice(c.env, {
        userId,
        deviceIdentifier: identifier,
        type,
        pushUuid,
        pushToken,
      });
    }
  }

  const device = await deviceRepo(c.env.DB).getDevice(userId, identifier);
  if (!device) return errorResponse(c, 'Device registration failed', 500);
  await writeAuditEvent(c.env.DB, {
    actorUserId: userId,
    action: 'device.register',
    category: 'device',
    level: 'info',
    targetType: 'device',
    targetId: identifier,
    metadata: auditRequestMetadata(c.req.raw),
  });
  return c.json(buildDeviceResponse(device));
}

// POST /api/devices/lost-trust
export async function handleReportLostTrust(c: AppContext): Promise<Response> {
  const { userId } = c.var;
  // Official clients post no body and send the device in the Device-Identifier header.
  const deviceInfo = readAuthRequestDeviceInfo({}, c.req.raw);
  if (!deviceInfo.deviceIdentifier) return errorResponse(c, 'Please provide a device identifier', 400);

  await writeAuditEvent(c.env.DB, {
    actorUserId: userId,
    action: 'device.lost_trust',
    category: 'device',
    level: 'warn',
    targetType: 'device',
    targetId: deviceInfo.deviceIdentifier,
    metadata: {
      deviceIdentifier: deviceInfo.deviceIdentifier,
      deviceType: deviceInfo.deviceType,
      ...auditRequestMetadata(c.req.raw),
    },
  });
  return new Response(null, { status: 200 });
}

// GET /api/devices/knowndevice
// Compatible with Bitwarden/Vaultwarden behavior:
// - X-Request-Email: base64url(email) without padding
// - X-Device-Identifier: client device identifier
export async function handleKnownDevice(c: AppContext): Promise<Response> {
  const { email, deviceIdentifier } = readKnownDeviceProbe(c.req.raw);

  if (!email || !deviceIdentifier) {
    return c.json(false);
  }

  const known = await deviceRepo(c.env.DB).isKnownDeviceByEmail(email, deviceIdentifier);
  return c.json(known);
}

// GET /api/devices
export async function handleGetDevices(c: AppContext): Promise<Response> {
  const { userId } = c.var;
  void c.req.raw;
  const devices = await deviceRepo(c.env.DB).getDevicesByUserId(userId);

  return c.json({
    data: devices.map((device) => buildDeviceResponse(device)),
    object: 'list',
    continuationToken: null,
  });
}

// GET /api/devices/identifier/:deviceIdentifier
export async function handleGetDeviceByIdentifier(c: AppContext, deviceIdentifier: string): Promise<Response> {
  const { userId } = c.var;
  void c.req.raw;
  const normalized = normalizeIdentifier(deviceIdentifier);
  if (!normalized) return errorResponse(c, 'Invalid device identifier', 400);

  const device = await deviceRepo(c.env.DB).getDevice(userId, normalized);
  if (!device) {
    return errorResponse(c, 'Device not found', 404);
  }

  return c.json(buildDeviceResponse(device));
}

// GET /api/devices/:deviceIdentifier
export async function handleGetDevice(c: AppContext, deviceIdentifier: string): Promise<Response> {
  return handleGetDeviceByIdentifier(c, deviceIdentifier);
}

// GET /api/devices/authorized
// Returns known devices together with active 2FA remember-token expiry.
export async function handleGetAuthorizedDevices(c: AppContext): Promise<Response> {
  const { userId } = c.var;
  void c.req.raw;
  const [devices, trusted, onlineDeviceIdentifiers] = await Promise.all([
    deviceRepo(c.env.DB).getDevicesByUserId(userId),
    deviceRepo(c.env.DB).getTrustedDeviceTokenSummariesByUserId(userId),
    getOnlineUserDevices(c.env, userId),
  ]);
  const onlineSet = new Set(onlineDeviceIdentifiers);

  const trustedByIdentifier = new Map<string, { expiresAt: number; tokenCount: number }>();
  for (const row of trusted) {
    trustedByIdentifier.set(row.deviceIdentifier, { expiresAt: row.expiresAt, tokenCount: row.tokenCount });
  }

  const knownIdentifiers = new Set<string>();
  const data = devices.map((device) => {
    knownIdentifiers.add(device.deviceIdentifier);
    const trustedInfo = trustedByIdentifier.get(device.deviceIdentifier);
    return {
      ...buildDeviceResponse(device),
      online: onlineSet.has(device.deviceIdentifier),
      trusted: !!trustedInfo,
      trustedTokenCount: trustedInfo?.tokenCount || 0,
      trustedUntil: trustedInfo?.expiresAt ? new Date(trustedInfo.expiresAt).toISOString() : null,
      object: 'device',
    };
  });

  for (const row of trusted) {
    if (knownIdentifiers.has(row.deviceIdentifier)) continue;
    const placeholderDevice: Device = {
      userId,
      deviceIdentifier: row.deviceIdentifier,
      name: 'Unknown device',
      type: 14,
      sessionStamp: '',
      encryptedUserKey: null,
      encryptedPublicKey: null,
      encryptedPrivateKey: null,
      pushUuid: null,
      pushToken: null,
      devicePendingAuthRequest: null,
      deviceNote: null,
      lastSeenAt: null,
      createdAt: '',
      updatedAt: '',
    };
    data.push({
      ...buildDeviceResponse(placeholderDevice),
      isTrusted: true,
      hasStoredDevice: false,
      online: onlineSet.has(row.deviceIdentifier),
      trusted: true,
      trustedTokenCount: row.tokenCount,
      trustedUntil: row.expiresAt ? new Date(row.expiresAt).toISOString() : null,
      object: 'device',
    });
  }

  return c.json({
    data,
    object: 'list',
    continuationToken: null,
  });
}

// DELETE /api/devices/authorized
export async function handleRevokeAllTrustedDevices(c: AppContext): Promise<Response> {
  const { userId } = c.var;
  void c.req.raw;
  const removed = await deviceRepo(c.env.DB).deleteTrustedTwoFactorTokensByUserId(userId);
  return c.json({ success: true, removed });
}

// DELETE /api/devices/authorized/:deviceIdentifier
export async function handleRevokeTrustedDevice(c: AppContext, deviceIdentifier: string): Promise<Response> {
  const { userId } = c.var;
  void c.req.raw;
  const normalized = String(deviceIdentifier || '').trim();
  if (!normalized) return errorResponse(c, 'Invalid device identifier', 400);

  const removed = await deviceRepo(c.env.DB).deleteTrustedTwoFactorTokensByDevice(userId, normalized);
  await writeAuditEvent(c.env.DB, {
    actorUserId: userId,
    action: 'device.trust.revoke',
    category: 'device',
    level: 'security',
    targetType: 'device',
    targetId: normalized,
    metadata: { removed, ...auditRequestMetadata(c.req.raw) },
  });
  return c.json({ success: true, removed });
}

// POST /api/devices/authorized/:deviceIdentifier/permanent
// Upgrades an existing active 2FA remember-token record to permanent trust.
export async function handleTrustDevicePermanently(c: AppContext, deviceIdentifier: string): Promise<Response> {
  const { userId } = c.var;
  void c.req.raw;
  const normalized = String(deviceIdentifier || '').trim();
  if (!normalized) return errorResponse(c, 'Invalid device identifier', 400);

  const updated = await deviceRepo(c.env.DB).updateTrustedTwoFactorTokensExpiryByDevice(
    userId,
    normalized,
    PERMANENT_TRUST_EXPIRES_AT_MS,
  );
  if (!updated) return errorResponse(c, 'Device is not currently trusted', 409);
  await writeAuditEvent(c.env.DB, {
    actorUserId: userId,
    action: 'device.trust.permanent',
    category: 'device',
    level: 'security',
    targetType: 'device',
    targetId: normalized,
    metadata: { updated, ...auditRequestMetadata(c.req.raw) },
  });

  return c.json({
    success: true,
    updated,
    trustedUntil: new Date(PERMANENT_TRUST_EXPIRES_AT_MS).toISOString(),
  });
}

// DELETE /api/devices/:deviceIdentifier
export async function handleDeleteDevice(c: AppContext, deviceIdentifier: string): Promise<Response> {
  const { userId } = c.var;
  void c.req.raw;
  const normalized = String(deviceIdentifier || '').trim();
  if (!normalized) return errorResponse(c, 'Invalid device identifier', 400);

  const device = await deviceRepo(c.env.DB).getDevice(userId, normalized);
  await deviceRepo(c.env.DB).deleteTrustedTwoFactorTokensByDevice(userId, normalized);
  await sessionRepo(c.env.DB).deleteRefreshTokensByDevice(userId, normalized);
  const deleted = await deviceRepo(c.env.DB).deleteDevice(userId, normalized);
  if (deleted) {
    await unregisterMobilePushDevice(c.env, device?.pushUuid);
    AuthService.invalidateDeviceCache(userId, normalized);
    notifyUserLogout(c.env, userId, normalized);
  }
  await writeAuditEvent(c.env.DB, {
    actorUserId: userId,
    action: 'device.delete',
    category: 'device',
    level: 'security',
    targetType: 'device',
    targetId: normalized,
    metadata: { deleted, ...auditRequestMetadata(c.req.raw) },
  });
  return c.json({ success: deleted });
}

// PUT /api/devices/:deviceIdentifier/name
export async function handleUpdateDeviceName(
  c: BodyContext<typeof DeviceNameSchema>,
  deviceIdentifier: string,
): Promise<Response> {
  const { userId } = c.var;
  const normalized = String(deviceIdentifier || '').trim();
  if (!normalized) return errorResponse(c, 'Invalid device identifier', 400);

  const body = c.req.valid('json');
  const { name } = body;

  const updated = await deviceRepo(c.env.DB).updateDeviceName(userId, normalized, name);
  if (!updated) return errorResponse(c, 'Device not found', 404);

  const device = await deviceRepo(c.env.DB).getDevice(userId, normalized);
  if (!device) return errorResponse(c, 'Device not found', 404);
  await writeAuditEvent(c.env.DB, {
    actorUserId: userId,
    action: 'device.name.update',
    category: 'device',
    level: 'info',
    targetType: 'device',
    targetId: normalized,
    metadata: { name, ...auditRequestMetadata(c.req.raw) },
  });
  return c.json(buildDeviceResponse(device));
}

// DELETE /api/devices
export async function handleDeleteAllDevices(c: BodyContext<typeof MasterPasswordSchema>): Promise<Response> {
  const { userId } = c.var;
  const user = await userRepo(c.env.DB).getUserById(userId);
  if (!user) return errorResponse(c, 'User not found', 404);

  const body = c.req.valid('json');
  const { masterPasswordHash } = body;
  const auth = new AuthService(c.env);
  const passwordValid = await auth.verifyPassword(masterPasswordHash, user.masterPasswordHash, user.email);
  if (!passwordValid) {
    return errorResponse(c, 'Invalid password', 400);
  }

  const originalSecurityStamp = user.securityStamp;
  user.securityStamp = generateUUID();
  user.updatedAt = new Date().toISOString();
  if (!(await userRepo(c.env.DB).saveUser(user, ['securityStamp'], originalSecurityStamp)))
    return errorResponse(c, 'User verification failed.', 400);
  const [removedTrusted, removedSessions, removedDevices] = await Promise.all([
    deviceRepo(c.env.DB).deleteTrustedTwoFactorTokensByUserId(userId),
    sessionRepo(c.env.DB).deleteRefreshTokensByUserId(userId),
    deviceRepo(c.env.DB).deleteDevicesByUserId(userId),
  ]);
  AuthService.invalidateUserCache(userId);
  notifyUserLogout(c.env, userId, null);
  await writeAuditEvent(c.env.DB, {
    actorUserId: userId,
    action: 'device.delete_all',
    category: 'device',
    level: 'security',
    targetType: 'user',
    targetId: userId,
    metadata: { removedTrusted, removedSessions, removedDevices, ...auditRequestMetadata(c.req.raw) },
  });
  return c.json({ success: true, removedTrusted, removedSessions: removedSessions ?? 0, removedDevices });
}

// PUT/POST /api/devices/identifier/:deviceIdentifier/keys
export async function handleUpdateDeviceKeys(
  c: BodyContext<typeof DeviceKeysSchema>,
  deviceIdentifier: string,
): Promise<Response> {
  const { userId } = c.var;
  const normalized = normalizeIdentifier(deviceIdentifier);
  if (!normalized) return errorResponse(c, 'Invalid device identifier', 400);

  const keys = c.req.valid('json');
  const device = await deviceRepo(c.env.DB).getDevice(userId, normalized);
  if (!device) {
    return errorResponse(c, 'Device not found', 404);
  }

  const updated = await deviceRepo(c.env.DB).updateDeviceKeys(userId, normalized, withStoredKeys(keys, device));
  if (!updated) {
    return errorResponse(c, 'Device not found', 404);
  }

  const nextDevice = await deviceRepo(c.env.DB).getDevice(userId, normalized);
  return c.json(buildDeviceResponse(nextDevice || device));
}

// POST /api/devices/update-trust
export async function handleUpdateDeviceTrust(c: BodyContext<typeof UpdateTrustSchema>): Promise<Response> {
  const { userId } = c.var;
  const body = c.req.valid('json');
  const currentDeviceIdentifier =
    normalizeIdentifier(c.req.raw.headers.get('Device-Identifier')) ||
    normalizeIdentifier(c.req.raw.headers.get('X-Device-Identifier'));
  const requested = [
    ...(currentDeviceIdentifier && body.currentDevice
      ? [{ ...body.currentDevice, deviceId: currentDeviceIdentifier }]
      : []),
    ...(body.otherDevices ?? []).filter((item) => item.deviceId),
  ];

  let updatedCount = 0;
  for (const { deviceId, ...keys } of requested) {
    const stored = (await deviceRepo(c.env.DB).getDevice(userId, deviceId)) || undefined;
    if (await deviceRepo(c.env.DB).updateDeviceKeys(userId, deviceId, withStoredKeys(keys, stored))) updatedCount++;
  }

  return c.json({ success: true, updated: updatedCount });
}

export const UntrustDevicesBody = z.object({ devices: z.array(z.coerce.string().trim()).default([]) });

// POST /api/devices/untrust
export async function handleUntrustDevices(c: BodyContext<typeof UntrustDevicesBody>): Promise<Response> {
  const { userId } = c.var;
  const body = c.req.valid('json');
  const { devices } = body;
  const removed = await deviceRepo(c.env.DB).clearDeviceKeys(userId, devices);
  for (const deviceIdentifier of devices) {
    if (!deviceIdentifier) continue;
    await deviceRepo(c.env.DB).deleteTrustedTwoFactorTokensByDevice(userId, deviceIdentifier);
  }
  await writeAuditEvent(c.env.DB, {
    actorUserId: userId,
    action: 'device.trust.revoke_batch',
    category: 'device',
    level: 'security',
    targetType: 'user',
    targetId: userId,
    metadata: { requested: devices.length, removed, ...auditRequestMetadata(c.req.raw) },
  });
  return c.json({ success: true, removed });
}

// POST /api/devices/:deviceIdentifier/retrieve-keys
export async function handleRetrieveDeviceKeys(c: AppContext, deviceIdentifier: string): Promise<Response> {
  const { userId } = c.var;
  void c.req.raw;
  const normalized = normalizeIdentifier(deviceIdentifier);
  if (!normalized) return errorResponse(c, 'Invalid device identifier', 400);

  const device = await deviceRepo(c.env.DB).getDevice(userId, normalized);
  if (!device) {
    return errorResponse(c, 'Device not found', 404);
  }

  return c.json({
    Id: device.deviceIdentifier,
    id: device.deviceIdentifier,
    Name: String(device.deviceNote || '').trim() || device.name,
    name: String(device.deviceNote || '').trim() || device.name,
    SystemName: device.name,
    systemName: device.name,
    DeviceNote: device.deviceNote,
    deviceNote: device.deviceNote,
    Identifier: device.deviceIdentifier,
    identifier: device.deviceIdentifier,
    Type: device.type,
    type: device.type,
    CreationDate: device.createdAt,
    creationDate: device.createdAt,
    EncryptedUserKey: device.encryptedUserKey,
    encryptedUserKey: device.encryptedUserKey,
    EncryptedPublicKey: device.encryptedPublicKey,
    encryptedPublicKey: device.encryptedPublicKey,
    object: 'protectedDevice',
  } as ProtectedDeviceWireResponse);
}

// POST /api/devices/:id/deactivate
export async function handleDeactivateDevice(c: AppContext, deviceIdentifier: string): Promise<Response> {
  const { userId } = c.var;
  void c.req.raw;
  const normalized = normalizeIdentifier(deviceIdentifier);
  if (!normalized) return errorResponse(c, 'Invalid device identifier', 400);

  const device = await deviceRepo(c.env.DB).getDevice(userId, normalized);
  await deviceRepo(c.env.DB).deleteTrustedTwoFactorTokensByDevice(userId, normalized);
  await sessionRepo(c.env.DB).deleteRefreshTokensByDevice(userId, normalized);
  const deleted = await deviceRepo(c.env.DB).deleteDevice(userId, normalized);
  if (deleted) {
    await unregisterMobilePushDevice(c.env, device?.pushUuid);
    AuthService.invalidateDeviceCache(userId, normalized);
    notifyUserLogout(c.env, userId, normalized);
  }
  await writeAuditEvent(c.env.DB, {
    actorUserId: userId,
    action: 'device.deactivate',
    category: 'device',
    level: 'security',
    targetType: 'device',
    targetId: normalized,
    metadata: { deleted, ...auditRequestMetadata(c.req.raw) },
  });
  return c.json({ success: deleted });
}

// PUT /api/devices/identifier/{deviceIdentifier}/token
// Bitwarden mobile reports APNs/FCM push token updates to this endpoint.
export async function handleUpdateDeviceToken(
  c: BodyContext<typeof PushTokenSchema>,
  deviceIdentifier: string,
): Promise<Response> {
  const { userId } = c.var;
  const normalized = normalizeIdentifier(deviceIdentifier);
  if (!normalized) return errorResponse(c, 'Invalid device identifier', 400);

  const body = c.req.valid('json');
  const { pushToken } = body;

  const device = await deviceRepo(c.env.DB).getDevice(userId, normalized);
  if (!device) return errorResponse(c, 'Device not found', 404);

  const pushUuid = device.pushUuid || generateUUID();
  const updated = await deviceRepo(c.env.DB).updateDevicePushToken(userId, normalized, pushUuid, pushToken);
  if (updated) {
    await registerMobilePushDevice(c.env, {
      userId,
      deviceIdentifier: normalized,
      type: device.type,
      pushUuid,
      pushToken,
    });
  }

  return new Response(null, { status: 200 });
}

// PUT/POST /api/devices/:deviceIdentifier/web-push-auth
export async function handleUpdateDeviceWebPushAuth(c: AppContext, deviceIdentifier: string): Promise<Response> {
  const { userId } = c.var;
  void c.req.raw;
  void c.env;
  void userId;
  void deviceIdentifier;
  return new Response(null, { status: 200 });
}

// PUT/POST /api/devices/:deviceIdentifier/clear-token
