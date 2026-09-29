import { jsonBody } from './utils/response';
import { Hono } from 'hono';
import {
  handleGetAuthorizedDevices,
  handleGetDevice,
  handleGetDevices,
  handleGetDeviceByIdentifier,
  handleUpdateDeviceKeys,
  handleUpdateDeviceTrust,
  handleUntrustDevices,
  handleRetrieveDeviceKeys,
  handleDeactivateDevice,
  handleRevokeAllTrustedDevices,
  handleRevokeTrustedDevice,
  handleTrustDevicePermanently,
  handleDeleteAllDevices,
  handleDeleteDevice,
  handleUpdateDeviceName,
  handleUpdateDeviceToken,
  handleUpdateDeviceWebPushAuth,
  handleRegisterDevice,
  handleReportLostTrust,
  RegisterDeviceSchema,
  DeviceNameSchema,
  MasterPasswordSchema,
  DeviceKeysSchema,
  UpdateTrustSchema,
  UntrustDevicesBody,
  PushTokenSchema,
} from './handlers/devices';
import type { AppEnv } from './router';

// Older clients call the device endpoints without the /api prefix.
const devices = <Suffix extends string>(suffix: Suffix): [`/api/devices${Suffix}`, `/devices${Suffix}`] => [
  `/api/devices${suffix}`,
  `/devices${suffix}`,
];

export const deviceRoutes = new Hono<AppEnv>();

deviceRoutes.on('GET', devices(''), handleGetDevices);
deviceRoutes.on('POST', devices(''), jsonBody(RegisterDeviceSchema), handleRegisterDevice);
deviceRoutes.on('DELETE', devices(''), jsonBody(MasterPasswordSchema), handleDeleteAllDevices);
deviceRoutes.on('POST', devices('/lost-trust'), handleReportLostTrust);
deviceRoutes.on('GET', devices('/authorized'), handleGetAuthorizedDevices);
deviceRoutes.on('DELETE', devices('/authorized'), handleRevokeAllTrustedDevices);
deviceRoutes.on('DELETE', devices('/authorized/:deviceId'), (c) =>
  handleRevokeTrustedDevice(c, c.req.param('deviceId')),
);
deviceRoutes.on('POST', devices('/authorized/:deviceId/permanent'), (c) =>
  handleTrustDevicePermanently(c, c.req.param('deviceId')),
);
deviceRoutes.on('GET', devices('/:deviceId'), (c) => handleGetDevice(c, c.req.param('deviceId')));
deviceRoutes.on('DELETE', devices('/:deviceId'), (c) => handleDeleteDevice(c, c.req.param('deviceId')));
deviceRoutes.on('PUT', devices('/:deviceId/name'), jsonBody(DeviceNameSchema), (c) =>
  handleUpdateDeviceName(c, c.req.param('deviceId')),
);
deviceRoutes.on('GET', devices('/identifier/:deviceId'), (c) =>
  handleGetDeviceByIdentifier(c, c.req.param('deviceId')),
);
deviceRoutes.on(
  ['PUT', 'POST'],
  [...devices('/:deviceId/keys'), ...devices('/identifier/:deviceId/keys')],
  jsonBody(DeviceKeysSchema),
  (c) => handleUpdateDeviceKeys(c, c.req.param('deviceId')),
);
deviceRoutes.on(['PUT', 'POST'], devices('/identifier/:deviceId/token'), jsonBody(PushTokenSchema), (c) =>
  handleUpdateDeviceToken(c, c.req.param('deviceId')),
);
deviceRoutes.on(['PUT', 'POST'], devices('/identifier/:deviceId/web-push-auth'), (c) =>
  handleUpdateDeviceWebPushAuth(c, c.req.param('deviceId')),
);
deviceRoutes.on('POST', devices('/:deviceId/retrieve-keys'), (c) =>
  handleRetrieveDeviceKeys(c, c.req.param('deviceId')),
);
deviceRoutes.on(['POST', 'DELETE'], devices('/:deviceId/deactivate'), (c) =>
  handleDeactivateDevice(c, c.req.param('deviceId')),
);
deviceRoutes.on('POST', devices('/update-trust'), jsonBody(UpdateTrustSchema), handleUpdateDeviceTrust);
deviceRoutes.on('POST', devices('/untrust'), jsonBody(UntrustDevicesBody), handleUntrustDevices);
