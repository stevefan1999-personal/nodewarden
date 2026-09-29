import { Hono } from 'hono';
import { handleEventRoute } from './handlers/events';
import { errorResponse, jsonResponse, unsupportedResponse } from './utils/response';
import {
  handleGetProfile,
  handleUpdateProfile,
  handleGetKeys,
  handleGetUserPublicKey,
  handleSetKeys,
  handleGetRevisionDate,
  handleSetUserKeyId,
  handleVerifyPassword,
  handleChangePassword,
  handleDeleteAccount,
  handleEmailToken,
  handleChangeEmail,
  handleSetVerifyDevices,
  handleGetTotpRecoveryCode,
  handleGetTwoFactorProviders,
  handleGetTwoFactorEmail,
  handleSendTwoFactorEmail,
  handlePutTwoFactorEmail,
  handleGetTwoFactorAuthenticator,
  handlePutTwoFactorAuthenticator,
  handleGetTwoFactorYubiKey,
  handlePutTwoFactorYubiKey,
  handlePutTwoFactorYubiKeyConfig,
  handleBootstrapTwoFactorYubiKeyConfig,
  handleGetDeviceVerificationSettings,
  handlePutDeviceVerificationSettings,
  handleDisableTwoFactorProvider,
  handleGetApiKey,
  handleRotateApiKey,
} from './handlers/accounts';
import {
  handleGetCiphers,
  handleGetCipher,
  handleGetCipherAdmin,
  handleGetOrganizationCiphers,
  handleCreateCipher,
  handleUpdateCipher,
  handleDeleteCipher,
  handleDeleteCipherCompat,
  handlePermanentDeleteCipher,
  handleRestoreCipher,
  handleBulkArchiveCiphers,
  handlePartialUpdateCipher,
  handleBulkUnarchiveCiphers,
  handleBulkMoveCiphers,
  handleBulkDeleteCiphers,
  handleBulkPermanentDeleteCiphers,
  handleBulkRestoreCiphers,
  handleArchiveCipher,
  handleUnarchiveCipher,
  handleShareCipher,
  handleBulkShareCiphers,
  handleUpdateCipherCollections,
} from './handlers/ciphers';
import {
  handleGetFolders,
  handleGetFolder,
  handleCreateFolder,
  handleUpdateFolder,
  handleDeleteFolder,
  handleBulkDeleteFolders,
} from './handlers/folders';
import {
  handleGetSends,
  handleGetSend,
  handleCreateSend,
  handleCreateFileSendV2,
  handleGetSendFileUpload,
  handleUploadSendFile,
  handleUpdateSend,
  handleDeleteSend,
  handleBulkDeleteSends,
  handleRemoveSendPassword,
  handleRemoveSendAuth,
} from './handlers/sends';
import { handleSync } from './handlers/sync';
import { handleCiphersImport } from './handlers/import';
import {
  handleCreateAttachment,
  handleUploadAttachment,
  handleGetAttachment,
  handleUpdateAttachmentMetadata,
  handleDeleteAttachment,
} from './handlers/attachments';
import { deviceRoutes } from './router-devices';
import { adminRoutes } from './router-admin';
import { handleGetDomains, handleUpdateDomains } from './handlers/domains';
import {
  handleCreateAccountPasskeyCredential,
  handleDeleteAccountPasskeyCredential,
  handleDeleteTwoFactorWebAuthn,
  handleGetAccountPasskeyAttestationOptions,
  handleGetAccountPasskeyCredentials,
  handleGetAccountPasskeyUpdateAssertionOptions,
  handleGetTwoFactorWebAuthn,
  handleGetTwoFactorWebAuthnChallenge,
  handlePutTwoFactorWebAuthn,
  handleUpdateAccountPasskeyEncryption,
} from './handlers/account-passkeys';
import {
  handleCreateAdminAuthRequest,
  handleGetAuthRequest,
  handleListAuthRequests,
  handleListPendingAuthRequests,
  handleUpdateAuthRequest,
} from './handlers/auth-requests';
import { organizationRoutes } from './router-org';
import { handleEmergencyAccessRoute } from './handlers/emergency-access';
import { handleAccountLicenseUpload } from './handlers/licenses';
import { handleListAllCollections } from './handlers/organizations';
import type { AppEnv } from './router';

const methodNotAllowed = () => errorResponse('Method not allowed', 405);
const emptyList = () => jsonResponse({ data: [], object: 'list', continuationToken: null });

// Two-factor providers are disabled by provider type: 0 authenticator, 1 email, 3 YubiKey, 7 WebAuthn.
const TWO_FACTOR_AUTHENTICATOR = 0;
const TWO_FACTOR_EMAIL = 1;
const TWO_FACTOR_YUBIKEY = 3;
const TWO_FACTOR_WEBAUTHN = 7;

export const authenticatedRoutes = new Hono<AppEnv>();

authenticatedRoutes.use(async (c, next) => {
  const eventResponse = await handleEventRoute(c, c.req.path, c.req.method);
  if (eventResponse) return eventResponse;
  await next();
});

authenticatedRoutes.on(
  ['POST', 'PUT', 'DELETE'],
  ['/api/accounts/set-password', '/api/accounts/delete-account', '/api/accounts/delete-vault'],
  () => errorResponse('Not implemented', 501),
);

authenticatedRoutes.on('DELETE', ['/api/accounts', '/accounts'], handleDeleteAccount);
authenticatedRoutes.post('/api/accounts/delete', handleDeleteAccount);
authenticatedRoutes.on(['POST', 'PUT'], ['/api/accounts/kdf', '/accounts/kdf'], () =>
  unsupportedResponse('KDF changes are not supported by this server.'),
);
authenticatedRoutes.on('POST', ['/api/accounts/email-token', '/accounts/email-token'], handleEmailToken);
authenticatedRoutes.on('POST', ['/api/accounts/email', '/accounts/email'], handleChangeEmail);
authenticatedRoutes.on(
  ['POST', 'PUT'],
  [
    '/api/accounts/verify-email',
    '/accounts/verify-email',
    '/api/accounts/verify-email-token',
    '/accounts/verify-email-token',
    '/api/accounts/request-otp',
    '/accounts/request-otp',
    '/api/accounts/verify-otp',
    '/accounts/verify-otp',
  ],
  () => unsupportedResponse('Email delivery is not supported by this server.'),
);

authenticatedRoutes.on('POST', ['/api/two-factor/get-email', '/two-factor/get-email'], handleGetTwoFactorEmail);
authenticatedRoutes.on('POST', ['/api/two-factor/send-email', '/two-factor/send-email'], handleSendTwoFactorEmail);
authenticatedRoutes.on(['PUT', 'POST'], ['/api/two-factor/email', '/two-factor/email'], handlePutTwoFactorEmail);
authenticatedRoutes.on('DELETE', ['/api/two-factor/email', '/two-factor/email'], (c) =>
  handleDisableTwoFactorProvider(c, TWO_FACTOR_EMAIL),
);
authenticatedRoutes.on('ALL', ['/api/two-factor/email', '/two-factor/email'], methodNotAllowed);

authenticatedRoutes.get('/api/accounts/profile', handleGetProfile);
authenticatedRoutes.put('/api/accounts/profile', handleUpdateProfile);
authenticatedRoutes.all('/api/accounts/profile', methodNotAllowed);

authenticatedRoutes.on(
  ['POST', 'PUT'],
  ['/api/accounts/password', '/api/accounts/change-password'],
  handleChangePassword,
);

authenticatedRoutes.get('/api/accounts/keys', handleGetKeys);
authenticatedRoutes.post('/api/accounts/keys', handleSetKeys);
authenticatedRoutes.all('/api/accounts/keys', methodNotAllowed);

authenticatedRoutes.get('/api/users/:userId{[a-f0-9-]+}/public-key', (c) =>
  handleGetUserPublicKey(c, c.req.param('userId')),
);

authenticatedRoutes.post('/api/two-factor/get-recover', handleGetTotpRecoveryCode);

authenticatedRoutes.get('/api/two-factor', handleGetTwoFactorProviders);
authenticatedRoutes.all('/api/two-factor', methodNotAllowed);
authenticatedRoutes.post('/api/two-factor/get-authenticator', handleGetTwoFactorAuthenticator);
authenticatedRoutes.on(
  'POST',
  ['/api/two-factor/get-yubikey', '/api/two-factor/get-yubi-key'],
  handleGetTwoFactorYubiKey,
);
authenticatedRoutes.on(
  ['GET', 'POST'],
  '/api/two-factor/get-device-verification-settings',
  handleGetDeviceVerificationSettings,
);
authenticatedRoutes.on(
  ['PUT', 'POST'],
  '/api/two-factor/device-verification-settings',
  handlePutDeviceVerificationSettings,
);
authenticatedRoutes.all('/api/two-factor/device-verification-settings', methodNotAllowed);
authenticatedRoutes.post('/api/two-factor/get-webauthn', handleGetTwoFactorWebAuthn);
authenticatedRoutes.post('/api/two-factor/get-webauthn-challenge', handleGetTwoFactorWebAuthnChallenge);

authenticatedRoutes.on(['PUT', 'POST'], '/api/two-factor/authenticator', handlePutTwoFactorAuthenticator);
authenticatedRoutes.delete('/api/two-factor/authenticator', (c) =>
  handleDisableTwoFactorProvider(c, TWO_FACTOR_AUTHENTICATOR),
);
authenticatedRoutes.all('/api/two-factor/authenticator', methodNotAllowed);

authenticatedRoutes.on(
  ['PUT', 'POST'],
  ['/api/two-factor/yubikey', '/api/two-factor/yubi-key'],
  handlePutTwoFactorYubiKey,
);
authenticatedRoutes.on('DELETE', ['/api/two-factor/yubikey', '/api/two-factor/yubi-key'], (c) =>
  handleDisableTwoFactorProvider(c, TWO_FACTOR_YUBIKEY),
);
authenticatedRoutes.on('ALL', ['/api/two-factor/yubikey', '/api/two-factor/yubi-key'], methodNotAllowed);

authenticatedRoutes.delete('/api/two-factor/webauthn/all', (c) =>
  handleDisableTwoFactorProvider(c, TWO_FACTOR_WEBAUTHN),
);
authenticatedRoutes.on(['PUT', 'POST'], '/api/two-factor/webauthn', handlePutTwoFactorWebAuthn);
authenticatedRoutes.delete('/api/two-factor/webauthn', handleDeleteTwoFactorWebAuthn);
authenticatedRoutes.all('/api/two-factor/webauthn', methodNotAllowed);

authenticatedRoutes.on(
  ['PUT', 'POST'],
  ['/api/two-factor/yubikey/config', '/api/two-factor/yubi-key/config'],
  handlePutTwoFactorYubiKeyConfig,
);
authenticatedRoutes.on(
  'POST',
  ['/api/two-factor/yubikey/bootstrap', '/api/two-factor/yubi-key/bootstrap'],
  handleBootstrapTwoFactorYubiKeyConfig,
);
authenticatedRoutes.on(['PUT', 'POST'], '/api/two-factor/disable', (c) => handleDisableTwoFactorProvider(c));

authenticatedRoutes.get('/api/accounts/revision-date', handleGetRevisionDate);
authenticatedRoutes.post('/api/accounts/key-management/user-key-id', handleSetUserKeyId);
authenticatedRoutes.post('/api/accounts/verify-password', handleVerifyPassword);
authenticatedRoutes.on(
  ['PUT', 'POST'],
  ['/api/accounts/verify-devices', '/accounts/verify-devices'],
  handleSetVerifyDevices,
);
authenticatedRoutes.on('POST', ['/api/accounts/api-key', '/api/accounts/api_key'], handleGetApiKey);
authenticatedRoutes.on('POST', ['/api/accounts/rotate-api-key', '/api/accounts/rotate_api_key'], handleRotateApiKey);

authenticatedRoutes.on('GET', ['/api/webauthn', '/webauthn'], handleGetAccountPasskeyCredentials);
authenticatedRoutes.on('POST', ['/api/webauthn', '/webauthn'], handleCreateAccountPasskeyCredential);
authenticatedRoutes.on('PUT', ['/api/webauthn', '/webauthn'], handleUpdateAccountPasskeyEncryption);
authenticatedRoutes.on('ALL', ['/api/webauthn', '/webauthn'], methodNotAllowed);
authenticatedRoutes.on(
  'POST',
  ['/api/webauthn/attestation-options', '/webauthn/attestation-options'],
  handleGetAccountPasskeyAttestationOptions,
);
authenticatedRoutes.on(
  'POST',
  ['/api/webauthn/assertion-options', '/webauthn/assertion-options'],
  handleGetAccountPasskeyUpdateAssertionOptions,
);
authenticatedRoutes.on('POST', ['/api/webauthn/:credentialId/delete', '/webauthn/:credentialId/delete'], (c) =>
  handleDeleteAccountPasskeyCredential(c, c.req.param('credentialId')),
);

authenticatedRoutes.get('/api/sync', handleSync);
authenticatedRoutes.get('/api/collections', handleListAllCollections);

authenticatedRoutes.route('/', organizationRoutes);

authenticatedRoutes.on('POST', ['/api/accounts/license', '/accounts/license'], () => handleAccountLicenseUpload());

authenticatedRoutes.use(async (c, next) => {
  const emergency = await handleEmergencyAccessRoute(c, c.req.path, c.req.method);
  if (emergency) return emergency;
  await next();
});

authenticatedRoutes.get('/api/ciphers/organization-details', handleGetOrganizationCiphers);
authenticatedRoutes.on('GET', ['/api/ciphers', '/api/ciphers/create'], handleGetCiphers);
authenticatedRoutes.on('POST', ['/api/ciphers', '/api/ciphers/create'], handleCreateCipher);
authenticatedRoutes.post('/api/ciphers/import', handleCiphersImport);
authenticatedRoutes.post('/api/ciphers/delete', handleBulkDeleteCiphers);
authenticatedRoutes.post('/api/ciphers/delete-permanent', handleBulkPermanentDeleteCiphers);
authenticatedRoutes.post('/api/ciphers/restore', handleBulkRestoreCiphers);
authenticatedRoutes.on(['PUT', 'POST'], '/api/ciphers/archive', handleBulkArchiveCiphers);
authenticatedRoutes.on(['PUT', 'POST'], '/api/ciphers/unarchive', handleBulkUnarchiveCiphers);
authenticatedRoutes.on(['POST', 'PUT'], '/api/ciphers/move', handleBulkMoveCiphers);
authenticatedRoutes.on(['PUT', 'POST'], '/api/ciphers/share', handleBulkShareCiphers);

const cipher = '/api/ciphers/:cipherId{[a-f0-9-]+}';
authenticatedRoutes.get(cipher, (c) => handleGetCipher(c, c.req.param('cipherId')));
authenticatedRoutes.on(['PUT', 'POST'], cipher, (c) => handleUpdateCipher(c, c.req.param('cipherId')));
authenticatedRoutes.delete(cipher, (c) => handleDeleteCipherCompat(c, c.req.param('cipherId')));
authenticatedRoutes.put(`${cipher}/delete`, (c) => handleDeleteCipher(c, c.req.param('cipherId')));
authenticatedRoutes.delete(`${cipher}/delete`, (c) => handlePermanentDeleteCipher(c, c.req.param('cipherId')));
authenticatedRoutes.put(`${cipher}/restore`, (c) => handleRestoreCipher(c, c.req.param('cipherId')));
authenticatedRoutes.on(['PUT', 'POST'], `${cipher}/archive`, (c) => handleArchiveCipher(c, c.req.param('cipherId')));
authenticatedRoutes.on(['PUT', 'POST'], `${cipher}/unarchive`, (c) =>
  handleUnarchiveCipher(c, c.req.param('cipherId')),
);
authenticatedRoutes.on(['PUT', 'POST'], `${cipher}/partial`, (c) =>
  handlePartialUpdateCipher(c, c.req.param('cipherId')),
);
authenticatedRoutes.on(['PUT', 'POST'], `${cipher}/share`, (c) => handleShareCipher(c, c.req.param('cipherId')));
authenticatedRoutes.on(['PUT', 'POST'], `${cipher}/collections_v2`, (c) =>
  handleUpdateCipherCollections(c, c.req.param('cipherId'), 'member'),
);
authenticatedRoutes.on(['PUT', 'POST'], `${cipher}/collections-admin`, (c) =>
  handleUpdateCipherCollections(c, c.req.param('cipherId'), 'admin'),
);
authenticatedRoutes.get(`${cipher}/admin`, (c) => handleGetCipherAdmin(c, c.req.param('cipherId')));
authenticatedRoutes.put(`${cipher}/admin`, (c) => handleUpdateCipher(c, c.req.param('cipherId'), true));
authenticatedRoutes.delete(`${cipher}/admin`, (c) => handlePermanentDeleteCipher(c, c.req.param('cipherId'), true));
authenticatedRoutes.put(`${cipher}/delete-admin`, (c) => handleDeleteCipher(c, c.req.param('cipherId'), true));
authenticatedRoutes.get(`${cipher}/details`, (c) => handleGetCipher(c, c.req.param('cipherId')));
authenticatedRoutes.on('POST', [`${cipher}/attachment/v2`, `${cipher}/attachment`], (c) =>
  handleCreateAttachment(c, c.req.param('cipherId')),
);

const attachment = `${cipher}/attachment/:attachmentId{[a-f0-9-]+}`;
authenticatedRoutes.on(['POST', 'PUT'], attachment, (c) =>
  handleUploadAttachment(c, c.req.param('cipherId'), c.req.param('attachmentId')),
);
authenticatedRoutes.get(attachment, (c) =>
  handleGetAttachment(c, c.req.param('cipherId'), c.req.param('attachmentId')),
);
authenticatedRoutes.delete(attachment, (c) =>
  handleDeleteAttachment(c, c.req.param('cipherId'), c.req.param('attachmentId')),
);
authenticatedRoutes.on(['POST', 'PUT'], `${attachment}/metadata`, (c) =>
  handleUpdateAttachmentMetadata(c, c.req.param('cipherId'), c.req.param('attachmentId')),
);
authenticatedRoutes.post(`${attachment}/delete`, (c) =>
  handleDeleteAttachment(c, c.req.param('cipherId'), c.req.param('attachmentId')),
);

authenticatedRoutes.get('/api/folders', handleGetFolders);
authenticatedRoutes.post('/api/folders', handleCreateFolder);
authenticatedRoutes.post('/api/folders/delete', handleBulkDeleteFolders);
authenticatedRoutes.get('/api/folders/:folderId{[a-f0-9-]+}', (c) => handleGetFolder(c, c.req.param('folderId')));
authenticatedRoutes.put('/api/folders/:folderId{[a-f0-9-]+}', (c) => handleUpdateFolder(c, c.req.param('folderId')));
authenticatedRoutes.delete('/api/folders/:folderId{[a-f0-9-]+}', (c) => handleDeleteFolder(c, c.req.param('folderId')));

authenticatedRoutes.on('GET', ['/api/auth-requests', '/auth-requests'], handleListAuthRequests);
authenticatedRoutes.on('ALL', ['/api/auth-requests', '/auth-requests'], methodNotAllowed);
authenticatedRoutes.on('GET', ['/api/auth-requests/pending', '/auth-requests/pending'], handleListPendingAuthRequests);
authenticatedRoutes.on('ALL', ['/api/auth-requests/pending', '/auth-requests/pending'], methodNotAllowed);
authenticatedRoutes.on('POST', ['/api/auth-requests/admin-request', '/auth-requests/admin-request'], (c) =>
  handleCreateAdminAuthRequest(c, c.get('currentUser').email),
);
authenticatedRoutes.on('ALL', ['/api/auth-requests/admin-request', '/auth-requests/admin-request'], methodNotAllowed);
const authRequest = ['/api/auth-requests/:id{[a-f0-9-]+}', '/auth-requests/:id{[a-f0-9-]+}'] as const;
authenticatedRoutes.on('GET', [...authRequest], (c) => handleGetAuthRequest(c, c.req.param('id')));
authenticatedRoutes.on('PUT', [...authRequest], (c) => handleUpdateAuthRequest(c, c.req.param('id')));
authenticatedRoutes.on('ALL', [...authRequest], methodNotAllowed);

// Collection, organization and policy lists the clients poll but this server answers empty.
authenticatedRoutes.get('/api/collections/*', emptyList);
authenticatedRoutes.on('GET', ['/api/organizations', '/api/organizations/*'], emptyList);

authenticatedRoutes.get('/api/sends', handleGetSends);
authenticatedRoutes.post('/api/sends', handleCreateSend);
authenticatedRoutes.post('/api/sends/file/v2', handleCreateFileSendV2);
authenticatedRoutes.post('/api/sends/delete', handleBulkDeleteSends);
authenticatedRoutes.get('/api/sends/:sendId', (c) => handleGetSend(c, c.req.param('sendId')));
authenticatedRoutes.put('/api/sends/:sendId', (c) => handleUpdateSend(c, c.req.param('sendId')));
authenticatedRoutes.delete('/api/sends/:sendId', (c) => handleDeleteSend(c, c.req.param('sendId')));
authenticatedRoutes.on(['PUT', 'POST'], '/api/sends/:sendId/remove-password', (c) =>
  handleRemoveSendPassword(c, c.req.param('sendId')),
);
authenticatedRoutes.on(['PUT', 'POST'], '/api/sends/:sendId/remove-auth', (c) =>
  handleRemoveSendAuth(c, c.req.param('sendId')),
);
authenticatedRoutes.get('/api/sends/:sendId/file/:fileId', (c) =>
  handleGetSendFileUpload(c, c.req.param('sendId'), c.req.param('fileId')),
);
authenticatedRoutes.on(['POST', 'PUT'], '/api/sends/:sendId/file/:fileId', (c) =>
  handleUploadSendFile(c, c.req.param('sendId'), c.req.param('fileId')),
);

authenticatedRoutes.on('GET', ['/api/policies', '/api/policies/*'], emptyList);

authenticatedRoutes.on('GET', ['/api/settings/domains', '/settings/domains'], handleGetDomains);
authenticatedRoutes.on(['PUT', 'POST'], ['/api/settings/domains', '/settings/domains'], handleUpdateDomains);

authenticatedRoutes.route('/', deviceRoutes);
authenticatedRoutes.route('/', adminRoutes);
