import { verifyPassword } from '../services/auth-password';
import type { AppContext } from '../router';
import { EventType, recordUserEvent } from '../services/events';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import type { AccountPasskeyChallengeScope, AccountPasskeyCredential, Env, User } from '../types';
import { AuthService } from '../services/auth';
import { z } from 'zod';
import { errorResponse, type BodyContext } from '../utils/response';
import { bytesToBase64Url, parseClientDataJSON } from '../utils/passkey';
import {
  accountPasskeyCredentialToResponse,
  accountPasskeyPrfStatus,
  accountPasskeyTokenTtlMs,
  createAccountPasskeyToken,
  getAccountPasskeyRpConfig,
  isSerializedEncString,
  normalizeAccountPasskeyName,
  normalizeAuthenticationResponse,
  normalizeRegistrationResponse,
  normalizeTransports,
  passkeyDescriptor,
  sha256Base64Url,
  toSimpleWebAuthnCredential,
  userHandleToUserId,
  userIdToWebAuthnUserId,
  verifyAccountPasskeyToken,
} from '../utils/account-passkeys';
import { auditRequestMetadata, writeAuditEvent } from '../services/audit-events';
import { ensureTwoFactorRecoveryCode } from '../services/two-factor-providers';
import { createTwoFactorUserVerificationToken, verifyTwoFactorUserVerificationToken } from '../utils/jwt';
import { passkeyRepo } from '../services/storage-account-passkey-repo';
import { sessionRepo } from '../services/storage-session-repo';
import { userRepo } from '../services/storage-user-repo';
import { withoutQueryParams } from '../db/client';

const MAX_ACCOUNT_PASSKEYS = 5;
const MAX_TWO_FACTOR_PASSKEYS = 5;

// Passkey routes share one loose body: the user-verification fields are typed here (non-strings read as
// absent), while each route parses its own WebAuthn and PRF fields.
const optionalSecret = z.string().trim().optional().catch(undefined);
export const PasskeyRequestSchema = z.looseObject({
  masterPasswordHash: optionalSecret,
  master_password_hash: optionalSecret,
  secret: optionalSecret,
  password: optionalSecret,
  userVerificationToken: optionalSecret,
});
type PasskeyRequest = z.output<typeof PasskeyRequestSchema>;

async function verifyUserSecret(user: User, body: PasskeyRequest): Promise<boolean> {
  const secret = body.masterPasswordHash || body.master_password_hash || body.secret || body.password;
  if (!secret) return false;
  const storedHash = String(user.masterPasswordHash || '').trim();
  if (!storedHash) return false;
  return verifyPassword(secret, storedHash, user.email);
}

async function verifyTwoFactorWebAuthnUser(env: Env, user: User, body: PasskeyRequest): Promise<boolean> {
  const token = body.userVerificationToken || '';
  return (await verifyTwoFactorUserVerificationToken(env, user, 7, token)) || (await verifyUserSecret(user, body));
}

function hasCompletePrfKeySet(body: PasskeyRequest): boolean {
  return !!(body.encryptedUserKey && body.encryptedPublicKey && body.encryptedPrivateKey);
}

function twoFactorWebAuthnResponse(
  credentials: AccountPasskeyCredential[],
  object = 'twoFactorWebAuthn',
): Record<string, unknown> {
  const keys = credentials.map((credential, index) => ({
    Id: index + 1,
    id: index + 1,
    Name: credential.name,
    name: credential.name,
    Migrated: false,
    migrated: false,
  }));
  return {
    Enabled: credentials.length > 0,
    enabled: credentials.length > 0,
    Keys: keys,
    keys,
    WebAuthn: { Enabled: credentials.length > 0, Keys: keys },
    Object: object,
    object,
  };
}

// The client data carries the challenge the authenticator signed.
function readChallenge(response: { response: { clientDataJSON: string } }): string | null {
  const clientData = parseClientDataJSON(response.response.clientDataJSON);
  return String(clientData?.challenge || '').trim() || null;
}

const encryptedKey = z.string().trim().refine(isSerializedEncString);
const PrfKeySetSchema = z.object({
  encryptedUserKey: encryptedKey,
  encryptedPublicKey: encryptedKey,
  encryptedPrivateKey: encryptedKey,
});
const NO_PRF_KEY_SET = { encryptedUserKey: null, encryptedPublicKey: null, encryptedPrivateKey: null };

async function saveChallenge(
  db: D1Database,
  scope: AccountPasskeyChallengeScope,
  challenge: string,
  userId: string | null,
): Promise<void> {
  const now = Date.now();
  await passkeyRepo(db).saveAccountPasskeyChallenge({
    challengeHash: await sha256Base64Url(challenge),
    scope,
    userId,
    expiresAt: now + accountPasskeyTokenTtlMs(scope),
    usedAt: null,
    createdAt: now,
  });
}

export async function handleGetAccountPasskeyAssertionOptions(c: AppContext): Promise<Response> {
  const { rpId } = getAccountPasskeyRpConfig(c.req.raw, c.env);
  const options = await generateAuthenticationOptions({
    rpID: rpId,
    allowCredentials: [],
    userVerification: 'required',
    timeout: 60000,
  });
  await saveChallenge(c.env.DB, 'Authentication', options.challenge, null);
  const token = await createAccountPasskeyToken(c.env, {
    scope: 'Authentication',
    challenge: options.challenge,
    userId: null,
    rpId,
  });
  return c.json({
    options,
    token,
    object: 'webAuthnLoginAssertionOptions',
    Object: 'webAuthnLoginAssertionOptions',
  });
}

export async function assertAccountPasskeyCredential(
  request: Request,
  env: Env,
  db: D1Database,
  input: {
    token: string;
    deviceResponse: unknown;
    scope: 'Authentication' | 'UpdateKeySet';
    expectedUserId?: string | null;
  },
): Promise<{ user: User; credential: AccountPasskeyCredential }> {
  const payload = await verifyAccountPasskeyToken(env, input.token, input.scope);
  if (!payload) {
    throw new Error('Passkey challenge token is invalid or expired');
  }
  if (input.expectedUserId !== undefined && payload.userId !== input.expectedUserId) {
    throw new Error('Passkey challenge token does not match this user');
  }

  const response = normalizeAuthenticationResponse(input.deviceResponse);
  if (!response) {
    throw new Error('Invalid passkey assertion response');
  }

  const challengeHash = await sha256Base64Url(payload.challenge);
  const consumed = await passkeyRepo(db).consumeAccountPasskeyChallenge(
    challengeHash,
    input.scope,
    payload.userId,
    Date.now(),
  );
  if (!consumed) {
    throw new Error('Passkey challenge has expired or was already used');
  }

  const credential = await passkeyRepo(db).getAccountPasskeyCredentialByCredentialId(response.rawId);
  if (!credential) {
    throw new Error('Passkey is not registered for this server');
  }
  if (payload.userId && credential.userId !== payload.userId) {
    throw new Error('Passkey does not belong to this user');
  }
  if (credential.purpose !== 'login') {
    throw new Error('Passkey is not registered for login');
  }

  const userHandleUserId = userHandleToUserId(response.response.userHandle);
  const resolvedUserId = payload.userId || userHandleUserId || credential.userId;
  if (!resolvedUserId || resolvedUserId !== credential.userId) {
    throw new Error('Passkey user handle does not match this credential');
  }

  const user = await userRepo(db).getUserById(resolvedUserId);
  if (!user || user.status !== 'active') {
    throw new Error('Passkey user is not available');
  }

  const { origins } = getAccountPasskeyRpConfig(request, env);
  const verification = await verifyAuthenticationResponse({
    response,
    expectedChallenge: payload.challenge,
    expectedOrigin: origins,
    expectedRPID: payload.rpId,
    credential: toSimpleWebAuthnCredential(credential),
    requireUserVerification: true,
    advancedFIDOConfig: { userVerification: 'required' },
  });
  if (!verification.verified || !verification.authenticationInfo.userVerified) {
    throw new Error('Passkey assertion could not be verified');
  }

  await passkeyRepo(db).updateAccountPasskeyCounter(
    credential.userId,
    credential.credentialId,
    verification.authenticationInfo.newCounter,
    new Date().toISOString(),
  );
  credential.counter = verification.authenticationInfo.newCounter;
  return { user, credential };
}

export async function handleGetAccountPasskeyCredentials(c: AppContext): Promise<Response> {
  const { userId } = c.var;
  const credentials = await passkeyRepo(c.env.DB).listAccountPasskeyCredentialsByUserId(userId);
  return c.json({
    data: credentials.map(accountPasskeyCredentialToResponse),
    Data: credentials.map(accountPasskeyCredentialToResponse),
    object: 'list',
    Object: 'list',
    continuationToken: null,
    ContinuationToken: null,
  });
}

export async function buildTwoFactorPasskeyAssertionOptions(
  request: Request,
  env: Env,
  db: D1Database,
  user: User,
): Promise<Record<string, unknown> | null> {
  const credentials = await passkeyRepo(db).listAccountPasskeyCredentialsByUserId(user.id, 'twoFactor');
  if (!credentials.length) return null;

  const { rpId } = getAccountPasskeyRpConfig(request, env);
  const options = await generateAuthenticationOptions({
    rpID: rpId,
    allowCredentials: credentials.map(passkeyDescriptor),
    userVerification: 'discouraged',
    timeout: 60000,
  });
  await saveChallenge(db, 'TwoFactorAuthentication', options.challenge, user.id);
  return options as unknown as Record<string, unknown>;
}

export async function assertTwoFactorPasskeyCredential(
  request: Request,
  env: Env,
  db: D1Database,
  user: User,
  deviceResponse: unknown,
): Promise<AccountPasskeyCredential> {
  const response = normalizeAuthenticationResponse(deviceResponse);
  if (!response) {
    throw new Error('Invalid passkey assertion response');
  }

  const credential = await passkeyRepo(db).getAccountPasskeyCredentialByCredentialId(response.rawId);
  if (!credential || credential.userId !== user.id || credential.purpose !== 'twoFactor') {
    throw new Error('Passkey is not registered for two-step login');
  }

  const challenge = readChallenge(response);
  if (!challenge) {
    throw new Error('Passkey assertion challenge is missing');
  }
  const consumed = await passkeyRepo(db).consumeAccountPasskeyChallenge(
    await sha256Base64Url(challenge),
    'TwoFactorAuthentication',
    user.id,
    Date.now(),
  );
  if (!consumed) {
    throw new Error('Passkey challenge has expired or was already used');
  }

  const { origins, rpId } = getAccountPasskeyRpConfig(request, env);
  const verification = await verifyAuthenticationResponse({
    response,
    expectedChallenge: challenge,
    expectedOrigin: origins,
    expectedRPID: rpId,
    credential: toSimpleWebAuthnCredential(credential),
    requireUserVerification: false,
  });
  if (!verification.verified) {
    throw new Error('Passkey assertion could not be verified');
  }

  await passkeyRepo(db).updateAccountPasskeyCounter(
    credential.userId,
    credential.credentialId,
    verification.authenticationInfo.newCounter,
    new Date().toISOString(),
  );
  credential.counter = verification.authenticationInfo.newCounter;
  return credential;
}

export async function handleGetTwoFactorWebAuthn(c: BodyContext<typeof PasskeyRequestSchema>): Promise<Response> {
  const { userId, currentUser: user } = c.var;
  const body = c.req.valid('json');
  if (!(await verifyUserSecret(user, body))) {
    return errorResponse(c, 'User verification failed.', 400);
  }

  const credentials = await passkeyRepo(c.env.DB).listAccountPasskeyCredentialsByUserId(userId, 'twoFactor');
  return c.json({
    ...twoFactorWebAuthnResponse(credentials),
    UserVerificationToken: await createTwoFactorUserVerificationToken(c.env, user, 7),
  });
}

export async function handleGetTwoFactorWebAuthnChallenge(
  c: BodyContext<typeof PasskeyRequestSchema>,
): Promise<Response> {
  const { userId, currentUser: user } = c.var;
  const body = c.req.valid('json');
  if (!(await verifyTwoFactorWebAuthnUser(c.env, user, body))) {
    return errorResponse(c, 'User verification failed.', 400);
  }

  const credentials = await passkeyRepo(c.env.DB).listAccountPasskeyCredentialsByUserId(userId, 'twoFactor');
  if (credentials.length >= MAX_TWO_FACTOR_PASSKEYS) {
    return errorResponse(c, 'Maximum WebAuthn credential count reached.', 400);
  }

  const { rpId, rpName } = getAccountPasskeyRpConfig(c.req.raw, c.env);
  const options = await generateRegistrationOptions({
    rpID: rpId,
    rpName,
    userID: Uint8Array.from(userIdToWebAuthnUserId(user.id)),
    userName: user.email,
    userDisplayName: user.name || user.email,
    attestationType: 'none',
    timeout: 60000,
    excludeCredentials: credentials.map(passkeyDescriptor),
    authenticatorSelection: {
      residentKey: 'discouraged',
      requireResidentKey: false,
      userVerification: 'discouraged',
    },
  });
  await saveChallenge(c.env.DB, 'TwoFactorCreate', options.challenge, userId);
  return c.json({ ...options, Options: options, Object: 'twoFactorWebAuthnChallenge' });
}

export async function handlePutTwoFactorWebAuthn(c: BodyContext<typeof PasskeyRequestSchema>): Promise<Response> {
  const { userId, currentUser: user } = c.var;
  const body = c.req.valid('json');
  if (!(await verifyTwoFactorWebAuthnUser(c.env, user, body))) {
    return errorResponse(c, 'User verification failed.', 400);
  }

  const currentCount = await passkeyRepo(c.env.DB).countAccountPasskeyCredentialsByUserId(userId, 'twoFactor');
  if (currentCount >= MAX_TWO_FACTOR_PASSKEYS) {
    return errorResponse(c, 'Maximum WebAuthn credential count reached.', 400);
  }

  const registrationResponse = normalizeRegistrationResponse(body.deviceResponse);
  if (!registrationResponse) {
    return errorResponse(c, 'Invalid passkey registration response', 400);
  }
  const challenge = readChallenge(registrationResponse);
  if (!challenge) {
    return errorResponse(c, 'Passkey challenge is missing', 400);
  }
  const consumed = await passkeyRepo(c.env.DB).consumeAccountPasskeyChallenge(
    await sha256Base64Url(challenge),
    'TwoFactorCreate',
    userId,
    Date.now(),
  );
  if (!consumed) {
    return errorResponse(c, 'Passkey challenge has expired or was already used', 400);
  }

  const { origins, rpId } = getAccountPasskeyRpConfig(c.req.raw, c.env);
  let verification: Awaited<ReturnType<typeof verifyRegistrationResponse>>;
  try {
    verification = await verifyRegistrationResponse({
      response: registrationResponse,
      expectedChallenge: challenge,
      expectedOrigin: origins,
      expectedRPID: rpId,
      requireUserPresence: true,
      requireUserVerification: false,
    });
  } catch {
    return errorResponse(c, 'Passkey registration could not be verified', 400);
  }
  if (!verification.verified) {
    return errorResponse(c, 'Passkey registration could not be verified', 400);
  }

  const existing = await passkeyRepo(c.env.DB).getAccountPasskeyCredentialByCredentialId(
    verification.registrationInfo.credential.id,
  );
  if (existing) {
    return errorResponse(c, 'Passkey is already registered', 409);
  }

  if (!(await ensureTwoFactorRecoveryCode(c.env.DB, user.id, user.securityStamp)))
    return errorResponse(c, 'User verification failed.', 400);
  const now = new Date().toISOString();
  const transports = normalizeTransports(registrationResponse.response.transports);
  const saved = await passkeyRepo(c.env.DB).saveAccountPasskeyCredential(
    {
      id: crypto.randomUUID(),
      userId,
      purpose: 'twoFactor',
      name: normalizeAccountPasskeyName(body.name || `Passkey ${currentCount + 1}`),
      publicKey: bytesToBase64Url(verification.registrationInfo.credential.publicKey),
      credentialId: verification.registrationInfo.credential.id,
      counter: verification.registrationInfo.credential.counter,
      type: verification.registrationInfo.credentialType || 'public-key',
      aaGuid: verification.registrationInfo.aaguid || null,
      transports,
      encryptedUserKey: null,
      encryptedPublicKey: null,
      encryptedPrivateKey: null,
      supportsPrf: false,
      createdAt: now,
      updatedAt: now,
    },
    user.securityStamp,
  );
  if (!saved) return errorResponse(c, 'User verification failed.', 400);

  await sessionRepo(c.env.DB).deleteRefreshTokensByUserId(userId);
  AuthService.invalidateUserCache(userId);

  await recordUserEvent(c.env, c.req.raw, user.id, EventType.UserUpdated2fa);
  await writeAuditEvent(c.env.DB, {
    actorUserId: userId,
    action: 'account.webauthn_2fa.enable',
    category: 'security',
    level: 'security',
    targetType: 'accountPasskey',
    targetId: null,
    metadata: auditRequestMetadata(c.req.raw),
  });

  const credentials = await passkeyRepo(c.env.DB).listAccountPasskeyCredentialsByUserId(userId, 'twoFactor');
  return c.json(twoFactorWebAuthnResponse(credentials, 'twoFactorWebAuthnUpdate'));
}

export async function handleDeleteTwoFactorWebAuthn(c: BodyContext<typeof PasskeyRequestSchema>): Promise<Response> {
  const { userId, currentUser: user } = c.var;
  const body = c.req.valid('json');
  if (!(await verifyTwoFactorWebAuthnUser(c.env, user, body))) {
    return errorResponse(c, 'User verification failed.', 400);
  }

  const requestedId = Number(body.id);
  if (!Number.isInteger(requestedId) || requestedId <= 0) {
    return errorResponse(c, 'Invalid key id', 400);
  }

  const credentials = await passkeyRepo(c.env.DB).listAccountPasskeyCredentialsByUserId(userId, 'twoFactor');
  if (credentials.length < 2) {
    return errorResponse(c, 'Unable to delete WebAuthn credential.', 400);
  }
  const credential = credentials[requestedId - 1];
  if (!credential) {
    return errorResponse(c, 'Unable to delete WebAuthn credential.', 400);
  }

  const deleted = await passkeyRepo(c.env.DB).deleteAccountPasskeyCredential(userId, credential.id, 'twoFactor');
  if (!deleted) return errorResponse(c, 'Unable to delete WebAuthn credential.', 400);
  await sessionRepo(c.env.DB).deleteRefreshTokensByUserId(userId);
  AuthService.invalidateUserCache(userId);

  await recordUserEvent(c.env, c.req.raw, user.id, EventType.UserUpdated2fa);
  await writeAuditEvent(c.env.DB, {
    actorUserId: userId,
    action: 'account.webauthn_2fa.delete',
    category: 'security',
    level: 'security',
    targetType: 'accountPasskey',
    targetId: credential.id,
    metadata: auditRequestMetadata(c.req.raw),
  });

  return c.json(
    twoFactorWebAuthnResponse(
      await passkeyRepo(c.env.DB).listAccountPasskeyCredentialsByUserId(userId, 'twoFactor'),
      'twoFactorWebAuthnDelete',
    ),
  );
}

export async function handleGetAccountPasskeyAttestationOptions(
  c: BodyContext<typeof PasskeyRequestSchema>,
): Promise<Response> {
  const { userId, currentUser: user } = c.var;
  const body = c.req.valid('json');

  let stage = 'verify_master_password';
  try {
    if (!(await verifyUserSecret(user, body))) {
      return errorResponse(c, 'Master password verification failed', 400);
    }

    stage = 'load_existing_credentials';
    const credentials = await passkeyRepo(c.env.DB).listAccountPasskeyCredentialsByUserId(userId);
    if (credentials.length >= MAX_ACCOUNT_PASSKEYS) {
      return errorResponse(c, 'Maximum passkey count reached', 400);
    }

    const { rpId, rpName } = getAccountPasskeyRpConfig(c.req.raw, c.env);
    stage = 'generate_options';
    const options = await generateRegistrationOptions({
      rpID: rpId,
      rpName,
      userID: Uint8Array.from(userIdToWebAuthnUserId(user.id)),
      userName: user.email,
      userDisplayName: user.name || user.email,
      attestationType: 'none',
      timeout: 60000,
      excludeCredentials: credentials.map(passkeyDescriptor),
      authenticatorSelection: {
        residentKey: 'required',
        requireResidentKey: true,
        userVerification: 'required',
      },
    });
    stage = 'save_challenge';
    await saveChallenge(c.env.DB, 'CreateCredential', options.challenge, userId);
    stage = 'create_token';
    const token = await createAccountPasskeyToken(c.env, {
      scope: 'CreateCredential',
      challenge: options.challenge,
      userId,
      rpId,
    });
    return c.json({
      options: { ...options, extensions: { ...options.extensions, prf: {} } },
      token,
      object: 'webauthnCredentialCreateOptions',
      Object: 'webauthnCredentialCreateOptions',
    });
  } catch (error) {
    const redacted = withoutQueryParams(error);
    const err = redacted instanceof Error ? redacted : null;
    console.error('Account passkey handler failed', {
      stage,
      name: err?.name || typeof error,
      message: err?.message || String(redacted),
      stack: err?.stack,
      userId,
    });
    const stageMessage =
      stage === 'verify_master_password'
        ? 'verifying master password'
        : stage === 'load_existing_credentials'
          ? 'loading existing passkeys'
          : stage === 'generate_options'
            ? 'generating passkey options'
            : stage === 'save_challenge'
              ? 'saving passkey challenge'
              : stage === 'create_token'
                ? 'creating passkey challenge token'
                : 'preparing passkey setup';
    return errorResponse(c, `Passkey setup failed while ${stageMessage}`, 500);
  }
}

export async function handleGetAccountPasskeyUpdateAssertionOptions(
  c: BodyContext<typeof PasskeyRequestSchema>,
): Promise<Response> {
  const { userId, currentUser: user } = c.var;
  const body = c.req.valid('json');
  if (!(await verifyUserSecret(user, body))) {
    return errorResponse(c, 'Master password verification failed', 400);
  }

  let credentials = await passkeyRepo(c.env.DB).listAccountPasskeyCredentialsByUserId(userId);
  const requestedId = String(body.credentialId || body.id || '').trim();
  if (requestedId) {
    credentials = credentials.filter((credential) => credential.id === requestedId);
    if (!credentials.length) return errorResponse(c, 'Account passkey not found', 404);
  }
  if (!credentials.length) return errorResponse(c, 'No account passkeys registered', 404);

  const { rpId } = getAccountPasskeyRpConfig(c.req.raw, c.env);
  const options = await generateAuthenticationOptions({
    rpID: rpId,
    allowCredentials: credentials.map(passkeyDescriptor),
    userVerification: 'required',
    timeout: 60000,
  });
  await saveChallenge(c.env.DB, 'UpdateKeySet', options.challenge, userId);
  const token = await createAccountPasskeyToken(c.env, {
    scope: 'UpdateKeySet',
    challenge: options.challenge,
    userId,
    rpId,
  });
  return c.json({
    options,
    token,
    object: 'webAuthnLoginAssertionOptions',
    Object: 'webAuthnLoginAssertionOptions',
  });
}

export async function handleCreateAccountPasskeyCredential(
  c: BodyContext<typeof PasskeyRequestSchema>,
): Promise<Response> {
  const { userId } = c.var;
  const body = c.req.valid('json');

  const payload = await verifyAccountPasskeyToken(c.env, String(body.token || ''), 'CreateCredential');
  if (!payload || payload.userId !== userId) {
    return errorResponse(c, 'Passkey challenge token is invalid or expired', 400);
  }

  const challengeHash = await sha256Base64Url(payload.challenge);
  const consumed = await passkeyRepo(c.env.DB).consumeAccountPasskeyChallenge(
    challengeHash,
    'CreateCredential',
    userId,
    Date.now(),
  );
  if (!consumed) {
    return errorResponse(c, 'Passkey challenge has expired or was already used', 400);
  }

  const currentCount = await passkeyRepo(c.env.DB).countAccountPasskeyCredentialsByUserId(userId);
  if (currentCount >= MAX_ACCOUNT_PASSKEYS) {
    return errorResponse(c, 'Maximum passkey count reached', 400);
  }

  // A partial key set stores nothing; a complete one must be three EncStrings.
  const prfKeySet = hasCompletePrfKeySet(body)
    ? PrfKeySetSchema.safeParse(body)
    : { success: true as const, data: NO_PRF_KEY_SET };
  if (!prfKeySet.success) return errorResponse(c, 'Invalid encrypted passkey key set', 400);

  const registrationResponse = normalizeRegistrationResponse(body.deviceResponse);
  if (!registrationResponse) {
    return errorResponse(c, 'Invalid passkey registration response', 400);
  }

  const { origins } = getAccountPasskeyRpConfig(c.req.raw, c.env);
  let verification: Awaited<ReturnType<typeof verifyRegistrationResponse>>;
  try {
    verification = await verifyRegistrationResponse({
      response: registrationResponse,
      expectedChallenge: payload.challenge,
      expectedOrigin: origins,
      expectedRPID: payload.rpId,
      requireUserPresence: true,
      requireUserVerification: true,
    });
  } catch {
    return errorResponse(c, 'Passkey registration could not be verified', 400);
  }
  if (!verification.verified) {
    return errorResponse(c, 'Passkey registration could not be verified', 400);
  }

  const existing = await passkeyRepo(c.env.DB).getAccountPasskeyCredentialByCredentialId(
    verification.registrationInfo.credential.id,
  );
  if (existing) {
    return errorResponse(c, 'Passkey is already registered', 409);
  }

  const now = new Date().toISOString();
  const supportsPrf = !!body.supportsPrf || hasCompletePrfKeySet(body);
  const transports = normalizeTransports(registrationResponse.response.transports);
  const credential: AccountPasskeyCredential = {
    id: crypto.randomUUID(),
    userId,
    purpose: 'login',
    name: normalizeAccountPasskeyName(body.name),
    publicKey: bytesToBase64Url(verification.registrationInfo.credential.publicKey),
    credentialId: verification.registrationInfo.credential.id,
    counter: verification.registrationInfo.credential.counter,
    type: verification.registrationInfo.credentialType || 'public-key',
    aaGuid: verification.registrationInfo.aaguid || null,
    transports,
    ...prfKeySet.data,
    supportsPrf,
    createdAt: now,
    updatedAt: now,
  };

  await passkeyRepo(c.env.DB).saveAccountPasskeyCredential(credential);
  await writeAuditEvent(c.env.DB, {
    actorUserId: userId,
    action: 'account.passkey.create',
    category: 'security',
    level: 'info',
    targetType: 'accountPasskey',
    targetId: credential.id,
    metadata: {
      prfStatus: accountPasskeyPrfStatus(credential),
      ...auditRequestMetadata(c.req.raw),
    },
  });

  return c.json(accountPasskeyCredentialToResponse(credential));
}

export async function handleUpdateAccountPasskeyEncryption(
  c: BodyContext<typeof PasskeyRequestSchema>,
): Promise<Response> {
  const { userId } = c.var;
  const body = c.req.valid('json');

  if (!hasCompletePrfKeySet(body)) return errorResponse(c, 'Encrypted passkey key set is required', 400);
  const prfKeySet = PrfKeySetSchema.safeParse(body);
  if (!prfKeySet.success) return errorResponse(c, 'Invalid encrypted passkey key set', 400);

  let assertion: Awaited<ReturnType<typeof assertAccountPasskeyCredential>>;
  try {
    assertion = await assertAccountPasskeyCredential(c.req.raw, c.env, c.env.DB, {
      token: String(body.token || ''),
      deviceResponse: body.deviceResponse,
      scope: 'UpdateKeySet',
      expectedUserId: userId,
    });
  } catch (error) {
    return errorResponse(c, error instanceof Error ? error.message : 'Passkey assertion failed', 400);
  }

  const updated = await passkeyRepo(c.env.DB).updateAccountPasskeyEncryption(
    userId,
    assertion.credential.credentialId,
    prfKeySet.data.encryptedUserKey,
    prfKeySet.data.encryptedPublicKey,
    prfKeySet.data.encryptedPrivateKey,
  );
  if (!updated) return errorResponse(c, 'Passkey not found', 404);

  await writeAuditEvent(c.env.DB, {
    actorUserId: userId,
    action: 'account.passkey.encryption.enable',
    category: 'security',
    level: 'info',
    targetType: 'accountPasskey',
    targetId: assertion.credential.id,
    metadata: auditRequestMetadata(c.req.raw),
  });
  return c.json({ success: true });
}

export async function handleDeleteAccountPasskeyCredential(
  c: BodyContext<typeof PasskeyRequestSchema>,
  credentialId: string,
): Promise<Response> {
  const { userId, currentUser: user } = c.var;
  const body = c.req.valid('json');
  if (!(await verifyUserSecret(user, body))) {
    return errorResponse(c, 'Master password verification failed', 400);
  }

  const deleted = await passkeyRepo(c.env.DB).deleteAccountPasskeyCredential(userId, credentialId);
  if (!deleted) return errorResponse(c, 'Passkey not found', 404);

  await writeAuditEvent(c.env.DB, {
    actorUserId: userId,
    action: 'account.passkey.delete',
    category: 'security',
    level: 'info',
    targetType: 'accountPasskey',
    targetId: credentialId,
    metadata: auditRequestMetadata(c.req.raw),
  });
  return c.json({ success: true });
}
