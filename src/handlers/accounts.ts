import { hashPassword, verifyPassword } from '../services/auth-password';
import type { AppContext } from '../router';
import { EventType, recordUserEvent } from '../services/events';
import { and, eq } from 'drizzle-orm';
import { getOrm, userRowMatches, withoutQueryParams } from '../db/client';
import { devices, session, userRevisions, users, webauthnCredentials } from '../db/schema';
import { bound, excluded } from '../db/sql';
import { toSafeUrl } from '../utils/html';
import {
  runInBackground,
  notifyMail,
  notifyFailedTwoFactor,
  notifyNewDeviceVerification,
} from '../services/mail-notify';
import { Env, User } from '../types';
import { AuthService } from '../services/auth';
import { isAuthRequestLoginApproved, authRequestRepo } from '../services/storage-auth-request-repo';
import { readAuthRequestDeviceInfo, deviceTypeName } from '../utils/device';
import { syncVaultAdminRoles } from '../services/vault-admin-role';
import { deleteUserAccount } from '../services/account-deletion';
import { notifyUserLogout } from '../durable/notifications-hub';
import { issueEmailOtp, redeemEmailOtp, spendEmailOtpIssueBudget } from '../services/email-otp';
import {
  twoFactorProviders,
  twoFactorClearStatements,
  ensureTwoFactorRecoveryCode,
  existingOrNewRecoveryCode,
} from '../services/two-factor-providers';
import { upsertCredentialAccount, credentialAccountStatement } from '../services/auth-accounts';
import { RateLimitService, getClientIdentifier } from '../services/ratelimit';
import { auditRequestMetadata, writeAuditEvent, auditEventStatement } from '../services/audit-events';
import { z } from 'zod';
import { errorResponse, unsupportedResponse, validationErrorResponse, type BodyContext } from '../utils/response';
import { LIMITS } from '../config/limits';
import { readEnvConfig } from '../config/env';
import { isStoredApiKeyHash, randomStringAlphanum } from '../utils/api-key';
import { Secret } from 'otpauth';
import { findMatchingTotpCounter, isTotpEnabled, normalizeTotpSecret } from '../utils/totp';
import { createRecoveryCode, recoveryCodeEquals } from '../utils/recovery-code';
import { buildAccountKeys } from '../utils/user-decryption';
import { buildProfileResponse } from '../utils/profile-response';
import {
  createRegisterVerifyToken,
  verifyRegisterVerifyToken,
  createTwoFactorUserVerificationToken,
  verifyTwoFactorUserVerificationToken,
  verifySsoEmail2faSessionToken,
  createDeleteRecoverToken,
  verifyDeleteRecoverToken,
} from '../utils/jwt';
import {
  isOpenRegistrationEnabled,
  KdfSettings,
  MasterPasswordHint,
  RegisterSchema,
} from '../services/register-payload';
import {
  mailStatusCheck,
  type MailOutcome,
  readMailConfig,
  EMAIL_PATTERN,
  isReservedDocumentationEmail,
  registerVerifyVaultOrigin,
  configuredVaultOrigin,
  sendMail,
} from '../services/mail';
import {
  isYubiKeyEnabled,
  isYubiKeyPublicId,
  requestYubicoApiCredentials,
  verifyYubicoOtp,
  yubiKeyPublicIdFromOtp,
} from '../utils/yubico-otp';
import {
  getYubicoCredentials,
  initializeYubicoCredentialsOnce,
  replaceYubicoCredentials,
} from '../services/yubico-config';
import { passkeyRepo } from '../services/storage-account-passkey-repo';
import { adminRepo } from '../services/storage-admin-repo';
import { configRepo } from '../services/storage-config-repo';
import { revisionRepo } from '../services/storage-revision-repo';
import { sessionRepo } from '../services/storage-session-repo';
import { totpReplayRepo } from '../services/storage-totp-replay-repo';
import { userRepo } from '../services/storage-user-repo';

const TWO_FACTOR_PROVIDER_AUTHENTICATOR = 0;
const TWO_FACTOR_PROVIDER_EMAIL = 1;
const TWO_FACTOR_PROVIDER_YUBIKEY = 3;
const TWO_FACTOR_PROVIDER_WEBAUTHN = 7;

// CONTRACT:
// users.master_password_hash is server-side login verification only. It does
// not decrypt vault data. Password changes must keep encrypted user key material,
// securityStamp, refresh-token invalidation, and client compatibility together.
// Password hints are non-secret reminders; never treat them as recovery secrets.
function looksLikeEncString(value: string): boolean {
  if (!value) return false;
  const firstDot = value.indexOf('.');
  if (firstDot <= 0 || firstDot === value.length - 1) return false;
  const payload = value.slice(firstDot + 1);
  const parts = payload.split('|');
  // Bitwarden encrypted payloads should have at least IV + ciphertext.
  return parts.length >= 2;
}

async function verifyUserSecret(user: User, secret: string | null | undefined): Promise<boolean> {
  const normalized = String(secret || '').trim();
  if (!normalized) return false;
  return verifyPassword(normalized, user.masterPasswordHash, user.email);
}

// Account bodies read an absent or wrongly typed string as empty; the verification that follows rejects it.
const text = z.string().catch('');
const trimmed = z.string().trim().catch('');

// Mail goes to, and codes bind to, one address the transport accepts.
export const emailAddress = (error: string) =>
  z
    .string({ error })
    .trim()
    .toLowerCase()
    .refine((email) => email.length <= 256 && EMAIL_PATTERN.test(email), { error });

// User verification takes the master password hash, which older clients also post as otp or secret.
export const VerifiedBody = z.object({ masterPasswordHash: text, otp: text, OTP: text, secret: text });
const verificationSecret = (body: z.output<typeof VerifiedBody>) =>
  body.masterPasswordHash || body.otp || body.OTP || body.secret;

// Older clients post the current master password hash as master_password_hash or password.
export const CurrentPasswordHash = z
  .object({ masterPasswordHash: text, master_password_hash: text, password: text })
  .transform((body) => (body.masterPasswordHash || body.master_password_hash || body.password).trim())
  .refine(Boolean, 'masterPasswordHash is required');

// Clients may echo the account KDF; changing it takes the KDF endpoint, which this server does not support.
// Official clients echo the account's KDF settings with a password or email change. The route keeps them (kdfEcho);
// kdfChangeRefused answers a changed one once the account is loaded.
const echoed = z.unknown().optional();
const kdfEcho = { kdf: echoed, kdfType: echoed, kdfIterations: echoed, kdfMemory: echoed, kdfParallelism: echoed };

function kdfChangeRefused(c: AppContext, user: User, endpoint: 'password' | 'email', body: unknown): Response | null {
  const same = (expected: unknown) =>
    z
      .unknown()
      .refine((value) => value === expected, { error: `KDF settings cannot be changed with the ${endpoint} endpoint` })
      .optional();
  const echoed = z
    .object({
      kdf: same(user.kdfType),
      kdfType: same(user.kdfType),
      kdfIterations: same(user.kdfIterations),
      kdfMemory: same(user.kdfMemory ?? null),
      kdfParallelism: same(user.kdfParallelism ?? null),
    })
    .safeParse(body);
  return echoed.success ? null : validationErrorResponse(c, echoed.error);
}

const masterPasswordHalf = { salt: text, kdf: KdfSettings };

// A new master password arrives either as web 2026.9's nested authenticationData/unlockData
// (server MasterPasswordAuthenticationData/UnlockData) or as legacy newMasterPasswordHash + key.
export const MasterPasswordFields = z.object(
  {
    authenticationData: z
      .object({ ...masterPasswordHalf, masterPasswordAuthenticationHash: trimmed })
      .optional()
      .catch(undefined),
    unlockData: z
      .object({ ...masterPasswordHalf, masterKeyWrappedUserKey: trimmed })
      .optional()
      .catch(undefined),
    newMasterPasswordHash: trimmed,
    newKey: trimmed,
    key: trimmed,
  },
  { error: 'Request body must be a JSON object' },
);

// Password change, email change and emergency takeover share this check: the nested halves must agree
// with each other and with the user's stored KDF and email salt, otherwise the stored hash and wrapped
// user key stop matching what clients derive at the next login.
export function masterPasswordUpdate(
  c: AppContext,
  body: z.output<typeof MasterPasswordFields>,
  user: User,
): { masterPasswordHash: string; key: string } | Response {
  const reject = (message: string) => errorResponse(c, message, 400);
  const { authenticationData: auth, unlockData: unlock } = body;
  if (!auth !== !unlock) return reject('authenticationData and unlockData must be provided together');
  const update =
    auth && unlock
      ? { masterPasswordHash: auth.masterPasswordAuthenticationHash, key: unlock.masterKeyWrappedUserKey }
      : { masterPasswordHash: body.newMasterPasswordHash, key: body.newKey || body.key };

  if (auth && unlock) {
    if (!update.masterPasswordHash || !update.key) return reject('authenticationData and unlockData are incomplete');
    const [authKdf, unlockKdf] = [auth.kdf, unlock.kdf];
    if (
      authKdf?.kdfType === undefined ||
      authKdf.iterations === undefined ||
      unlockKdf?.kdfType === undefined ||
      unlockKdf.iterations === undefined
    ) {
      return reject('authenticationData and unlockData must include KDF settings');
    }
    if (
      (['kdfType', 'iterations', 'memory', 'parallelism'] as const).some((name) => authKdf[name] !== unlockKdf[name])
    ) {
      return reject('authenticationData and unlockData must use the same KDF settings');
    }
    if (!auth.salt || auth.salt !== unlock.salt || auth.salt !== user.email.trim().toLowerCase()) {
      return reject('Invalid master password salt');
    }
    if (
      authKdf.kdfType !== user.kdfType ||
      authKdf.iterations !== user.kdfIterations ||
      (authKdf.kdfType === 1 && (authKdf.memory !== user.kdfMemory || authKdf.parallelism !== user.kdfParallelism))
    ) {
      return reject('KDF settings cannot be changed with the password endpoint');
    }
  } else if (!update.masterPasswordHash || !update.key) {
    return reject('newMasterPasswordHash and key must be provided together');
  }

  if (!looksLikeEncString(update.key)) return reject('new key is not a valid encrypted string');
  return update;
}

function keysResponse(user: User): Record<string, unknown> {
  const accountKeys = buildAccountKeys(user);
  return {
    Key: user.key,
    PublicKey: user.publicKey ?? '',
    PrivateKey: user.privateKey ?? '',
    AccountKeys: accountKeys,
    Object: 'keys',
    key: user.key,
    publicKey: user.publicKey ?? '',
    privateKey: user.privateKey ?? '',
    accountKeys,
    object: 'keys',
  };
}

// POST /api/accounts/register
// - First user becomes admin.
// - Any subsequent user must provide a valid inviteCode.
export async function handleRegister(c: BodyContext<typeof RegisterSchema>): Promise<Response> {
  const parsed = c.req.valid('json');
  const { email, name, masterPasswordHash, key, privateKey, publicKey, inviteCode, masterPasswordHint } = parsed;

  const userCount = await userRepo(c.env.DB).getUserCount();
  const { NODEWARDEN_DEPLOYMENT, TENANT_OWNER_EMAIL } = readEnvConfig(c.env);
  if (userCount === 0 && (TENANT_OWNER_EMAIL !== undefined || NODEWARDEN_DEPLOYMENT === 'dispatch')) {
    if (TENANT_OWNER_EMAIL !== email) {
      return errorResponse(c, 'Registration is reserved for the instance owner', 403);
    }
    if (!parsed.emailVerificationToken) {
      return errorResponse(c, 'Email verification token is invalid or expired', 400);
    }
  }

  if (parsed.emailVerificationToken) {
    const claims = await verifyRegisterVerifyToken(parsed.emailVerificationToken, c.env.JWT_SECRET);
    if (!claims || claims.email !== email) {
      return errorResponse(c, 'Email verification token is invalid or expired', 400);
    }
  }
  if (!looksLikeEncString(key)) {
    return errorResponse(c, 'key is not a valid encrypted string', 400);
  }
  if (!looksLikeEncString(privateKey)) {
    return errorResponse(c, 'encryptedPrivateKey is not a valid encrypted string', 400);
  }

  const now = new Date().toISOString();
  const serverHash = await hashPassword(masterPasswordHash);

  const user: User = {
    id: crypto.randomUUID(),
    email,
    emailVerified: !!parsed.emailVerificationToken,
    name,
    masterPasswordHint,
    masterPasswordHash: serverHash,
    key,
    privateKey,
    publicKey,
    kdfType: parsed.kdf ?? 0,
    kdfIterations: parsed.kdfIterations ?? LIMITS.auth.defaultKdfIterations,
    kdfMemory: parsed.kdfMemory,
    kdfParallelism: parsed.kdfParallelism,
    securityStamp: crypto.randomUUID(),
    role: 'user',
    status: 'active',
    verifyDevices: true,
    totpSecret: null,
    totpRecoveryCode: null,
    twoFactorEmail: null,
    yubikeyKey1: null,
    yubikeyKey2: null,
    yubikeyKey3: null,
    yubikeyKey4: null,
    yubikeyKey5: null,
    yubikeyNfc: false,
    // Bitwarden creates a readable personal API key with the account. It is
    // returned only after fresh user verification and is excluded from backups.
    apiKey: randomStringAlphanum(LIMITS.auth.clientSecretLength),
    userKeyId: null,
    createdAt: now,
    updatedAt: now,
  };

  if (userCount === 0) {
    user.role = 'admin';
    const created = await userRepo(c.env.DB).createFirstUser(user);
    if (!created) {
      return errorResponse(c, 'Registration is temporarily unavailable, retry once', 409);
    }
    AuthService.invalidateUserCache(user.id);
    if (!(await upsertCredentialAccount(c.env.DB, user.id, user.masterPasswordHash, user.securityStamp)))
      return errorResponse(c, 'User verification failed.', 400);
    await configRepo(c.env.DB).setRegistered();
    await writeAuditEvent(c.env.DB, {
      actorUserId: user.id,
      action: 'user.register.first_admin',
      targetType: 'user',
      targetId: user.id,
      category: 'security',
      level: 'security',
      metadata: { email: user.email, ...auditRequestMetadata(c.req.raw) },
    });
    notifyMail(c.env, user.email, 'welcome', {
      name: user.name || user.email,
      vaultOrigin: configuredVaultOrigin(c.req.raw, c.env),
    });
    await syncVaultAdminRoles(c.env);
    return registerSuccessResponse(c, (await userRepo(c.env.DB).getUserById(user.id))!.role);
  }

  if (!inviteCode && !isOpenRegistrationEnabled(c.env)) {
    return errorResponse(c, 'Invite code is required', 403);
  }

  if (inviteCode) {
    const inviteMarked = await adminRepo(c.env.DB).markInviteUsed(inviteCode, user.id);
    if (!inviteMarked) {
      return errorResponse(c, 'Invite code is invalid or expired', 403);
    }
  }

  try {
    await userRepo(c.env.DB).createUser(user);
    AuthService.invalidateUserCache(user.id);
    if (!(await upsertCredentialAccount(c.env.DB, user.id, user.masterPasswordHash, user.securityStamp)))
      return errorResponse(c, 'User verification failed.', 400);
  } catch (error) {
    if (inviteCode) await adminRepo(c.env.DB).revertInviteUsed(inviteCode, user.id);
    let cause = error;
    while (cause instanceof Error && cause.cause) cause = cause.cause;
    const msg = (cause instanceof Error ? cause.message : String(cause)).toLowerCase();
    if (msg.includes('unique') || msg.includes('constraint')) {
      return errorResponse(c, 'Email already registered', 409);
    }
    console.error('Registration failed after invite reservation:', withoutQueryParams(error));
    throw error;
  }

  if (inviteCode) {
    try {
      const assigned = await adminRepo(c.env.DB).assignInviteUsedBy(inviteCode, user.id);
      if (!assigned) {
        // Invite codes are credentials, so the log names the account, never the code.
        console.warn('Invite used_by was not assigned after registration', { userId: user.id });
      }
    } catch (error) {
      console.error('Invite used_by assignment failed after registration:', withoutQueryParams(error));
    }
  }

  await writeAuditEvent(c.env.DB, {
    actorUserId: user.id,
    action: inviteCode ? 'user.register.invite' : 'user.register.open',
    targetType: 'user',
    targetId: user.id,
    category: 'security',
    level: 'info',
    metadata: { email: user.email, inviteCode, ...auditRequestMetadata(c.req.raw) },
  });

  notifyMail(c.env, user.email, 'welcome', {
    name: user.name || user.email,
    vaultOrigin: configuredVaultOrigin(c.req.raw, c.env),
  });
  await syncVaultAdminRoles(c.env);
  return registerSuccessResponse(c, (await userRepo(c.env.DB).getUserById(user.id))!.role);
}

function registerSuccessResponse(c: AppContext, role: User['role']): Response {
  return c.json(
    {
      object: 'register',
      captchaBypassToken: '',
      success: true,
      role,
    },
    200,
  );
}

export const RegisterSendVerificationEmailBody = z.object({
  email: emailAddress('Invalid email address'),
  name: trimmed,
});

export const RegisterVerificationEmailClickedBody = z.object({
  email: emailAddress('Invalid email address'),
  emailVerificationToken: trimmed,
});

export async function handleRegisterVerificationEmailClicked(
  c: BodyContext<typeof RegisterVerificationEmailClickedBody>,
): Promise<Response> {
  const { email, emailVerificationToken } = c.req.valid('json');
  const claims = await verifyRegisterVerifyToken(emailVerificationToken, c.env.JWT_SECRET);
  if (!claims || claims.email !== email) {
    return errorResponse(c, 'Email verification token is invalid or expired', 400);
  }
  // Official web acknowledges the link before sending client-generated keys to /finish.
  return c.body(null, 204);
}

export async function handleRegisterSendVerificationEmail(
  c: BodyContext<typeof RegisterSendVerificationEmailBody>,
): Promise<Response> {
  const body = c.req.valid('json');
  const { email } = body;
  const name = body.name || null;

  const userCount = await userRepo(c.env.DB).getUserCount();
  const { NODEWARDEN_DEPLOYMENT, TENANT_OWNER_EMAIL } = readEnvConfig(c.env);
  if (
    userCount === 0 &&
    (TENANT_OWNER_EMAIL !== undefined || NODEWARDEN_DEPLOYMENT === 'dispatch') &&
    TENANT_OWNER_EMAIL !== email
  ) {
    return errorResponse(c, 'Registration is reserved for the instance owner', 403);
  }
  if (userCount > 0 && !isOpenRegistrationEnabled(c.env)) {
    return errorResponse(c, 'Registration is invite-only', 403);
  }

  if (readMailConfig(c.env).kind !== 'enabled') return errorResponse(c, 'Email sending is not configured', 503);
  runInBackground('register-verification', async () => {
    if (isReservedDocumentationEmail(email) || (await userRepo(c.env.DB).getUser(email))) return;
    const token = await createRegisterVerifyToken(c.env.JWT_SECRET, email, name);
    await sendMail(c.env, email, 'registerVerification', {
      vaultOrigin: registerVerifyVaultOrigin(c.req.raw, c.env),
      email,
      token,
    });
  });

  // Official clients treat a non-empty string as an inline token (no SMTP).
  // An empty JSON string means "check your email".
  return c.json('');
}

export async function handleRegisterFinish(c: BodyContext<typeof RegisterSchema>): Promise<Response> {
  // Official self-host web still continues to the password form when
  // send-verification-email returns an empty body. The emailed link carries a
  // token when present. Hosted owner bootstrap requires that token in handleRegister.
  return handleRegister(c);
}

export const GetPasswordHintBody = z.object({
  email: z.string({ error: 'Email is required' }).trim().toLowerCase().min(1, { error: 'Email is required' }),
});

// POST /api/accounts/password-hint
export async function handleGetPasswordHint(c: BodyContext<typeof GetPasswordHintBody>): Promise<Response> {
  const clientIdentifier = getClientIdentifier(c.req.raw);
  if (!clientIdentifier) {
    return errorResponse(c, 'Client IP is required', 403);
  }

  const body = c.req.valid('json');
  const { email } = body;

  const rateLimit = new RateLimitService(c.env);
  const minuteBudget = await rateLimit.consumeStrictBudgetWithWindow(
    `${clientIdentifier}:password-hint`,
    LIMITS.rateLimit.passwordHintRequestsPerMinute,
    60,
  );
  if (!minuteBudget.allowed) {
    return new Response(
      JSON.stringify({
        error: 'Too many requests',
        error_description: `Rate limit exceeded. Try again in ${minuteBudget.retryAfterSeconds || 60} seconds.`,
      }),
      {
        status: 429,
        headers: {
          'Content-Type': 'application/json',
          'Retry-After': String(minuteBudget.retryAfterSeconds || 60),
          'X-RateLimit-Remaining': '0',
        },
      },
    );
  }

  const hourlyBudget = await rateLimit.consumeStrictBudgetWithWindow(
    `${clientIdentifier}:password-hint-hour`,
    LIMITS.rateLimit.passwordHintRequestsPerHour,
    60 * 60,
  );
  if (!hourlyBudget.allowed) {
    return new Response(
      JSON.stringify({
        error: 'Too many requests',
        error_description: `Rate limit exceeded. Try again in ${hourlyBudget.retryAfterSeconds || 3600} seconds.`,
      }),
      {
        status: 429,
        headers: {
          'Content-Type': 'application/json',
          'Retry-After': String(hourlyBudget.retryAfterSeconds || 3600),
          'X-RateLimit-Remaining': '0',
        },
      },
    );
  }

  const mail = readMailConfig(c.env);
  if (mail.kind === 'misconfigured') return errorResponse(c, 'Email sending is not configured', 503);
  if (mail.kind === 'enabled') {
    runInBackground('password-hint', async () => {
      const user = await userRepo(c.env.DB).getUser(email);
      if (!user || user.status !== 'active') return;
      const hint = user.masterPasswordHint?.trim();
      if (hint) await sendMail(c.env, user.email, 'passwordHint', { hint });
      else await sendMail(c.env, user.email, 'noPasswordHint');
    });
    return c.json({ object: 'passwordHint', hasHint: false, masterPasswordHint: null, sentByEmail: true });
  }
  const user = await userRepo(c.env.DB).getUser(email);
  const hint = user?.status === 'active' ? user.masterPasswordHint?.trim() || null : null;
  return c.json({
    object: 'passwordHint',
    hasHint: !!hint,
    masterPasswordHint: hint,
  });
}

// DELETE /api/accounts; POST /api/accounts/delete
export async function handleDeleteAccount(c: BodyContext<typeof VerifiedBody>): Promise<Response> {
  const { userId } = c.var;
  const user = await userRepo(c.env.DB).getUserById(userId);
  if (!user) return errorResponse(c, 'User not found', 404);
  const body = c.req.valid('json');
  if (!(await verifyUserSecret(user, body.masterPasswordHash)))
    return errorResponse(c, 'User verification failed.', 400);
  const result = await deleteUserAccount(
    c.env,
    userId,
    {
      actorUserId: userId,
      action: 'user.account.delete',
      category: 'security',
      level: 'security',
      targetType: 'user',
      targetId: userId,
      metadata: auditRequestMetadata(c.req.raw),
    },
    user.securityStamp,
  );
  if (result.kind === 'not-found') return errorResponse(c, 'User not found', 404);
  if (result.kind === 'blocked-by-orgs')
    return errorResponse(
      c,
      'You cannot delete this member because they are the sole owner of at least one organization vault. Delete these organization vaults or make another member an owner.',
      400,
    );
  if (result.kind === 'last-vault-admin')
    return errorResponse(c, 'You cannot delete the last instance administrator.', 400);
  notifyUserLogout(c.env, userId, null);
  return new Response(null, { status: 200 });
}

export const EmailTokenBody = VerifiedBody.extend({ newEmail: emailAddress('Invalid email address') });

export async function handleEmailToken(c: BodyContext<typeof EmailTokenBody>): Promise<Response> {
  const { userId } = c.var;
  const user = await userRepo(c.env.DB).getUserById(userId);
  if (!user) return errorResponse(c, 'User not found', 404);
  const body = c.req.valid('json');
  if (!(await verifyUserSecret(user, body.masterPasswordHash))) {
    return errorResponse(c, 'Invalid password.', 400, {}, { MasterPasswordHash: ['Invalid password.'] });
  }
  const email = body.newEmail;
  if (readMailConfig(c.env).kind !== 'enabled') return errorResponse(c, 'Email sending is not configured', 503);
  const target = { purpose: 'email-change' as const, subject: user.id, binding: `${user.securityStamp}:${email}` };
  let outcome: MailOutcome;
  if (await userRepo(c.env.DB).getUser(email)) {
    outcome = (await spendEmailOtpIssueBudget(c.env, target))
      ? await sendMail(c.env, user.email, 'emailChangeAlreadyExists')
      : { kind: 'throttled', retryAfterSeconds: 3600 - (Math.floor(Date.now() / 1000) % 3600) };
  } else {
    outcome = await issueEmailOtp(c.env, target, (code) =>
      sendMail(c.env, email, 'verificationCode', { code, reason: 'email-change' }),
    );
  }
  const check = mailStatusCheck(outcome);
  return check.ok ? new Response(null, { status: 200 }) : errorResponse(c, check.message, check.status, check.headers);
}

export const ChangeEmailBody = MasterPasswordFields.extend({
  masterPasswordHash: text,
  newEmail: emailAddress('Invalid email address'),
  token: text,
  ...kdfEcho,
});

export async function handleChangeEmail(c: BodyContext<typeof ChangeEmailBody>): Promise<Response> {
  const { userId } = c.var;
  const user = await userRepo(c.env.DB).getUserById(userId);
  if (!user) return errorResponse(c, 'User not found', 404);
  const body = c.req.valid('json');
  const kdfChange = kdfChangeRefused(c, user, 'email', body);
  if (kdfChange) return kdfChange;
  if (!(await verifyUserSecret(user, body.masterPasswordHash)))
    return errorResponse(c, 'Invalid password.', 400, {}, { MasterPasswordHash: ['Invalid password.'] });
  const email = body.newEmail;
  const update = masterPasswordUpdate(c, body, { ...user, email });
  if (update instanceof Response) return update;
  if (
    !(await redeemEmailOtp(
      c.env,
      { purpose: 'email-change', subject: user.id, binding: `${user.securityStamp}:${email}` },
      body.token,
    ))
  )
    return errorResponse(c, 'Invalid token.', 400);
  const passwordHash = await hashPassword(update.masterPasswordHash);
  const stamp = crypto.randomUUID();
  const now = new Date().toISOString();
  const orm = getOrm(c.env.DB);
  // Every dependent write runs only if the first statement installed this batch's fresh stamp.
  const guard = userRowMatches(orm, user.id, eq(users.securityStamp, stamp));
  let changed: D1Result;
  try {
    [changed] = await orm.batch([
      orm
        .update(users)
        .set({
          email,
          emailVerified: 1,
          masterPasswordHash: passwordHash,
          key: update.key,
          securityStamp: stamp,
          updatedAt: now,
        })
        .where(and(eq(users.id, user.id), eq(users.securityStamp, user.securityStamp), eq(users.status, 'active'))),
      credentialAccountStatement(c.env.DB, user.id, passwordHash, stamp),
      orm.delete(session).where(and(eq(session.userId, user.id), guard)),
      orm
        .insert(userRevisions)
        .select(
          orm
            .select({ userId: users.id, revisionDate: bound(now).as('revision_date') })
            .from(users)
            .where(and(eq(users.id, user.id), eq(users.securityStamp, stamp))),
        )
        .onConflictDoUpdate({
          target: userRevisions.userId,
          set: { revisionDate: excluded(userRevisions.revisionDate) },
        }),
      auditEventStatement(
        c.env.DB,
        {
          actorUserId: user.id,
          action: 'user.email.change',
          category: 'security',
          level: 'security',
          targetType: 'user',
          targetId: user.id,
          metadata: auditRequestMetadata(c.req.raw),
        },
        guard,
      ),
    ]);
  } catch (error) {
    if (error instanceof Error && /UNIQUE constraint failed: users\.email/i.test(error.message))
      return errorResponse(c, 'Email already in use.', 400);
    throw error;
  }
  if (!changed.meta.changes) return errorResponse(c, 'User verification failed.', 400);
  AuthService.invalidateUserCache(user.id);
  notifyUserLogout(c.env, user.id, null);
  notifyMail(c.env, user.email, 'emailChanged', { utc: now, ip: getClientIdentifier(c.req.raw) ?? 'Unknown' });
  await syncVaultAdminRoles(c.env);
  return new Response(null, { status: 200 });
}

export const DeleteRecoverBody = z.object({ email: emailAddress('Invalid email address') });

export async function handleDeleteRecover(c: BodyContext<typeof DeleteRecoverBody>): Promise<Response> {
  const body = c.req.valid('json');
  const { email } = body;
  const clientId = getClientIdentifier(c.req.raw);
  if (!clientId) return errorResponse(c, 'Client IP is required', 403);
  const budget = await new RateLimitService(c.env).consumeStrictBudgetWithWindow(
    `delete-recover:${clientId}`,
    LIMITS.rateLimit.deleteRecoverPerIpPerHour,
    3600,
  );
  if (!budget.allowed)
    return errorResponse(c, 'Too many requests', 429, { 'Retry-After': String(budget.retryAfterSeconds ?? 3600) });
  const origin = configuredVaultOrigin(c.req.raw, c.env);
  if (readMailConfig(c.env).kind !== 'enabled' || !origin)
    return errorResponse(c, 'Email sending is not configured', 503);
  runInBackground('delete-recover', async () => {
    const user = await userRepo(c.env.DB).getUser(email);
    if (!user || user.status !== 'active') return;
    const token = await createDeleteRecoverToken(c.env, user);
    const params = new URLSearchParams({ userId: user.id, token, email: user.email });
    await sendMail(c.env, user.email, 'verifyDelete', {
      url: toSafeUrl(new URL(`${origin}/#/verify-recover-delete?${params}`)),
    });
  });
  return c.json('');
}

export const DeleteRecoverTokenBody = z.object({ userId: text, token: text });
// One answer for every refusal, a body its schema refuses included, so it tells nothing about the account.
export const invalidRecoverToken = (c: AppContext) => errorResponse(c, 'Invalid token.', 400);

export async function handleDeleteRecoverToken(c: BodyContext<typeof DeleteRecoverTokenBody>): Promise<Response> {
  const body = c.req.valid('json');
  const user = body.userId ? await userRepo(c.env.DB).getUserById(body.userId) : null;
  if (!user || user.status !== 'active' || !(await verifyDeleteRecoverToken(c.env, user, body.token)))
    return invalidRecoverToken(c);
  const result = await deleteUserAccount(
    c.env,
    user.id,
    {
      actorUserId: null,
      action: 'user.account.delete_recover',
      category: 'security',
      level: 'security',
      targetType: 'user',
      targetId: user.id,
      metadata: auditRequestMetadata(c.req.raw),
    },
    user.securityStamp,
  );
  if (result.kind === 'not-found') return invalidRecoverToken(c);
  if (result.kind === 'blocked-by-orgs')
    return errorResponse(
      c,
      'You cannot delete this member because they are the sole owner of at least one organization vault. Delete these organization vaults or make another member an owner.',
      400,
    );
  if (result.kind === 'last-vault-admin')
    return errorResponse(c, 'You cannot delete the last instance administrator.', 400);
  notifyUserLogout(c.env, user.id, null);
  return new Response(null, { status: 200 });
}

// GET /api/accounts/profile
export async function handleGetProfile(c: AppContext): Promise<Response> {
  const { userId } = c.var;
  const user = await userRepo(c.env.DB).getUserById(userId);
  if (!user) return errorResponse(c, 'User not found', 404);
  return c.json(await buildProfileResponse(user, c.env));
}

export const UpdateProfileBody = z.object({ masterPasswordHint: MasterPasswordHint });

// PUT /api/accounts/profile
export async function handleUpdateProfile(c: BodyContext<typeof UpdateProfileBody>): Promise<Response> {
  const { userId } = c.var;
  const user = await userRepo(c.env.DB).getUserById(userId);
  if (!user) return errorResponse(c, 'User not found', 404);

  const body = c.req.valid('json');

  user.masterPasswordHint = body.masterPasswordHint;
  user.updatedAt = new Date().toISOString();
  if (!(await userRepo(c.env.DB).saveUser(user, ['masterPasswordHint'])))
    return errorResponse(c, 'User verification failed.', 400);
  await writeAuditEvent(c.env.DB, {
    actorUserId: user.id,
    action: 'account.profile.update',
    category: 'security',
    level: 'info',
    targetType: 'user',
    targetId: user.id,
    metadata: {
      updatedMasterPasswordHint: true,
      ...auditRequestMetadata(c.req.raw),
    },
  });

  return c.json(await buildProfileResponse(user, c.env));
}

export const SetVerifyDevicesBody = VerifiedBody.extend({
  verifyDevices: z.boolean({ error: 'verifyDevices must be true or false' }),
});

// PUT/POST /api/accounts/verify-devices
// Preferences are editable while opt-in new-device verification is active.
export async function handleSetVerifyDevices(c: BodyContext<typeof SetVerifyDevicesBody>): Promise<Response> {
  const { userId } = c.var;
  const user = await userRepo(c.env.DB).getUserById(userId);
  if (!user) return errorResponse(c, 'User not found', 404);
  const mail = readMailConfig(c.env);
  if (mail.kind !== 'enabled' || !mail.newDeviceVerification)
    return errorResponse(
      c,
      'New device verification is not available on this server. Enable TOTP or WebAuthn two-factor authentication instead.',
      400,
    );
  const body = c.req.valid('json');
  if (!(await verifyUserSecret(user, body.masterPasswordHash)))
    return errorResponse(c, 'User verification failed.', 400);
  const { verifyDevices } = body;
  user.verifyDevices = verifyDevices;
  if (!(await userRepo(c.env.DB).saveUser(user, ['verifyDevices'])))
    return errorResponse(c, 'User verification failed.', 400);
  await revisionRepo(c.env.DB).updateRevisionDate(user.id);
  AuthService.invalidateUserCache(user.id);
  await writeAuditEvent(c.env.DB, {
    actorUserId: user.id,
    action: 'account.verify_devices.update',
    category: 'security',
    level: 'security',
    targetType: 'user',
    targetId: user.id,
    metadata: { verifyDevices, ...auditRequestMetadata(c.req.raw) },
  });
  return new Response(null, { status: 200 });
}

export const ResendNewDeviceOtpBody = VerifiedBody.extend({
  email: z.string().trim().toLowerCase().catch(''),
  deviceType: text,
});

export async function handleResendNewDeviceOtp(c: BodyContext<typeof ResendNewDeviceOtpBody>): Promise<Response> {
  const mail = readMailConfig(c.env);
  if (mail.kind === 'disabled') return unsupportedResponse(c, 'Email delivery is not supported by this server.');
  if (mail.kind === 'misconfigured') return errorResponse(c, 'Email sending is not configured', 503);
  const body = c.req.valid('json');
  if (mail.newDeviceVerification)
    runInBackground('new-device-resend', async () => {
      const user = body.email ? await userRepo(c.env.DB).getUser(body.email) : null;
      if (
        !user ||
        user.status !== 'active' ||
        !user.verifyDevices ||
        !(Date.now() - Date.parse(user.createdAt) >= LIMITS.auth.newDeviceVerificationMinAccountAgeSeconds * 1000)
      )
        return;
      if (!(await verifyUserSecret(user, body.masterPasswordHash))) return;
      const hasPasskey = (await passkeyRepo(c.env.DB).countAccountPasskeyCredentialsByUserId(user.id, 'twoFactor')) > 0;
      if (twoFactorProviders(user, hasPasskey).length) return;
      const [knownDevice] = await getOrm(c.env.DB)
        .select({ userId: devices.userId })
        .from(devices)
        .where(eq(devices.userId, user.id))
        .limit(1);
      if (!knownDevice) return;
      const device = readAuthRequestDeviceInfo({ deviceType: body.deviceType }, c.req.raw);
      notifyNewDeviceVerification(c.env, c.req.raw, user, device.deviceType);
    });
  return c.json('');
}

// GET /api/accounts/keys
export async function handleGetKeys(c: AppContext): Promise<Response> {
  const { userId } = c.var;
  const user = await userRepo(c.env.DB).getUserById(userId);

  if (!user) {
    return errorResponse(c, 'User not found', 404);
  }

  return c.json(keysResponse(user));
}

// GET /api/users/{id}/public-key: upstream UsersController.GetPublicKeyAsync. Official clients
// wrap keys for another account (emergency access and org member confirm) with it, so any
// logged-in caller may read it.
export async function handleGetUserPublicKey(c: AppContext, id: string): Promise<Response> {
  const user = await userRepo(c.env.DB).getUserById(id);
  if (!user?.publicKey) return errorResponse(c, 'Resource not found.', 404);
  return c.json({ userId: user.id, publicKey: user.publicKey, object: 'userKey' });
}

export const SetKeysBody = z.object({
  masterPasswordHash: text,
  key: text,
  encryptedPrivateKey: text,
  publicKey: text,
});

// POST /api/accounts/keys
export async function handleSetKeys(c: BodyContext<typeof SetKeysBody>): Promise<Response> {
  const { userId } = c.var;
  const user = await userRepo(c.env.DB).getUserById(userId);

  if (!user) {
    return errorResponse(c, 'User not found', 404);
  }

  const body = c.req.valid('json');

  // Require password verification before allowing key replacement.
  if (!body.masterPasswordHash) {
    return errorResponse(c, 'masterPasswordHash is required', 400);
  }
  const passwordValid = await verifyPassword(body.masterPasswordHash, user.masterPasswordHash, user.email);
  if (!passwordValid) {
    return errorResponse(c, 'Invalid password', 400);
  }

  if (body.key && !looksLikeEncString(body.key)) {
    return errorResponse(c, 'key is not a valid encrypted string', 400);
  }
  if (body.encryptedPrivateKey && !looksLikeEncString(body.encryptedPrivateKey)) {
    return errorResponse(c, 'encryptedPrivateKey is not a valid encrypted string', 400);
  }

  if (body.key) user.key = body.key;
  if (body.encryptedPrivateKey) user.privateKey = body.encryptedPrivateKey;
  if (body.publicKey) user.publicKey = body.publicKey;
  user.updatedAt = new Date().toISOString();

  if (
    !(await userRepo(c.env.DB).saveUser(user, [
      ...(body.key ? ['key' as const] : []),
      ...(body.encryptedPrivateKey ? ['privateKey' as const] : []),
      ...(body.publicKey ? ['publicKey' as const] : []),
    ]))
  )
    return errorResponse(c, 'User verification failed.', 400);
  await writeAuditEvent(c.env.DB, {
    actorUserId: user.id,
    action: 'account.keys.update',
    category: 'security',
    level: 'security',
    targetType: 'user',
    targetId: user.id,
    metadata: {
      updatedKey: !!body.key,
      updatedPrivateKey: !!body.encryptedPrivateKey,
      updatedPublicKey: !!body.publicKey,
      ...auditRequestMetadata(c.req.raw),
    },
  });

  return c.json(keysResponse(user));
}

// POST/PUT /api/accounts/password
export const ChangePasswordBody = MasterPasswordFields.extend({
  masterPasswordHash: text,
  currentPasswordHash: text,
  masterPasswordHint: MasterPasswordHint.optional(),
  encryptedPrivateKey: text,
  newEncryptedPrivateKey: text,
  publicKey: text,
  newPublicKey: text,
  ...kdfEcho,
});

export async function handleChangePassword(c: BodyContext<typeof ChangePasswordBody>): Promise<Response> {
  const { userId } = c.var;
  const user = await userRepo(c.env.DB).getUserById(userId);
  if (!user) return errorResponse(c, 'User not found', 404);

  const body = c.req.valid('json');
  const kdfChange = kdfChangeRefused(c, user, 'password', body);
  if (kdfChange) return kdfChange;

  const currentHash = body.currentPasswordHash || body.masterPasswordHash;
  if (!currentHash) return errorResponse(c, 'Current password hash is required', 400);
  const valid = await verifyPassword(currentHash, user.masterPasswordHash, user.email);
  if (!valid) return errorResponse(c, 'Invalid password', 400);

  const update = masterPasswordUpdate(c, body, user);
  if (update instanceof Response) return update;

  const nextPrivateKey = body.newEncryptedPrivateKey || body.encryptedPrivateKey;
  const nextPublicKey = body.newPublicKey || body.publicKey;
  if (nextPrivateKey && !looksLikeEncString(nextPrivateKey)) {
    return errorResponse(c, 'new encryptedPrivateKey is not a valid encrypted string', 400);
  }
  const shouldUpdateHint = 'masterPasswordHint' in body;

  user.masterPasswordHash = await hashPassword(update.masterPasswordHash);
  user.key = update.key;
  if (nextPrivateKey) user.privateKey = nextPrivateKey;
  if (nextPublicKey) user.publicKey = nextPublicKey;
  if (shouldUpdateHint) {
    user.masterPasswordHint = body.masterPasswordHint ?? null;
  }
  const originalSecurityStamp = user.securityStamp;
  user.securityStamp = crypto.randomUUID();
  user.updatedAt = new Date().toISOString();
  if (
    !(await userRepo(c.env.DB).saveUser(
      user,
      [
        'masterPasswordHash',
        'key',
        'securityStamp',
        ...(nextPrivateKey ? ['privateKey' as const] : []),
        ...(nextPublicKey ? ['publicKey' as const] : []),
        ...(shouldUpdateHint ? ['masterPasswordHint' as const] : []),
      ],
      originalSecurityStamp,
    ))
  )
    return errorResponse(c, 'User verification failed.', 400);
  AuthService.invalidateUserCache(user.id);
  if (!(await upsertCredentialAccount(c.env.DB, user.id, user.masterPasswordHash, user.securityStamp)))
    return errorResponse(c, 'User verification failed.', 400);
  await sessionRepo(c.env.DB).deleteRefreshTokensByUserId(user.id);
  await recordUserEvent(c.env, c.req.raw, user.id, EventType.UserChangedPassword);
  await writeAuditEvent(c.env.DB, {
    actorUserId: user.id,
    action: 'user.password.change',
    targetType: 'user',
    targetId: user.id,
    category: 'security',
    level: 'security',
    metadata: { email: user.email, ...auditRequestMetadata(c.req.raw) },
  });

  return new Response(null, { status: 200 });
}

function twoFactorProviderResponse(type: number, enabled: boolean): Record<string, unknown> {
  return {
    Enabled: enabled,
    Type: type,
    Object: 'twoFactorProvider',
  };
}

function twoFactorAuthenticatorResponse(
  enabled: boolean,
  key: string,
  userVerificationToken?: string,
): Record<string, unknown> {
  return {
    Enabled: enabled,
    Key: key,
    UserVerificationToken: userVerificationToken ?? null,
    Authenticator: { Enabled: enabled, Key: key },
    Object: userVerificationToken ? 'twoFactorAuthenticator' : 'twoFactorAuthenticatorUpdate',
  };
}

async function yubiKeySettingsResponse(db: D1Database, user: User): Promise<Record<string, unknown>> {
  const credentials = await getYubicoCredentials(db);
  const canManageCredentials = user.role === 'admin' && user.status === 'active';
  const provider = {
    Enabled: isYubiKeyEnabled(user),
    Key1: user.yubikeyKey1,
    Key2: user.yubikeyKey2,
    Key3: user.yubikeyKey3,
    Key4: user.yubikeyKey4,
    Key5: user.yubikeyKey5,
    Nfc: !!user.yubikeyNfc,
  };
  return {
    ...provider,
    YubiKey: provider,
    Object: 'twoFactorYubiKey',
    YubicoConfigured: !!credentials?.clientId,
    YubicoCanManage: canManageCredentials,
    ...(canManageCredentials
      ? {
          YubicoClientId: credentials?.clientId ?? '',
          YubicoSecretKey: credentials?.secretKey ?? '',
        }
      : {}),
  };
}

// GET /api/two-factor
export async function handleGetTwoFactorProviders(c: AppContext): Promise<Response> {
  const { userId } = c.var;
  const user = await userRepo(c.env.DB).getUserById(userId);
  if (!user) return errorResponse(c, 'User not found', 404);

  const hasTwoFactorPasskey =
    (await passkeyRepo(c.env.DB).countAccountPasskeyCredentialsByUserId(user.id, 'twoFactor')) > 0;
  const data = twoFactorProviders(user, hasTwoFactorPasskey).map((type) => twoFactorProviderResponse(type, true));

  return c.json({
    Data: data,
    ContinuationToken: null,
    Object: 'list',
  });
}

// POST /api/two-factor/get-authenticator
export async function handleGetTwoFactorAuthenticator(c: BodyContext<typeof VerifiedBody>): Promise<Response> {
  const { userId } = c.var;
  const user = await userRepo(c.env.DB).getUserById(userId);
  if (!user) return errorResponse(c, 'User not found', 404);

  const body = c.req.valid('json');

  const verified = await verifyUserSecret(user, verificationSecret(body));
  if (!verified) return errorResponse(c, 'User verification failed.', 400);

  const key = normalizeTotpSecret(user.totpSecret || '') || new Secret().base32;
  const userVerificationToken = await createTwoFactorUserVerificationToken(
    c.env,
    user,
    TWO_FACTOR_PROVIDER_AUTHENTICATOR,
    key,
  );
  return c.json(twoFactorAuthenticatorResponse(!!user.totpSecret, key, userVerificationToken));
}

// POST /api/two-factor/get-yubikey
export async function handleGetTwoFactorYubiKey(c: BodyContext<typeof VerifiedBody>): Promise<Response> {
  const { userId } = c.var;
  const user = await userRepo(c.env.DB).getUserById(userId);
  if (!user) return errorResponse(c, 'User not found', 404);

  const body = c.req.valid('json');

  const verified = await verifyUserSecret(user, verificationSecret(body));
  if (!verified) return errorResponse(c, 'User verification failed.', 400);

  return c.json({
    ...(await yubiKeySettingsResponse(c.env.DB, user)),
    UserVerificationToken: await createTwoFactorUserVerificationToken(c.env, user, TWO_FACTOR_PROVIDER_YUBIKEY),
  });
}

// Upstream binds this model case-insensitively, so keys are compared lower-cased.
const optionalText = z
  .string()
  .nullish()
  .transform((value) => value?.trim() ?? '');
// One answer for every refusal before mail availability, a body its schema refuses included, so it tells nothing
// about the credentials.
export const twoFactorEmailRejected = (c: AppContext) => errorResponse(c, 'Cannot send two-factor email.', 400);
export const TwoFactorEmailLoginBody = z.preprocess(
  (body) => Object.fromEntries(Object.entries(body ?? {}).map(([name, value]) => [name.toLowerCase(), value])),
  z.object({
    email: optionalText,
    authrequestid: optionalText,
    authrequestaccesscode: optionalText,
    ssoemail2fasessiontoken: optionalText,
    masterpasswordhash: optionalText,
    devicetype: text,
  }),
);

export async function handleSendTwoFactorEmailLogin(c: BodyContext<typeof TwoFactorEmailLoginBody>): Promise<Response> {
  const body = c.req.valid('json');
  const email = body.email.toLowerCase();
  const user = email ? await userRepo(c.env.DB).getUser(email) : null;
  if (!user || user.status !== 'active' || !user.twoFactorEmail) return twoFactorEmailRejected(c);
  const accessCode = body.authrequestaccesscode;
  const sessionToken = body.ssoemail2fasessiontoken;
  let verified: boolean;
  if (accessCode) {
    const authRequest = await authRequestRepo(c.env.DB).getAuthRequestByIdForUser(body.authrequestid, user.id);
    verified = isAuthRequestLoginApproved(authRequest, user.id, accessCode);
  } else if (sessionToken) {
    verified = await verifySsoEmail2faSessionToken(c.env, user, sessionToken);
  } else {
    verified = await verifyUserSecret(user, body.masterpasswordhash);
  }
  if (!verified) return twoFactorEmailRejected(c);
  if (readMailConfig(c.env).kind !== 'enabled') return errorResponse(c, 'Email sending is not configured', 503);
  const device = readAuthRequestDeviceInfo({ deviceType: body.devicetype }, c.req.raw);
  const outcome = await issueEmailOtp(
    c.env,
    { purpose: 'two-factor-login', subject: user.id, binding: user.securityStamp },
    (code) =>
      sendMail(c.env, user.twoFactorEmail!, 'signInCode', {
        code,
        reason: 'two-factor',
        ip: getClientIdentifier(c.req.raw) ?? 'Unknown',
        deviceTypeName: deviceTypeName(device.deviceType),
        utc: new Date().toISOString(),
      }),
  );
  const check = mailStatusCheck(outcome);
  return check.ok ? new Response(null, { status: 200 }) : errorResponse(c, check.message, check.status, check.headers);
}

function twoFactorEmailResponse(email: string | null, userVerificationToken?: string): Record<string, unknown> {
  return {
    Email: { Enabled: !!email, Email: email },
    ...(userVerificationToken ? { UserVerificationToken: userVerificationToken } : {}),
    Object: userVerificationToken ? 'twoFactorEmail' : 'twoFactorEmailUpdate',
  };
}

export const EmailTwoFactorBody = VerifiedBody.extend({
  userVerificationToken: text,
  email: emailAddress('Invalid email address'),
  token: text,
});

async function verifyEmailTwoFactorUser(
  env: Env,
  user: User,
  body: z.output<typeof EmailTwoFactorBody>,
): Promise<boolean> {
  return (
    (await verifyTwoFactorUserVerificationToken(env, user, TWO_FACTOR_PROVIDER_EMAIL, body.userVerificationToken)) ||
    (await verifyUserSecret(user, body.masterPasswordHash || body.secret))
  );
}

export async function handleGetTwoFactorEmail(c: BodyContext<typeof VerifiedBody>): Promise<Response> {
  const { userId } = c.var;
  const user = await userRepo(c.env.DB).getUserById(userId);
  if (!user) return errorResponse(c, 'User not found', 404);
  const body = c.req.valid('json');
  if (!(await verifyUserSecret(user, body.masterPasswordHash || body.secret)))
    return errorResponse(c, 'User verification failed.', 400);
  return c.json(
    twoFactorEmailResponse(
      user.twoFactorEmail,
      await createTwoFactorUserVerificationToken(c.env, user, TWO_FACTOR_PROVIDER_EMAIL),
    ),
  );
}

export async function handleSendTwoFactorEmail(c: BodyContext<typeof EmailTwoFactorBody>): Promise<Response> {
  const { userId } = c.var;
  const user = await userRepo(c.env.DB).getUserById(userId);
  if (!user) return errorResponse(c, 'User not found', 404);
  const body = c.req.valid('json');
  if (!(await verifyEmailTwoFactorUser(c.env, user, body))) return errorResponse(c, 'User verification failed.', 400);
  const { email } = body;
  if (readMailConfig(c.env).kind !== 'enabled') return errorResponse(c, 'Email sending is not configured', 503);
  const outcome = await issueEmailOtp(
    c.env,
    { purpose: 'two-factor-setup', subject: user.id, binding: `${user.securityStamp}:${email}` },
    (code) => sendMail(c.env, email, 'verificationCode', { code, reason: 'two-factor-setup' }),
  );
  const check = mailStatusCheck(outcome);
  if (!check.ok) return errorResponse(c, check.message, check.status, check.headers);
  return new Response(null, { status: 200 });
}

export async function handlePutTwoFactorEmail(c: BodyContext<typeof EmailTwoFactorBody>): Promise<Response> {
  const { userId } = c.var;
  const user = await userRepo(c.env.DB).getUserById(userId);
  if (!user) return errorResponse(c, 'User not found', 404);
  const body = c.req.valid('json');
  if (!(await verifyEmailTwoFactorUser(c.env, user, body))) return errorResponse(c, 'User verification failed.', 400);
  const { email } = body;
  if (
    !(await redeemEmailOtp(
      c.env,
      { purpose: 'two-factor-setup', subject: user.id, binding: `${user.securityStamp}:${email}` },
      body.token,
    ))
  ) {
    return errorResponse(c, 'Invalid token.', 400, {}, { Token: ['Invalid token.'] });
  }
  const [changed] = await getOrm(c.env.DB)
    .update(users)
    .set({ twoFactorEmail: email, totpRecoveryCode: existingOrNewRecoveryCode(), updatedAt: new Date().toISOString() })
    .where(and(eq(users.id, user.id), eq(users.securityStamp, user.securityStamp)))
    .returning({ id: users.id });
  if (!changed) return errorResponse(c, 'User verification failed.', 400);
  await revisionRepo(c.env.DB).updateRevisionDate(user.id);
  AuthService.invalidateUserCache(user.id);
  if (user.twoFactorEmail !== email) await recordUserEvent(c.env, c.req.raw, user.id, EventType.UserUpdated2fa);
  await writeAuditEvent(c.env.DB, {
    actorUserId: user.id,
    action: 'account.two_factor.email.enable',
    category: 'security',
    level: 'security',
    targetType: 'user',
    targetId: user.id,
    metadata: auditRequestMetadata(c.req.raw),
  });
  return c.json(twoFactorEmailResponse(email));
}

// POST /api/two-factor/get-device-verification-settings
export async function handleGetDeviceVerificationSettings(c: AppContext): Promise<Response> {
  const { userId } = c.var;
  const user = await userRepo(c.env.DB).getUserById(userId);
  if (!user) return errorResponse(c, 'User not found', 404);
  // This obsolete two-factor surface stays disabled; /accounts/verify-devices owns the preference.
  return c.json({
    isDeviceVerificationSectionEnabled: false,
    unknownDeviceVerificationEnabled: false,
    object: 'deviceVerificationSettings',
  });
}

// PUT/POST /api/two-factor/authenticator
// Every factor change revokes refresh tokens and cached auth state, then records the event and audit row.
async function finalizeTwoFactorChange(
  request: Request,
  env: Env,
  user: User,
  action: string,
  eventType: number | null,
): Promise<void> {
  await sessionRepo(env.DB).deleteRefreshTokensByUserId(user.id);
  AuthService.invalidateUserCache(user.id);
  if (eventType) await recordUserEvent(env, request, user.id, eventType);
  await writeAuditEvent(env.DB, {
    actorUserId: user.id,
    action,
    category: 'security',
    level: 'security',
    targetType: 'user',
    targetId: user.id,
    metadata: auditRequestMetadata(request),
  });
}

export const PutTwoFactorAuthenticatorBody = z.object({ key: text, token: trimmed, userVerificationToken: text });

export async function handlePutTwoFactorAuthenticator(
  c: BodyContext<typeof PutTwoFactorAuthenticatorBody>,
): Promise<Response> {
  const { userId } = c.var;
  const user = await userRepo(c.env.DB).getUserById(userId);
  if (!user) return errorResponse(c, 'User not found', 404);

  const body = c.req.valid('json');

  const key = normalizeTotpSecret(body.key);
  const { token, userVerificationToken } = body;
  if (!key || !token || !userVerificationToken) {
    return errorResponse(c, 'Key, token and userVerificationToken are required', 400);
  }
  if (
    !(await verifyTwoFactorUserVerificationToken(
      c.env,
      user,
      TWO_FACTOR_PROVIDER_AUTHENTICATOR,
      userVerificationToken,
      key,
    ))
  ) {
    return errorResponse(c, 'User verification failed.', 400);
  }
  if (!isTotpEnabled(key)) return errorResponse(c, 'Invalid TOTP secret', 400);
  const matchedCounter = await findMatchingTotpCounter(key, token);
  if (matchedCounter == null || !(await totpReplayRepo(c.env.DB).consumeTotpLoginCounter(user.id, matchedCounter))) {
    return errorResponse(c, 'Invalid token.', 400);
  }

  const factorChanged = user.totpSecret !== key;
  user.totpSecret = key;
  user.totpRecoveryCode = await ensureTwoFactorRecoveryCode(c.env.DB, user.id, user.securityStamp);
  if (!user.totpRecoveryCode) return errorResponse(c, 'User verification failed.', 400);
  user.updatedAt = new Date().toISOString();
  if (!(await userRepo(c.env.DB).saveUser(user, ['totpSecret'])))
    return errorResponse(c, 'User verification failed.', 400);
  await finalizeTwoFactorChange(
    c.req.raw,
    c.env,
    user,
    'account.totp.enable',
    factorChanged ? EventType.UserUpdated2fa : null,
  );

  return c.json(twoFactorAuthenticatorResponse(true, key));
}

export const PutTwoFactorYubiKeyBody = VerifiedBody.extend({
  userVerificationToken: text,
  key1: text,
  key2: text,
  key3: text,
  key4: text,
  key5: text,
  nfc: z.unknown().optional(),
});

// PUT/POST /api/two-factor/yubikey
export async function handlePutTwoFactorYubiKey(c: BodyContext<typeof PutTwoFactorYubiKeyBody>): Promise<Response> {
  const { userId } = c.var;
  const user = await userRepo(c.env.DB).getUserById(userId);
  if (!user) return errorResponse(c, 'User not found', 404);

  const body = c.req.valid('json');

  const verified =
    (await verifyTwoFactorUserVerificationToken(
      c.env,
      user,
      TWO_FACTOR_PROVIDER_YUBIKEY,
      body.userVerificationToken,
    )) || (await verifyUserSecret(user, verificationSecret(body)));
  if (!verified) return errorResponse(c, 'User verification failed.', 400);

  const keys = [body.key1, body.key2, body.key3, body.key4, body.key5];
  const publicIds: Array<string | null> = [];
  let credentials = await getYubicoCredentials(c.env.DB);
  let apiKeyBootstrapOtpIndex: number | null = null;
  for (const key of keys) {
    const trimmed = key.trim();
    if (!trimmed) {
      publicIds.push(null);
      continue;
    }
    const publicId = yubiKeyPublicIdFromOtp(trimmed);
    if (!publicId) return errorResponse(c, 'Invalid YubiKey OTP.', 400);
    if (isYubiKeyPublicId(trimmed)) {
      publicIds.push(publicId);
      continue;
    }
    if (!credentials) {
      const initialized = await initializeYubicoCredentialsOnce(c.env.DB, user.email, trimmed);
      if (!initialized) return errorResponse(c, 'Unable to initialize Yubico validation credentials.', 400);
      credentials = initialized.credentials;
      if (initialized.created) apiKeyBootstrapOtpIndex = publicIds.length;
    }
    if (apiKeyBootstrapOtpIndex !== publicIds.length && !(await verifyYubicoOtp(c.env, trimmed, credentials))) {
      return errorResponse(c, 'Invalid YubiKey OTP.', 400);
    }
    publicIds.push(publicId);
  }
  if (!publicIds.some(Boolean)) return errorResponse(c, 'At least one YubiKey OTP is required.', 400);

  const factorChanged =
    [user.yubikeyKey1, user.yubikeyKey2, user.yubikeyKey3, user.yubikeyKey4, user.yubikeyKey5].some(
      (key, index) => key !== (publicIds[index] ?? null),
    ) || user.yubikeyNfc !== !!body.nfc;
  user.yubikeyKey1 = publicIds[0] ?? null;
  user.yubikeyKey2 = publicIds[1] ?? null;
  user.yubikeyKey3 = publicIds[2] ?? null;
  user.yubikeyKey4 = publicIds[3] ?? null;
  user.yubikeyKey5 = publicIds[4] ?? null;
  user.yubikeyNfc = !!body.nfc;
  user.totpRecoveryCode = await ensureTwoFactorRecoveryCode(c.env.DB, user.id, user.securityStamp);
  if (!user.totpRecoveryCode) return errorResponse(c, 'User verification failed.', 400);
  user.updatedAt = new Date().toISOString();
  if (
    !(await userRepo(c.env.DB).saveUser(user, [
      'yubikeyKey1',
      'yubikeyKey2',
      'yubikeyKey3',
      'yubikeyKey4',
      'yubikeyKey5',
      'yubikeyNfc',
    ]))
  )
    return errorResponse(c, 'User verification failed.', 400);
  await finalizeTwoFactorChange(
    c.req.raw,
    c.env,
    user,
    'account.yubikey.enable',
    factorChanged ? EventType.UserUpdated2fa : null,
  );

  return c.json({ ...(await yubiKeySettingsResponse(c.env.DB, user)), Object: 'twoFactorYubiKeyUpdate' });
}

export const PutTwoFactorYubiKeyConfigBody = VerifiedBody.extend({
  yubicoClientId: trimmed,
  clientId: trimmed,
  yubicoSecretKey: trimmed,
  secretKey: trimmed,
});

// PUT/POST /api/two-factor/yubikey/config
export async function handlePutTwoFactorYubiKeyConfig(
  c: BodyContext<typeof PutTwoFactorYubiKeyConfigBody>,
): Promise<Response> {
  const { userId } = c.var;
  const user = await userRepo(c.env.DB).getUserById(userId);
  if (!user) return errorResponse(c, 'User not found', 404);
  if (user.role !== 'admin' || user.status !== 'active') return errorResponse(c, 'Forbidden', 403);

  const body = c.req.valid('json');

  const verified = await verifyUserSecret(user, verificationSecret(body));
  if (!verified) return errorResponse(c, 'User verification failed.', 400);

  const clientId = body.yubicoClientId || body.clientId;
  const secretKey = body.yubicoSecretKey || body.secretKey;
  if (!clientId || !secretKey) return errorResponse(c, 'Yubico Client ID and Secret Key are required.', 400);

  await replaceYubicoCredentials(c.env.DB, { clientId, secretKey });
  await writeAuditEvent(c.env.DB, {
    actorUserId: user.id,
    action: 'system.yubico.credentials.update',
    category: 'security',
    level: 'security',
    targetType: 'system',
    targetId: 'yubico',
    metadata: auditRequestMetadata(c.req.raw),
  });

  return c.json(await yubiKeySettingsResponse(c.env.DB, user));
}

export const BootstrapTwoFactorYubiKeyConfigBody = VerifiedBody.extend({ token: text });

// POST /api/two-factor/yubikey/bootstrap
export async function handleBootstrapTwoFactorYubiKeyConfig(
  c: BodyContext<typeof BootstrapTwoFactorYubiKeyConfigBody>,
): Promise<Response> {
  const { userId } = c.var;
  const user = await userRepo(c.env.DB).getUserById(userId);
  if (!user) return errorResponse(c, 'User not found', 404);

  const body = c.req.valid('json');

  const verified = await verifyUserSecret(user, body.masterPasswordHash || body.secret);
  if (!verified) return errorResponse(c, 'User verification failed.', 400);

  const otp = (body.otp || body.OTP || body.token).trim();
  if (!yubiKeyPublicIdFromOtp(otp)) return errorResponse(c, 'Invalid YubiKey OTP.', 400);
  const existing = await getYubicoCredentials(c.env.DB);
  if (user.role !== 'admin' && existing) {
    return errorResponse(c, 'Yubico validation credentials are already configured.', 403);
  }

  let credentials;
  if (user.role === 'admin') {
    credentials = await requestYubicoApiCredentials(user.email, otp);
    if (!credentials?.clientId || !credentials.secretKey) {
      return errorResponse(c, 'Unable to initialize Yubico validation credentials.', 400);
    }
    await replaceYubicoCredentials(c.env.DB, credentials);
  } else {
    const initialized = await initializeYubicoCredentialsOnce(c.env.DB, user.email, otp);
    if (!initialized?.created) {
      return errorResponse(
        c,
        initialized?.credentials
          ? 'Yubico validation credentials are already configured.'
          : 'Unable to initialize Yubico validation credentials.',
        initialized?.credentials ? 403 : 400,
      );
    }
    credentials = initialized.credentials;
  }

  await writeAuditEvent(c.env.DB, {
    actorUserId: user.id,
    action: user.role === 'admin' ? 'system.yubico.credentials.reconfigure' : 'system.yubico.credentials.initialize',
    category: 'security',
    level: 'security',
    targetType: 'system',
    targetId: 'yubico',
    metadata: auditRequestMetadata(c.req.raw),
  });

  return c.json(await yubiKeySettingsResponse(c.env.DB, user));
}

export const DisableTwoFactorProviderBody = VerifiedBody.extend({
  type: z.unknown().optional(),
  userVerificationToken: text,
  key: text,
});

// DELETE /api/two-factor/authenticator and PUT/POST /api/two-factor/disable
export async function handleDisableTwoFactorProvider(
  c: BodyContext<typeof DisableTwoFactorProviderBody>,
  routeType?: number,
): Promise<Response> {
  const { userId } = c.var;
  const user = await userRepo(c.env.DB).getUserById(userId);
  if (!user) return errorResponse(c, 'User not found', 404);

  const body = c.req.valid('json');

  const typeRaw = routeType ?? body.type ?? TWO_FACTOR_PROVIDER_AUTHENTICATOR;
  const type = typeof typeRaw === 'number' ? typeRaw : Number.parseInt(String(typeRaw), 10);
  if (
    ![
      TWO_FACTOR_PROVIDER_AUTHENTICATOR,
      TWO_FACTOR_PROVIDER_EMAIL,
      TWO_FACTOR_PROVIDER_YUBIKEY,
      TWO_FACTOR_PROVIDER_WEBAUTHN,
    ].includes(type)
  ) {
    return errorResponse(c, 'Two-factor provider is not supported by this server.', 400);
  }

  const verified =
    (routeType !== undefined &&
      (await verifyTwoFactorUserVerificationToken(
        c.env,
        user,
        type,
        body.userVerificationToken,
        normalizeTotpSecret(body.key),
      ))) ||
    (await verifyUserSecret(user, verificationSecret(body)));
  if (!verified) return errorResponse(c, 'User verification failed.', 400);

  const wasEnabled = twoFactorProviders(
    user,
    type === TWO_FACTOR_PROVIDER_WEBAUTHN &&
      (await passkeyRepo(c.env.DB).countAccountPasskeyCredentialsByUserId(user.id, 'twoFactor')) > 0,
  ).some((provider) => provider === type);
  if (type === TWO_FACTOR_PROVIDER_AUTHENTICATOR) {
    user.totpSecret = null;
  } else if (type === TWO_FACTOR_PROVIDER_YUBIKEY) {
    user.yubikeyKey1 = null;
    user.yubikeyKey2 = null;
    user.yubikeyKey3 = null;
    user.yubikeyKey4 = null;
    user.yubikeyKey5 = null;
    user.yubikeyNfc = false;
  }
  user.updatedAt = new Date().toISOString();
  if (
    !(await userRepo(c.env.DB).saveUser(
      user,
      type === TWO_FACTOR_PROVIDER_AUTHENTICATOR
        ? ['totpSecret']
        : type === TWO_FACTOR_PROVIDER_YUBIKEY
          ? ['yubikeyKey1', 'yubikeyKey2', 'yubikeyKey3', 'yubikeyKey4', 'yubikeyKey5', 'yubikeyNfc']
          : [],
    ))
  )
    return errorResponse(c, 'User verification failed.', 400);
  if (type === TWO_FACTOR_PROVIDER_EMAIL) {
    const [updated] = await getOrm(c.env.DB)
      .update(users)
      .set({ twoFactorEmail: null })
      .where(and(eq(users.id, user.id), eq(users.securityStamp, user.securityStamp)))
      .returning({ id: users.id });
    if (!updated) return errorResponse(c, 'User verification failed.', 400);
  }
  if (type === TWO_FACTOR_PROVIDER_WEBAUTHN) {
    const orm = getOrm(c.env.DB);
    const deleted = await orm
      .delete(webauthnCredentials)
      .where(
        and(
          eq(webauthnCredentials.userId, user.id),
          eq(webauthnCredentials.purpose, 'twoFactor'),
          userRowMatches(orm, user.id, eq(users.securityStamp, user.securityStamp)),
        ),
      )
      .returning({ id: webauthnCredentials.id });
    // Deleting nothing while two-step keys remain means the stamp guard failed: the account changed after
    // verification, so the provider is still enabled.
    if (
      !deleted.length &&
      (await passkeyRepo(c.env.DB).countAccountPasskeyCredentialsByUserId(user.id, 'twoFactor')) > 0
    )
      return errorResponse(c, 'User verification failed.', 400);
  }
  await finalizeTwoFactorChange(
    c.req.raw,
    c.env,
    user,
    type === TWO_FACTOR_PROVIDER_AUTHENTICATOR
      ? 'account.totp.disable'
      : type === TWO_FACTOR_PROVIDER_EMAIL
        ? 'account.two_factor.email.disable'
        : type === TWO_FACTOR_PROVIDER_YUBIKEY
          ? 'account.yubikey.disable'
          : 'account.webauthn_2fa.disable',
    wasEnabled ? EventType.UserDisabled2fa : null,
  );

  await revisionRepo(c.env.DB).updateRevisionDate(user.id);
  return routeType === undefined ? c.json(twoFactorProviderResponse(type, false)) : new Response(null, { status: 204 });
}

// POST /api/two-factor/get-recover
export async function handleGetTotpRecoveryCode(c: BodyContext<typeof CurrentPasswordHash>): Promise<Response> {
  const { userId } = c.var;
  const user = await userRepo(c.env.DB).getUserById(userId);
  if (!user) return errorResponse(c, 'User not found', 404);

  const currentHash = c.req.valid('json');
  const valid = await verifyPassword(currentHash, user.masterPasswordHash, user.email);
  if (!valid) return errorResponse(c, 'Invalid password', 400);

  user.totpRecoveryCode = await ensureTwoFactorRecoveryCode(c.env.DB, user.id, user.securityStamp);
  if (!user.totpRecoveryCode) return errorResponse(c, 'User verification failed.', 400);

  return c.json({
    Code: user.totpRecoveryCode,
    code: user.totpRecoveryCode,
    Object: 'twoFactorRecover',
    object: 'twoFactorRecover',
  });
}

// Recovery posts the login form's field names or the API model's; codes compare as upper-case base32.
export const RecoverTwoFactorBody = z
  .object({
    email: text,
    username: text,
    masterPasswordHash: text,
    password: text,
    recoveryCode: text,
    twoFactorToken: text,
    recovery_code: text,
  })
  .transform((body) => ({
    email: (body.email || body.username).trim().toLowerCase(),
    masterPasswordHash: (body.masterPasswordHash || body.password).trim(),
    recoveryCode: (body.recoveryCode || body.twoFactorToken || body.recovery_code)
      .toUpperCase()
      .replace(/[^A-Z2-7]/g, ''),
  }));

// POST /identity/accounts/recover-2fa
// Disable TOTP by recovery code + password, then rotate recovery code.
export async function handleRecoverTwoFactor(c: BodyContext<typeof RecoverTwoFactorBody>): Promise<Response> {
  const rateLimit = new RateLimitService(c.env);

  const body = c.req.valid('json');
  const { email, masterPasswordHash, recoveryCode } = body;
  const clientIdentifier = getClientIdentifier(c.req.raw);
  if (!clientIdentifier) {
    return errorResponse(c, 'Client IP is required', 403);
  }
  const recoverLimitKey = `${clientIdentifier}:recover-2fa`;

  const recoverAttemptCheck = await rateLimit.checkLoginAttempt(recoverLimitKey);
  if (!recoverAttemptCheck.allowed) {
    return errorResponse(
      c,
      `Too many failed recovery attempts. Try again in ${Math.ceil((recoverAttemptCheck.retryAfterSeconds || 60) / 60)} minutes.`,
      429,
    );
  }

  if (!email || !masterPasswordHash || !recoveryCode) {
    return errorResponse(c, 'Email, masterPasswordHash and recoveryCode are required', 400);
  }

  const user = await userRepo(c.env.DB).getUser(email);
  if (!user || user.status !== 'active') {
    await rateLimit.recordFailedLogin(recoverLimitKey);
    return errorResponse(c, 'Invalid credentials or recovery code', 400);
  }

  const validPassword = await verifyPassword(masterPasswordHash, user.masterPasswordHash, user.email);
  if (!validPassword) {
    await rateLimit.recordFailedLogin(recoverLimitKey);
    return errorResponse(c, 'Invalid credentials or recovery code', 400);
  }

  if (!recoveryCodeEquals(recoveryCode, user.totpRecoveryCode)) {
    notifyFailedTwoFactor(c.env, c.req.raw, user, 8);
    await rateLimit.recordFailedLogin(recoverLimitKey);
    return errorResponse(c, 'Invalid credentials or recovery code', 400);
  }

  const nextRecoveryCode = createRecoveryCode();
  const [cleared] = await getOrm(c.env.DB).batch(
    twoFactorClearStatements(
      c.env.DB,
      user.id,
      {
        recoveryCode: nextRecoveryCode,
        securityStamp: crypto.randomUUID(),
      },
      user,
    ),
  );
  if (!cleared.meta.changes) {
    notifyFailedTwoFactor(c.env, c.req.raw, user, 8);
    await rateLimit.recordFailedLogin(recoverLimitKey);
    return errorResponse(c, 'Invalid credentials or recovery code', 400);
  }
  AuthService.invalidateUserCache(user.id);
  await recordUserEvent(c.env, c.req.raw, user.id, EventType.UserRecovered2fa);
  notifyMail(c.env, user.email, 'twoFactorRecovered', {
    time: new Date().toISOString(),
    ip: getClientIdentifier(c.req.raw) ?? 'Unknown',
  });
  await rateLimit.clearLoginAttempts(recoverLimitKey);
  await writeAuditEvent(c.env.DB, {
    actorUserId: user.id,
    action: 'account.totp.recover',
    category: 'security',
    level: 'security',
    targetType: 'user',
    targetId: user.id,
    metadata: auditRequestMetadata(c.req.raw),
  });

  return c.json({
    success: true,
    twoFactorEnabled: false,
    newRecoveryCode: nextRecoveryCode,
    object: 'twoFactorRecovery',
  });
}

// GET /api/accounts/revision-date
export async function handleGetRevisionDate(c: AppContext): Promise<Response> {
  const { userId } = c.var;
  const revisionDate = await revisionRepo(c.env.DB).getRevisionDate(userId);

  // Return as milliseconds timestamp (Bitwarden format)
  const timestamp = new Date(revisionDate).getTime();
  return c.json(timestamp);
}

// Upstream KeyId: exactly 16 bytes as lowercase hex. The SDK rejects a whole sync whose
// UserKeyId is malformed, so uppercase is refused rather than normalized.
const USER_KEY_ID_PATTERN = /^[0-9a-f]{32}$/;
export const UserKeyIdBody = z.object({
  userKeyId: z
    .string({
      error: (issue) => (issue.input == null ? 'The UserKeyId field is required.' : 'UserKeyId is not a valid key id.'),
    })
    .min(1, { error: 'The UserKeyId field is required.', abort: true })
    .regex(USER_KEY_ID_PATTERN, { error: 'UserKeyId is not a valid key id.' }),
});

// POST /api/accounts/key-management/user-key-id
// 2026.9 clients report their user key id once, then clear it and re-post on every unlock
// unless /api/sync echoes it. The revision bump is what evicts the cached pre-backfill sync.
export async function handleSetUserKeyId(c: BodyContext<typeof UserKeyIdBody>): Promise<Response> {
  const { userId } = c.var;
  const body = c.req.valid('json');

  if (!(await userRepo(c.env.DB).setUserKeyIdIfUnset(userId, body.userKeyId))) {
    return errorResponse(c, 'User key id is already set.', 400);
  }
  await revisionRepo(c.env.DB).updateRevisionDate(userId);
  return new Response(null, { status: 200 });
}

export const VerifyPasswordBody = MasterPasswordFields.pick({ authenticationData: true }).extend({
  masterPasswordHash: text,
});

// POST /api/accounts/verify-password
export async function handleVerifyPassword(c: BodyContext<typeof VerifyPasswordBody>): Promise<Response> {
  const { userId } = c.var;
  const user = await userRepo(c.env.DB).getUserById(userId);

  if (!user) {
    return errorResponse(c, 'User not found', 404);
  }

  const body = c.req.valid('json');

  const masterPasswordHash = body.masterPasswordHash || body.authenticationData?.masterPasswordAuthenticationHash;
  if (!masterPasswordHash) {
    return errorResponse(c, 'masterPasswordHash is required', 400);
  }

  const valid = await verifyPassword(masterPasswordHash, user.masterPasswordHash, user.email);
  if (!valid) {
    return errorResponse(c, 'Invalid password', 400);
  }

  return c.json({
    minComplexity: 0,
    minLength: 0,
    requireUpper: false,
    requireLower: false,
    requireNumbers: false,
    requireSpecial: false,
    enforceOnLogin: false,
    object: 'masterPasswordPolicy',
  });
}

// POST /api/accounts/api-key
export async function handleGetApiKey(c: BodyContext<typeof CurrentPasswordHash>): Promise<Response> {
  const { userId } = c.var;
  return apiKey(c, userId, c.req.valid('json'), false);
}

// POST /api/accounts/rotate-api-key
export async function handleRotateApiKey(c: BodyContext<typeof CurrentPasswordHash>): Promise<Response> {
  const { userId } = c.var;
  return apiKey(c, userId, c.req.valid('json'), true);
}

async function apiKey(c: AppContext, userId: string, currentHash: string, rotate: boolean): Promise<Response> {
  const user = await userRepo(c.env.DB).getUserById(userId);
  if (!user) return errorResponse(c, 'User not found', 404);

  const valid = await verifyPassword(currentHash, user.masterPasswordHash, user.email);
  if (!valid) return errorResponse(c, 'Invalid password', 400);

  if (!rotate && isStoredApiKeyHash(user.apiKey)) {
    return errorResponse(
      c,
      'This API key was created by an older CloudWarden version and cannot be displayed. Rotate it once to use the Bitwarden-compatible readable format.',
      409,
    );
  }

  let auditAction = 'account.api_key.view';
  if (rotate || !user.apiKey) {
    user.apiKey = randomStringAlphanum(LIMITS.auth.clientSecretLength);
    user.updatedAt = new Date().toISOString();
    if (!(await userRepo(c.env.DB).saveUser(user, ['apiKey'])))
      return errorResponse(c, 'User verification failed.', 400);
    AuthService.invalidateUserCache(user.id);
    auditAction = rotate ? 'account.api_key.rotate' : 'account.api_key.create';
  }
  await writeAuditEvent(c.env.DB, {
    actorUserId: user.id,
    action: auditAction,
    category: 'security',
    level: rotate ? 'security' : 'info',
    targetType: 'user',
    targetId: user.id,
    metadata: auditRequestMetadata(c.req.raw),
  });

  return c.json({
    apiKey: user.apiKey,
    revisionDate: user.updatedAt,
    object: 'apiKey',
  });
}
