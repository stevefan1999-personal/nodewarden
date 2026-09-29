import type { AppContext } from '../router';
import { z } from 'zod';
import type { Env, User } from '../types';
import { AuthService } from '../services/auth';
import { errorResponse, type BodyContext } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import { createEmergencyAccessInviteToken, verifyEmergencyAccessInviteToken } from '../utils/jwt';
import { LIMITS } from '../config/limits';
import { RateLimitService } from '../services/ratelimit';
import { configuredVaultOrigin, mailStatusCheck, readMailConfig, sendMail, type MailOutcome } from '../services/mail';
import { runInBackground } from '../services/mail-notify';
import { upsertCredentialAccount } from '../services/auth-accounts';
import { cipherToResponse } from './ciphers';
import { emailAddress, MasterPasswordFields, masterPasswordUpdate } from './accounts';
import {
  emergencyRepo,
  type EmergencyAccessRecord,
  EmergencyAccessStatus,
  EmergencyAccessType,
} from '../services/storage-emergency-repo';
import { cipherRepo } from '../services/storage-cipher-repo';
import { attachmentRepo } from '../services/storage-attachment-repo';
import { sessionRepo } from '../services/storage-session-repo';
import { userRepo } from '../services/storage-user-repo';

// Type and wait time coerce like Number(); anything non-finite keeps the current or default value.
const setting = z.coerce.number().optional().catch(undefined);
export const EmergencyAccessSettings = z.object({
  type: setting,
  waitTimeDays: setting,
  keyEncrypted: z.string().optional().catch(undefined),
});
const text = z.string().catch('');

function emergencyJson(record: EmergencyAccessRecord) {
  return {
    id: record.id,
    status: record.status,
    type: record.type,
    waitTimeDays: record.waitTimeDays,
    object: 'emergencyAccess',
  };
}

async function userSummary(db: D1Database, userId: string | null, email: string | null) {
  const user = userId ? await userRepo(db).getUserById(userId) : email ? await userRepo(db).getUser(email) : null;
  return {
    id: user?.id || null,
    email: user?.email || email,
    name: user?.name || null,
    avatarColor: null,
  };
}

async function granteeDetails(db: D1Database, record: EmergencyAccessRecord) {
  const user = await userSummary(db, record.granteeId, record.email);
  return {
    ...emergencyJson(record),
    granteeId: user.id,
    email: user.email,
    name: user.name,
    avatarColor: null,
    object: 'emergencyAccessGranteeDetails',
  };
}

function canAct(record: EmergencyAccessRecord, userId: string, type: number): boolean {
  if (record.granteeId !== userId || record.type !== type) return false;
  if (record.status === EmergencyAccessStatus.RecoveryApproved) return true;
  if (record.status !== EmergencyAccessStatus.RecoveryInitiated || !record.recoveryInitiatedAt) return false;
  const started = Date.parse(record.recoveryInitiatedAt);
  return Number.isFinite(started) && Date.now() - started >= record.waitTimeDays * 24 * 60 * 60 * 1000;
}

async function mailEmergencyAccessInvite(
  request: Request,
  env: Env,
  grantor: User,
  record: EmergencyAccessRecord,
): Promise<MailOutcome> {
  const config = readMailConfig(env);
  if (config.kind !== 'enabled') return config;
  const vaultOrigin = configuredVaultOrigin(request, env);
  if (!vaultOrigin) return { kind: 'disabled' };
  const budget = await new RateLimitService(env).consumeStrictBudgetWithWindow(
    `ea-invite-mail:${grantor.id}`,
    LIMITS.mail.emergencyAccessInvitesPerGrantorPerHour,
    3600,
  );
  if (!budget.allowed) return { kind: 'throttled', retryAfterSeconds: budget.retryAfterSeconds ?? 3600 };
  return sendMail(env, record.email!, 'emergencyAccessInvite', {
    vaultOrigin,
    id: record.id,
    grantorName: grantor.name || grantor.email,
    grantorEmail: grantor.email,
    token: await createEmergencyAccessInviteToken(env.JWT_SECRET, record.id, record.email!),
  });
}

type EmergencyAccessNotice =
  | 'emergencyAccessAccepted'
  | 'emergencyAccessConfirmed'
  | 'emergencyAccessRecoveryInitiated'
  | 'emergencyAccessApproved'
  | 'emergencyAccessRejected'
  | 'emergencyAccessTimedOut'
  | 'emergencyAccessReminder';

async function sendEmergencyAccessNotice(
  env: Env,
  record: EmergencyAccessRecord,
  name: EmergencyAccessNotice,
  recipient: 'grantor' | 'grantee',
  daysLeft = record.waitTimeDays,
): Promise<void> {
  const [grantor, grantee] = await Promise.all([
    userRepo(env.DB).getUserById(record.grantorId),
    record.granteeId ? userRepo(env.DB).getUserById(record.granteeId) : null,
  ]);
  if (!grantor || !grantee) return;
  const [to, other] = recipient === 'grantor' ? [grantor, grantee] : [grantee, grantor];
  await sendMail(env, to.email, name, {
    name: other.name || other.email,
    accessType: record.type === EmergencyAccessType.Takeover ? 'take over your account' : 'view your vault',
    daysLeft,
  });
}

export const EmergencyInviteBody = EmergencyAccessSettings.extend({ email: emailAddress('Email is not valid.') });
export const EmergencyAcceptBody = z.object({ token: text });
export const EmergencyConfirmBody = z.object({ key: text });

// Every /emergency-access/:id route answers an id that does not exist alike, before its own checks.
export function withEmergencyAccess<C extends AppContext>(
  handler: (c: C, record: EmergencyAccessRecord) => Promise<Response>,
): (c: C) => Promise<Response> {
  return async (c) => {
    const record = await emergencyRepo(c.env.DB).getEmergencyAccess(c.req.param('id')!);
    return record ? handler(c, record) : errorResponse(c, 'Emergency access not valid', 404);
  };
}

// GET /emergency-access/trusted
export async function handleEmergencyAccessTrusted(c: AppContext): Promise<Response> {
  const { currentUser: user } = c.var;
  const rows = await emergencyRepo(c.env.DB).listByGrantor(user.id);
  const data = [];
  for (const row of rows) data.push(await granteeDetails(c.env.DB, row));
  return c.json({ data, object: 'list', continuationToken: null });
}

// GET /emergency-access/granted
export async function handleEmergencyAccessGranted(c: AppContext): Promise<Response> {
  const { currentUser: user } = c.var;
  const rows = await emergencyRepo(c.env.DB).listByGrantee(user.id);
  const data = [];
  for (const row of rows) {
    const grantor = await userSummary(c.env.DB, row.grantorId, null);
    data.push({
      ...emergencyJson(row),
      grantorId: grantor.id,
      email: grantor.email,
      name: grantor.name,
      avatarColor: null,
      object: 'emergencyAccessGrantorDetails',
    });
  }
  return c.json({ data, object: 'list', continuationToken: null });
}

// POST /emergency-access/invite
export async function handleEmergencyAccessInvite(c: BodyContext<typeof EmergencyInviteBody>): Promise<Response> {
  const { currentUser: user } = c.var;
  const body = c.req.valid('json');
  const { email } = body;
  if (email === user.email.toLowerCase()) return errorResponse(c, 'Cannot invite yourself', 400);
  const existing = await emergencyRepo(c.env.DB).findInvite(user.id, email);
  if (existing) return errorResponse(c, 'User already invited', 400);
  const grantee = await userRepo(c.env.DB).getUser(email);
  const now = new Date().toISOString();
  const record: EmergencyAccessRecord = {
    id: generateUUID(),
    grantorId: user.id,
    granteeId: grantee?.id || null,
    email,
    keyEncrypted: null,
    type: body.type ?? EmergencyAccessType.View,
    status: grantee ? EmergencyAccessStatus.Accepted : EmergencyAccessStatus.Invited,
    waitTimeDays: Math.max(0, body.waitTimeDays ?? 7),
    recoveryInitiatedAt: null,
    lastNotificationAt: null,
    createdAt: now,
    updatedAt: now,
  };
  const outcome = await mailEmergencyAccessInvite(c.req.raw, c.env, user, record);
  const check = mailStatusCheck(outcome);
  if (!check.ok) return errorResponse(c, check.message, check.status, check.headers);
  if (outcome.kind === 'sent') record.status = EmergencyAccessStatus.Invited;
  await emergencyRepo(c.env.DB).saveEmergencyAccess(record);
  return new Response(null, { status: 200 });
}

// GET /emergency-access/:id
export async function handleGetEmergencyAccess(c: AppContext, record: EmergencyAccessRecord): Promise<Response> {
  const { currentUser: user } = c.var;
  if (record.grantorId !== user.id) return errorResponse(c, 'Emergency access not valid', 404);
  return c.json(await granteeDetails(c.env.DB, record));
}

// PUT or POST /emergency-access/:id
export async function handleUpdateEmergencyAccess(
  c: BodyContext<typeof EmergencyAccessSettings>,
  record: EmergencyAccessRecord,
): Promise<Response> {
  const { currentUser: user } = c.var;
  if (record.grantorId !== user.id) return errorResponse(c, 'Emergency access not valid', 404);
  const body = c.req.valid('json');
  record.type = body.type ?? record.type;
  record.waitTimeDays = Math.max(0, body.waitTimeDays ?? record.waitTimeDays);
  if (body.keyEncrypted !== undefined) record.keyEncrypted = body.keyEncrypted;
  record.updatedAt = new Date().toISOString();
  await emergencyRepo(c.env.DB).saveEmergencyAccess(record);
  return c.json(emergencyJson(record));
}

// DELETE /emergency-access/:id, POST /emergency-access/:id/delete
export async function handleDeleteEmergencyAccess(c: AppContext, record: EmergencyAccessRecord): Promise<Response> {
  const { currentUser: user } = c.var;
  if (record.grantorId !== user.id && record.granteeId !== user.id) {
    return errorResponse(c, 'Emergency access not valid', 404);
  }
  await emergencyRepo(c.env.DB).deleteEmergencyAccess(record.id);
  return new Response(null, { status: 200 });
}

// POST /emergency-access/:id/reinvite
export async function handleReinviteEmergencyAccess(c: AppContext, record: EmergencyAccessRecord): Promise<Response> {
  const { currentUser: user } = c.var;
  if (record.grantorId !== user.id) return errorResponse(c, 'Emergency access not valid', 404);
  if (record.status !== EmergencyAccessStatus.Invited || !record.email)
    return errorResponse(c, 'Emergency access not valid', 400);
  const outcome = await mailEmergencyAccessInvite(c.req.raw, c.env, user, record);
  const check = mailStatusCheck(outcome);
  if (!check.ok) return errorResponse(c, check.message, check.status, check.headers);
  if (outcome.kind === 'sent') return new Response(null, { status: 200 });
  if (record.email) {
    const grantee = await userRepo(c.env.DB).getUser(record.email);
    if (grantee && record.status === EmergencyAccessStatus.Invited) {
      record.granteeId = grantee.id;
      record.status = EmergencyAccessStatus.Accepted;
      record.updatedAt = new Date().toISOString();
      await emergencyRepo(c.env.DB).saveEmergencyAccess(record);
    }
  }
  return new Response(null, { status: 200 });
}

// POST /emergency-access/:id/accept
export async function handleAcceptEmergencyAccess(
  c: BodyContext<typeof EmergencyAcceptBody>,
  record: EmergencyAccessRecord,
): Promise<Response> {
  const { currentUser: user } = c.var;
  // Only a pending invite may bind a grantee: later states drop `email` on confirm,
  // so without the status gate a guessed id could re-bind an already-confirmed record.
  if (record.status !== EmergencyAccessStatus.Invited) return errorResponse(c, 'Emergency access not valid', 400);
  const email = user.email.toLowerCase();
  if (!record.email || record.email.toLowerCase() !== email) {
    return errorResponse(c, 'Emergency access not valid', 404);
  }
  const body = c.req.valid('json');
  const config = readMailConfig(c.env);
  const check = mailStatusCheck(config.kind === 'enabled' ? { kind: 'sent' } : config);
  if (!check.ok) return errorResponse(c, check.message, check.status, check.headers);
  if (
    config.kind === 'enabled' &&
    configuredVaultOrigin(c.req.raw, c.env) &&
    !(await verifyEmergencyAccessInviteToken(body.token, c.env.JWT_SECRET, record.id, email))
  ) {
    return errorResponse(c, 'Emergency access invitation is invalid or expired', 400);
  }
  record.granteeId = user.id;
  record.status = EmergencyAccessStatus.Accepted;
  record.updatedAt = new Date().toISOString();
  await emergencyRepo(c.env.DB).saveEmergencyAccess(record);
  runInBackground('emergency-access-accepted', () =>
    sendEmergencyAccessNotice(c.env, record, 'emergencyAccessAccepted', 'grantor'),
  );
  return new Response(null, { status: 200 });
}

// POST /emergency-access/:id/confirm
export async function handleConfirmEmergencyAccess(
  c: BodyContext<typeof EmergencyConfirmBody>,
  record: EmergencyAccessRecord,
): Promise<Response> {
  const { currentUser: user } = c.var;
  if (record.grantorId !== user.id || record.status !== EmergencyAccessStatus.Accepted) {
    return errorResponse(c, 'Emergency access not valid', 400);
  }
  const body = c.req.valid('json');
  record.keyEncrypted = body.key;
  record.status = EmergencyAccessStatus.Confirmed;
  record.email = null;
  record.updatedAt = new Date().toISOString();
  await emergencyRepo(c.env.DB).saveEmergencyAccess(record);
  runInBackground('emergency-access-confirmed', () =>
    sendEmergencyAccessNotice(c.env, record, 'emergencyAccessConfirmed', 'grantee'),
  );
  return c.json(emergencyJson(record));
}

// POST /emergency-access/:id/initiate
export async function handleInitiateEmergencyAccess(c: AppContext, record: EmergencyAccessRecord): Promise<Response> {
  const { currentUser: user } = c.var;
  if (record.granteeId !== user.id || record.status !== EmergencyAccessStatus.Confirmed) {
    return errorResponse(c, 'Emergency access not valid', 400);
  }
  const now = new Date().toISOString();
  record.recoveryInitiatedAt = now;
  record.lastNotificationAt = now;
  record.status =
    record.waitTimeDays <= 0 ? EmergencyAccessStatus.RecoveryApproved : EmergencyAccessStatus.RecoveryInitiated;
  record.updatedAt = now;
  await emergencyRepo(c.env.DB).saveEmergencyAccess(record);
  runInBackground('emergency-access-initiated', async () => {
    await sendEmergencyAccessNotice(c.env, record, 'emergencyAccessRecoveryInitiated', 'grantor');
    if (record.status === EmergencyAccessStatus.RecoveryApproved)
      await sendEmergencyAccessNotice(c.env, record, 'emergencyAccessApproved', 'grantee');
  });
  return c.json(emergencyJson(record));
}

// POST /emergency-access/:id/approve
export async function handleApproveEmergencyAccess(c: AppContext, record: EmergencyAccessRecord): Promise<Response> {
  const { currentUser: user } = c.var;
  if (record.grantorId !== user.id || record.status !== EmergencyAccessStatus.RecoveryInitiated) {
    return errorResponse(c, 'Emergency access not valid', 400);
  }
  record.status = EmergencyAccessStatus.RecoveryApproved;
  record.updatedAt = new Date().toISOString();
  await emergencyRepo(c.env.DB).saveEmergencyAccess(record);
  runInBackground('emergency-access-approved', () =>
    sendEmergencyAccessNotice(c.env, record, 'emergencyAccessApproved', 'grantee'),
  );
  return c.json(emergencyJson(record));
}

// POST /emergency-access/:id/reject
export async function handleRejectEmergencyAccess(c: AppContext, record: EmergencyAccessRecord): Promise<Response> {
  const { currentUser: user } = c.var;
  if (record.grantorId !== user.id) return errorResponse(c, 'Emergency access not valid', 404);
  if (
    record.status !== EmergencyAccessStatus.RecoveryInitiated &&
    record.status !== EmergencyAccessStatus.RecoveryApproved
  ) {
    return errorResponse(c, 'Emergency access not valid', 400);
  }
  record.status = EmergencyAccessStatus.Confirmed;
  record.recoveryInitiatedAt = null;
  record.updatedAt = new Date().toISOString();
  await emergencyRepo(c.env.DB).saveEmergencyAccess(record);
  runInBackground('emergency-access-rejected', () =>
    sendEmergencyAccessNotice(c.env, record, 'emergencyAccessRejected', 'grantee'),
  );
  return c.json(emergencyJson(record));
}

// POST /emergency-access/:id/view
export async function handleViewEmergencyAccess(c: AppContext, record: EmergencyAccessRecord): Promise<Response> {
  const { currentUser: user } = c.var;
  if (!canAct(record, user.id, EmergencyAccessType.View)) return errorResponse(c, 'Emergency access not valid', 400);
  const ciphers = await cipherRepo(c.env.DB).getAllCiphers(record.grantorId);
  const attachments = await attachmentRepo(c.env.DB).getAttachmentsByCipherIds(ciphers.map((cipher) => cipher.id));
  return c.json({
    ciphers: ciphers.map((cipher) => cipherToResponse(cipher, attachments.get(cipher.id) || [])),
    keyEncrypted: record.keyEncrypted,
    object: 'emergencyAccessView',
  });
}

// POST /emergency-access/:id/takeover
export async function handleTakeoverEmergencyAccess(c: AppContext, record: EmergencyAccessRecord): Promise<Response> {
  const { currentUser: user } = c.var;
  if (!canAct(record, user.id, EmergencyAccessType.Takeover))
    return errorResponse(c, 'Emergency access not valid', 400);
  const grantor = await userRepo(c.env.DB).getUserById(record.grantorId);
  if (!grantor) return errorResponse(c, 'Grantor user not found', 404);
  return c.json({
    kdf: grantor.kdfType,
    kdfIterations: grantor.kdfIterations,
    kdfMemory: grantor.kdfMemory ?? null,
    kdfParallelism: grantor.kdfParallelism ?? null,
    keyEncrypted: record.keyEncrypted,
    // Web 2026.9 salts the new password with this and only falls back to the email it was given.
    salt: grantor.email.toLowerCase(),
    object: 'emergencyAccessTakeover',
  });
}

// POST /emergency-access/:id/password
export async function handleEmergencyAccessPassword(
  c: BodyContext<typeof MasterPasswordFields>,
  record: EmergencyAccessRecord,
): Promise<Response> {
  const { currentUser: user } = c.var;
  if (!canAct(record, user.id, EmergencyAccessType.Takeover))
    return errorResponse(c, 'Emergency access not valid', 400);
  const grantor = await userRepo(c.env.DB).getUserById(record.grantorId);
  if (!grantor) return errorResponse(c, 'Grantor user not found', 404);
  const body = c.req.valid('json');
  const update = masterPasswordUpdate(c, body, grantor);
  if (update instanceof Response) return update;
  const auth = new AuthService(c.env);
  grantor.masterPasswordHash = await auth.hashPasswordServer(update.masterPasswordHash);
  grantor.key = update.key;
  const originalSecurityStamp = grantor.securityStamp;
  grantor.securityStamp = generateUUID();
  grantor.updatedAt = new Date().toISOString();
  if (
    !(await userRepo(c.env.DB).saveUser(grantor, ['masterPasswordHash', 'key', 'securityStamp'], originalSecurityStamp))
  )
    return errorResponse(c, 'User verification failed.', 400);
  AuthService.invalidateUserCache(grantor.id);
  if (!(await upsertCredentialAccount(c.env.DB, grantor.id, grantor.masterPasswordHash, grantor.securityStamp)))
    return errorResponse(c, 'User verification failed.', 400);
  await sessionRepo(c.env.DB).deleteRefreshTokensByUserId(grantor.id);
  return new Response(null, { status: 200 });
}

// GET /emergency-access/:id/policies
export async function handleEmergencyAccessPolicies(c: AppContext, record: EmergencyAccessRecord): Promise<Response> {
  const { currentUser: user } = c.var;
  if (!canAct(record, user.id, EmergencyAccessType.Takeover))
    return errorResponse(c, 'Emergency access not valid', 400);
  return c.json({ data: [], object: 'list', continuationToken: null });
}

export async function approveExpiredEmergencyAccess(env: Env): Promise<void> {
  const now = new Date().toISOString();
  const ready = await emergencyRepo(env.DB).listRecoveryReady(now);
  for (const record of ready) {
    record.status = EmergencyAccessStatus.RecoveryApproved;
    record.updatedAt = now;
    await emergencyRepo(env.DB).saveEmergencyAccess(record);
    await sendEmergencyAccessNotice(env, record, 'emergencyAccessTimedOut', 'grantor');
    await sendEmergencyAccessNotice(env, record, 'emergencyAccessApproved', 'grantee');
  }
}

export async function remindPendingEmergencyAccess(env: Env): Promise<void> {
  const now = new Date().toISOString();
  for (const record of await emergencyRepo(env.DB).listRecoveryToNotify(now)) {
    if (!(await emergencyRepo(env.DB).claimRecoveryNotification(record, now))) continue;
    const daysLeft = Math.ceil(
      (Date.parse(record.recoveryInitiatedAt!) + record.waitTimeDays * 86_400_000 - Date.parse(now)) / 86_400_000,
    );
    await sendEmergencyAccessNotice(env, record, 'emergencyAccessReminder', 'grantor', daysLeft);
  }
}
