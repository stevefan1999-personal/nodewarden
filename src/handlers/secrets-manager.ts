import type { AppContext } from '../router';
import { z } from 'zod';
import type { Principal } from '../services/auth';
import { LIMITS } from '../config/limits';
import { policyConflict, prepareSecretPolicies } from './sm-access-policies';
import { isSerializedEncString } from '../utils/account-passkeys';
import {
  projectAccess,
  serviceAccountAccess,
  secretAccess,
  canCreateSecret,
  canUpdateSecret,
  resolveSmActor,
  type SmAccess,
} from '../services/sm-authz';
import type { Env } from '../types';
import { smRepo, type SmSecret, type SmProject, type SmServiceAccount } from '../services/storage-secret-repo';
import { errorResponse, type BodyContext } from '../utils/response';
import { hashApiKey, randomStringAlphanum } from '../utils/api-key';
import { EventType, listEventsResponse, recordEvents } from '../services/events';
import { canAccessEventLogs, isActiveMember } from '../services/org-authz';
import { MembershipType } from '../services/org-types';
import { orgRepo } from '../services/storage-org-repo';

// SM names, keys, values and notes stay client ciphertext: each must be a serialized EncString.
const encrypted = (max: number, error: string) =>
  z.string({ error }).refine((value) => value.length <= max && isSerializedEncString(value), { error });
const guids = (error: string) =>
  z.array(z.guid({ error }), { error }).transform((ids) => ids.map((id) => id.toLowerCase()));
const NAME_ERROR = 'Name must be an encrypted string of at most 1000 characters.';
export const NameBody = z.object({ name: encrypted(1000, NAME_ERROR) }, { error: NAME_ERROR });
const IDS_ERROR = 'Ids must be an array of GUIDs.';
export const IdsBody = z.object({ ids: guids(IDS_ERROR) }, { error: IDS_ERROR });
export const GuidsBody = guids('Request body must be an array of GUIDs');
export const SecretIdsBody = guids('Request body must be an array of secret GUIDs');

// The grant lists stay unknown here because parsePolicyRequests owns their messages.
export const PolicyRequests = z.record(z.string(), z.unknown(), { error: 'Access policies must be an object.' });

const SECRET_ERROR = 'Key, value and note must be encrypted strings within their size limits.';
export const SecretBody = z
  .object(
    {
      key: encrypted(1000, SECRET_ERROR),
      value: encrypted(35000, SECRET_ERROR),
      note: encrypted(10000, SECRET_ERROR),
      projectIds: guids('ProjectIds must be an array of GUIDs.')
        .nullish()
        .transform((ids) => ids ?? []),
      accessPoliciesRequests: PolicyRequests.nullish(),
    },
    { error: SECRET_ERROR },
  )
  .refine((input) => input.projectIds.length <= 1, {
    error: 'Only one project assignment is supported.',
    path: ['ProjectIds'],
  });

const TOKEN_ERROR = 'Name, encryptedPayload and key must be encrypted strings within their size limits.';
const EXPIRE_ERROR = 'ExpireAt must be in the future.';
export const AccessTokenBody = z.object(
  {
    name: encrypted(200, TOKEN_ERROR),
    encryptedPayload: encrypted(4000, TOKEN_ERROR),
    key: encrypted(Infinity, TOKEN_ERROR),
    expireAt: z
      .string({ error: EXPIRE_ERROR })
      .refine((value) => Date.parse(value) > Date.now(), { error: EXPIRE_ERROR })
      .transform((value) => new Date(value).toISOString())
      .nullish(),
  },
  { error: TOKEN_ERROR },
);

function eventActor(principal: Principal) {
  return principal.kind === 'user' ? { userId: principal.user.id } : { serviceAccountId: principal.serviceAccountId };
}

// Upstream ProjectsAreInOrganization: a missing or foreign project is 404 before any write, so a
// secret or machine account in one org can never link to another org's project. Like upstream's
// count comparison, a repeated id fails too instead of hitting the link table's primary key.
async function allProjectsInOrg(db: D1Database, orgId: string, projectIds: string[]): Promise<boolean> {
  const orgProjectIds = await smRepo(db).projectsInOrg(orgId, projectIds);
  return new Set(projectIds).size === projectIds.length && projectIds.every((id) => orgProjectIds.has(id));
}

export function secretResponse(
  secret: SmSecret,
  projects: Map<string, string>,
  access: SmAccess = 'write',
  base = false,
) {
  return {
    id: secret.id,
    organizationId: secret.orgId,
    key: secret.key,
    value: secret.value,
    note: secret.note,
    creationDate: secret.createdAt,
    revisionDate: secret.updatedAt,
    projects: secret.projectIds.map((id) => ({ id, name: projects.get(id) })),
    ...(base ? {} : { read: access !== 'none', write: access === 'write' }),
    object: base ? 'baseSecret' : 'secret',
  };
}

export async function projectNames(db: D1Database, orgId: string): Promise<Map<string, string>> {
  return new Map((await smRepo(db).listProjects(orgId)).map((project) => [project.id, project.name]));
}

export async function secretsListResponse(
  env: Env,
  orgId: string,
  secrets: SmSecret[],
  context: NonNullable<Awaited<ReturnType<typeof smContext>>>,
) {
  const names = await projectNames(env.DB, orgId);
  const visible = secrets.filter((secret) => secretAccess(context.actor, context.grants, secret) !== 'none');
  return {
    secrets: visible.map((secret) => {
      const { value, note, object, ...response } = secretResponse(
        secret,
        names,
        secretAccess(context.actor, context.grants, secret),
      );
      return response;
    }),
    projects: [...new Set(visible.flatMap((secret) => secret.projectIds))].map((id) => ({ id, name: names.get(id) })),
    object: 'SecretsWithProjectsList',
  };
}

export async function handleListSecrets(c: AppContext, orgId: string, projectId?: string): Promise<Response> {
  const { principal } = c.var;
  const context = await smContext(c.env, principal, orgId);
  if (!context) return errorResponse(c, 'Not found', 404);
  const secrets = (await smRepo(c.env.DB).listSecrets(orgId)).filter(
    (secret) => !projectId || secret.projectIds.includes(projectId),
  );
  return c.json(await secretsListResponse(c.env, orgId, secrets, context));
}

export async function handleProjectSecrets(c: AppContext, id: string): Promise<Response> {
  const project = await smRepo(c.env.DB).getProject(id);
  return project ? handleListSecrets(c, project.orgId, id) : errorResponse(c, 'Not found', 404);
}

export async function handleCreateSecret(c: BodyContext<typeof SecretBody>, orgId: string): Promise<Response> {
  const { principal } = c.var;
  const context = await smContext(c.env, principal, orgId);
  if (!context) return errorResponse(c, 'Not found', 404);
  const input = c.req.valid('json');
  if (!(await allProjectsInOrg(c.env.DB, orgId, input.projectIds))) return errorResponse(c, 'Resource not found.', 404);
  if (!canCreateSecret(context.actor, context.grants, input.projectIds[0])) return errorResponse(c, 'Not found', 404);
  const now = new Date().toISOString();
  const secret = { ...input, id: crypto.randomUUID(), orgId, createdAt: now, updatedAt: now, deletedAt: null };
  const policies = await prepareSecretPolicies(c, context, orgId, secret.id, input.accessPoliciesRequests, true);
  if (policies instanceof Response) return policies;
  try {
    await smRepo(c.env.DB).createSecret(secret, policies);
  } catch (error) {
    const conflict = policyConflict(c, error);
    if (conflict) return conflict;
    throw error;
  }
  await recordEvents(c.env, c.req.raw, eventActor(principal), [
    { organizationId: orgId, type: EventType.SecretCreated, resourceType: 'secret', resourceId: secret.id },
  ]);
  return c.json(secretResponse(secret, await projectNames(c.env.DB, orgId)));
}

export async function handleGetSecret(c: AppContext, secretId: string): Promise<Response> {
  const { principal } = c.var;
  const secret = await smRepo(c.env.DB).getSecret(secretId);
  const context = secret && !secret.deletedAt && (await smContext(c.env, principal, secret.orgId));
  if (!secret || !context) return errorResponse(c, 'Not found', 404);
  const access = secretAccess(context.actor, context.grants, secret);
  if (access === 'none') return errorResponse(c, 'Not found', 404);
  await recordEvents(c.env, c.req.raw, eventActor(principal), [
    { organizationId: secret.orgId, type: EventType.SecretRetrieved, resourceType: 'secret', resourceId: secret.id },
  ]);
  return c.json(secretResponse(secret, await projectNames(c.env.DB, secret.orgId), access));
}

export async function handleUpdateSecret(c: BodyContext<typeof SecretBody>, secretId: string): Promise<Response> {
  const { principal } = c.var;
  const existing = await smRepo(c.env.DB).getSecret(secretId);
  const context = existing && !existing.deletedAt && (await smContext(c.env, principal, existing.orgId));
  if (!existing || !context) return errorResponse(c, 'Not found', 404);
  const input = c.req.valid('json');
  if (!(await allProjectsInOrg(c.env.DB, existing.orgId, input.projectIds)))
    return errorResponse(c, 'Resource not found.', 404);
  if (!canUpdateSecret(context.actor, context.grants, existing, input.projectIds))
    return errorResponse(c, 'Not found', 404);
  const secret = { ...existing, ...input, updatedAt: new Date().toISOString() };
  const policies = await prepareSecretPolicies(
    c,
    context,
    secret.orgId,
    secret.id,
    input.accessPoliciesRequests,
    false,
  );
  if (policies instanceof Response) return policies;
  try {
    if (!(await smRepo(c.env.DB).updateSecret(secret, existing.projectIds, existing.updatedAt, policies)))
      return errorResponse(c, 'Not found', 404);
  } catch (error) {
    const conflict = policyConflict(c, error);
    if (conflict) return conflict;
    throw error;
  }
  await recordEvents(c.env, c.req.raw, eventActor(principal), [
    { organizationId: secret.orgId, type: EventType.SecretEdited, resourceType: 'secret', resourceId: secret.id },
  ]);
  return c.json(secretResponse(secret, await projectNames(c.env.DB, secret.orgId)));
}

export async function handleDeleteSecrets(c: BodyContext<typeof SecretIdsBody>): Promise<Response> {
  const { principal } = c.var;
  const ids = c.req.valid('json');
  if (!ids.length || new Set(ids).size !== ids.length) return errorResponse(c, 'Not found', 404);
  const secrets = await smRepo(c.env.DB).getSecretsByIds(ids);
  const orgId = secrets[0]?.orgId;
  if (!orgId || secrets.length !== ids.length || secrets.some((secret) => secret.orgId !== orgId || secret.deletedAt))
    return errorResponse(c, 'Not found', 404);
  const context = await smContext(c.env, principal, orgId);
  if (!context) return errorResponse(c, 'Not found', 404);
  const data = secrets.map((secret) => ({
    id: secret.id,
    error: secretAccess(context.actor, context.grants, secret) === 'write' ? null : 'access denied',
    object: 'BulkDeleteResponseModel',
  }));
  const allowed = data.filter((item) => !item.error).map((item) => item.id);
  const changed = await smRepo(c.env.DB).deleteSecrets(orgId, allowed);
  await recordEvents(
    c.env,
    c.req.raw,
    eventActor(principal),
    changed.map((resourceId) => ({
      organizationId: orgId,
      type: EventType.SecretDeleted,
      resourceType: 'secret',
      resourceId,
    })),
  );
  return c.json(listResponse(data));
}

export async function handleSecretsByIds(c: BodyContext<typeof IdsBody>): Promise<Response> {
  const { principal } = c.var;
  const body = c.req.valid('json');
  const { ids } = body;
  if (!ids.length || new Set(ids).size !== ids.length) return errorResponse(c, 'Not found', 404);
  const secrets = await smRepo(c.env.DB).getSecretsByIds(ids);
  const orgId = secrets[0]?.orgId;
  if (!orgId || secrets.length !== ids.length || secrets.some((secret) => secret.orgId !== orgId || secret.deletedAt))
    return errorResponse(c, 'Not found', 404);
  const context = await smContext(c.env, principal, orgId);
  if (!context || secrets.some((secret) => secretAccess(context.actor, context.grants, secret) === 'none'))
    return errorResponse(c, 'Not found', 404);
  const names = await projectNames(c.env.DB, orgId);
  await recordEvents(
    c.env,
    c.req.raw,
    eventActor(principal),
    secrets.map((secret) => ({
      organizationId: orgId,
      type: EventType.SecretRetrieved,
      resourceType: 'secret',
      resourceId: secret.id,
    })),
  );
  return c.json(listResponse(secrets.map((secret) => secretResponse(secret, names, 'read', true))));
}

export async function smContext(env: Env, principal: Principal, orgId: string) {
  const actor = await resolveSmActor(env.DB, principal, orgId);
  return actor ? { actor, grants: await smRepo(env.DB).loadSmGrants(actor, orgId) } : null;
}

export function listResponse<T>(data: T[]) {
  return { data, object: 'list', continuationToken: null };
}

function projectResponse(project: SmProject, level: SmAccess) {
  return {
    id: project.id,
    organizationId: project.orgId,
    name: project.name,
    creationDate: project.createdAt,
    revisionDate: project.updatedAt,
    read: level !== 'none',
    write: level === 'write',
    object: 'project',
  };
}

export async function handleListProjects(c: AppContext, orgId: string): Promise<Response> {
  const { principal } = c.var;
  const context = await smContext(c.env, principal, orgId);
  if (!context) return errorResponse(c, 'Not found', 404);
  // ponytail: in-memory filter loads every org row; push grants into SQL if an org passes ~10k secrets.
  const projects = (await smRepo(c.env.DB).listProjects(orgId))
    .map((project) => projectResponse(project, projectAccess(context.actor, context.grants, project.id)))
    .filter((project) => project.read);
  return c.json(listResponse(projects));
}

export async function handleCreateProject(c: BodyContext<typeof NameBody>, orgId: string): Promise<Response> {
  const { principal } = c.var;
  const context = await smContext(c.env, principal, orgId);
  if (!context) return errorResponse(c, 'Not found', 404);
  const body = c.req.valid('json');
  const now = new Date().toISOString();
  const project = { id: crypto.randomUUID(), orgId, name: body.name, createdAt: now, updatedAt: now };
  await smRepo(c.env.DB).createProject(project, context.actor);
  await recordEvents(c.env, c.req.raw, eventActor(principal), [
    { organizationId: orgId, type: EventType.ProjectCreated, resourceType: 'project', resourceId: project.id },
  ]);
  return c.json(projectResponse(project, 'write'));
}

export async function handleProject(c: BodyContext<typeof NameBody>, id: string, counts = false): Promise<Response> {
  const { principal } = c.var;
  const project = await smRepo(c.env.DB).getProject(id);
  const context = project && (await smContext(c.env, principal, project.orgId));
  if (!project || !context) return errorResponse(c, 'Not found', 404);
  const access = projectAccess(context.actor, context.grants, id);
  if (counts)
    return context.actor.kind === 'serviceAccount'
      ? errorResponse(c, 'Not found', 404)
      : c.json(await smRepo(c.env.DB).projectCounts(project, access));
  if (access === 'none' || (c.req.raw.method === 'PUT' && access !== 'write'))
    return errorResponse(c, 'Not found', 404);
  if (c.req.raw.method === 'PUT') {
    const body = c.req.valid('json');
    project.name = body.name;
    project.updatedAt = new Date().toISOString();
    if (!(await smRepo(c.env.DB).updateProject(project))) return errorResponse(c, 'Not found', 404);
  }
  await recordEvents(c.env, c.req.raw, eventActor(principal), [
    {
      organizationId: project.orgId,
      type: c.req.raw.method === 'PUT' ? EventType.ProjectEdited : EventType.ProjectRetrieved,
      resourceType: 'project',
      resourceId: id,
    },
  ]);
  return c.json(projectResponse(project, access));
}

export async function handleDeleteProjects(c: BodyContext<typeof GuidsBody>): Promise<Response> {
  const { principal } = c.var;
  const ids = c.req.valid('json');
  if (!ids.length || new Set(ids).size !== ids.length) return errorResponse(c, 'Not found', 404);
  const projects = await smRepo(c.env.DB).getProjectsByIds(ids);
  const orgId = projects[0]?.orgId;
  if (!orgId || projects.length !== ids.length || projects.some((project) => project.orgId !== orgId))
    return errorResponse(c, 'Not found', 404);
  const context = await smContext(c.env, principal, orgId);
  if (!context) return errorResponse(c, 'Not found', 404);
  const data = ids.map((id) => ({
    id,
    error: projectAccess(context.actor, context.grants, id) === 'write' ? null : 'access denied',
    object: 'BulkDeleteResponseModel',
  }));
  const changed = await smRepo(c.env.DB).deleteProjects(
    orgId,
    data.filter((item) => !item.error).map((item) => item.id),
  );
  await recordEvents(
    c.env,
    c.req.raw,
    eventActor(principal),
    changed.map((resourceId) => ({
      organizationId: orgId,
      type: EventType.ProjectDeleted,
      resourceType: 'project',
      resourceId,
    })),
  );
  return c.json(listResponse(data));
}

function serviceAccountResponse(account: SmServiceAccount) {
  return {
    id: account.id,
    organizationId: account.orgId,
    name: account.name,
    creationDate: account.createdAt,
    revisionDate: account.updatedAt,
    object: 'serviceAccount',
  };
}

export async function handleListServiceAccounts(c: AppContext, orgId: string): Promise<Response> {
  const { principal } = c.var;
  const context = await smContext(c.env, principal, orgId);
  if (!context || context.actor.kind === 'serviceAccount') return errorResponse(c, 'Not found', 404);
  const counts = await smRepo(c.env.DB).serviceAccountSecretCounts(orgId);
  const accounts = (await smRepo(c.env.DB).listServiceAccounts(orgId)).filter(
    (account) => serviceAccountAccess(context.actor, context.grants, account.id) !== 'none',
  );
  return c.json(
    listResponse(
      accounts.map((account) => ({ ...serviceAccountResponse(account), accessToSecrets: counts.get(account.id) ?? 0 })),
    ),
  );
}

export async function handleCreateServiceAccount(c: BodyContext<typeof NameBody>, orgId: string): Promise<Response> {
  const { principal } = c.var;
  const context = await smContext(c.env, principal, orgId);
  if (!context || context.actor.kind === 'serviceAccount') return errorResponse(c, 'Not found', 404);
  const body = c.req.valid('json');
  const now = new Date().toISOString();
  const account = { id: crypto.randomUUID(), orgId, name: body.name, createdAt: now, updatedAt: now };
  await smRepo(c.env.DB).createServiceAccount(account, context.actor.membershipId);
  await recordEvents(c.env, c.req.raw, eventActor(principal), [
    { organizationId: orgId, type: EventType.ServiceAccountCreated, grantedServiceAccountId: account.id },
    {
      organizationId: orgId,
      type: EventType.ServiceAccountUserAdded,
      grantedServiceAccountId: account.id,
      resourceType: 'organizationUser',
      resourceId: context.actor.membershipId,
      userId: context.actor.membershipId,
    },
  ]);
  return c.json(serviceAccountResponse(account));
}

export async function handleServiceAccount(
  c: BodyContext<typeof NameBody>,
  id: string,
  counts = false,
): Promise<Response> {
  const { principal } = c.var;
  const account = await smRepo(c.env.DB).getServiceAccount(id);
  const context = account && (await smContext(c.env, principal, account.orgId));
  if (!account || !context || context.actor.kind === 'serviceAccount') return errorResponse(c, 'Not found', 404);
  const access = serviceAccountAccess(context.actor, context.grants, id);
  if (counts) return c.json(await smRepo(c.env.DB).serviceAccountCounts(account, access));
  if (access === 'none') return errorResponse(c, 'Not found', 404);
  if (c.req.raw.method === 'PUT') {
    const body = c.req.valid('json');
    account.name = body.name;
    account.updatedAt = new Date().toISOString();
    if (!(await smRepo(c.env.DB).updateServiceAccount(account))) return errorResponse(c, 'Not found', 404);
  }
  return c.json(serviceAccountResponse(account));
}

export async function handleDeleteServiceAccounts(c: BodyContext<typeof GuidsBody>): Promise<Response> {
  const { principal } = c.var;
  const ids = c.req.valid('json');
  if (!ids.length || new Set(ids).size !== ids.length) return errorResponse(c, 'Not found', 404);
  const accounts = await smRepo(c.env.DB).getServiceAccountsByIds(ids);
  const orgId = accounts[0]?.orgId;
  if (!orgId || accounts.length !== ids.length || accounts.some((account) => account.orgId !== orgId))
    return errorResponse(c, 'Not found', 404);
  const context = await smContext(c.env, principal, orgId);
  if (!context || context.actor.kind === 'serviceAccount') return errorResponse(c, 'Not found', 404);
  const data = accounts.map((account) => ({
    id: account.id,
    error: serviceAccountAccess(context.actor, context.grants, account.id) === 'write' ? null : 'access denied',
    object: 'BulkDeleteResponseModel',
  }));
  const changed = await smRepo(c.env.DB).deleteServiceAccounts(
    orgId,
    data.filter((item) => !item.error).map((item) => item.id),
  );
  await recordEvents(
    c.env,
    c.req.raw,
    eventActor(principal),
    changed.map((grantedServiceAccountId) => ({
      organizationId: orgId,
      type: EventType.ServiceAccountDeleted,
      grantedServiceAccountId,
    })),
  );
  return c.json(listResponse(data));
}

export async function handleRevokeAccessTokens(c: BodyContext<typeof IdsBody>, id: string): Promise<Response> {
  const { principal } = c.var;
  const account = await smRepo(c.env.DB).getServiceAccount(id);
  const context = account && (await smContext(c.env, principal, account.orgId));
  if (!context || serviceAccountAccess(context.actor, context.grants, id) !== 'write')
    return errorResponse(c, 'Not found', 404);
  const body = c.req.valid('json');
  await smRepo(c.env.DB).revokeAccessTokens(id, body.ids);
  return new Response(null, { status: 200 });
}

export async function handleSmCounts(c: AppContext, orgId: string): Promise<Response> {
  const { principal } = c.var;
  const context = await smContext(c.env, principal, orgId);
  if (!context || context.actor.kind === 'serviceAccount') return errorResponse(c, 'Not found', 404);
  const [projects, secrets, accounts] = await Promise.all([
    smRepo(c.env.DB).listProjects(orgId),
    smRepo(c.env.DB).listSecrets(orgId),
    smRepo(c.env.DB).listServiceAccounts(orgId),
  ]);
  return c.json({
    projects: projects.filter((row) => projectAccess(context.actor, context.grants, row.id) !== 'none').length,
    secrets: secrets.filter((row) => secretAccess(context.actor, context.grants, row) !== 'none').length,
    serviceAccounts: accounts.filter((row) => serviceAccountAccess(context.actor, context.grants, row.id) !== 'none')
      .length,
    object: 'organizationCounts',
  });
}

export async function handleCreateAccessToken(
  c: BodyContext<typeof AccessTokenBody>,
  serviceAccountId: string,
): Promise<Response> {
  const { principal } = c.var;
  const account = await smRepo(c.env.DB).getServiceAccount(serviceAccountId);
  const context = account && (await smContext(c.env, principal, account.orgId));
  if (!account || !context || serviceAccountAccess(context.actor, context.grants, account.id) !== 'write')
    return errorResponse(c, 'Not found', 404);
  const body = c.req.valid('json');
  const clientSecret = randomStringAlphanum(LIMITS.auth.clientSecretLength);
  const token = {
    id: crypto.randomUUID(),
    serviceAccountId,
    name: body.name,
    encryptedPayload: body.encryptedPayload,
    key: body.key,
    clientSecretHash: await hashApiKey(clientSecret),
    expireAt: body.expireAt ?? null,
    revokedAt: null,
    createdAt: new Date().toISOString(),
  };
  await smRepo(c.env.DB).saveAccessToken(token);
  return c.json({
    id: token.id,
    name: token.name,
    clientSecret,
    expireAt: token.expireAt,
    creationDate: token.createdAt,
    revisionDate: token.createdAt,
    object: 'accessTokenCreation',
  });
}

export async function handleListAccessTokens(c: AppContext, serviceAccountId: string): Promise<Response> {
  const { principal } = c.var;
  const account = await smRepo(c.env.DB).getServiceAccount(serviceAccountId);
  const context = account && (await smContext(c.env, principal, account.orgId));
  if (!context || serviceAccountAccess(context.actor, context.grants, serviceAccountId) !== 'write')
    return errorResponse(c, 'Not found', 404);
  const tokens = await smRepo(c.env.DB).listAccessTokens(serviceAccountId);
  return c.json(
    listResponse(
      tokens.map((token) => ({
        id: token.id,
        name: token.name,
        scopes: ['api.secrets'],
        expireAt: token.expireAt,
        creationDate: token.createdAt,
        revisionDate: token.createdAt,
        object: 'accessToken',
      })),
    ),
  );
}

export async function handleSmEvents(
  c: AppContext,
  kind: 'projects' | 'secrets' | 'service-account',
  id: string,
  orgId?: string,
): Promise<Response> {
  const { principal } = c.var;
  if (principal.kind === 'serviceAccount') return errorResponse(c, 'Not found', 404);
  const row =
    kind === 'projects'
      ? await smRepo(c.env.DB).getProject(id)
      : kind === 'secrets'
        ? await smRepo(c.env.DB).getSecret(id)
        : await smRepo(c.env.DB).getServiceAccount(id);
  if (orgId) {
    if (row && row.orgId !== orgId) return errorResponse(c, 'Not found', 404);
    const member = await orgRepo(c.env.DB).getMembershipByUserAndOrg(principal.user.id, orgId);
    // Upstream answers NotFound here too; official web treats 403 as a revoked token and logs out.
    if (!isActiveMember(member) || !canAccessEventLogs(member)) return errorResponse(c, 'Not found', 404);
    if (kind === 'secrets') {
      if (!row || ('deletedAt' in row && row.deletedAt)) {
        if (member.type !== MembershipType.Owner && member.type !== MembershipType.Admin)
          return errorResponse(c, 'Not found', 404);
      } else {
        const context = await smContext(c.env, principal, orgId);
        if (!context || !('projectIds' in row) || secretAccess(context.actor, context.grants, row) === 'none')
          return errorResponse(c, 'Not found', 404);
      }
    }
  } else {
    if (!row) return errorResponse(c, 'Not found', 404);
    orgId = row.orgId;
    const context = await smContext(c.env, principal, orgId);
    if (!context || serviceAccountAccess(context.actor, context.grants, id) === 'none')
      return errorResponse(c, 'Not found', 404);
  }
  return listEventsResponse(
    c,
    kind === 'service-account'
      ? { organizationId: orgId, serviceAccountId: id }
      : { organizationId: orgId, resourceType: kind === 'secrets' ? 'secret' : 'project', resourceId: id },
  );
}

export async function handleSecretsSync(c: AppContext, orgId: string): Promise<Response> {
  const { principal } = c.var;
  const lastSyncedDate = new URL(c.req.raw.url).searchParams.get('lastSyncedDate');
  const lastSynced = lastSyncedDate === null ? null : Date.parse(lastSyncedDate);
  if (lastSynced !== null && (!Number.isFinite(lastSynced) || lastSynced > Date.now()))
    return errorResponse(c, 'LastSyncedDate must be a valid date in the past.', 400);
  const context = await smContext(c.env, principal, orgId);
  if (!context) return errorResponse(c, 'Not found', 404);
  if (context.actor.kind !== 'serviceAccount') return errorResponse(c, 'Only service accounts can sync secrets.', 400);
  const account = await smRepo(c.env.DB).getServiceAccount(context.actor.serviceAccountId);
  if (!account) return errorResponse(c, 'Not found', 404);
  const hasChanges = lastSynced === null || lastSynced <= Date.parse(account.updatedAt);
  if (!hasChanges) return c.json({ hasChanges, secrets: null, object: 'secretsSync' });
  const names = await projectNames(c.env.DB, orgId);
  const secrets = (await smRepo(c.env.DB).listSecrets(orgId)).filter(
    (secret) => secretAccess(context.actor, context.grants, secret) !== 'none',
  );
  await recordEvents(
    c.env,
    c.req.raw,
    eventActor(principal),
    secrets.map((secret) => ({
      organizationId: orgId,
      type: EventType.SecretRetrieved,
      resourceType: 'secret',
      resourceId: secret.id,
    })),
  );
  return c.json({
    hasChanges,
    secrets: listResponse(secrets.map((secret) => secretResponse(secret, names, 'read', true))),
    object: 'secretsSync',
  });
}

export async function handleSecretsTrash(
  c: BodyContext<typeof GuidsBody>,
  orgId: string,
  action?: 'empty' | 'restore',
): Promise<Response> {
  const { principal } = c.var;
  const context = await smContext(c.env, principal, orgId);
  if (!context || context.actor.kind !== 'admin') return errorResponse(c, 'Not found', 404);
  if (!action)
    return c.json(
      await secretsListResponse(
        c.env,
        orgId,
        (await smRepo(c.env.DB).listSecrets(orgId, true)).filter((secret) => !!secret.deletedAt),
        context,
      ),
    );
  const ids = c.req.valid('json');
  if (!ids.length || new Set(ids).size !== ids.length) return errorResponse(c, 'Not found', 404);
  const secrets = await smRepo(c.env.DB).getSecretsByIds(ids);
  if (secrets.length !== ids.length || secrets.some((secret) => secret.orgId !== orgId || !secret.deletedAt))
    return errorResponse(c, 'Not found', 404);
  const changed = await smRepo(c.env.DB).changeSecretsTrash(orgId, ids, action === 'restore');
  await recordEvents(
    c.env,
    c.req.raw,
    eventActor(principal),
    changed.map((resourceId) => ({
      organizationId: orgId,
      type: action === 'restore' ? EventType.SecretRestored : EventType.SecretPermanentlyDeleted,
      resourceType: 'secret',
      resourceId,
    })),
  );
  return new Response(null, { status: 200 });
}
