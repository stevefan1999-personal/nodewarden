import type { AppContext } from '../router';
import type { z } from 'zod';
import { and, eq } from 'drizzle-orm';
import type { BatchItem } from 'drizzle-orm/batch';
import { getOrm } from '../db/client';
import { orgGroupMembers, orgGroups } from '../db/schema';
import type { Env } from '../types';
import { MembershipStatus } from '../services/org-types';
import { orgRepo } from '../services/storage-org-repo';
import { smRepo, type SmPeopleTarget } from '../services/storage-secret-repo';
import {
  diffPolicies,
  parsePolicyRequests,
  projectAccess,
  secretAccess,
  serviceAccountAccess,
} from '../services/sm-authz';
import { errorResponse, type BodyContext } from '../utils/response';
import { listResponse, PolicyRequests, smContext } from './secrets-manager';
import { EventType, recordEvents, type EventInput } from '../services/events';

export async function peopleDirectory(db: D1Database, orgId: string, membershipId: string) {
  const [members, groups, ownGroups] = await Promise.all([
    orgRepo(db).listMembershipsWithAccountsByOrg(orgId),
    orgRepo(db).listGroupsByOrg(orgId),
    getOrm(db)
      .select({ id: orgGroups.id })
      .from(orgGroups)
      .innerJoin(orgGroupMembers, eq(orgGroupMembers.groupId, orgGroups.id))
      .where(and(eq(orgGroups.orgId, orgId), eq(orgGroupMembers.membershipId, membershipId))),
  ]);
  return { members, groups, ownGroups: new Set(ownGroups.map((row) => row.id)) };
}

export async function handlePotentialPeople(c: AppContext, orgId: string): Promise<Response> {
  const { principal } = c.var;
  const context = await smContext(c.env, principal, orgId);
  if (!context || context.actor.kind === 'serviceAccount') return errorResponse(c, 'Not found', 404);
  const membershipId = context.actor.membershipId;
  const { members, groups, ownGroups } = await peopleDirectory(c.env.DB, orgId, membershipId);
  return c.json(
    listResponse([
      ...members
        .filter(({ item }) => item.status === MembershipStatus.Confirmed)
        .map(({ item, account }) => ({
          id: item.id,
          name: account?.name || account?.email || item.email || '',
          email: account?.email || item.email,
          type: 'user',
          currentUser: item.id === membershipId,
          object: 'potentialGrantee',
        })),
      ...groups.map((group) => ({
        id: group.id,
        name: group.name,
        type: 'group',
        currentUserInGroup: ownGroups.has(group.id),
        object: 'potentialGrantee',
      })),
    ]),
  );
}

export async function peoplePolicyResponse(
  env: Env,
  kind: SmPeopleTarget,
  id: string,
  orgId: string,
  membershipId: string,
) {
  const [{ users, groups: policies }, directory] = await Promise.all([
    smRepo(env.DB).readPeoplePolicies(kind, id),
    peopleDirectory(env.DB, orgId, membershipId),
  ]);
  return {
    userAccessPolicies: directory.members
      .filter(({ item }) => users.has(item.id))
      .map(({ item, account }) => ({
        organizationUserId: item.id,
        organizationUserName: account?.name || account?.email || item.email || '',
        currentUser: item.id === membershipId,
        read: true,
        write: users.get(item.id) === 'write',
        object: 'userAccessPolicy',
      })),
    groupAccessPolicies: directory.groups
      .filter((group) => policies.has(group.id))
      .map((group) => ({
        groupId: group.id,
        groupName: group.name,
        currentUserInGroup: directory.ownGroups.has(group.id),
        read: true,
        write: policies.get(group.id) === 'write',
        object: 'groupAccessPolicy',
      })),
    object:
      kind === 'project'
        ? 'projectPeopleAccessPolicies'
        : kind === 'secret'
          ? 'secretAccessPolicies'
          : 'serviceAccountAccessPolicies',
  };
}

export async function handlePeoplePolicies(
  c: BodyContext<typeof PolicyRequests>,
  kind: 'project' | 'serviceAccount',
  id: string,
): Promise<Response> {
  const { principal } = c.var;
  const row = kind === 'project' ? await smRepo(c.env.DB).getProject(id) : await smRepo(c.env.DB).getServiceAccount(id);
  const context = row && (await smContext(c.env, principal, row.orgId));
  if (!row || !context || context.actor.kind === 'serviceAccount') return errorResponse(c, 'Not found', 404);
  const access =
    kind === 'project'
      ? projectAccess(context.actor, context.grants, id)
      : serviceAccountAccess(context.actor, context.grants, id);
  if (access !== 'write') return errorResponse(c, 'Not found', 404);
  if (c.req.raw.method === 'PUT') {
    const body = c.req.valid('json');
    const users = parsePolicyRequests(body.userAccessPolicyRequests ?? [], 'granteeId', kind === 'serviceAccount');
    const groups = parsePolicyRequests(body.groupAccessPolicyRequests ?? [], 'granteeId', kind === 'serviceAccount');
    if (!users.ok) return errorResponse(c, users.message, 400);
    if (!groups.ok) return errorResponse(c, groups.message, 400);
    const directory = await peopleDirectory(c.env.DB, row.orgId, context.actor.membershipId);
    const memberIds = new Set(directory.members.map(({ item }) => item.id));
    const groupIds = new Set(directory.groups.map((group) => group.id));
    if (
      [...users.value.keys()].some((id) => !memberIds.has(id)) ||
      [...groups.value.keys()].some((id) => !groupIds.has(id))
    )
      return errorResponse(c, 'Not found', 404);
    const current = await smRepo(c.env.DB).replacePeoplePolicies(kind, id, users.value, groups.value);
    if (kind === 'serviceAccount' && principal.kind === 'user') {
      const userChanges = diffPolicies(current.users, users.value);
      const groupChanges = diffPolicies(current.groups, groups.value);
      const events: EventInput[] = [
        ...userChanges.created.map((resourceId) => ({
          type: EventType.ServiceAccountUserAdded,
          resourceType: 'organizationUser' as const,
          resourceId,
        })),
        ...userChanges.deleted.map((resourceId) => ({
          type: EventType.ServiceAccountUserRemoved,
          resourceType: 'organizationUser' as const,
          resourceId,
        })),
        ...groupChanges.created.map((resourceId) => ({
          type: EventType.ServiceAccountGroupAdded,
          resourceType: 'group' as const,
          resourceId,
        })),
        ...groupChanges.deleted.map((resourceId) => ({
          type: EventType.ServiceAccountGroupRemoved,
          resourceType: 'group' as const,
          resourceId,
        })),
      ].map((event) => ({
        ...event,
        organizationId: row.orgId,
        grantedServiceAccountId: id,
        userId: event.resourceType === 'organizationUser' ? event.resourceId : undefined,
      }));
      await recordEvents(c.env, c.req.raw, { userId: principal.user.id }, events);
    }
  }
  return c.json(await peoplePolicyResponse(c.env, kind, id, row.orgId, context.actor.membershipId));
}

export async function handlePotentialMachines(
  c: AppContext,
  orgId: string,
  kind: 'projects' | 'serviceAccounts',
): Promise<Response> {
  const { principal } = c.var;
  const context = await smContext(c.env, principal, orgId);
  if (!context || context.actor.kind === 'serviceAccount') return errorResponse(c, 'Not found', 404);
  const rows =
    kind === 'projects'
      ? await smRepo(c.env.DB).listProjects(orgId)
      : await smRepo(c.env.DB).listServiceAccounts(orgId);
  const access = kind === 'projects' ? projectAccess : serviceAccountAccess;
  return c.json(
    listResponse(
      rows
        .filter((row) => access(context.actor, context.grants, row.id) === 'write')
        .map((row) => ({
          id: row.id,
          name: row.name,
          type: kind === 'projects' ? 'project' : 'serviceAccount',
          object: 'potentialGrantee',
        })),
    ),
  );
}

export function policyConflict(c: AppContext, error: unknown): Response | null {
  let cause: unknown = error;
  while (cause instanceof Error) {
    if (cause.message.includes('UNIQUE constraint failed: sm_'))
      return errorResponse(c, 'Access policy already exists.', 409);
    cause = cause.cause;
  }
  return null;
}

export async function handleMachinePolicies(
  c: BodyContext<typeof PolicyRequests>,
  kind: 'project' | 'serviceAccount',
  id: string,
): Promise<Response> {
  const { principal } = c.var;
  const row = kind === 'project' ? await smRepo(c.env.DB).getProject(id) : await smRepo(c.env.DB).getServiceAccount(id);
  const context = row && (await smContext(c.env, principal, row.orgId));
  if (!row || !context || context.actor.kind === 'serviceAccount') return errorResponse(c, 'Not found', 404);
  const access =
    kind === 'project'
      ? projectAccess(context.actor, context.grants, id)
      : serviceAccountAccess(context.actor, context.grants, id);
  if (access !== 'write') return errorResponse(c, 'Not found', 404);
  let policies =
    kind === 'project'
      ? await smRepo(c.env.DB).readProjectMachinePolicies(row.orgId, id)
      : await smRepo(c.env.DB).readGrantedProjects(row.orgId, id);
  if (c.req.raw.method === 'PUT') {
    const body = c.req.valid('json');
    const parsed = parsePolicyRequests(
      body[kind === 'project' ? 'serviceAccountAccessPolicyRequests' : 'projectGrantedPolicyRequests'],
      kind === 'project' ? 'granteeId' : 'grantedId',
      false,
    );
    if (!parsed.ok) return errorResponse(c, parsed.message, 400);
    const current = new Map(
      policies.map((policy) => [policy.id, policy.write_access ? ('write' as const) : ('read' as const)]),
    );
    const { created, updated, deleted } = diffPolicies(current, parsed.value);
    const known =
      kind === 'project'
        ? new Set((await smRepo(c.env.DB).listServiceAccounts(row.orgId)).map((account) => account.id))
        : await smRepo(c.env.DB).projectsInOrg(row.orgId, [...parsed.value.keys()]);
    if ([...parsed.value.keys()].some((id) => !known.has(id))) return errorResponse(c, 'Not found', 404);
    if (
      kind === 'project'
        ? created.some((id) => serviceAccountAccess(context.actor, context.grants, id) !== 'write')
        : [...created, ...updated, ...deleted].some(
            (id) => projectAccess(context.actor, context.grants, id) !== 'write',
          )
    )
      return errorResponse(c, 'Not found', 404);
    try {
      await getOrm(c.env.DB).batch([
        smRepo(c.env.DB).bumpServiceAccounts(row.orgId),
        ...smRepo(c.env.DB).policyDiffStatements(
          kind === 'project' ? 'projectServiceAccounts' : 'serviceAccountProjects',
          id,
          current,
          parsed.value,
        ),
      ]);
    } catch (error) {
      const conflict = policyConflict(c, error);
      if (conflict) return conflict;
      throw error;
    }
    policies =
      kind === 'project'
        ? await smRepo(c.env.DB).readProjectMachinePolicies(row.orgId, id)
        : await smRepo(c.env.DB).readGrantedProjects(row.orgId, id);
  }
  return c.json(
    kind === 'project'
      ? {
          serviceAccountAccessPolicies: policies.map((policy) => ({
            serviceAccountId: policy.id,
            serviceAccountName: policy.name,
            read: true,
            write: !!policy.write_access,
            object: 'serviceAccountProjectAccessPolicy',
          })),
          object: 'ProjectServiceAccountsAccessPolicies',
        }
      : {
          grantedProjectPolicies: policies.map((policy) => ({
            accessPolicy: {
              grantedProjectId: policy.id,
              grantedProjectName: policy.name,
              read: true,
              write: !!policy.write_access,
              object: 'grantedProjectAccessPolicy',
            },
            hasPermission: projectAccess(context.actor, context.grants, policy.id) === 'write',
            object: 'grantedProjectAccessPolicyPermissionDetails',
          })),
          object: 'ServiceAccountGrantedPoliciesPermissionDetails',
        },
  );
}

export async function prepareSecretPolicies(
  c: AppContext,
  context: NonNullable<Awaited<ReturnType<typeof smContext>>>,
  orgId: string,
  secretId: string,
  body: z.output<typeof PolicyRequests> | null | undefined,
  creating: boolean,
): Promise<BatchItem<'sqlite'>[] | Response> {
  if (body == null) return [];
  const users = parsePolicyRequests(body.userAccessPolicyRequests, 'granteeId', false);
  const groups = parsePolicyRequests(body.groupAccessPolicyRequests, 'granteeId', false);
  const accounts = parsePolicyRequests(body.serviceAccountAccessPolicyRequests, 'granteeId', false);
  if (!users.ok) return errorResponse(c, users.message, 400);
  if (!groups.ok) return errorResponse(c, groups.message, 400);
  if (!accounts.ok) return errorResponse(c, accounts.message, 400);
  if (context.actor.kind === 'serviceAccount')
    return users.value.size || groups.value.size || accounts.value.size ? errorResponse(c, 'Not found', 404) : [];
  const directory = await peopleDirectory(c.env.DB, orgId, context.actor.membershipId);
  const members = new Set(directory.members.map(({ item }) => item.id));
  const groupIds = new Set(directory.groups.map((group) => group.id));
  const machines = new Set((await smRepo(c.env.DB).listServiceAccounts(orgId)).map((account) => account.id));
  if (
    [...users.value.keys()].some((id) => !members.has(id)) ||
    [...groups.value.keys()].some((id) => !groupIds.has(id)) ||
    [...accounts.value.keys()].some((id) => !machines.has(id))
  )
    return errorResponse(c, 'Not found', 404);
  const current = creating
    ? { users: new Map(), groups: new Map() }
    : await smRepo(c.env.DB).readPeoplePolicies('secret', secretId);
  const currentAccounts = new Map(
    (creating ? [] : await smRepo(c.env.DB).readSecretMachinePolicies(orgId, secretId)).map((policy) => [
      policy.id,
      policy.write_access ? ('write' as const) : ('read' as const),
    ]),
  );
  if (
    diffPolicies(currentAccounts, accounts.value).created.some(
      (id) => serviceAccountAccess(context.actor, context.grants, id) !== 'write',
    )
  )
    return errorResponse(c, 'Not found', 404);
  return [
    ...smRepo(c.env.DB).policyDiffStatements('secretMembers', secretId, current.users, users.value),
    ...smRepo(c.env.DB).policyDiffStatements('secretGroups', secretId, current.groups, groups.value),
    ...smRepo(c.env.DB).policyDiffStatements('secretServiceAccounts', secretId, currentAccounts, accounts.value),
  ];
}

export async function handleSecretPolicies(c: AppContext, id: string): Promise<Response> {
  const { principal } = c.var;
  const secret = await smRepo(c.env.DB).getSecret(id);
  const context = secret && !secret.deletedAt && (await smContext(c.env, principal, secret.orgId));
  if (
    !secret ||
    !context ||
    context.actor.kind === 'serviceAccount' ||
    secretAccess(context.actor, context.grants, secret) !== 'write'
  )
    return errorResponse(c, 'Not found', 404);
  const people = await peoplePolicyResponse(c.env, 'secret', id, secret.orgId, context.actor.membershipId);
  const accounts = await smRepo(c.env.DB).readSecretMachinePolicies(secret.orgId, id);
  return c.json({
    ...people,
    serviceAccountAccessPolicies: accounts.map((policy) => ({
      serviceAccountId: policy.id,
      serviceAccountName: policy.name,
      read: true,
      write: !!policy.write_access,
      object: 'serviceAccountProjectAccessPolicy',
    })),
  });
}
