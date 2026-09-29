import { verifyPassword } from '../services/auth-password';
import type { ContentfulStatusCode } from 'hono/utils/http-status';
import type { AppContext } from '../router';
import { z } from 'zod';
import { twoFactorProviders } from '../services/two-factor-providers';
import type { Env, User } from '../types';
import { LIMITS } from '../config/limits';
import { EventType, recordEvents } from '../services/events';
import {
  acceptInviteCheck,
  canAccessSecretsManager,
  canCreateCollection,
  canDeleteOrganization,
  canManageGroups,
  canManageMembers,
  canManagePolicies,
  canManageScim,
  canActOnCollection,
  type CollectionOperation,
  confirmMemberCheck,
  hasFullCollectionAccess,
  isActiveMember,
  type MemberCheck,
  memberCollectionsCheck,
  memberRemovalCheck,
  memberRoleChangeCheck,
  resolveCollectionPermission,
  resolvePermissions,
  restrictsEditingSelf,
} from '../services/org-authz';
import {
  clientMembershipType,
  MembershipStatus,
  MembershipType,
  type CollectionAccess,
  type CollectionRecord,
  type MembershipRecord,
  OrgPermissions,
  publicMembershipStatus,
} from '../services/org-types';
import { deleteOrganizationAccount } from '../services/account-deletion';
import { orgRepo, type CollectionAccessGrants, type OrgRepository } from '../services/storage-org-repo';
import { errorResponse, type BodyContext } from '../utils/response';
import { isUUID } from '../utils/uuid';
import { organizationResponse, policyResponse } from '../utils/org-response';
import { enterprisePlansResponse } from '../services/enterprise-license';
import { RateLimitService } from '../services/ratelimit';
import { hashApiKey, verifyApiKey } from '../utils/api-key';
import { createOrgInviteToken, verifyOrgInviteToken, ORG_INVITE_TTL_DAYS } from '../utils/jwt';
import { runInBackground } from '../services/mail-notify';
import {
  readMailConfig,
  mailStatusCheck,
  EMAIL_PATTERN,
  type StatusCheck,
  isReservedDocumentationEmail,
  configuredVaultOrigin,
  sendMail,
} from '../services/mail';
import { userRepo } from '../services/storage-user-repo';

// Official clients always wrap a member's org key with that member's RSA public key (EncString
// types 3-6). Any other type, such as a symmetric type 2, leaves the member unable to decrypt.
const MEMBER_ORG_KEY_PATTERN = /^[3-6]\./;

// Upstream StrictEmailAddressListAttribute on OrganizationUserInviteRequestModel.Emails. Every
// invite sends mail from EMAIL_FROM, so the batch is capped and bad addresses are rejected before
// any row is written.
const MAX_INVITE_EMAILS = 20;
const MAX_INVITE_EMAIL_LENGTH = 256;
// Clients post null or '' for unset text, so a blank value falls back to the stored one.
const optionalText = z.string().trim().nullish();
const requiredText = (message: string) => z.string({ error: message }).trim().min(1, { error: message });

export const OrganizationKeysRequest = z.object({ publicKey: optionalText, encryptedPrivateKey: optionalText });

export const CreateOrganizationRequest = z.object({
  name: requiredText('Name and key are required'),
  key: requiredText('Name and key are required'),
  billingEmail: optionalText,
  collectionName: optionalText,
  identifier: optionalText,
  keys: OrganizationKeysRequest.nullish(),
});

// Upstream CollectionAccessSelection; a flag that is not a boolean reads as false.
const accessFlag = z.boolean().catch(false);
const AccessSelection = z.object({
  id: z.string(),
  readOnly: accessFlag,
  hidePasswords: accessFlag,
  manage: accessFlag,
});
type AccessSelection = z.output<typeof AccessSelection>;

export const CollectionRequest = z.object({
  name: optionalText,
  externalId: optionalText,
  users: z.array(AccessSelection).nullish(),
  groups: z.array(AccessSelection).nullish(),
});

async function requireMember(c: AppContext, userId: string, orgId: string): Promise<MembershipRecord | Response> {
  const member = await orgRepo(c.env.DB).getMembershipByUserAndOrg(userId, orgId);
  if (!isActiveMember(member)) return errorResponse(c, 'Organization not found', 404);
  return member;
}

export async function createOwnedOrganization(
  db: D1Database,
  user: User,
  input: {
    name: string;
    billingEmail?: string;
    collectionName?: string;
    key: string;
    publicKey?: string | null;
    privateKey?: string | null;
    identifier?: string | null;
  },
) {
  const now = new Date().toISOString();
  const orgId = crypto.randomUUID();
  const org = {
    id: orgId,
    name: input.name,
    billingEmail: input.billingEmail || user.email,
    identifier: input.identifier || null,
    privateKey: input.privateKey || null,
    publicKey: input.publicKey || null,
    createdAt: now,
    updatedAt: now,
  };
  await orgRepo(db).insertOrganization(org);
  await orgRepo(db).saveMembership({
    id: crypto.randomUUID(),
    userId: user.id,
    orgId,
    email: user.email,
    invitedByEmail: null,
    accessAll: true,
    key: input.key,
    status: MembershipStatus.Confirmed,
    type: MembershipType.Owner,
    permissions: null,
    resetPasswordKey: null,
    externalId: null,
    createdAt: now,
    updatedAt: now,
  });
  await orgRepo(db).saveCollection({
    id: crypto.randomUUID(),
    orgId,
    name: input.collectionName || 'Default Collection',
    externalId: null,
    createdAt: now,
    updatedAt: now,
  });
  await orgRepo(db).bumpOrgMemberRevisions(orgId);
  return org;
}

export async function handleCreateOrganization(c: BodyContext<typeof CreateOrganizationRequest>): Promise<Response> {
  const { currentUser: user } = c.var;
  const body = c.req.valid('json');

  const org = await createOwnedOrganization(c.env.DB, user, {
    name: body.name,
    billingEmail: body.billingEmail || user.email,
    collectionName: body.collectionName || 'Default Collection',
    key: body.key,
    identifier: body.identifier || null,
    privateKey: body.keys?.encryptedPrivateKey || null,
    publicKey: body.keys?.publicKey || null,
  });
  return c.json(organizationResponse(org));
}

export async function handleGetOrganization(c: AppContext, orgId: string): Promise<Response> {
  const { userId } = c.var;
  const member = await requireMember(c, userId, orgId);
  if (member instanceof Response) return member;
  const org = await orgRepo(c.env.DB).getOrganization(orgId);
  if (!org) return errorResponse(c, 'Organization not found', 404);
  return c.json(organizationResponse(org));
}

export const UpdateOrganizationBody = z.object({ name: optionalText, billingEmail: optionalText });

export async function handleUpdateOrganization(
  c: BodyContext<typeof UpdateOrganizationBody>,
  orgId: string,
): Promise<Response> {
  const { userId } = c.var;
  const member = await requireMember(c, userId, orgId);
  if (member instanceof Response) return member;
  if (member.type > MembershipType.Admin) return errorResponse(c, 'Access denied', 403);
  const org = await orgRepo(c.env.DB).getOrganization(orgId);
  if (!org) return errorResponse(c, 'Organization not found', 404);
  const body = c.req.valid('json');
  const previousSettings = [org.name, org.billingEmail];
  org.name = body.name || org.name;
  org.billingEmail = body.billingEmail || org.billingEmail;
  org.updatedAt = new Date().toISOString();
  await orgRepo(c.env.DB).updateOrganization(org);
  if (org.name !== previousSettings[0] || org.billingEmail !== previousSettings[1]) {
    await recordEvents(c.env, c.req.raw, { userId }, [{ type: EventType.OrganizationUpdated, organizationId: orgId }]);
  }
  return c.json(organizationResponse(org));
}

export async function handleDeleteOrganization(c: AppContext, orgId: string): Promise<Response> {
  const { userId } = c.var;
  const member = await requireMember(c, userId, orgId);
  if (member instanceof Response) return member;
  if (!canDeleteOrganization(member)) return errorResponse(c, 'Only an owner can delete the organization', 403);
  await deleteOrganizationAccount(c.env, orgId, {
    actorUserId: userId,
    action: 'organization.delete',
    category: 'security',
    level: 'security',
    targetType: 'organization',
    targetId: orgId,
  });
  return c.json({});
}

export async function handleLeaveOrganization(c: AppContext, orgId: string): Promise<Response> {
  const { userId } = c.var;
  const member = await requireMember(c, userId, orgId);
  if (member instanceof Response) return member;
  if (member.type === MembershipType.Owner && (await orgRepo(c.env.DB).countConfirmedOwners(orgId)) <= 1) {
    return errorResponse(c, 'The last owner cannot leave', 400);
  }
  await orgRepo(c.env.DB).applyMembershipAction(orgId, [member.id], 'remove');
  await recordEvents(c.env, c.req.raw, { userId }, [
    {
      type: EventType.OrganizationUserLeft,
      organizationId: orgId,
      resourceType: 'organizationUser',
      resourceId: member.id,
      userId: member.userId,
    },
  ]);
  return c.json({});
}

export async function handlePostOrganizationKeys(
  c: BodyContext<typeof OrganizationKeysRequest>,
  orgId: string,
): Promise<Response> {
  const { userId } = c.var;
  const member = await requireMember(c, userId, orgId);
  if (member instanceof Response) return member;
  if (member.type > MembershipType.Admin) return errorResponse(c, 'Access denied', 403);
  const org = await orgRepo(c.env.DB).getOrganization(orgId);
  if (!org) return errorResponse(c, 'Organization not found', 404);
  const body = c.req.valid('json');
  const previousKeys = [org.publicKey, org.privateKey];
  org.publicKey = body.publicKey || org.publicKey;
  org.privateKey = body.encryptedPrivateKey || org.privateKey;
  org.updatedAt = new Date().toISOString();
  await orgRepo(c.env.DB).updateOrganization(org);
  if (org.publicKey !== previousKeys[0] || org.privateKey !== previousKeys[1]) {
    await recordEvents(c.env, c.req.raw, { userId }, [{ type: EventType.OrganizationUpdated, organizationId: orgId }]);
  }
  return c.json({ publicKey: org.publicKey, privateKey: org.privateKey, object: 'organizationKeys' });
}

export async function handleGetOrganizationKeys(c: AppContext, orgId: string): Promise<Response> {
  const { userId } = c.var;
  const member = await requireMember(c, userId, orgId);
  if (member instanceof Response) return member;
  const org = await orgRepo(c.env.DB).getOrganization(orgId);
  if (!org) return errorResponse(c, 'Organization not found', 404);
  return c.json({ publicKey: org.publicKey, privateKey: org.privateKey, object: 'organizationKeys' });
}

function collectionJson(
  collection: Awaited<ReturnType<OrgRepository['getCollection']>>,
  extra?: Record<string, unknown>,
) {
  if (!collection) return null;
  return {
    id: collection.id,
    organizationId: collection.orgId,
    name: collection.name,
    externalId: collection.externalId,
    type: 0,
    defaultUserCollectionEmail: null,
    object: extra ? 'collectionDetails' : 'collection',
    ...extra,
  };
}

export async function handleListAllCollections(c: AppContext): Promise<Response> {
  const { userId } = c.var;
  const memberships = await orgRepo(c.env.DB).listMembershipsByUser(userId);
  const data = [];
  for (const member of memberships) {
    if (!isActiveMember(member)) continue;
    const collections = await orgRepo(c.env.DB).listCollectionsByOrg(member.orgId);
    const assigned = await orgRepo(c.env.DB).listUserCollectionAccess(userId, member.orgId);
    const assignedMap = new Map(assigned.map((item) => [item.collectionId, item]));
    for (const collection of collections) {
      const permission = resolveCollectionPermission(member, assignedMap.get(collection.id) || null);
      if (!permission.canView && !hasFullCollectionAccess(member)) continue;
      data.push(
        collectionJson(collection, {
          readOnly: permission.readOnly,
          hidePasswords: permission.hidePasswords,
          manage: permission.manage,
        }),
      );
    }
  }
  return c.json({ data, object: 'list', continuationToken: null });
}

export async function handleListOrgCollections(c: AppContext, orgId: string): Promise<Response> {
  const { userId } = c.var;
  if (!orgId) return handleListAllCollections(c);
  const member = await requireMember(c, userId, orgId);
  if (member instanceof Response) return member;
  const collections = await orgRepo(c.env.DB).listCollectionsByOrg(orgId);
  const assigned = await orgRepo(c.env.DB).listUserCollectionAccess(userId, orgId);
  const assignedMap = new Map(assigned.map((item) => [item.collectionId, item]));
  const visible = collections.filter((collection) => hasFullCollectionAccess(member) || assignedMap.has(collection.id));
  return c.json({
    data: visible.map((collection) => collectionJson(collection)),
    object: 'list',
    continuationToken: null,
  });
}

const NO_ACCESS_GRANTS: CollectionAccessGrants = { users: [], groups: [] };
const NO_ACTOR_FLAGS = { readOnly: false, hidePasswords: false, manage: false };

// Upstream CollectionAccessDetailsResponseModel: the collection with the actor's own access and
// every member and group grant, which official web's collection dialog opens with and saves back
// whole. NodeWarden's sync lists every collection to Owners and Admins, so assigned and the actor's
// flags follow resolveCollectionPermission: the web drops a saved collection that is not assigned
// from the local store that sync fills.
function collectionAccessDetailsJson(
  collection: CollectionRecord,
  member: MembershipRecord,
  access: CollectionAccess | null,
  grants: CollectionAccessGrants,
) {
  const permission = resolveCollectionPermission(member, access);
  // Upstream aggregates the actor's own grants, so a reader holding none gets every flag false.
  const { readOnly, hidePasswords, manage } = permission.canView ? permission : NO_ACTOR_FLAGS;
  return collectionJson(collection, {
    readOnly,
    hidePasswords,
    manage,
    assigned: permission.canView,
    // As upstream, no member (invited ones included) or group holds Manage on the collection.
    unmanaged: ![...grants.users, ...grants.groups].some(({ manage }) => manage),
    users: grants.users,
    groups: grants.groups,
    object: 'collectionAccessDetails',
  });
}

async function actorCollectionAccess(
  db: D1Database,
  userId: string,
  orgId: string,
  collectionId: string,
): Promise<CollectionAccess | null> {
  return (
    (await orgRepo(db).listUserCollectionAccess(userId, orgId)).find((item) => item.collectionId === collectionId) ||
    null
  );
}

// Upstream GetManyWithDetails: every collection for those who may read all access, otherwise only
// the collections the member manages.
export async function handleListOrgCollectionDetails(c: AppContext, orgId: string): Promise<Response> {
  const { userId } = c.var;
  const member = await requireMember(c, userId, orgId);
  if (member instanceof Response) return member;
  const collections = await orgRepo(c.env.DB).listCollectionsByOrg(orgId);
  const accessById = new Map(
    (await orgRepo(c.env.DB).listUserCollectionAccess(userId, orgId)).map((item) => [item.collectionId, item]),
  );
  const grants = await orgRepo(c.env.DB).listCollectionAccessGrants(orgId);
  // The 9.0 member-access report maps grants in the client; AccessReports needs this bulk metadata
  // even though upstream's old collection gate omits it. Single-resource and write gates stay separate.
  const canReadReports = resolvePermissions(member).accessReports;
  const data = collections
    .filter(
      (collection) =>
        canReadReports || canActOnCollection(member, accessById.get(collection.id) || null, 'readAllWithAccess'),
    )
    .map((collection) =>
      collectionAccessDetailsJson(
        collection,
        member,
        accessById.get(collection.id) || null,
        grants.get(collection.id) || NO_ACCESS_GRANTS,
      ),
    );
  return c.json({ data, object: 'list', continuationToken: null });
}

// Upstream answers a missing collection and one the actor may not read or update with the same 404.
async function authorizedCollection(
  c: AppContext,
  userId: string,
  orgId: string,
  collectionId: string,
  operation: CollectionOperation,
): Promise<{ member: MembershipRecord; collection: CollectionRecord; access: CollectionAccess | null } | Response> {
  const member = await requireMember(c, userId, orgId);
  if (member instanceof Response) return member;
  const collection = await orgRepo(c.env.DB).getCollection(collectionId);
  const access = await actorCollectionAccess(c.env.DB, userId, orgId, collectionId);
  if (!collection || collection.orgId !== orgId || !canActOnCollection(member, access, operation)) {
    return errorResponse(c, 'Collection not found', 404);
  }
  return { member, collection, access };
}

async function collectionGrants(db: D1Database, orgId: string, collectionId: string): Promise<CollectionAccessGrants> {
  return (await orgRepo(db).listCollectionAccessGrants(orgId, collectionId)).get(collectionId) || NO_ACCESS_GRANTS;
}

export async function handleGetOrgCollectionDetails(
  c: AppContext,
  orgId: string,
  collectionId: string,
): Promise<Response> {
  const { userId } = c.var;
  const target = await authorizedCollection(c, userId, orgId, collectionId, 'readWithAccess');
  if (target instanceof Response) return target;
  const grants = await collectionGrants(c.env.DB, orgId, collectionId);
  return c.json(collectionAccessDetailsJson(target.collection, target.member, target.access, grants));
}

// Upstream GetUsers: a bare SelectionReadOnlyResponseModel array, not a list envelope.
export async function handleListOrgCollectionUsers(
  c: AppContext,
  orgId: string,
  collectionId: string,
): Promise<Response> {
  const { userId } = c.var;
  const target = await authorizedCollection(c, userId, orgId, collectionId, 'readAccess');
  if (target instanceof Response) return target;
  return c.json((await collectionGrants(c.env.DB, orgId, collectionId)).users);
}

// Upstream Post and Put answer with the saved collection's fresh access details when the actor may
// read them, and otherwise with the bare Collection constructor: no grants and every flag false.
async function savedCollectionJson(
  db: D1Database,
  userId: string,
  member: MembershipRecord,
  collection: CollectionRecord,
) {
  const access = await actorCollectionAccess(db, userId, collection.orgId, collection.id);
  if (canActOnCollection(member, access, 'readWithAccess')) {
    return collectionAccessDetailsJson(
      collection,
      member,
      access,
      await collectionGrants(db, collection.orgId, collection.id),
    );
  }
  return collectionJson(collection, {
    ...NO_ACTOR_FLAGS,
    assigned: false,
    unmanaged: false,
    users: null,
    groups: null,
    object: 'collectionAccessDetails',
  });
}

export const CreateOrgCollectionBody = CollectionRequest.extend({ name: requiredText('Name is required') });

export async function handleCreateOrgCollection(
  c: BodyContext<typeof CreateOrgCollectionBody>,
  orgId: string,
): Promise<Response> {
  const { userId } = c.var;
  const member = await requireMember(c, userId, orgId);
  if (member instanceof Response) return member;
  if (!canCreateCollection(member)) return errorResponse(c, 'Access denied', 403);
  const body = c.req.valid('json');
  const now = new Date().toISOString();
  const collection = {
    id: crypto.randomUUID(),
    orgId,
    name: body.name,
    externalId: body.externalId || null,
    createdAt: now,
    updatedAt: now,
  };
  await orgRepo(c.env.DB).saveCollection(collection);
  await applyCollectionAccess(c.env.DB, orgId, collection.id, body);
  await recordEvents(c.env, c.req.raw, { userId }, [
    { type: EventType.CollectionCreated, organizationId: orgId, resourceType: 'collection', resourceId: collection.id },
  ]);
  await orgRepo(c.env.DB).bumpOrgMemberRevisions(orgId);
  return c.json(await savedCollectionJson(c.env.DB, userId, member, collection));
}

export async function handleUpdateOrgCollection(
  c: BodyContext<typeof CollectionRequest>,
  orgId: string,
  collectionId: string,
): Promise<Response> {
  const { userId } = c.var;
  const target = await authorizedCollection(c, userId, orgId, collectionId, 'update');
  if (target instanceof Response) return target;
  const { member, collection } = target;
  const body = c.req.valid('json');
  const previousSettings = [collection.name, collection.externalId];
  collection.name = body.name || collection.name;
  collection.externalId = body.externalId || collection.externalId;
  collection.updatedAt = new Date().toISOString();
  await orgRepo(c.env.DB).saveCollection(collection);
  const accessChanged = await applyCollectionAccess(c.env.DB, collection.orgId, collection.id, body);
  if (accessChanged || collection.name !== previousSettings[0] || collection.externalId !== previousSettings[1]) {
    await recordEvents(c.env, c.req.raw, { userId }, [
      {
        type: EventType.CollectionUpdated,
        organizationId: orgId,
        resourceType: 'collection',
        resourceId: collection.id,
      },
    ]);
  }
  await orgRepo(c.env.DB).bumpOrgMemberRevisions(orgId);
  return c.json(await savedCollectionJson(c.env.DB, userId, member, collection));
}

export async function handleDeleteOrgCollection(c: AppContext, orgId: string, collectionId: string): Promise<Response> {
  const { userId } = c.var;
  const member = await requireMember(c, userId, orgId);
  if (member instanceof Response) return member;
  const collection = await orgRepo(c.env.DB).getCollection(collectionId);
  if (!collection || collection.orgId !== orgId) return errorResponse(c, 'Collection not found', 404);
  if (!hasFullCollectionAccess(member) && !resolvePermissions(member).deleteAnyCollection) {
    return errorResponse(c, 'Access denied', 403);
  }
  await orgRepo(c.env.DB).deleteCollection(collectionId);
  await recordEvents(c.env, c.req.raw, { userId }, [
    {
      type: EventType.CollectionDeleted,
      organizationId: collection.orgId,
      resourceType: 'collection',
      resourceId: collection.id,
    },
  ]);
  await orgRepo(c.env.DB).bumpOrgMemberRevisions(orgId);
  return c.json({});
}

// Membership and group ids come straight from the request body, so each posted entry is matched
// against the organization's own records and unknown ids are skipped. An omitted list stays undefined.
function grantedSelections<T extends { id: string }, R>(
  entries: AccessSelection[] | null | undefined,
  records: T[],
  grantee: (record: T) => R,
) {
  if (!entries) return undefined;
  const recordsById = new Map(records.map((record) => [record.id, record]));
  return entries.flatMap(({ id, ...flags }) => {
    const record = recordsById.get(id);
    return record ? [{ ...grantee(record), ...flags }] : [];
  });
}

function accessEventState(entries: unknown[]): string {
  return JSON.stringify(entries.map((entry) => JSON.stringify(entry, Object.keys(entry as object).sort())).sort());
}

// As upstream ReplaceAsync, an omitted list leaves that access as is and an empty one removes it,
// since official web's collection dialog always posts the full lists it opened with. The org's
// members and groups are read once rather than per entry, as every save posts back each grant.
async function applyCollectionAccess(
  db: D1Database,
  orgId: string,
  collectionId: string,
  { users, groups }: z.output<typeof CollectionRequest>,
): Promise<boolean> {
  if (!users && !groups) return false;
  const [members, groupRecords] = await Promise.all([
    users ? orgRepo(db).listMembershipsByOrg(orgId) : [],
    groups ? orgRepo(db).listGroupsByOrg(orgId) : [],
  ]);
  const previous = (await orgRepo(db).listCollectionAccessGrants(orgId, collectionId)).get(collectionId) ?? {
    users: [],
    groups: [],
  };
  const selection = {
    users: grantedSelections(users, members, (member) => ({ member })),
    groups: grantedSelections(groups, groupRecords, (group) => ({ groupId: group.id })),
  };
  await orgRepo(db).replaceCollectionAccess(collectionId, selection);
  return (
    (selection.users !== undefined &&
      accessEventState(previous.users) !==
        accessEventState(selection.users.map(({ member, ...flags }) => ({ id: member.id, ...flags })))) ||
    (selection.groups !== undefined &&
      accessEventState(previous.groups) !==
        accessEventState(selection.groups.map(({ groupId, ...flags }) => ({ id: groupId, ...flags }))))
  );
}

// Upstream deleted Manager (3), so EnumDataType on the request's Type rejects it like any unknown value.
const ASSIGNABLE_MEMBER_TYPES = Object.values(MembershipType).filter((type) => type !== MembershipType.Manager);

// The role, custom permissions, collections and groups that OrganizationUserInviteRequestModel and
// OrganizationUserUpdateRequestModel share. An omitted collections or groups list leaves that access as is.
const memberChangeFields = {
  type: z.literal(ASSIGNABLE_MEMBER_TYPES, {
    error: ({ input }) => (input == null ? 'The Type field is required.' : 'The field Type is invalid.'),
  }),
  permissions: OrgPermissions,
  collections: z.array(AccessSelection).nullish(),
  groups: z.array(z.string()).nullish(),
};
export const MemberUpdateRequest = z.object(memberChangeFields);

// Upstream checks the invited emails before the rest of the request.
export const MemberInviteRequest = z.object({
  emails: z
    .array(z.string())
    .nullish()
    .transform((emails) => (emails ?? []).map((email) => email.trim().toLowerCase()).filter(Boolean))
    .superRefine((emails, context) => {
      const message = !emails.length
        ? 'An email is required.'
        : emails.length > MAX_INVITE_EMAILS
          ? `You can only submit up to ${MAX_INVITE_EMAILS} emails at a time.`
          : // Upstream reports the first failing address, checking its format before its length.
            emails.flatMap((email, index) => {
              if (!EMAIL_PATTERN.test(email)) return [`Email #${index + 1} is not valid.`];
              if (email.length > MAX_INVITE_EMAIL_LENGTH)
                return [`Email #${index + 1} is longer than ${MAX_INVITE_EMAIL_LENGTH} characters.`];
              return [];
            })[0];
      if (message) context.addIssue({ code: 'custom', message });
    }),
  ...memberChangeFields,
});

type MemberChange =
  | { ok: true; type: number; permissions: OrgPermissions; collections?: CollectionAccess[]; groupIds?: string[] }
  | { ok: false; status: ContentfulStatusCode; message: string };

// Checks the requested collections and groups against the organization's own records.
async function readMemberChange(
  db: D1Database,
  orgId: string,
  body: z.output<typeof MemberUpdateRequest>,
): Promise<MemberChange> {
  const collections = body.collections?.map(({ id, ...flags }) => ({ collectionId: id, ...flags }));
  const groupIds = body.groups ?? undefined;
  // Upstream 735cc5db4: every id must belong to this organization, and missing or foreign ids fail
  // alike so the response cannot probe other organizations.
  const orgCollectionIds = new Set((await orgRepo(db).listCollectionsByOrg(orgId)).map((collection) => collection.id));
  const orgGroupIds = new Set((await orgRepo(db).listGroupsByOrg(orgId)).map((group) => group.id));
  const foreignCollection = collections?.some(({ collectionId }) => !orgCollectionIds.has(collectionId));
  if (foreignCollection || groupIds?.some((groupId) => !orgGroupIds.has(groupId))) {
    return { ok: false, status: 404, message: 'Resource not found.' };
  }
  // Upstream CollectionAccessSelection.Valid: Manage already includes seeing and editing every item.
  if (collections?.some(({ manage, readOnly, hidePasswords }) => manage && (readOnly || hidePasswords))) {
    return {
      ok: false,
      status: 400,
      message:
        'The Manage property is mutually exclusive and cannot be true while the ReadOnly or HidePasswords properties are also true.',
    };
  }
  return { ok: true, type: body.type, permissions: body.permissions, collections, groupIds };
}

// Loads what memberCollectionsCheck compares. An invite has no target yet, so it has no access to
// keep and no self-edit to restrict. An omitted list stays omitted.
async function authorizeMemberCollections(
  c: AppContext,
  actorUserId: string,
  actor: MembershipRecord,
  target: MembershipRecord | null,
  requested: CollectionAccess[] | undefined,
): Promise<CollectionAccess[] | undefined | Response> {
  if (!requested) return undefined;
  const check = memberCollectionsCheck({
    actor,
    actorAccess: await orgRepo(c.env.DB).listUserCollectionAccess(actorUserId, actor.orgId),
    requested,
    current: target ? await orgRepo(c.env.DB).listMemberCollectionAccess(target) : [],
    restrictSelf: !!target && restrictsEditingSelf(actor, target),
  });
  return check.ok ? check.collections : errorResponse(c, check.message, check.status);
}

// Upstream stores custom permissions only for the Custom role, so a demoted member keeps no stale grants.
function storedPermissions(change: { type: number; permissions: OrgPermissions }): OrgPermissions | null {
  return change.type === MembershipType.Custom ? change.permissions : null;
}

// The OrganizationUserUserMiniDetailsResponseModel fields, which the full member listing extends.
// Named after the bound account, with the invited email standing in until an account accepts.
function memberMiniDetails(item: MembershipRecord, account: Pick<User, 'name' | 'email'> | null) {
  return {
    id: item.id,
    userId: item.userId,
    type: clientMembershipType(item.type),
    status: publicMembershipStatus(item.status),
    name: account?.name || null,
    email: account?.email || item.email,
  };
}

export async function handleListMembers(c: AppContext, orgId: string, includeGroups = false): Promise<Response> {
  const { userId } = c.var;
  const member = await requireMember(c, userId, orgId);
  if (member instanceof Response) return member;
  const groupsByMember = includeGroups ? await orgRepo(c.env.DB).listMembershipGroupIdsByOrg(orgId) : null;
  const data = (await orgRepo(c.env.DB).listMembershipsWithAccountsByOrg(orgId)).map(
    ({ item, account, hasTwoFactorPasskey }) => ({
      ...memberMiniDetails(item, account),
      ...(groupsByMember ? { groups: groupsByMember.get(item.id) || [] } : {}),
      externalId: item.externalId,
      accessAll: item.accessAll,
      twoFactorEnabled: account ? twoFactorProviders(account, hasTwoFactorPasskey).length > 0 : false,
      resetPasswordEnrolled: !!item.resetPasswordKey,
      permissions: item.type === MembershipType.Custom ? resolvePermissions(item) : null,
      accessSecretsManager: canAccessSecretsManager(item),
      object: 'organizationUserUserDetails',
    }),
  );
  return c.json({ data, object: 'list', continuationToken: null });
}

// Upstream OrganizationUsersController.GetMiniDetails: open to every confirmed member because
// official web's collection, group, event log and sponsorship dialogs all look members up here,
// so it carries no keys, permissions or 2FA state.
export async function handleListMemberMiniDetails(c: AppContext, orgId: string): Promise<Response> {
  const { userId } = c.var;
  const member = await requireMember(c, userId, orgId);
  if (member instanceof Response) return member;
  const data = (await orgRepo(c.env.DB).listMembershipsWithAccountsByOrg(orgId)).map(({ item, account }) => ({
    ...memberMiniDetails(item, account),
    object: 'organizationUserUserMiniDetails',
  }));
  return c.json({ data, object: 'list', continuationToken: null });
}

// Upstream OrganizationUsersController.Get: the OrganizationUserDetailsResponseModel that official
// web's edit-member dialog loads with includeGroups=true before it can open.
export async function handleGetMember(c: AppContext, orgId: string, memberId: string): Promise<Response> {
  const { userId } = c.var;
  const actor = await requireMember(c, userId, orgId);
  if (actor instanceof Response) return actor;
  if (!canManageMembers(actor)) return errorResponse(c, 'Access denied', 403);
  const membership = await orgRepo(c.env.DB).getMembership(memberId);
  if (!membership || membership.orgId !== orgId) return errorResponse(c, 'Member not found', 404);
  const account = membership.userId ? await userRepo(c.env.DB).getUserById(membership.userId) : null;
  const type = clientMembershipType(membership.type);
  const collections = await orgRepo(c.env.DB).listMemberCollectionAccess(membership);
  const includeGroups = new URL(c.req.raw.url).searchParams.get('includeGroups') === 'true';
  return c.json({
    id: membership.id,
    userId: membership.userId,
    type,
    status: publicMembershipStatus(membership.status),
    externalId: membership.externalId,
    accessSecretsManager: canAccessSecretsManager(membership),
    accessPam: false,
    permissions: type === MembershipType.Custom ? resolvePermissions(membership) : null,
    resetPasswordEnrolled: !!membership.resetPasswordKey,
    usesKeyConnector: false,
    hasMasterPassword: !!account?.masterPasswordHash,
    claimedByOrganization: false,
    ssoExternalId: null,
    collections: collections.map(({ collectionId, ...flags }) => ({ id: collectionId, ...flags })),
    // Upstream omits groups unless asked for them.
    ...(includeGroups ? { groups: await orgRepo(c.env.DB).listMembershipGroupIds(membership.id) } : {}),
    creationDate: membership.createdAt,
    object: 'organizationUserDetails',
  });
}

export async function handleInviteMembers(
  c: BodyContext<typeof MemberInviteRequest>,
  orgId: string,
): Promise<Response> {
  const { currentUser: user } = c.var;
  const member = await requireMember(c, user.id, orgId);
  if (member instanceof Response) return member;
  if (!canManageMembers(member)) return errorResponse(c, 'Access denied', 403);
  const body = c.req.valid('json');
  const change = await readMemberChange(c.env.DB, orgId, body);
  if (!change.ok) return errorResponse(c, change.message, change.status);
  const collections = await authorizeMemberCollections(c, user.id, member, null, change.collections);
  if (collections instanceof Response) return collections;
  // Upstream InviteUsersAsync runs the same role guard; an invite has no current role, so the
  // requested one stands on both sides.
  const roleCheck = memberRoleChangeCheck(member, change.type, change.type, change.permissions, 'invite');
  if (!roleCheck.ok) return errorResponse(c, roleCheck.message, 400);
  // Upstream InviteUsersAsync invites each distinct address once and skips any address already in the
  // org by its invited or bound account email (SelectKnownEmailsAsync), so a re-invite neither mails
  // nor adds a row that accept would refuse. Nothing left to invite still succeeds, as upstream.
  const knownEmails = new Set(
    (await orgRepo(c.env.DB).listMembershipsWithAccountsByOrg(orgId)).flatMap(({ item, account }) => [
      item.email?.toLowerCase(),
      account?.email.toLowerCase(),
    ]),
  );
  const now = new Date().toISOString();
  // Upstream OrganizationService.InviteUsersAsync: every invite starts Invited and unbound, even for
  // an existing account, so the invitee stays hidden until they accept with the emailed token.
  const invites = [...new Set(body.emails)]
    .filter((email) => !knownEmails.has(email))
    .map((email) => ({ id: crypto.randomUUID(), email, invitedByEmail: user.email }));
  if (!invites.length) return c.json({});
  const mailed = await mailOrganizationInvites(c.req.raw, c.env, orgId, user.id, invites);
  if (!mailed.ok) return errorResponse(c, mailed.message, mailed.status, mailed.headers);
  await orgRepo(c.env.DB).insertInvitedMemberships(
    invites.map(({ id, email }) => ({
      id,
      userId: null,
      orgId,
      email,
      invitedByEmail: user.email,
      // Upstream's invite request has no AccessAll either; see handleEditMember.
      accessAll: false,
      key: '',
      status: MembershipStatus.Invited,
      type: change.type,
      permissions: storedPermissions(change),
      resetPasswordKey: null,
      externalId: null,
      createdAt: now,
      updatedAt: now,
    })),
    { ...change, collections },
  );
  await recordEvents(
    c.env,
    c.req.raw,
    { userId: user.id },
    invites.map((invite) => ({
      type: EventType.OrganizationUserInvited,
      organizationId: orgId,
      resourceType: 'organizationUser',
      resourceId: invite.id,
    })),
  );
  await orgRepo(c.env.DB).bumpOrgMemberRevisions(orgId);
  return c.json({});
}

// Upstream SendOrganizationInvitesCommand, shared by member invite, reinvite and SCIM provisioning:
// accept needs the emailed token, so every Invited row is mailed. Callers mail before saving, so a
// failed or refused send leaves no row behind (upstream deletes the rows it saved) and a retried
// request cannot pile up duplicates. Without mail configured the rows stay Invited and cannot be accepted yet.
// Any user can create an org and invite any address, so the mail spends a strict budget keyed by
// the inviter across all of their orgs (upstream throttles the invite endpoint per IP instead).
export async function mailOrganizationInvites(
  request: Request,
  env: Env,
  orgId: string,
  inviter: string,
  invites: Array<{ id: string; email: string; invitedByEmail?: string | null }>,
): Promise<StatusCheck> {
  const config = readMailConfig(env);
  if (config.kind !== 'enabled') return mailStatusCheck(config);
  const vaultOrigin = configuredVaultOrigin(request, env);
  if (!vaultOrigin) {
    console.warn('Organization invite email skipped: WEB_VAULT_ORIGINS is not set');
    return { ok: true };
  }

  // Documentation domains bounce and hurt sender reputation, as in register verification.
  const deliverable = invites.filter(({ email }) => !isReservedDocumentationEmail(email));
  const budget = await new RateLimitService(env).consumeStrictBudgetWithWindow(
    `org-invite-mail:${inviter}`,
    LIMITS.rateLimit.orgInviteEmailsPerHour,
    LIMITS.rateLimit.orgInviteEmailWindowSeconds,
    deliverable.length,
  );
  if (!budget.allowed) {
    return {
      ok: false,
      status: 429,
      message: `Rate limit exceeded. Try again in ${budget.retryAfterSeconds} seconds.`,
      headers: { 'Retry-After': String(budget.retryAfterSeconds) },
    };
  }
  const organization = await orgRepo(env.DB).getOrganization(orgId);
  const registered = await orgRepo(env.DB).listRegisteredEmails(deliverable.map(({ email }) => email));
  const expiresAt = Math.floor(Date.now() / 1000) + ORG_INVITE_TTL_DAYS * 86400;
  const outcomes = await Promise.all(
    deliverable.map(async ({ id, email, invitedByEmail }) =>
      sendMail(env, email, 'organizationInvite', {
        vaultOrigin,
        organizationId: orgId,
        organizationUserId: id,
        organizationName: organization?.name ?? '',
        email,
        token: await createOrgInviteToken(env.JWT_SECRET, id, email, expiresAt),
        hasExistingUser: registered.has(email),
        inviterEmail:
          !inviter.startsWith('scim:') && invitedByEmail && EMAIL_PATTERN.test(invitedByEmail)
            ? invitedByEmail
            : undefined,
        expiresAt: new Date(expiresAt * 1000).toISOString(),
      }),
    ),
  );
  for (const outcome of outcomes) {
    const check = mailStatusCheck(outcome);
    if (!check.ok) return check;
  }
  return { ok: true };
}

export const AcceptInviteBody = z.object({ token: requiredText('The Token field is required.') });

export async function handleAcceptInvite(
  c: BodyContext<typeof AcceptInviteBody>,
  orgId: string,
  memberId: string,
): Promise<Response> {
  const { currentUser: user } = c.var;
  const membership = await orgRepo(c.env.DB).getMembership(memberId);
  if (!membership || membership.orgId !== orgId) return errorResponse(c, 'Organization user mismatch', 404);
  // The emailed token is the only proof that this user owns the invited mailbox (upstream
  // OrganizationUserAcceptRequestModel.Token is [Required]).
  const body = c.req.valid('json');
  const tokenCheck = await verifyOrgInviteToken(body.token, c.env.JWT_SECRET, membership.id, membership.email);
  if (!tokenCheck.ok) return errorResponse(c, tokenCheck.message, 400);
  const organization = await orgRepo(c.env.DB).getOrganization(orgId);
  const check = acceptInviteCheck(
    membership,
    user.email,
    await orgRepo(c.env.DB).getMembershipByUserAndOrg(user.id, orgId),
    organization?.name ?? '',
  );
  if (!check.ok) return errorResponse(c, check.message, 400);
  await orgRepo(c.env.DB).saveAcceptedMembership({
    ...check.member,
    userId: user.id,
    email: user.email,
    status: MembershipStatus.Accepted,
    updatedAt: new Date().toISOString(),
  });
  // The invitee now sees the org in their profile, so their cached sync must refresh.
  await orgRepo(c.env.DB).bumpOrgMemberRevisions(orgId);
  runInBackground('organization-user-accepted', async () => {
    for (const { item, account } of await orgRepo(c.env.DB).listMembershipsWithAccountsByOrg(orgId)) {
      const email = account?.email || item.email;
      if (
        item.status !== MembershipStatus.Confirmed ||
        item.type > MembershipType.Admin ||
        item.userId === user.id ||
        !email
      )
        continue;
      await sendMail(c.env, email, 'organizationUserAccepted', {
        organizationName: organization?.name || '',
        memberName: user.name || user.email,
      });
    }
  });
  return c.json({});
}

function notifyConfirmedMembers(request: Request, env: Env, orgId: string, members: MembershipRecord[]): void {
  const vaultOrigin = configuredVaultOrigin(request, env);
  runInBackground('organization-user-confirmed', async () => {
    const ids = new Set(members.map((member) => member.id));
    const [organization, rows] = await Promise.all([
      orgRepo(env.DB).getOrganization(orgId),
      orgRepo(env.DB).listMembershipsWithAccountsByOrg(orgId),
    ]);
    for (const { item, account } of rows) {
      const email = account?.email || item.email;
      if (ids.has(item.id) && email)
        await sendMail(env, email, 'organizationUserConfirmed', {
          organizationName: organization?.name || '',
          vaultOrigin,
        });
    }
  });
}

// Upstream OrganizationUserBulkRequestModel.Ids is [Required, MinLength(1)] and defaults to an empty
// list, so an absent field fails MinLength and only an explicit null fails Required.
export const BulkIdsRequest = z.object({
  ids: z
    .array(z.string(), { error: 'The Ids field is required.' })
    .min(1, { error: "The field Ids must be a string or array type with a minimum length of '1'." })
    .prefault([]),
});

// Upstream OrganizationUserBulkResponseModel, whose object name is the same for every bulk member
// action. Official web counts an entry as done only when its error is the empty string.
function bulkResultsResponse(c: AppContext, results: Array<{ id: string; error: string }>): Response {
  return c.json({
    data: results.map((result) => ({ ...result, object: 'OrganizationBulkConfirmResponseModel' })),
    object: 'list',
    continuationToken: null,
  });
}

// Upstream OrganizationUsersController.UserPublicKeys: official web's bulk confirm dialog wraps the
// org key with each selected member's public key before it posts the confirm.
export async function handleListMemberPublicKeys(
  c: BodyContext<typeof BulkIdsRequest>,
  orgId: string,
): Promise<Response> {
  const { userId } = c.var;
  const actor = await requireMember(c, userId, orgId);
  if (actor instanceof Response) return actor;
  if (!canManageMembers(actor)) return errorResponse(c, 'Access denied', 403);
  const body = c.req.valid('json');
  const { ids } = body;
  const keys = await orgRepo(c.env.DB).listAcceptedMemberPublicKeys(orgId, ids);
  return c.json({
    data: keys.map(({ publicKey, ...member }) => ({
      ...member,
      key: publicKey,
      object: 'organizationUserPublicKeyResponseModel',
    })),
    object: 'list',
    continuationToken: null,
  });
}

export const ConfirmMemberBody = z.object({ key: requiredText('Key is required') });

export async function handleConfirmMember(
  c: BodyContext<typeof ConfirmMemberBody>,
  orgId: string,
  memberId: string,
): Promise<Response> {
  const { userId } = c.var;
  const actor = await requireMember(c, userId, orgId);
  if (actor instanceof Response) return actor;
  if (!canManageMembers(actor)) return errorResponse(c, 'Access denied', 403);
  const check = confirmMemberCheck(await orgRepo(c.env.DB).getMembership(memberId), orgId);
  if (!check.ok) return errorResponse(c, check.message, 400);
  const body = c.req.valid('json');
  const confirmed = confirmedWithKey(check, body.key);
  if (!confirmed.ok) return errorResponse(c, confirmed.message, 400);
  await orgRepo(c.env.DB).saveMembership(confirmed.member);
  await recordEvents(c.env, c.req.raw, { userId }, [
    {
      type: EventType.OrganizationUserConfirmed,
      organizationId: orgId,
      resourceType: 'organizationUser',
      resourceId: confirmed.member.id,
      userId: confirmed.member.userId,
    },
  ]);
  await orgRepo(c.env.DB).bumpOrgMemberRevisions(orgId);
  notifyConfirmedMembers(c.req.raw, c.env, orgId, [confirmed.member]);
  return c.json({});
}

// The row a passed confirmMemberCheck saves, once its org key is wrapped for the member.
function confirmedWithKey(check: MemberCheck, key: string): MemberCheck {
  if (!check.ok) return check;
  if (!MEMBER_ORG_KEY_PATTERN.test(key)) return { ok: false, message: 'Key is not a valid encrypted string.' };
  return {
    ok: true,
    member: { ...check.member, key, status: MembershipStatus.Confirmed, updatedAt: new Date().toISOString() },
  };
}

export const BulkConfirmMembersBody = z.object({
  keys: z.array(z.object({ id: z.string(), key: z.string().trim() }), { error: 'The Keys field is required.' }),
});

// Upstream BulkConfirm: each {id, key} entry is confirmed on its own and reports its own error, and
// the confirmed rows are saved together. Upstream drops entries it will not confirm; every entry
// gets a result here, and the org's rows are read once, so another org's member reads like an id
// that does not exist.
export async function handleBulkConfirmMembers(
  c: BodyContext<typeof BulkConfirmMembersBody>,
  orgId: string,
): Promise<Response> {
  const { userId } = c.var;
  const actor = await requireMember(c, userId, orgId);
  if (actor instanceof Response) return actor;
  if (!canManageMembers(actor)) return errorResponse(c, 'Access denied', 403);
  const body = c.req.valid('json');
  const membersById = new Map(
    (await orgRepo(c.env.DB).listMembershipsByOrg(orgId)).map((member) => [member.id, member]),
  );
  // Upstream's ToDictionary rejects a repeated id; here the last key sent for an id wins, so each
  // member is confirmed once.
  const keysById = new Map(body.keys.map(({ id, key }) => [id, key]));
  const results = [...keysById].map(([id, key]) => ({
    id,
    check: confirmedWithKey(confirmMemberCheck(membersById.get(id) ?? null, orgId), key),
  }));
  const confirmed = results.flatMap(({ check }) => (check.ok ? [check.member] : []));
  if (confirmed.length) {
    await orgRepo(c.env.DB).saveMemberships(confirmed);
    await recordEvents(
      c.env,
      c.req.raw,
      { userId },
      confirmed.map((member) => ({
        type: EventType.OrganizationUserConfirmed,
        organizationId: orgId,
        resourceType: 'organizationUser',
        resourceId: member.id,
        userId: member.userId,
      })),
    );
    await orgRepo(c.env.DB).bumpOrgMemberRevisions(orgId);
    notifyConfirmedMembers(c.req.raw, c.env, orgId, confirmed);
  }
  return bulkResultsResponse(
    c,
    results.map(({ id, check }) => ({ id, error: check.ok ? '' : check.message })),
  );
}

// Upstream ResendOrganizationInviteCommand and BulkResendOrganizationInvitesCommand only mail
// Invited rows of the org; an accepted, confirmed, revoked or staged row is "User invalid.".
const REINVITE_INVALID = 'User invalid.';

function isReinvitable(
  membership: MembershipRecord | null,
  orgId: string,
): membership is MembershipRecord & { email: string } {
  return membership?.status === MembershipStatus.Invited && membership.orgId === orgId && !!membership.email;
}

// A resend mails the row a fresh token through mailOrganizationInvites, so it spends the inviter's
// budget like an invite and recovers an invite whose token has expired.
export async function handleReinviteMember(c: AppContext, orgId: string, memberId: string): Promise<Response> {
  const { userId } = c.var;
  const actor = await requireMember(c, userId, orgId);
  if (actor instanceof Response) return actor;
  if (!canManageMembers(actor)) return errorResponse(c, 'Access denied', 403);
  const membership = await orgRepo(c.env.DB).getMembership(memberId);
  if (!isReinvitable(membership, orgId)) return errorResponse(c, REINVITE_INVALID, 400);
  const mailed = await mailOrganizationInvites(c.req.raw, c.env, orgId, userId, [membership]);
  if (!mailed.ok) return errorResponse(c, mailed.message, mailed.status, mailed.headers);
  return c.json({});
}

// Every requested id gets a result and the Invited rows go out in one budgeted send, so a batch
// over the budget mails nothing. Upstream drops missing ids and reports another org's rows; both
// read as "User invalid." here, since only the org's own rows are loaded.
export async function handleBulkReinviteMembers(
  c: BodyContext<typeof BulkIdsRequest>,
  orgId: string,
): Promise<Response> {
  const { userId } = c.var;
  const actor = await requireMember(c, userId, orgId);
  if (actor instanceof Response) return actor;
  if (!canManageMembers(actor)) return errorResponse(c, 'Access denied', 403);
  const body = c.req.valid('json');
  const { ids } = body;
  const membersById = new Map(
    (await orgRepo(c.env.DB).listMembershipsByOrg(orgId)).map((member) => [member.id, member]),
  );
  const targets = [...new Set(ids)].map((id) => ({ id, membership: membersById.get(id) ?? null }));
  const invites = targets.flatMap(({ membership }) => (isReinvitable(membership, orgId) ? [membership] : []));
  const mailed = await mailOrganizationInvites(c.req.raw, c.env, orgId, userId, invites);
  if (!mailed.ok) return errorResponse(c, mailed.message, mailed.status, mailed.headers);
  return bulkResultsResponse(
    c,
    targets.map(({ id, membership }) => ({ id, error: isReinvitable(membership, orgId) ? '' : REINVITE_INVALID })),
  );
}

export async function handleEditMember(
  c: BodyContext<typeof MemberUpdateRequest>,
  orgId: string,
  memberId: string,
): Promise<Response> {
  const { userId } = c.var;
  const actor = await requireMember(c, userId, orgId);
  if (actor instanceof Response) return actor;
  if (!canManageMembers(actor)) return errorResponse(c, 'Access denied', 403);
  const membership = await orgRepo(c.env.DB).getMembership(memberId);
  if (!membership || membership.orgId !== orgId) return errorResponse(c, 'Member not found', 404);
  const body = c.req.valid('json');
  const change = await readMemberChange(c.env.DB, orgId, body);
  if (!change.ok) return errorResponse(c, change.message, change.status);
  const collections = await authorizeMemberCollections(c, userId, actor, membership, change.collections);
  if (collections instanceof Response) return collections;
  const roleCheck = memberRoleChangeCheck(
    actor,
    clientMembershipType(membership.type),
    change.type,
    change.permissions,
    'update',
  );
  if (!roleCheck.ok) return errorResponse(c, roleCheck.message, 400);
  // Leaving Owner must leave another confirmed owner behind. Upstream HasConfirmedOwnersExceptAsync
  // does not count this member when it is a confirmed Owner itself.
  const isConfirmedOwner = membership.type === MembershipType.Owner && membership.status === MembershipStatus.Confirmed;
  if (
    change.type !== MembershipType.Owner &&
    !((await orgRepo(c.env.DB).countConfirmedOwners(membership.orgId)) > (isConfirmedOwner ? 1 : 0))
  ) {
    return errorResponse(c, 'Organization must have at least one confirmed owner.', 400);
  }
  const previousType = membership.type;
  const previousPermissions = JSON.stringify(membership.permissions);
  const previousAccessAll = membership.accessAll;
  const previousCollections = collections ? await orgRepo(c.env.DB).listMemberCollectionAccess(membership) : [];
  const previousGroups = change.groupIds ? await orgRepo(c.env.DB).listMembershipGroupIds(membership.id) : [];
  membership.type = change.type;
  membership.permissions = storedPermissions(change);
  // Upstream's update request has no AccessAll: Owners and Admins get full access from their type,
  // and a body flag would let a Custom manageUsers member grant every collection permission past
  // memberRoleChangeCheck. Clearing it also stops a demoted org creator keeping full access.
  membership.accessAll = false;
  membership.updatedAt = new Date().toISOString();
  // Upstream skips groups on a restricted self-edit rather than failing it, as groups carry collection access.
  const groupIds = restrictsEditingSelf(actor, membership) ? undefined : change.groupIds;
  await orgRepo(c.env.DB).saveMembershipWithAccess(membership, { collections, groupIds });
  const memberChanged =
    previousType !== membership.type ||
    previousPermissions !== JSON.stringify(membership.permissions) ||
    previousAccessAll !== membership.accessAll ||
    (collections !== undefined && accessEventState(previousCollections) !== accessEventState(collections));
  const groupsChanged =
    groupIds !== undefined &&
    JSON.stringify([...new Set(previousGroups)].sort()) !== JSON.stringify([...new Set(groupIds)].sort());
  // Upstream's member update logs OrganizationUser_Updated even when only groups change; it reserves
  // OrganizationUser_UpdatedGroups for the group endpoints.
  if (memberChanged || groupsChanged) {
    await recordEvents(c.env, c.req.raw, { userId }, [
      {
        type: EventType.OrganizationUserUpdated,
        organizationId: orgId,
        resourceType: 'organizationUser',
        resourceId: membership.id,
        userId: membership.userId,
      },
    ]);
  }
  await orgRepo(c.env.DB).bumpOrgMemberRevisions(orgId);
  return c.json({});
}

type MemberAction = 'remove' | 'revoke' | 'restore';

// One membership transition for any number of ids: per-id role checks, the last-confirmed-owner
// guard (an Owner can only be restored by another Owner), then one chunked batch and its events.
async function applyMemberAction(
  c: AppContext,
  userId: string,
  orgId: string,
  ids: string[],
  action: MemberAction,
): Promise<Array<{ id: string; error: string }> | Response> {
  const actor = await requireMember(c, userId, orgId);
  if (actor instanceof Response) return actor;
  if (!canManageMembers(actor)) return errorResponse(c, 'Access denied', 403);
  const members = await orgRepo(c.env.DB).listMembershipsByOrg(orgId);
  const byId = new Map(members.map((member) => [member.id, member]));
  const results = [...new Set(ids)].map((id) => {
    const member = byId.get(id);
    const check = member ? memberRemovalCheck(actor, member, action) : { ok: false as const, message: 'Invalid user.' };
    return { id, error: check.ok ? '' : check.message };
  });
  if (action !== 'restore') {
    const owners = new Set(
      members
        .filter((member) => member.type === MembershipType.Owner && isActiveMember(member))
        .map((member) => member.id),
    );
    const removedOwners = results.filter((result) => !result.error && owners.has(result.id));
    if (removedOwners.length && removedOwners.length === owners.size) {
      for (const result of removedOwners) result.error = 'Organization must have at least one confirmed owner.';
    }
  }
  const successful = results.filter((result) => !result.error);
  await orgRepo(c.env.DB).applyMembershipAction(
    orgId,
    successful.map((result) => result.id),
    action,
  );
  const type = {
    remove: EventType.OrganizationUserRemoved,
    revoke: EventType.OrganizationUserRevoked,
    restore: EventType.OrganizationUserRestored,
  }[action];
  await recordEvents(
    c.env,
    c.req.raw,
    { userId },
    successful.map(({ id }) => ({
      type,
      organizationId: orgId,
      resourceType: 'organizationUser',
      resourceId: id,
      userId: byId.get(id)!.userId,
    })),
  );
  return results;
}

export async function handleBulkMemberAction(
  c: BodyContext<typeof BulkIdsRequest>,
  orgId: string,
  action: MemberAction,
): Promise<Response> {
  const { userId } = c.var;
  const body = c.req.valid('json');
  const { ids } = body;
  if (!ids.every(isUUID)) return errorResponse(c, 'The Ids field must contain valid GUIDs.', 400);
  const results = await applyMemberAction(c, userId, orgId, ids, action);
  return results instanceof Response ? results : bulkResultsResponse(c, results);
}

export async function handleMemberAction(
  c: AppContext,
  orgId: string,
  memberId: string,
  action: MemberAction,
): Promise<Response> {
  const { userId } = c.var;
  const results = await applyMemberAction(c, userId, orgId, [memberId], action);
  if (results instanceof Response) return results;
  const [{ error }] = results;
  if (error === 'Invalid user.') return errorResponse(c, 'Member not found', 404);
  return error ? errorResponse(c, error, 400) : c.json({});
}

export async function handleListGroups(c: AppContext, orgId: string): Promise<Response> {
  const { userId } = c.var;
  const member = await requireMember(c, userId, orgId);
  if (member instanceof Response) return member;
  const groups = await orgRepo(c.env.DB).listGroupsByOrg(orgId);
  const data = [];
  for (const group of groups) {
    data.push({
      id: group.id,
      organizationId: group.orgId,
      name: group.name,
      accessAll: group.accessAll,
      externalId: group.externalId,
      collections: [],
      users: await orgRepo(c.env.DB).listGroupMemberIds(group.id),
      object: 'groupDetails',
    });
  }
  return c.json({ data, object: 'list', continuationToken: null });
}

export const SaveGroupBody = z.object({
  name: optionalText,
  accessAll: z.boolean().nullish(),
  externalId: optionalText,
  users: z.array(z.string()).nullish(),
});

export async function handleSaveGroup(
  c: BodyContext<typeof SaveGroupBody>,
  orgId: string,
  groupId?: string,
): Promise<Response> {
  const { userId } = c.var;
  const member = await requireMember(c, userId, orgId);
  if (member instanceof Response) return member;
  if (!canManageGroups(member)) return errorResponse(c, 'Access denied', 403);
  const body = c.req.valid('json');
  const now = new Date().toISOString();
  const existing = groupId ? await orgRepo(c.env.DB).getGroup(groupId) : null;
  if (groupId && (!existing || existing.orgId !== orgId)) return errorResponse(c, 'Group not found', 404);
  const users = body.users ?? [];
  // Upstream ValidateMemberAccessAsync: missing and foreign membership ids fail alike, before any
  // write, so the response cannot probe other organizations. Like upstream, skip it without users.
  const orgMemberships = users.length ? await orgRepo(c.env.DB).listMembershipsByOrg(orgId) : [];
  if (users.length) {
    const orgMembershipIds = new Set(orgMemberships.map((membership) => membership.id));
    if (users.some((id) => !orgMembershipIds.has(id))) return errorResponse(c, 'Resource not found.', 404);
  }
  const group = {
    id: existing?.id || crypto.randomUUID(),
    orgId,
    name: body.name || existing?.name || 'Group',
    accessAll: body.accessAll ?? existing?.accessAll ?? false,
    externalId: body.externalId || existing?.externalId || null,
    createdAt: existing?.createdAt || now,
    updatedAt: now,
  };
  const previousUsers = existing ? await orgRepo(c.env.DB).listGroupMemberIds(group.id) : [];
  await orgRepo(c.env.DB).saveGroup(group);
  if (users.length || !existing) await orgRepo(c.env.DB).replaceGroupMembers(group.id, users);
  const previousUserIds = new Set(previousUsers);
  const currentUserIds = new Set(users.length || !existing ? users : previousUsers);
  const changedUsers = orgMemberships.filter(
    (membership) => previousUserIds.has(membership.id) !== currentUserIds.has(membership.id),
  );
  const groupChanged =
    !existing ||
    changedUsers.length > 0 ||
    existing.name !== group.name ||
    existing.accessAll !== group.accessAll ||
    existing.externalId !== group.externalId;
  await recordEvents(c.env, c.req.raw, { userId }, [
    ...(groupChanged
      ? [
          {
            type: existing ? EventType.GroupUpdated : EventType.GroupCreated,
            organizationId: orgId,
            resourceType: 'group' as const,
            resourceId: group.id,
          },
        ]
      : []),
    ...changedUsers.map((membership) => ({
      type: EventType.OrganizationUserUpdatedGroups,
      organizationId: orgId,
      resourceType: 'organizationUser' as const,
      resourceId: membership.id,
      userId: membership.userId,
    })),
  ]);
  await orgRepo(c.env.DB).bumpOrgMemberRevisions(orgId);
  return c.json({
    id: group.id,
    organizationId: group.orgId,
    name: group.name,
    accessAll: group.accessAll,
    externalId: group.externalId,
    object: 'group',
  });
}

export async function handleDeleteGroup(c: AppContext, orgId: string, groupId: string): Promise<Response> {
  const { userId } = c.var;
  const member = await requireMember(c, userId, orgId);
  if (member instanceof Response) return member;
  if (!canManageGroups(member)) return errorResponse(c, 'Access denied', 403);
  const group = await orgRepo(c.env.DB).getGroup(groupId);
  if (!group || group.orgId !== orgId) return errorResponse(c, 'Group not found', 404);
  await orgRepo(c.env.DB).deleteGroup(groupId);
  await recordEvents(c.env, c.req.raw, { userId }, [
    { type: EventType.GroupDeleted, organizationId: group.orgId, resourceType: 'group', resourceId: group.id },
  ]);
  await orgRepo(c.env.DB).bumpOrgMemberRevisions(orgId);
  return c.json({});
}

export async function handleListPolicies(c: AppContext, orgId: string): Promise<Response> {
  const { userId } = c.var;
  const member = await requireMember(c, userId, orgId);
  if (member instanceof Response) return member;
  const policies = await orgRepo(c.env.DB).listPoliciesByOrg(orgId);
  return c.json({ data: policies.map(policyResponse), object: 'list', continuationToken: null });
}

// Official web's policy drawer loads one policy here. Upstream PolicyQuery synthesizes a disabled
// status with empty data when no row exists, so the drawer opens with the toggle off.
export async function handleGetPolicy(c: AppContext, orgId: string, policyType: number): Promise<Response> {
  const { userId } = c.var;
  const member = await requireMember(c, userId, orgId);
  if (member instanceof Response) return member;
  if (!canManagePolicies(member)) return errorResponse(c, 'Access denied', 403);
  const policy = await orgRepo(c.env.DB).getPolicy(orgId, policyType);
  return c.json(
    policy
      ? policyResponse(policy)
      : { organizationId: orgId, type: policyType, enabled: false, data: {}, object: 'policy' },
  );
}

// Official clients send SavePolicyRequest {policy:{enabled,data},metadata}; older clients
// still send the flat policy. Metadata only feeds upstream side effects we do not run. Upstream
// marks Policy [Required], so a malformed envelope is rejected instead of saving a disabled policy.
const policyState = z.object(
  {
    enabled: z.boolean().catch(false),
    data: z
      .record(z.string(), z.unknown())
      .nullish()
      .transform((data) => data ?? {}),
  },
  { error: 'The Policy field is required.' },
);
export const SavePolicyRequest = policyState
  .extend({ policy: policyState.optional() })
  .transform(({ policy, ...flat }) => policy ?? flat);

export async function handlePutPolicy(
  c: BodyContext<typeof SavePolicyRequest>,
  orgId: string,
  policyType: number,
): Promise<Response> {
  const { userId } = c.var;
  const member = await requireMember(c, userId, orgId);
  if (member instanceof Response) return member;
  if (!canManagePolicies(member)) return errorResponse(c, 'Access denied', 403);
  const source = c.req.valid('json');
  const existing = await orgRepo(c.env.DB).getPolicy(orgId, policyType);
  const policy = {
    id: existing?.id || crypto.randomUUID(),
    orgId,
    type: policyType,
    enabled: source.enabled,
    data: source.data,
    updatedAt: new Date().toISOString(),
  };
  await orgRepo(c.env.DB).savePolicy(policy);
  if (
    !existing ||
    existing.enabled !== policy.enabled ||
    JSON.stringify(existing.data) !== JSON.stringify(policy.data)
  ) {
    await recordEvents(c.env, c.req.raw, { userId }, [
      { type: EventType.PolicyUpdated, organizationId: orgId, resourceType: 'policy', resourceId: policy.id },
    ]);
  }
  await orgRepo(c.env.DB).bumpOrgMemberRevisions(orgId);
  return c.json(policyResponse(policy));
}

export async function handleGetPlans(c: AppContext): Promise<Response> {
  return c.json(enterprisePlansResponse());
}

// Bitwarden guards the organization API key endpoints with a SecretVerificationRequestModel,
// so re-authenticate the caller before minting a key instead of trusting the session alone. A sent
// masterPasswordHash wins over secret even when it is null.
export const SecretVerificationRequest = z
  .object({ masterPasswordHash: z.string().nullish(), secret: z.string().nullish() })
  .transform((body) => ('masterPasswordHash' in body ? body.masterPasswordHash : body.secret)?.trim() ?? '');

export async function handleOrgApiKey(
  c: BodyContext<typeof SecretVerificationRequest>,
  orgId: string,
  rotate: boolean,
): Promise<Response> {
  const { userId } = c.var;
  const member = await requireMember(c, userId, orgId);
  if (member instanceof Response) return member;
  if (member.type > MembershipType.Admin) return errorResponse(c, 'Access denied', 403);
  const secret = c.req.valid('json');
  if (!secret) return errorResponse(c, 'masterPasswordHash is required', 400);
  const user = await userRepo(c.env.DB).getUserById(userId);
  if (!user) return errorResponse(c, 'User not found', 404);
  if (!(await verifyPassword(secret, user.masterPasswordHash, user.email))) {
    return errorResponse(c, 'Invalid password', 400);
  }

  // Only the hash is persisted, so an existing key can never be displayed again:
  // a non-rotating read has nothing to hand back and must be rotated instead.
  const existing = await orgRepo(c.env.DB).getOrganizationApiKey(orgId);
  if (!rotate && existing) {
    return errorResponse(
      c,
      'The organization API key is only shown when it is created or rotated. Rotate it to get a new key.',
      409,
    );
  }

  const apiKey = crypto.randomUUID().replace(/-/g, '') + crypto.randomUUID().replace(/-/g, '');
  const revisionDate = new Date().toISOString();
  await orgRepo(c.env.DB).saveOrganizationApiKey({
    id: existing?.id || crypto.randomUUID(),
    orgId,
    type: 0,
    apiKeyHash: await hashApiKey(apiKey),
    revisionDate,
  });
  return c.json({ apiKey, revisionDate, object: 'organizationApiKey' });
}

export async function handleRotateScimKey(c: AppContext, orgId: string): Promise<Response> {
  const { userId } = c.var;
  const member = await requireMember(c, userId, orgId);
  if (member instanceof Response) return member;
  if (!canManageScim(member)) return errorResponse(c, 'Access denied', 403);
  const token = `scim.${orgId}.${crypto.randomUUID().replace(/-/g, '')}`;
  await orgRepo(c.env.DB).saveScimToken(orgId, await hashApiKey(token), new Date().toISOString());
  return c.json({ token, object: 'organizationScimKey' });
}

export async function verifyScimBearer(db: D1Database, orgId: string, authorization: string | null): Promise<boolean> {
  const token = String(authorization || '')
    .replace(/^Bearer\s+/i, '')
    .trim();
  if (!token) return false;
  const stored = await orgRepo(db).getScimTokenHash(orgId);
  if (!stored) return false;
  return verifyApiKey(token, stored);
}

export async function handleGetAutoEnrollStatus(c: AppContext, orgId: string): Promise<Response> {
  const { userId } = c.var;
  const member = await orgRepo(c.env.DB).getMembershipByUserAndOrg(userId, orgId);
  return c.json({
    id: orgId,
    resetPasswordEnabled: false,
    object: 'organizationAutoEnrollStatus',
    enrolled: !!member?.resetPasswordKey,
  });
}

export async function handleEnableSecretsManager(c: AppContext, orgId: string): Promise<Response> {
  const { userId } = c.var;
  const member = await requireMember(c, userId, orgId);
  if (member instanceof Response) return member;
  if (!canManageMembers(member)) return errorResponse(c, 'Access denied', 403);
  return new Response(null, { status: 200 });
}
