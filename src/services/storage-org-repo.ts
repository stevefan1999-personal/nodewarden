import { z } from 'zod';
import { and, asc, count, desc, eq, exists, gt, inArray, isNotNull, isNull, lte, or, type SQL } from 'drizzle-orm';
import type { BatchItem } from 'drizzle-orm/batch';
import { alias, type SQLiteTable } from 'drizzle-orm/sqlite-core';

import { chunkRows, columnCount, Repository, repository, statementChunks, type Orm } from '../db/client';
import {
  cipherCollections,
  ciphers,
  collectionGroups,
  collections,
  collectionUsers,
  organizationApiKeys,
  organizationMemberships,
  organizations,
  organizationScimTokens,
  orgGroupMembers,
  orgGroups,
  orgPolicies,
  pendingCollectionUsers,
  smProjects,
  smSecrets,
  smServiceAccounts,
  ssoAuth,
  ssoUsers,
  userRevisions,
  users,
} from '../db/schema';
import { bound, excluded, likeEscaped, lower, plus } from '../db/sql';
import type { Attachment, Cipher } from '../types';
import { hasFullCollectionAccess, type CollectionAssignmentPlan } from './org-authz';
import { attachmentRepo } from './storage-attachment-repo';
import { cipherRepo } from './storage-cipher-repo';
import { hasTwoFactorPasskey } from './two-factor-providers';
import {
  MembershipStatus,
  REVOKE_STATUS_OFFSET,
  type CollectionAccess,
  type CollectionRecord,
  type GroupRecord,
  type MembershipRecord,
  type OrganizationRecord,
  type PolicyRecord,
  jsonText,
  parsePermissions,
} from './org-types';

function mapMembership(row: typeof organizationMemberships.$inferSelect): MembershipRecord {
  return {
    id: row.id,
    userId: row.userId,
    orgId: row.orgId,
    email: row.email,
    invitedByEmail: row.invitedByEmail,
    accessAll: !!row.accessAll,
    key: row.key || '',
    status: Number(row.status),
    type: Number(row.type),
    permissions: parsePermissions(row.permissions),
    resetPasswordKey: row.resetPasswordKey,
    externalId: row.externalId,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

function mapGroup(row: typeof orgGroups.$inferSelect): GroupRecord {
  return {
    id: row.id,
    orgId: row.orgId,
    name: row.name,
    accessAll: !!row.accessAll,
    externalId: row.externalId,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

// A stored JSON object column; any other JSON value reads as empty.
const storedObject = z.record(z.string(), z.unknown()).catch({});

function mapPolicy(row: typeof orgPolicies.$inferSelect): PolicyRecord {
  return {
    id: row.id,
    orgId: row.orgId,
    type: Number(row.type),
    enabled: !!row.enabled,
    data: jsonText.pipe(storedObject).catch({}).parse(row.data),
    updatedAt: row.updatedAt,
  };
}

function mapAccess(row: {
  collectionId: string;
  readOnly: number;
  hidePasswords: number;
  manage: number;
}): CollectionAccess {
  return {
    collectionId: row.collectionId,
    readOnly: !!row.readOnly,
    hidePasswords: !!row.hidePasswords,
    manage: !!row.manage,
  };
}

function accessRow({ collectionId, readOnly, hidePasswords, manage }: CollectionAccess) {
  return { collectionId, readOnly: Number(readOnly), hidePasswords: Number(hidePasswords), manage: Number(manage) };
}

function membershipUpsert(orm: Orm, member: MembershipRecord) {
  const values = {
    id: member.id,
    userId: member.userId,
    orgId: member.orgId,
    email: member.email,
    invitedByEmail: member.invitedByEmail,
    accessAll: member.accessAll ? 1 : 0,
    key: member.key,
    status: member.status,
    type: member.type,
    permissions: member.permissions ? JSON.stringify(member.permissions) : null,
    resetPasswordKey: member.resetPasswordKey,
    externalId: member.externalId,
    createdAt: member.createdAt,
    updatedAt: member.updatedAt,
  };
  return orm
    .insert(organizationMemberships)
    .values(values)
    .onConflictDoUpdate({
      target: organizationMemberships.id,
      set: {
        userId: values.userId,
        email: values.email,
        invitedByEmail: values.invitedByEmail,
        accessAll: values.accessAll,
        key: values.key,
        status: values.status,
        type: values.type,
        permissions: values.permissions,
        resetPasswordKey: values.resetPasswordKey,
        externalId: values.externalId,
        updatedAt: values.updatedAt,
      },
    });
}

type AccessFlags = Omit<CollectionAccess, 'collectionId'>;

// A collection's direct member access (invited members included) and group access; an omitted list is left as is.
export interface CollectionAccessChange {
  users?: Array<AccessFlags & { member: MembershipRecord }>;
  groups?: Array<AccessFlags & { groupId: string }>;
}

// Upstream CollectionAccessSelection: one member (by membership id) or group granted a collection.
export interface CollectionAccessSelection extends AccessFlags {
  id: string;
}

export interface CollectionAccessGrants {
  users: CollectionAccessSelection[];
  groups: CollectionAccessSelection[];
}

type MemberGrant = CollectionAccess & { member: MembershipRecord };

// An invited member has no user for collection_users yet, so its direct access waits in
// pending_collection_users keyed by membership until accept binds a user. Each table gets as few
// multi-row INSERTs as the bound-parameter limit allows, since D1 also caps statements per invocation.
function memberAccessInserts(orm: Orm, grants: MemberGrant[]): BatchItem<'sqlite'>[] {
  const boundRows = grants.flatMap(({ member, ...access }) =>
    member.userId ? [{ ...accessRow(access), userId: member.userId }] : [],
  );
  const pendingRows = grants.flatMap(({ member, ...access }) =>
    member.userId ? [] : [{ ...accessRow(access), membershipId: member.id }],
  );
  return [
    ...chunkRows(boundRows, columnCount(collectionUsers)).map((chunk) =>
      orm.insert(collectionUsers).values(chunk).onConflictDoNothing(),
    ),
    ...chunkRows(pendingRows, columnCount(pendingCollectionUsers)).map((chunk) =>
      orm.insert(pendingCollectionUsers).values(chunk).onConflictDoNothing(),
    ),
  ];
}

function pendingAccessDelete(orm: Orm, membershipId: string) {
  return orm.delete(pendingCollectionUsers).where(eq(pendingCollectionUsers.membershipId, membershipId));
}

// collection_users has no membership key, so removing a member leaves these rows behind; they are
// cleared whenever the user's direct access to the org is replaced.
function userOrgAccessDelete(orm: Orm, userId: string, orgId: string) {
  const orgCollectionIds = orm.select({ id: collections.id }).from(collections).where(eq(collections.orgId, orgId));
  return orm
    .delete(collectionUsers)
    .where(and(eq(collectionUsers.userId, userId), inArray(collectionUsers.collectionId, orgCollectionIds)));
}

function membershipGroupInserts(orm: Orm, membershipId: string, groupIds: string[]) {
  return chunkRows(groupIds, columnCount(orgGroupMembers)).map((chunk) =>
    orm
      .insert(orgGroupMembers)
      .values(chunk.map((groupId) => ({ groupId, membershipId })))
      .onConflictDoNothing(),
  );
}

// A member's direct collection access and group ids; an omitted list is left as is.
export interface MemberAccessChange {
  collections?: CollectionAccess[];
  groupIds?: string[];
}

// Sets every listed cipher's collections to exactly collectionIds. Deletes and inserts span all
// ciphers so a bulk change adds a handful of statements, each within the bound-parameter limit.
function cipherCollectionReplacement(orm: Orm, cipherIds: string[], collectionIds: string[]): BatchItem<'sqlite'>[] {
  const links = cipherIds.flatMap((cipherId) => collectionIds.map((collectionId) => ({ cipherId, collectionId })));
  const unlink = (chunk: string[]) => orm.delete(cipherCollections).where(inArray(cipherCollections.cipherId, chunk));
  return [
    ...statementChunks(cipherIds, unlink).map(unlink),
    ...chunkRows(links, columnCount(cipherCollections)).map((chunk) =>
      orm.insert(cipherCollections).values(chunk).onConflictDoNothing(),
    ),
  ];
}

function mapOrgCipherRow(
  row: typeof ciphers.$inferSelect,
  userId: string,
  orgId: string,
  collectionIds: string[],
): Cipher | null {
  // Unparseable cipher data skips the row rather than serving it without its encrypted fields.
  const parsed = jsonText.pipe(storedObject).safeParse(row.data || '{}');
  if (!parsed.success) return null;
  return {
    ...(parsed.data as Cipher),
    id: row.id,
    userId: row.userId || userId,
    organizationId: row.organizationId || orgId,
    type: Number(row.type) || 1,
    folderId: row.folderId ?? null,
    name: row.name ?? null,
    notes: row.notes ?? null,
    favorite: !!row.favorite,
    reprompt: Number(row.reprompt || 0),
    key: row.key ?? null,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    archivedAt: row.archivedAt ?? null,
    deletedAt: row.deletedAt ?? null,
    collectionIds,
  };
}

export class OrgRepository extends Repository {
  async insertOrganization(org: OrganizationRecord): Promise<void> {
    await this.orm.insert(organizations).values({
      id: org.id,
      name: org.name,
      billingEmail: org.billingEmail,
      identifier: org.identifier,
      privateKey: org.privateKey,
      publicKey: org.publicKey,
      createdAt: org.createdAt,
      updatedAt: org.updatedAt,
    });
  }

  async updateOrganization(org: OrganizationRecord): Promise<void> {
    await this.orm
      .update(organizations)
      .set({
        name: org.name,
        billingEmail: org.billingEmail,
        identifier: org.identifier,
        privateKey: org.privateKey,
        publicKey: org.publicKey,
        updatedAt: org.updatedAt,
      })
      .where(eq(organizations.id, org.id));
  }

  async getOrganization(id: string): Promise<OrganizationRecord | null> {
    const [row] = await this.orm.select().from(organizations).where(eq(organizations.id, id)).limit(1);
    return row ?? null;
  }

  deleteOrganization(id: string) {
    return this.orm.delete(organizations).where(eq(organizations.id, id));
  }

  async saveMembership(member: MembershipRecord): Promise<void> {
    await membershipUpsert(this.orm, member);
  }

  // A bulk member change saves every row in one batch, so it lands whole or not at all. Callers pass
  // at least one row.
  // ponytail: one upsert per row, which counts against D1's per-invocation query limit; move to a
  // chunked multi-row upsert if bulk confirms grow past it.
  async saveMemberships(members: MembershipRecord[]): Promise<void> {
    const statements = members.map((member) => membershipUpsert(this.orm, member));
    await this.orm.batch(statements as [(typeof statements)[0], ...typeof statements]);
  }

  async getMembership(id: string): Promise<MembershipRecord | null> {
    const [row] = await this.orm
      .select()
      .from(organizationMemberships)
      .where(eq(organizationMemberships.id, id))
      .limit(1);
    return row ? mapMembership(row) : null;
  }

  async getMembershipByUserAndOrg(userId: string, orgId: string): Promise<MembershipRecord | null> {
    const [row] = await this.orm
      .select()
      .from(organizationMemberships)
      .where(and(eq(organizationMemberships.userId, userId), eq(organizationMemberships.orgId, orgId)))
      .limit(1);
    return row ? mapMembership(row) : null;
  }

  async listMembershipsByUser(userId: string): Promise<MembershipRecord[]> {
    const rows = await this.orm
      .select()
      .from(organizationMemberships)
      .where(eq(organizationMemberships.userId, userId))
      .orderBy(asc(organizationMemberships.createdAt));
    return rows.map(mapMembership);
  }

  async listMembershipsByOrg(orgId: string): Promise<MembershipRecord[]> {
    const rows = await this.orm
      .select()
      .from(organizationMemberships)
      .where(eq(organizationMemberships.orgId, orgId))
      .orderBy(asc(organizationMemberships.createdAt));
    return rows.map(mapMembership);
  }

  // Upstream OrganizationUserUserDetailsView: one LEFT JOIN rather than a user lookup per member,
  // which would hit the Workers per-invocation D1 query cap in large orgs. Invited rows have no account.
  async listMembershipsWithAccountsByOrg(orgId: string) {
    const rows = await this.orm
      .select({
        membership: organizationMemberships,
        account: {
          name: users.name,
          email: users.email,
          totpSecret: users.totpSecret,
          twoFactorEmail: users.twoFactorEmail,
          yubikeyKey1: users.yubikeyKey1,
          yubikeyKey2: users.yubikeyKey2,
          yubikeyKey3: users.yubikeyKey3,
          yubikeyKey4: users.yubikeyKey4,
          yubikeyKey5: users.yubikeyKey5,
        },
        hasTwoFactorPasskey: hasTwoFactorPasskey(this.orm),
      })
      .from(organizationMemberships)
      .leftJoin(users, eq(users.id, organizationMemberships.userId))
      .where(eq(organizationMemberships.orgId, orgId))
      .orderBy(asc(organizationMemberships.createdAt));
    return rows.map(({ membership, account, hasTwoFactorPasskey }) => ({
      item: mapMembership(membership),
      account,
      hasTwoFactorPasskey,
    }));
  }

  // Invite mail sends existing accounts to login instead of signup. One query per chunk of emails
  // rather than a user lookup per invitee, which ran alongside every send in the same invocation.
  async listRegisteredEmails(emails: string[]): Promise<Set<string>> {
    const read = (chunk: string[]) =>
      this.orm.select({ email: users.email }).from(users).where(inArray(users.email, chunk));
    const chunks = await Promise.all(statementChunks(emails, read).map(read));
    return new Set(chunks.flat().map(({ email }) => email));
  }

  // Bump revisions before deleting memberships so removed users also invalidate their cached sync.
  // The revision write and every chunk commit together, including a failed later chunk.
  async applyMembershipAction(orgId: string, ids: string[], action: 'remove' | 'revoke' | 'restore'): Promise<void> {
    if (!ids.length) return;
    const now = new Date().toISOString();
    const { orgId: memberOrgId, id: memberId, status } = organizationMemberships;
    // Revoking shifts a status REVOKE_STATUS_OFFSET below Revoked and restoring shifts it back. The guard
    // skips rows already on the target side, so repeating an action never shifts a status twice.
    const write = (chunk: string[]) => {
      const inOrg = and(eq(memberOrgId, orgId), inArray(memberId, chunk));
      return action === 'remove'
        ? this.orm.delete(organizationMemberships).where(inOrg)
        : this.orm
            .update(organizationMemberships)
            .set({
              status: plus(status, action === 'revoke' ? -REVOKE_STATUS_OFFSET : REVOKE_STATUS_OFFSET),
              updatedAt: now,
            })
            .where(
              and(
                inOrg,
                action === 'revoke' ? gt(status, MembershipStatus.Revoked) : lte(status, MembershipStatus.Revoked),
              ),
            );
    };
    const writes = statementChunks(ids, write).map(write);
    await this.orm.batch([this.bumpOrgMemberRevisions(orgId, now), ...writes]);
  }

  async countConfirmedOwners(orgId: string): Promise<number> {
    const [row] = await this.orm
      .select({ count: count() })
      .from(organizationMemberships)
      .where(
        and(
          eq(organizationMemberships.orgId, orgId),
          eq(organizationMemberships.type, 0),
          eq(organizationMemberships.status, 2),
        ),
      );
    return Number(row?.count || 0);
  }

  // Upstream User_ReadPublicKeysByOrganizationUserIds: only Accepted members are awaiting confirm,
  // so the bulk confirm dialog gets no keys for anyone else.
  async listAcceptedMemberPublicKeys(
    orgId: string,
    memberIds: string[],
  ): Promise<Array<{ id: string; userId: string; publicKey: string | null }>> {
    // The caller picks how many ids to send, so filter the org's Accepted members in memory instead
    // of binding the ids: one statement with two parameters, however long the list.
    const rows = await this.orm
      .select({ id: organizationMemberships.id, userId: users.id, publicKey: users.publicKey })
      .from(organizationMemberships)
      .innerJoin(users, eq(users.id, organizationMemberships.userId))
      .where(
        and(eq(organizationMemberships.orgId, orgId), eq(organizationMemberships.status, MembershipStatus.Accepted)),
      );
    const wanted = new Set(memberIds);
    return rows.filter(({ id }) => wanted.has(id));
  }

  async saveCollection(collection: CollectionRecord): Promise<void> {
    await this.orm
      .insert(collections)
      .values({
        id: collection.id,
        orgId: collection.orgId,
        name: collection.name,
        externalId: collection.externalId,
        createdAt: collection.createdAt,
        updatedAt: collection.updatedAt,
      })
      .onConflictDoUpdate({
        target: collections.id,
        set: {
          name: collection.name,
          externalId: collection.externalId,
          updatedAt: collection.updatedAt,
        },
      });
  }

  async getCollection(id: string): Promise<CollectionRecord | null> {
    const [row] = await this.orm.select().from(collections).where(eq(collections.id, id)).limit(1);
    return row ?? null;
  }

  async listCollectionsByOrg(orgId: string): Promise<CollectionRecord[]> {
    const rows = await this.orm
      .select()
      .from(collections)
      .where(eq(collections.orgId, orgId))
      .orderBy(asc(collections.createdAt));
    return rows;
  }

  async deleteCollection(id: string): Promise<void> {
    await this.orm.delete(collections).where(eq(collections.id, id));
  }

  // Replaces the given access lists in one batch with chunked inserts, so a save too large for one
  // statement cannot commit its deletes and then fail with the old grants gone.
  async replaceCollectionAccess(collectionId: string, change: CollectionAccessChange): Promise<void> {
    const groupRows = (change.groups ?? []).map(({ groupId, ...flags }) => ({
      ...accessRow({ ...flags, collectionId }),
      groupId,
    }));
    const statements = [
      ...(change.users
        ? [
            this.orm.delete(collectionUsers).where(eq(collectionUsers.collectionId, collectionId)),
            this.orm.delete(pendingCollectionUsers).where(eq(pendingCollectionUsers.collectionId, collectionId)),
            ...memberAccessInserts(
              this.orm,
              change.users.map((user) => ({ ...user, collectionId })),
            ),
          ]
        : []),
      ...(change.groups
        ? [
            this.orm.delete(collectionGroups).where(eq(collectionGroups.collectionId, collectionId)),
            ...chunkRows(groupRows, columnCount(collectionGroups)).map((chunk) =>
              this.orm.insert(collectionGroups).values(chunk).onConflictDoNothing(),
            ),
          ]
        : []),
    ];
    if (!statements.length) return;
    await this.orm.batch(statements as [(typeof statements)[0], ...typeof statements]);
  }

  async listCollectionUsers(collectionId: string): Promise<CollectionAccess[]> {
    const rows = await this.orm
      .select({
        userId: collectionUsers.userId,
        collectionId: collectionUsers.collectionId,
        readOnly: collectionUsers.readOnly,
        hidePasswords: collectionUsers.hidePasswords,
        manage: collectionUsers.manage,
      })
      .from(collectionUsers)
      .where(eq(collectionUsers.collectionId, collectionId));
    return rows.map((row) => ({
      ...mapAccess(row),
      userId: row.userId,
    })) as CollectionAccess[];
  }

  // Every member and group grant on the org's collections (or just one), keyed by collection, as
  // official web's collection dialog edits them. collection_users is keyed by user, so it joins that
  // user's membership in this org, which also skips rows a removed member left behind; invited
  // members' grants come from pending_collection_users.
  async listCollectionAccessGrants(orgId: string, collectionId?: string): Promise<Map<string, CollectionAccessGrants>> {
    const inScope = and(eq(collections.orgId, orgId), collectionId ? eq(collections.id, collectionId) : undefined);
    const [bound, pending, groups] = await Promise.all([
      this.orm
        .select({
          id: organizationMemberships.id,
          collectionId: collectionUsers.collectionId,
          readOnly: collectionUsers.readOnly,
          hidePasswords: collectionUsers.hidePasswords,
          manage: collectionUsers.manage,
        })
        .from(collectionUsers)
        .innerJoin(collections, eq(collections.id, collectionUsers.collectionId))
        .innerJoin(
          organizationMemberships,
          and(eq(organizationMemberships.userId, collectionUsers.userId), eq(organizationMemberships.orgId, orgId)),
        )
        .where(inScope),
      this.orm
        .select({
          id: pendingCollectionUsers.membershipId,
          collectionId: pendingCollectionUsers.collectionId,
          readOnly: pendingCollectionUsers.readOnly,
          hidePasswords: pendingCollectionUsers.hidePasswords,
          manage: pendingCollectionUsers.manage,
        })
        .from(pendingCollectionUsers)
        .innerJoin(collections, eq(collections.id, pendingCollectionUsers.collectionId))
        .where(inScope),
      this.orm
        .select({
          id: collectionGroups.groupId,
          collectionId: collectionGroups.collectionId,
          readOnly: collectionGroups.readOnly,
          hidePasswords: collectionGroups.hidePasswords,
          manage: collectionGroups.manage,
        })
        .from(collectionGroups)
        .innerJoin(collections, eq(collections.id, collectionGroups.collectionId))
        .where(inScope),
    ]);
    const grants = new Map<string, CollectionAccessGrants>();
    const add =
      (kind: keyof CollectionAccessGrants) =>
      ({ id, ...row }: (typeof groups)[number]) => {
        const { collectionId: grantedCollectionId, ...flags } = mapAccess(row);
        const entry = grants.get(grantedCollectionId) ?? { users: [], groups: [] };
        entry[kind].push({ id, ...flags });
        grants.set(grantedCollectionId, entry);
      };
    [...bound, ...pending].forEach(add('users'));
    groups.forEach(add('groups'));
    return grants;
  }

  async listUserCollectionAccess(userId: string, orgId: string): Promise<CollectionAccess[]> {
    const direct = await this.orm
      .select({
        collectionId: collectionUsers.collectionId,
        readOnly: collectionUsers.readOnly,
        hidePasswords: collectionUsers.hidePasswords,
        manage: collectionUsers.manage,
      })
      .from(collectionUsers)
      .innerJoin(collections, eq(collections.id, collectionUsers.collectionId))
      .where(and(eq(collectionUsers.userId, userId), eq(collections.orgId, orgId)));

    const groupRows = await this.orm
      .select({
        collectionId: collectionGroups.collectionId,
        readOnly: collectionGroups.readOnly,
        hidePasswords: collectionGroups.hidePasswords,
        manage: collectionGroups.manage,
      })
      .from(collectionGroups)
      .innerJoin(orgGroupMembers, eq(orgGroupMembers.groupId, collectionGroups.groupId))
      .innerJoin(organizationMemberships, eq(organizationMemberships.id, orgGroupMembers.membershipId))
      .innerJoin(collections, eq(collections.id, collectionGroups.collectionId))
      .where(and(eq(organizationMemberships.userId, userId), eq(collections.orgId, orgId)));

    const merged = new Map<string, CollectionAccess>();
    for (const access of [...direct, ...groupRows].map(mapAccess)) {
      const existing = merged.get(access.collectionId);
      if (!existing) {
        merged.set(access.collectionId, access);
        continue;
      }
      merged.set(access.collectionId, {
        collectionId: access.collectionId,
        readOnly: existing.readOnly && access.readOnly,
        hidePasswords: existing.hidePasswords && access.hidePasswords,
        manage: existing.manage || access.manage,
      });
    }
    return [...merged.values()];
  }

  // A member's direct collection access (group grants excluded), as the edit-member dialog shows it.
  async listMemberCollectionAccess(member: MembershipRecord): Promise<CollectionAccess[]> {
    const rows = member.userId
      ? await this.orm
          .select({
            collectionId: collectionUsers.collectionId,
            readOnly: collectionUsers.readOnly,
            hidePasswords: collectionUsers.hidePasswords,
            manage: collectionUsers.manage,
          })
          .from(collectionUsers)
          .innerJoin(collections, eq(collections.id, collectionUsers.collectionId))
          .where(and(eq(collectionUsers.userId, member.userId), eq(collections.orgId, member.orgId)))
      : await this.orm
          .select({
            collectionId: pendingCollectionUsers.collectionId,
            readOnly: pendingCollectionUsers.readOnly,
            hidePasswords: pendingCollectionUsers.hidePasswords,
            manage: pendingCollectionUsers.manage,
          })
          .from(pendingCollectionUsers)
          .where(eq(pendingCollectionUsers.membershipId, member.id));
    return rows.map(mapAccess);
  }

  // Saves a membership and replaces the given access lists in one batch, so a failed write cannot
  // leave the row changed while its access is not.
  async saveMembershipWithAccess(member: MembershipRecord, change: MemberAccessChange): Promise<void> {
    await this.orm.batch([
      membershipUpsert(this.orm, member),
      // New collections first clear the member's direct access to this org's collections. Pending rows are
      // always dropped, so once a user is bound the two tables never disagree.
      ...(change.collections
        ? [
            pendingAccessDelete(this.orm, member.id),
            ...(member.userId ? [userOrgAccessDelete(this.orm, member.userId, member.orgId)] : []),
            ...memberAccessInserts(
              this.orm,
              change.collections.map((access) => ({ ...access, member })),
            ),
          ]
        : []),
      ...(change.groupIds
        ? [
            this.orm.delete(orgGroupMembers).where(eq(orgGroupMembers.membershipId, member.id)),
            ...membershipGroupInserts(this.orm, member.id, change.groupIds),
          ]
        : []),
    ]);
  }

  // A bulk invite writes every new membership with its access in one batch: all or none are created,
  // and new rows have nothing to clear first. Memberships go first for the access rows' foreign keys.
  async insertInvitedMemberships(members: MembershipRecord[], change: MemberAccessChange): Promise<void> {
    const grants = members.flatMap((member) => (change.collections ?? []).map((access) => ({ ...access, member })));
    const statements = [
      ...members.map((member) => membershipUpsert(this.orm, member)),
      ...memberAccessInserts(this.orm, grants),
      ...members.flatMap((member) => membershipGroupInserts(this.orm, member.id, change.groupIds ?? [])),
    ];
    await this.orm.batch(statements as [(typeof statements)[0], ...typeof statements]);
  }

  // Accept binds a user to an invited membership and moves its pending access to collection_users.
  // The copy is an INSERT ... SELECT inside the batch, so a collection save between a separate read
  // and this write cannot be lost.
  async saveAcceptedMembership(member: MembershipRecord & { userId: string }): Promise<void> {
    const pendingAccess = this.orm
      .select({
        userId: bound(member.userId).as(collectionUsers.userId.name),
        collectionId: pendingCollectionUsers.collectionId,
        readOnly: pendingCollectionUsers.readOnly,
        hidePasswords: pendingCollectionUsers.hidePasswords,
        manage: pendingCollectionUsers.manage,
      })
      .from(pendingCollectionUsers)
      .where(eq(pendingCollectionUsers.membershipId, member.id));
    await this.orm.batch([
      membershipUpsert(this.orm, member),
      userOrgAccessDelete(this.orm, member.userId, member.orgId),
      this.orm.insert(collectionUsers).select(pendingAccess),
      pendingAccessDelete(this.orm, member.id),
    ]);
  }

  async replaceCipherCollections(cipherId: string, collectionIds: string[]): Promise<void> {
    const statements = cipherCollectionReplacement(this.orm, [cipherId], collectionIds);
    await this.orm.batch(statements as [(typeof statements)[0], ...typeof statements]);
  }

  // Applies a collection plan to one cipher in one batch.
  async updateCipherCollections(cipherId: string, plan: CollectionAssignmentPlan): Promise<void> {
    const unlink = (chunk: string[]) =>
      this.orm
        .delete(cipherCollections)
        .where(and(eq(cipherCollections.cipherId, cipherId), inArray(cipherCollections.collectionId, chunk)));
    const statements = [
      ...statementChunks(plan.remove, unlink).map(unlink),
      ...chunkRows(
        plan.insert.map((collectionId) => ({ cipherId, collectionId })),
        columnCount(cipherCollections),
      ).map((chunk) => this.orm.insert(cipherCollections).values(chunk).onConflictDoNothing()),
    ];
    if (!statements.length) return;
    await this.orm.batch(statements as [(typeof statements)[0], ...typeof statements]);
  }

  // Moves personal ciphers into an org in one batch, so no cipher lands in the org without its
  // collections or re-encrypted attachment keys, and a whole-vault transfer costs one D1 round trip.
  // ponytail: one statement per cipher in a single batch, bounded by the importItemLimit share cap;
  // split into bulkMoveChunkSize batches (atomic per chunk only) if D1 rejects batches that large.
  async shareCiphers(
    sharedCiphers: Cipher[],
    collectionIds: string[],
    changedAttachments: Attachment[],
  ): Promise<void> {
    const statements = [
      ...changedAttachments.map((attachment) => attachmentRepo(this.db).attachmentUpsert(attachment)),
      ...sharedCiphers.map((cipher) => cipherRepo(this.db).cipherUpsert(cipher)),
      ...cipherCollectionReplacement(
        this.orm,
        sharedCiphers.map((cipher) => cipher.id),
        collectionIds,
      ),
    ];
    await this.orm.batch(statements as [(typeof statements)[0], ...typeof statements]);
  }

  async listCipherCollectionIds(cipherId: string, orgId?: string): Promise<string[]> {
    const rows = await this.orm
      .select({ collectionId: cipherCollections.collectionId })
      .from(cipherCollections)
      .innerJoin(collections, eq(collections.id, cipherCollections.collectionId))
      .where(and(eq(cipherCollections.cipherId, cipherId), orgId ? eq(collections.orgId, orgId) : undefined));
    return rows.map((row) => row.collectionId);
  }

  async listCipherCollectionIdsByCipherIds(cipherIds: string[]): Promise<Map<string, string[]>> {
    const map = new Map<string, string[]>();
    if (cipherIds.length === 0) return map;
    const chunkSize = 90;
    for (let offset = 0; offset < cipherIds.length; offset += chunkSize) {
      const chunk = cipherIds.slice(offset, offset + chunkSize);
      const rows = await this.orm
        .select({
          cipherId: cipherCollections.cipherId,
          collectionId: cipherCollections.collectionId,
        })
        .from(cipherCollections)
        .where(inArray(cipherCollections.cipherId, chunk));
      for (const row of rows) {
        const list = map.get(row.cipherId) || [];
        list.push(row.collectionId);
        map.set(row.cipherId, list);
      }
    }
    return map;
  }

  private async listOrgCipherCollectionIds(orgId: string): Promise<Map<string, string[]>> {
    const rows = await this.orm
      .select({
        cipherId: cipherCollections.cipherId,
        collectionId: cipherCollections.collectionId,
      })
      .from(cipherCollections)
      .innerJoin(ciphers, eq(ciphers.id, cipherCollections.cipherId))
      .innerJoin(
        collections,
        and(eq(collections.id, cipherCollections.collectionId), eq(collections.orgId, ciphers.organizationId)),
      )
      .where(eq(ciphers.organizationId, orgId));
    const map = new Map<string, string[]>();
    for (const row of rows) {
      const list = map.get(row.cipherId);
      if (list) list.push(row.collectionId);
      else map.set(row.cipherId, [row.collectionId]);
    }
    return map;
  }

  async listAccessibleOrgCiphers(userId: string): Promise<Cipher[]> {
    const memberships = await this.listMembershipsByUser(userId);
    const confirmed = memberships.filter((member) => member.status === 2);
    if (confirmed.length === 0) return [];

    const orgCiphers: Cipher[] = [];
    for (const member of confirmed) {
      // Members without full access only reach ciphers in collections assigned to them
      // directly or through a group they belong to; everything else stays invisible.
      let rows: Array<typeof ciphers.$inferSelect>;
      if (hasFullCollectionAccess(member)) {
        rows = await this.orm
          .select()
          .from(ciphers)
          .where(eq(ciphers.organizationId, member.orgId))
          .orderBy(desc(ciphers.updatedAt));
      } else {
        const direct = this.orm
          .select({ collectionId: collectionUsers.collectionId })
          .from(collectionUsers)
          .where(eq(collectionUsers.userId, userId));
        const grouped = this.orm
          .select({ collectionId: collectionGroups.collectionId })
          .from(collectionGroups)
          .innerJoin(orgGroupMembers, eq(orgGroupMembers.groupId, collectionGroups.groupId))
          .where(eq(orgGroupMembers.membershipId, member.id));
        const joined = await this.orm
          .select({ cipher: ciphers })
          .from(ciphers)
          .innerJoin(cipherCollections, eq(cipherCollections.cipherId, ciphers.id))
          .where(
            and(
              eq(ciphers.organizationId, member.orgId),
              or(inArray(cipherCollections.collectionId, direct), inArray(cipherCollections.collectionId, grouped)),
            ),
          )
          .orderBy(desc(ciphers.updatedAt));

        // The join repeats a cipher once per allowed collection; keep its first row.
        const seen = new Set<string>();
        rows = [];
        for (const row of joined) {
          if (seen.has(row.cipher.id)) continue;
          seen.add(row.cipher.id);
          rows.push(row.cipher);
        }
      }

      if (rows.length === 0) continue;
      const collectionsByCipher = await this.listOrgCipherCollectionIds(member.orgId);
      for (const row of rows) {
        const cipher = mapOrgCipherRow(row, userId, member.orgId, collectionsByCipher.get(row.id) || []);
        if (cipher) orgCiphers.push(cipher);
      }
    }
    return orgCiphers;
  }

  async saveGroup(group: GroupRecord): Promise<void> {
    await this.orm
      .insert(orgGroups)
      .values({
        id: group.id,
        orgId: group.orgId,
        name: group.name,
        accessAll: group.accessAll ? 1 : 0,
        externalId: group.externalId,
        createdAt: group.createdAt,
        updatedAt: group.updatedAt,
      })
      .onConflictDoUpdate({
        target: orgGroups.id,
        set: {
          name: group.name,
          accessAll: group.accessAll ? 1 : 0,
          externalId: group.externalId,
          updatedAt: group.updatedAt,
        },
      });
  }

  async getGroup(id: string): Promise<GroupRecord | null> {
    const [row] = await this.orm.select().from(orgGroups).where(eq(orgGroups.id, id)).limit(1);
    return row ? mapGroup(row) : null;
  }

  async listGroupsByOrg(orgId: string): Promise<GroupRecord[]> {
    const rows = await this.orm.select().from(orgGroups).where(eq(orgGroups.orgId, orgId)).orderBy(asc(orgGroups.name));
    return rows.map(mapGroup);
  }

  async deleteGroup(id: string): Promise<void> {
    await this.orm.delete(orgGroups).where(eq(orgGroups.id, id));
  }

  async replaceGroupMembers(groupId: string, membershipIds: string[]): Promise<void> {
    await this.orm.delete(orgGroupMembers).where(eq(orgGroupMembers.groupId, groupId));
    if (membershipIds.length) {
      await this.orm
        .insert(orgGroupMembers)
        .values(membershipIds.map((membershipId) => ({ groupId, membershipId })))
        .onConflictDoNothing();
    }
  }

  async listGroupMemberIds(groupId: string): Promise<string[]> {
    const rows = await this.orm
      .select({ membershipId: orgGroupMembers.membershipId })
      .from(orgGroupMembers)
      .where(eq(orgGroupMembers.groupId, groupId));
    return rows.map((row) => row.membershipId);
  }

  async listMembershipGroupIds(membershipId: string): Promise<string[]> {
    const rows = await this.orm
      .select({ groupId: orgGroupMembers.groupId })
      .from(orgGroupMembers)
      .where(eq(orgGroupMembers.membershipId, membershipId));
    return rows.map((row) => row.groupId);
  }

  async savePolicy(policy: PolicyRecord): Promise<void> {
    await this.orm
      .insert(orgPolicies)
      .values({
        id: policy.id,
        orgId: policy.orgId,
        type: policy.type,
        enabled: policy.enabled ? 1 : 0,
        data: JSON.stringify(policy.data || {}),
        updatedAt: policy.updatedAt,
      })
      .onConflictDoUpdate({
        target: [orgPolicies.orgId, orgPolicies.type],
        set: {
          enabled: policy.enabled ? 1 : 0,
          data: JSON.stringify(policy.data || {}),
          updatedAt: policy.updatedAt,
        },
      });
  }

  async listPoliciesByOrg(orgId: string): Promise<PolicyRecord[]> {
    const rows = await this.orm.select().from(orgPolicies).where(eq(orgPolicies.orgId, orgId));
    return rows.map(mapPolicy);
  }

  async listEnabledPoliciesForUser(userId: string): Promise<PolicyRecord[]> {
    const rows = await this.orm
      .select({ policy: orgPolicies })
      .from(orgPolicies)
      .innerJoin(organizationMemberships, eq(organizationMemberships.orgId, orgPolicies.orgId))
      .where(
        and(
          eq(organizationMemberships.userId, userId),
          eq(organizationMemberships.status, 2),
          eq(orgPolicies.enabled, 1),
        ),
      );
    return rows.map((row) => mapPolicy(row.policy));
  }

  async getPolicy(orgId: string, type: number): Promise<PolicyRecord | null> {
    const [row] = await this.orm
      .select()
      .from(orgPolicies)
      .where(and(eq(orgPolicies.orgId, orgId), eq(orgPolicies.type, type)))
      .limit(1);
    return row ? mapPolicy(row) : null;
  }

  // The api_key column holds a one-way hash only; the plaintext key is shown once at mint time.
  async saveOrganizationApiKey(row: {
    id: string;
    orgId: string;
    type: number;
    apiKeyHash: string;
    revisionDate: string;
  }): Promise<void> {
    await this.orm
      .insert(organizationApiKeys)
      .values({
        id: row.id,
        orgId: row.orgId,
        type: row.type,
        apiKey: row.apiKeyHash,
        revisionDate: row.revisionDate,
      })
      .onConflictDoUpdate({
        target: organizationApiKeys.id,
        set: { apiKey: row.apiKeyHash, revisionDate: row.revisionDate },
      });
  }

  async getOrganizationApiKey(orgId: string): Promise<{ id: string; apiKeyHash: string } | null> {
    const [row] = await this.orm
      .select({ id: organizationApiKeys.id, apiKey: organizationApiKeys.apiKey })
      .from(organizationApiKeys)
      .where(eq(organizationApiKeys.orgId, orgId))
      .orderBy(desc(organizationApiKeys.revisionDate))
      .limit(1);
    return row ? { id: row.id, apiKeyHash: row.apiKey } : null;
  }

  async saveScimToken(orgId: string, tokenHash: string, createdAt: string): Promise<void> {
    await this.orm.insert(organizationScimTokens).values({ orgId, tokenHash, createdAt }).onConflictDoUpdate({
      target: organizationScimTokens.orgId,
      set: { tokenHash, createdAt },
    });
  }

  async getScimTokenHash(orgId: string): Promise<string | null> {
    const [row] = await this.orm
      .select({ tokenHash: organizationScimTokens.tokenHash })
      .from(organizationScimTokens)
      .where(eq(organizationScimTokens.orgId, orgId))
      .limit(1);
    return row?.tokenHash || null;
  }

  async saveSsoAuth(row: {
    state: string;
    codeChallenge: string | null;
    redirectUri: string;
    clientId: string;
    bindingHash: string | null;
    identifier?: string | null;
    codeResponse?: string | null;
    codeResponseError?: string | null;
    createdAt: string;
    updatedAt: string;
  }): Promise<void> {
    const values = {
      state: row.state,
      codeChallenge: row.codeChallenge,
      redirectUri: row.redirectUri,
      clientId: row.clientId,
      bindingHash: row.bindingHash,
      identifier: row.identifier || null,
      codeResponse: row.codeResponse || null,
      codeResponseError: row.codeResponseError || null,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
    };
    await this.orm
      .insert(ssoAuth)
      .values(values)
      .onConflictDoUpdate({
        target: ssoAuth.state,
        set: {
          codeChallenge: values.codeChallenge,
          redirectUri: values.redirectUri,
          clientId: values.clientId,
          bindingHash: values.bindingHash,
          identifier: values.identifier,
          codeResponse: values.codeResponse,
          codeResponseError: values.codeResponseError,
          updatedAt: values.updatedAt,
        },
      });
  }

  async getSsoAuth(state: string): Promise<{
    state: string;
    codeChallenge: string | null;
    redirectUri: string;
    clientId: string;
    bindingHash: string | null;
    identifier: string | null;
    codeResponse: string | null;
    codeResponseError: string | null;
  } | null> {
    const [row] = await this.orm.select().from(ssoAuth).where(eq(ssoAuth.state, state)).limit(1);
    if (!row) return null;
    return {
      state: row.state,
      codeChallenge: row.codeChallenge,
      redirectUri: row.redirectUri,
      clientId: row.clientId,
      bindingHash: row.bindingHash,
      identifier: row.identifier,
      codeResponse: row.codeResponse,
      codeResponseError: row.codeResponseError,
    };
  }

  async saveSsoUser(userId: string, identifier: string, createdAt: string): Promise<void> {
    await this.orm.insert(ssoUsers).values({ userId, identifier, createdAt }).onConflictDoUpdate({
      target: ssoUsers.userId,
      set: { identifier },
    });
  }

  async getSsoUserByIdentifier(identifier: string): Promise<{ userId: string; identifier: string } | null> {
    const [row] = await this.orm
      .select({ userId: ssoUsers.userId, identifier: ssoUsers.identifier })
      .from(ssoUsers)
      .where(eq(ssoUsers.identifier, identifier))
      .limit(1);
    return row ?? null;
  }

  bumpOrgMemberRevisions(orgId: string, now = new Date().toISOString()) {
    return this.orm
      .insert(userRevisions)
      .select(
        this.orm
          .select({
            userId: organizationMemberships.userId,
            revisionDate: bound(now).as(userRevisions.revisionDate.name),
          })
          .from(organizationMemberships)
          .where(and(eq(organizationMemberships.orgId, orgId), isNotNull(organizationMemberships.userId))),
      )
      .onConflictDoUpdate({
        target: userRevisions.userId,
        set: { revisionDate: excluded(userRevisions.revisionDate) },
      });
  }

  async searchOrganizations(options: { nameContains: string; memberEmail: string; offset: number; limit: number }) {
    const pattern = '%' + options.nameContains.replace(/[\\%_]/g, (value) => `\\${value}`) + '%';
    const member = alias(organizationMemberships, 'm');
    const memberAccount = alias(users, 'u');
    const loweredEmail = lower(options.memberEmail);
    const rows = await this.orm
      .select()
      .from(organizations)
      .where(
        and(
          likeEscaped(organizations.name, pattern),
          // SQL lower() on both sides, not toLowerCase(): the two fold non-ASCII letters differently.
          options.memberEmail
            ? exists(
                this.orm
                  .select({ id: member.id })
                  .from(member)
                  .leftJoin(memberAccount, eq(memberAccount.id, member.userId))
                  .where(
                    and(
                      eq(member.orgId, organizations.id),
                      or(eq(lower(member.email), loweredEmail), eq(lower(memberAccount.email), loweredEmail)),
                    ),
                  ),
              )
            : undefined,
        ),
      )
      .orderBy(asc(organizations.createdAt), asc(organizations.id))
      .limit(options.limit + 1)
      .offset(options.offset);
    return rows;
  }

  async getOrganizationPortalStats(orgId: string): Promise<Array<[string, number]>> {
    const countRows = (table: SQLiteTable, where: SQL | undefined) =>
      this.orm.select({ total: count() }).from(table).where(where);
    const stats: Array<[string, ReturnType<typeof countRows>]> = [
      ['Collections', countRows(collections, eq(collections.orgId, orgId))],
      ['Groups', countRows(orgGroups, eq(orgGroups.orgId, orgId))],
      ['Enabled policies', countRows(orgPolicies, and(eq(orgPolicies.orgId, orgId), eq(orgPolicies.enabled, 1)))],
      ['Organization items', countRows(ciphers, eq(ciphers.organizationId, orgId))],
      ['SM projects', countRows(smProjects, eq(smProjects.orgId, orgId))],
      ['SM secrets', countRows(smSecrets, and(eq(smSecrets.orgId, orgId), isNull(smSecrets.deletedAt)))],
      ['SM machine accounts', countRows(smServiceAccounts, eq(smServiceAccounts.orgId, orgId))],
    ];
    const queries = stats.map(([, query]) => query);
    const results = await this.orm.batch(queries as [(typeof queries)[0], ...typeof queries]);
    return stats.map(([name], index) => [name, results[index][0]?.total ?? 0]);
  }

  // Administrative reports need the complete encrypted organization vault, independent of assignments.
  async listOrganizationCiphers(orgId: string): Promise<Cipher[]> {
    const rows = await this.orm
      .select()
      .from(ciphers)
      .where(eq(ciphers.organizationId, orgId))
      .orderBy(desc(ciphers.updatedAt));
    const links = await this.listOrgCipherCollectionIds(orgId);
    return rows.flatMap((row) => {
      const cipher = mapOrgCipherRow(row, row.userId, orgId, links.get(row.id) || []);
      return cipher ? [cipher] : [];
    });
  }

  async listMembershipGroupIdsByOrg(orgId: string): Promise<Map<string, string[]>> {
    const rows = await this.orm
      .select({ membershipId: orgGroupMembers.membershipId, groupId: orgGroupMembers.groupId })
      .from(orgGroupMembers)
      .innerJoin(organizationMemberships, eq(organizationMemberships.id, orgGroupMembers.membershipId))
      .innerJoin(
        orgGroups,
        and(eq(orgGroups.id, orgGroupMembers.groupId), eq(orgGroups.orgId, organizationMemberships.orgId)),
      )
      .where(eq(organizationMemberships.orgId, orgId));
    const result = new Map<string, string[]>();
    for (const row of rows) {
      const groups = result.get(row.membershipId) || [];
      groups.push(row.groupId);
      result.set(row.membershipId, groups);
    }
    return result;
  }
}

export const orgRepo = repository(OrgRepository);
