import { diffPolicies, grantsFromRows, type SmActor, type SmGrants, type SmAccess } from './sm-authz';
import {
  and,
  asc,
  count,
  desc,
  eq,
  exists,
  inArray,
  isNull,
  isNotNull,
  lt,
  notExists,
  notInArray,
  or,
  type SQL,
} from 'drizzle-orm';
import type { BatchItem } from 'drizzle-orm/batch';

import { abortUnlessChanged, chunkRows, columnCount, Repository, repository, statementChunks } from '../db/client';
import {
  orgGroupMembers,
  orgGroups,
  smAccessTokens,
  smProjects,
  smProjectGroups,
  smProjectMembers,
  smSecretGroups,
  smSecretMembers,
  smSecretProjects,
  smSecrets,
  smSecretServiceAccounts,
  smServiceAccountGroups,
  smServiceAccountProjects,
  smServiceAccounts,
  smServiceAccountMembers,
} from '../db/schema';
import { bound, jsonValues } from '../db/sql';

export type SmProject = typeof smProjects.$inferSelect;

export interface SmSecret {
  id: string;
  orgId: string;
  key: string;
  value: string;
  note: string | null;
  projectIds: string[];
  createdAt: string;
  updatedAt: string;
  deletedAt: string | null;
}

export type SmServiceAccount = typeof smServiceAccounts.$inferSelect;

export interface SmAccessToken {
  id: string;
  serviceAccountId: string;
  name: string;
  clientSecretHash: string;
  encryptedPayload?: string | null;
  key?: string | null;
  expireAt: string | null;
  revokedAt: string | null;
  createdAt: string;
}

function mapSecret(row: typeof smSecrets.$inferSelect, projectIds: string[]): SmSecret {
  return {
    id: row.id,
    orgId: row.orgId,
    key: row.key,
    value: row.value,
    note: row.note,
    projectIds,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    deletedAt: row.deletedAt,
  };
}

function mapAccessToken(row: typeof smAccessTokens.$inferSelect): SmAccessToken {
  return {
    id: row.id,
    serviceAccountId: row.serviceAccountId,
    name: row.name,
    clientSecretHash: row.clientSecretHash,
    encryptedPayload: row.encryptedPayload,
    key: row.key,
    expireAt: row.expireAt,
    revokedAt: row.revokedAt,
    createdAt: row.createdAt,
  };
}

// Upstream requires write on a machine account's people policies, so their tables have no permission
// column and reads select a constant. D1 batch rows are objects, so the constant needs a column name:
// a numeric one would enumerate first and shift the positional mapping.
const MACHINE_ACCOUNT_PEOPLE_WRITE = bound(1).as('write_access');

// People policy grant tables per target kind, with the columns statements filter on and the insert
// row, since drizzle keys rows by property. `targets` scopes a member's grants to the org.
export const peoplePolicyTables = {
  secret: {
    targets: smSecrets,
    member: {
      table: smSecretMembers,
      target: smSecretMembers.secretId,
      grantee: smSecretMembers.membershipId,
      writeAccess: smSecretMembers.writeAccess,
      row: (secretId: string, membershipId: string, writeAccess: number) => ({ secretId, membershipId, writeAccess }),
    },
    group: {
      table: smSecretGroups,
      target: smSecretGroups.secretId,
      grantee: smSecretGroups.groupId,
      writeAccess: smSecretGroups.writeAccess,
      row: (secretId: string, groupId: string, writeAccess: number) => ({ secretId, groupId, writeAccess }),
    },
  },
  project: {
    targets: smProjects,
    member: {
      table: smProjectMembers,
      target: smProjectMembers.projectId,
      grantee: smProjectMembers.membershipId,
      writeAccess: smProjectMembers.writeAccess,
      row: (projectId: string, membershipId: string, writeAccess: number) => ({ projectId, membershipId, writeAccess }),
    },
    group: {
      table: smProjectGroups,
      target: smProjectGroups.projectId,
      grantee: smProjectGroups.groupId,
      writeAccess: smProjectGroups.writeAccess,
      row: (projectId: string, groupId: string, writeAccess: number) => ({ projectId, groupId, writeAccess }),
    },
  },
  serviceAccount: {
    targets: smServiceAccounts,
    member: {
      table: smServiceAccountMembers,
      target: smServiceAccountMembers.serviceAccountId,
      grantee: smServiceAccountMembers.membershipId,
      writeAccess: MACHINE_ACCOUNT_PEOPLE_WRITE,
      row: (serviceAccountId: string, membershipId: string) => ({ serviceAccountId, membershipId }),
    },
    group: {
      table: smServiceAccountGroups,
      target: smServiceAccountGroups.serviceAccountId,
      grantee: smServiceAccountGroups.groupId,
      writeAccess: MACHINE_ACCOUNT_PEOPLE_WRITE,
      row: (serviceAccountId: string, groupId: string) => ({ serviceAccountId, groupId }),
    },
  },
};
export type SmPeopleTarget = keyof typeof peoplePolicyTables;

function accessByGrantee(rows: { id: string; write_access: number }[]) {
  return new Map(rows.map((row) => [row.id, row.write_access ? ('write' as const) : ('read' as const)]));
}

// Grant tables per machine policy kind. Service-account project grants also carry a read bit, which
// every policy sets.
export const machinePolicyTables = {
  secretMembers: { ...peoplePolicyTables.secret.member, read: false },
  secretGroups: { ...peoplePolicyTables.secret.group, read: false },
  secretServiceAccounts: {
    table: smSecretServiceAccounts,
    target: smSecretServiceAccounts.secretId,
    grantee: smSecretServiceAccounts.serviceAccountId,
    row: (secretId: string, serviceAccountId: string, writeAccess: number) => ({
      secretId,
      serviceAccountId,
      writeAccess,
    }),
    read: false,
  },
  projectServiceAccounts: {
    table: smServiceAccountProjects,
    target: smServiceAccountProjects.projectId,
    grantee: smServiceAccountProjects.serviceAccountId,
    row: (projectId: string, serviceAccountId: string, writeAccess: number) => ({
      serviceAccountId,
      projectId,
      readAccess: 1,
      writeAccess,
    }),
    read: true,
  },
  serviceAccountProjects: {
    table: smServiceAccountProjects,
    target: smServiceAccountProjects.serviceAccountId,
    grantee: smServiceAccountProjects.projectId,
    row: (serviceAccountId: string, projectId: string, writeAccess: number) => ({
      serviceAccountId,
      projectId,
      readAccess: 1,
      writeAccess,
    }),
    read: true,
  },
};
export type SmMachinePolicy = keyof typeof machinePolicyTables;

export class SecretRepository extends Repository {
  // A link counts only when its project is in the secret's org, so a link stored across
  // organizations never shows. `secretScope` filters sm_secrets by org or by one id, never by an id
  // list, which broke past D1's bound-parameter cap.
  private async projectIdsBySecret(secretScope: SQL): Promise<Map<string, string[]>> {
    const grouped = new Map<string, string[]>();
    const rows = await this.orm
      .select({ secretId: smSecretProjects.secretId, projectId: smSecretProjects.projectId })
      .from(smSecretProjects)
      .innerJoin(smSecrets, eq(smSecrets.id, smSecretProjects.secretId))
      .innerJoin(smProjects, and(eq(smProjects.id, smSecretProjects.projectId), eq(smProjects.orgId, smSecrets.orgId)))
      .where(secretScope);
    for (const row of rows) {
      const list = grouped.get(row.secretId);
      if (list) list.push(row.projectId);
      else grouped.set(row.secretId, [row.projectId]);
    }
    return grouped;
  }

  async saveProject(project: SmProject): Promise<void> {
    await this.orm.batch([
      this.orm
        .insert(smProjects)
        .values(project)
        .onConflictDoUpdate({
          target: smProjects.id,
          set: { name: project.name, updatedAt: project.updatedAt },
        }),
    ]);
  }

  async listProjects(orgId: string): Promise<SmProject[]> {
    const rows = await this.orm
      .select()
      .from(smProjects)
      .where(eq(smProjects.orgId, orgId))
      .orderBy(asc(smProjects.name));
    return rows;
  }

  async getProject(id: string): Promise<SmProject | null> {
    const [row] = await this.orm.select().from(smProjects).where(eq(smProjects.id, id)).limit(1);
    return row ?? null;
  }

  // The subset of `ids` that are projects of `orgId`.
  async projectsInOrg(orgId: string, ids: string[]): Promise<Set<string>> {
    const select = (chunk: string[]) =>
      this.orm
        .select({ id: smProjects.id })
        .from(smProjects)
        .where(and(eq(smProjects.orgId, orgId), inArray(smProjects.id, chunk)));
    const chunks = await Promise.all(statementChunks(ids, select).map(select));
    return new Set(chunks.flat().map(({ id }) => id));
  }

  // Saves the secret and replaces its links in one batch with chunked inserts, so a link that fails
  // cannot leave the secret saved with its previous links gone.
  async saveSecret(secret: SmSecret): Promise<void> {
    const upsert = this.orm
      .insert(smSecrets)
      .values({
        id: secret.id,
        orgId: secret.orgId,
        key: secret.key,
        value: secret.value,
        note: secret.note,
        createdAt: secret.createdAt,
        updatedAt: secret.updatedAt,
        deletedAt: secret.deletedAt,
      })
      .onConflictDoUpdate({
        target: smSecrets.id,
        set: {
          key: secret.key,
          value: secret.value,
          note: secret.note,
          updatedAt: secret.updatedAt,
          deletedAt: secret.deletedAt,
        },
      });
    const links = secret.projectIds.map((projectId) => ({ secretId: secret.id, projectId }));
    await this.orm.batch([
      upsert,
      this.orm.delete(smSecretProjects).where(eq(smSecretProjects.secretId, secret.id)),
      ...chunkRows(links, columnCount(smSecretProjects)).map((chunk) =>
        this.orm.insert(smSecretProjects).values(chunk).onConflictDoNothing(),
      ),
    ]);
  }

  async getSecret(id: string): Promise<SmSecret | null> {
    const [row] = await this.orm.select().from(smSecrets).where(eq(smSecrets.id, id)).limit(1);
    if (!row) return null;
    const projects = await this.projectIdsBySecret(eq(smSecrets.id, id));
    return mapSecret(row, projects.get(id) ?? []);
  }

  async listSecrets(orgId: string, includeDeleted = false): Promise<SmSecret[]> {
    const rows = await this.orm
      .select()
      .from(smSecrets)
      .where(includeDeleted ? eq(smSecrets.orgId, orgId) : and(eq(smSecrets.orgId, orgId), isNull(smSecrets.deletedAt)))
      .orderBy(desc(smSecrets.updatedAt));
    const projects = await this.projectIdsBySecret(eq(smSecrets.orgId, orgId));
    return rows.map((row) => mapSecret(row, projects.get(row.id) ?? []));
  }

  async saveServiceAccount(account: SmServiceAccount): Promise<void> {
    await this.orm
      .insert(smServiceAccounts)
      .values(account)
      .onConflictDoUpdate({
        target: smServiceAccounts.id,
        set: { name: account.name, updatedAt: account.updatedAt },
      });
  }

  async listServiceAccounts(orgId: string): Promise<SmServiceAccount[]> {
    const rows = await this.orm
      .select()
      .from(smServiceAccounts)
      .where(eq(smServiceAccounts.orgId, orgId))
      .orderBy(asc(smServiceAccounts.name));
    return rows;
  }

  async getServiceAccount(id: string): Promise<SmServiceAccount | null> {
    const [row] = await this.orm.select().from(smServiceAccounts).where(eq(smServiceAccounts.id, id)).limit(1);
    return row ?? null;
  }

  // One batch with chunked inserts, so a grant that fails leaves the previous grants in place.
  async replaceServiceAccountProjects(serviceAccountId: string, projectIds: string[]): Promise<void> {
    const grants = projectIds.map((projectId) => ({ serviceAccountId, projectId, readAccess: 1, writeAccess: 0 }));
    await this.orm.batch([
      this.orm.delete(smServiceAccountProjects).where(eq(smServiceAccountProjects.serviceAccountId, serviceAccountId)),
      ...chunkRows(grants, columnCount(smServiceAccountProjects)).map((chunk) =>
        this.orm.insert(smServiceAccountProjects).values(chunk),
      ),
    ]);
  }

  // Upstream ignores a machine-account project policy without Read, so only read grants count.
  async listReadableServiceAccountProjectIds(serviceAccountId: string): Promise<string[]> {
    const rows = await this.orm
      .select({ projectId: smServiceAccountProjects.projectId })
      .from(smServiceAccountProjects)
      .where(
        and(
          eq(smServiceAccountProjects.serviceAccountId, serviceAccountId),
          eq(smServiceAccountProjects.readAccess, 1),
        ),
      );
    return rows.map((row) => row.projectId);
  }

  async saveAccessToken(token: SmAccessToken): Promise<void> {
    await this.orm.batch([this.orm.insert(smAccessTokens).values(token)]);
  }

  async listAccessTokens(serviceAccountId: string): Promise<SmAccessToken[]> {
    const rows = await this.orm
      .select()
      .from(smAccessTokens)
      .where(eq(smAccessTokens.serviceAccountId, serviceAccountId));
    return rows.map(mapAccessToken);
  }

  async getAccessToken(id: string): Promise<SmAccessToken | null> {
    const [row] = await this.orm.select().from(smAccessTokens).where(eq(smAccessTokens.id, id)).limit(1);
    return row ? mapAccessToken(row) : null;
  }

  async loadSmGrants(actor: SmActor, orgId: string): Promise<SmGrants> {
    if (actor.kind === 'admin') return grantsFromRows({ projects: [], secrets: [], serviceAccounts: [] });
    if (actor.kind === 'serviceAccount') {
      const [projects, secrets] = await this.orm.batch([
        this.orm
          .select({ id: smServiceAccountProjects.projectId, write_access: smServiceAccountProjects.writeAccess })
          .from(smServiceAccountProjects)
          .innerJoin(
            smProjects,
            and(eq(smProjects.id, smServiceAccountProjects.projectId), eq(smProjects.orgId, orgId)),
          )
          .where(
            and(
              eq(smServiceAccountProjects.serviceAccountId, actor.serviceAccountId),
              eq(smServiceAccountProjects.readAccess, 1),
            ),
          ),
        this.orm
          .select({ id: smSecretServiceAccounts.secretId, write_access: smSecretServiceAccounts.writeAccess })
          .from(smSecretServiceAccounts)
          .innerJoin(smSecrets, and(eq(smSecrets.id, smSecretServiceAccounts.secretId), eq(smSecrets.orgId, orgId)))
          .where(eq(smSecretServiceAccounts.serviceAccountId, actor.serviceAccountId)),
      ]);
      return grantsFromRows({ projects, secrets, serviceAccounts: [] });
    }
    // A member's grants on one target kind: direct policies plus those of the member's groups, each
    // counted only for targets and groups of this org.
    const grantsOn = (kind: SmPeopleTarget) => {
      const { targets, member, group } = peoplePolicyTables[kind];
      return this.orm
        .select({ id: member.target, write_access: member.writeAccess })
        .from(member.table)
        .innerJoin(targets, and(eq(targets.id, member.target), eq(targets.orgId, orgId)))
        .where(eq(member.grantee, actor.membershipId))
        .unionAll(
          this.orm
            .select({ id: group.target, write_access: group.writeAccess })
            .from(group.table)
            .innerJoin(targets, and(eq(targets.id, group.target), eq(targets.orgId, orgId)))
            .innerJoin(orgGroups, and(eq(orgGroups.id, group.grantee), eq(orgGroups.orgId, targets.orgId)))
            .innerJoin(orgGroupMembers, eq(orgGroupMembers.groupId, orgGroups.id))
            .where(eq(orgGroupMembers.membershipId, actor.membershipId)),
        );
    };
    const [projects, secrets, serviceAccounts] = await this.orm.batch([
      grantsOn('project'),
      grantsOn('secret'),
      grantsOn('serviceAccount'),
    ]);
    return grantsFromRows({ projects, secrets, serviceAccounts });
  }

  bumpServiceAccounts(orgId: string, now = new Date().toISOString()) {
    // ponytail: org-wide bump causes extra resyncs and moves every SA's Last edited; narrow to affected SAs if either matters.
    return this.orm.update(smServiceAccounts).set({ updatedAt: now }).where(eq(smServiceAccounts.orgId, orgId));
  }

  async createProject(project: SmProject, actor: SmActor): Promise<void> {
    const grant =
      actor.kind === 'serviceAccount'
        ? this.orm
            .insert(smServiceAccountProjects)
            .values({ projectId: project.id, serviceAccountId: actor.serviceAccountId, readAccess: 1, writeAccess: 1 })
        : this.orm
            .insert(smProjectMembers)
            .values({ projectId: project.id, membershipId: actor.membershipId, writeAccess: 1 });
    await this.orm.batch([this.orm.insert(smProjects).values(project), grant]);
  }

  async deleteProjects(orgId: string, ids: string[]): Promise<string[]> {
    if (!ids.length) return [];
    const remove = (chunk: string[]) =>
      this.orm
        .delete(smProjects)
        .where(and(eq(smProjects.orgId, orgId), inArray(smProjects.id, chunk)))
        .returning({ id: smProjects.id });
    const [, ...results] = await this.orm.batch([
      this.bumpServiceAccounts(orgId),
      ...statementChunks(ids, remove).map(remove),
    ]);
    return results.flat().map((row) => row.id);
  }

  async projectCounts(project: SmProject, access: SmAccess) {
    const counts = { secrets: 0, people: 0, serviceAccounts: 0, object: 'projectCounts' };
    if (access === 'none') return counts;
    const [secrets] = await this.orm
      .select({ n: count() })
      .from(smSecretProjects)
      .innerJoin(
        smSecrets,
        and(
          eq(smSecrets.id, smSecretProjects.secretId),
          eq(smSecrets.orgId, project.orgId),
          isNull(smSecrets.deletedAt),
        ),
      )
      .where(eq(smSecretProjects.projectId, project.id));
    counts.secrets = secrets.n;
    if (access === 'write') {
      const [[members], [groups], [accounts]] = await this.orm.batch([
        this.orm.select({ n: count() }).from(smProjectMembers).where(eq(smProjectMembers.projectId, project.id)),
        this.orm.select({ n: count() }).from(smProjectGroups).where(eq(smProjectGroups.projectId, project.id)),
        this.orm
          .select({ n: count() })
          .from(smServiceAccountProjects)
          .where(and(eq(smServiceAccountProjects.projectId, project.id), eq(smServiceAccountProjects.readAccess, 1))),
      ]);
      counts.people = members.n + groups.n;
      counts.serviceAccounts = accounts.n;
    }
    return counts;
  }

  async getProjectsByIds(ids: string[]): Promise<SmProject[]> {
    const read = (chunk: string[]) => this.orm.select().from(smProjects).where(inArray(smProjects.id, chunk));
    return (await Promise.all(statementChunks(ids, read).map(read))).flat();
  }

  async updateProject(project: SmProject): Promise<boolean> {
    const [rows] = await this.orm.batch([
      this.orm
        .update(smProjects)
        .set({ name: project.name, updatedAt: project.updatedAt })
        .where(eq(smProjects.id, project.id))
        .returning({ id: smProjects.id }),
    ]);
    return rows.length > 0;
  }

  async createSecret(secret: SmSecret, policies: BatchItem<'sqlite'>[] = []): Promise<void> {
    await this.orm.batch([
      this.orm.insert(smSecrets).values({
        id: secret.id,
        orgId: secret.orgId,
        key: secret.key,
        value: secret.value,
        note: secret.note,
        createdAt: secret.createdAt,
        updatedAt: secret.updatedAt,
        deletedAt: null,
      }),
      ...secret.projectIds.map((projectId) =>
        this.orm.insert(smSecretProjects).values({ secretId: secret.id, projectId }),
      ),
      ...policies,
      this.bumpServiceAccounts(secret.orgId, secret.updatedAt),
    ]);
  }

  async updateSecret(
    secret: SmSecret,
    previousProjectIds: string[],
    previousRevision: string,
    policies: BatchItem<'sqlite'>[] = [],
  ): Promise<boolean> {
    // The authorized snapshot's links are those whose project is in the secret's org; `sm_secrets` in
    // these subqueries is the row being updated. The previous ids bind as one JSON array, so a legacy
    // secret with many links stays within D1's bound-parameter cap.
    const linkInOrg = and(eq(smProjects.id, smSecretProjects.projectId), eq(smProjects.orgId, smSecrets.orgId));
    const snapshotLinks = this.orm
      .select({ links: count() })
      .from(smSecretProjects)
      .innerJoin(smProjects, linkInOrg)
      .where(eq(smSecretProjects.secretId, smSecrets.id));
    const unexpectedLinks = this.orm
      .select({ projectId: smSecretProjects.projectId })
      .from(smSecretProjects)
      .innerJoin(smProjects, linkInOrg)
      .where(
        and(
          eq(smSecretProjects.secretId, smSecrets.id),
          notInArray(smSecretProjects.projectId, jsonValues(previousProjectIds)),
        ),
      );
    const live = and(eq(smSecrets.id, secret.id), isNull(smSecrets.deletedAt));
    const relink =
      previousProjectIds.length !== secret.projectIds.length || previousProjectIds[0] !== secret.projectIds[0]
        ? [
            this.orm
              .delete(smSecretProjects)
              .where(
                and(
                  eq(smSecretProjects.secretId, secret.id),
                  exists(this.orm.select({ id: smSecrets.id }).from(smSecrets).where(live)),
                ),
              ),
            ...secret.projectIds.map((projectId) =>
              this.orm.insert(smSecretProjects).select(
                this.orm
                  .select({ secretId: smSecrets.id, projectId: bound(projectId).as(smSecretProjects.projectId.name) })
                  .from(smSecrets)
                  .where(live),
              ),
            ),
          ]
        : [];
    try {
      await this.orm.batch([
        this.orm
          .update(smSecrets)
          .set({ key: secret.key, value: secret.value, note: secret.note, updatedAt: secret.updatedAt })
          .where(
            and(
              live,
              eq(smSecrets.updatedAt, previousRevision),
              eq(snapshotLinks, previousProjectIds.length),
              notExists(unexpectedLinks),
            ),
          ),
        // Abort the atomic batch before links or policies if the authorized snapshot changed.
        abortUnlessChanged(this.orm, 'stale secret update'),
        ...relink,
        ...policies,
        this.bumpServiceAccounts(secret.orgId, secret.updatedAt),
      ]);
      return true;
    } catch (error) {
      if (error instanceof Error && error.message.includes('malformed JSON')) return false;
      throw error;
    }
  }

  async getSecretsByIds(ids: string[]): Promise<SmSecret[]> {
    const read = (chunk: string[]) => this.orm.select().from(smSecrets).where(inArray(smSecrets.id, chunk));
    const results = await Promise.all(
      statementChunks(ids, read).map(async (chunk) => {
        const rows = await read(chunk);
        const projects = await this.projectIdsBySecret(inArray(smSecrets.id, chunk));
        return rows.map((row) => mapSecret(row, projects.get(row.id) ?? []));
      }),
    );
    return results.flat();
  }

  async deleteSecrets(orgId: string, ids: string[]): Promise<string[]> {
    if (!ids.length) return [];
    const now = new Date().toISOString();
    const trash = (chunk: string[]) =>
      this.orm
        .update(smSecrets)
        .set({ deletedAt: now, updatedAt: now })
        .where(and(eq(smSecrets.orgId, orgId), inArray(smSecrets.id, chunk), isNull(smSecrets.deletedAt)))
        .returning({ id: smSecrets.id });
    const [, ...results] = await this.orm.batch([
      this.bumpServiceAccounts(orgId, now),
      ...statementChunks(ids, trash).map(trash),
    ]);
    return results.flat().map((row) => row.id);
  }

  async createServiceAccount(account: SmServiceAccount, membershipId: string): Promise<void> {
    await this.orm.batch([
      this.orm.insert(smServiceAccounts).values(account),
      this.orm.insert(smServiceAccountMembers).values({ serviceAccountId: account.id, membershipId }),
    ]);
  }

  async updateServiceAccount(account: SmServiceAccount): Promise<boolean> {
    const [rows] = await this.orm.batch([
      this.orm
        .update(smServiceAccounts)
        .set({ name: account.name, updatedAt: account.updatedAt })
        .where(eq(smServiceAccounts.id, account.id))
        .returning({ id: smServiceAccounts.id }),
    ]);
    return rows.length > 0;
  }

  async getServiceAccountsByIds(ids: string[]): Promise<SmServiceAccount[]> {
    const read = (chunk: string[]) =>
      this.orm.select().from(smServiceAccounts).where(inArray(smServiceAccounts.id, chunk));
    return (await Promise.all(statementChunks(ids, read).map(read))).flat();
  }

  async deleteServiceAccounts(orgId: string, ids: string[]): Promise<string[]> {
    if (!ids.length) return [];
    const remove = (chunk: string[]) =>
      this.orm
        .delete(smServiceAccounts)
        .where(and(eq(smServiceAccounts.orgId, orgId), inArray(smServiceAccounts.id, chunk)))
        .returning({ id: smServiceAccounts.id });
    const statements = statementChunks(ids, remove).map(remove);
    const results = await this.orm.batch([statements[0], ...statements.slice(1)]);
    return results.flat().map((row) => row.id);
  }

  async revokeAccessTokens(serviceAccountId: string, ids: string[]): Promise<void> {
    if (!ids.length) return;
    const revoke = (chunk: string[]) =>
      this.orm
        .delete(smAccessTokens)
        .where(and(eq(smAccessTokens.serviceAccountId, serviceAccountId), inArray(smAccessTokens.id, chunk)));
    const statements = statementChunks(ids, revoke).map(revoke);
    await this.orm.batch([statements[0], ...statements.slice(1)]);
  }

  async serviceAccountSecretCounts(orgId: string): Promise<Map<string, number>> {
    // A machine account reaches a live secret of its org through a direct policy or a readable
    // project of the same org.
    const directPolicy = this.orm
      .select({ secretId: smSecretServiceAccounts.secretId })
      .from(smSecretServiceAccounts)
      .where(
        and(
          eq(smSecretServiceAccounts.secretId, smSecrets.id),
          eq(smSecretServiceAccounts.serviceAccountId, smServiceAccounts.id),
        ),
      );
    const readableProject = this.orm
      .select({ secretId: smSecretProjects.secretId })
      .from(smSecretProjects)
      .innerJoin(
        smServiceAccountProjects,
        and(
          eq(smServiceAccountProjects.projectId, smSecretProjects.projectId),
          eq(smServiceAccountProjects.serviceAccountId, smServiceAccounts.id),
          eq(smServiceAccountProjects.readAccess, 1),
        ),
      )
      .innerJoin(
        smProjects,
        and(eq(smProjects.id, smSecretProjects.projectId), eq(smProjects.orgId, smServiceAccounts.orgId)),
      )
      .where(eq(smSecretProjects.secretId, smSecrets.id));
    const rows = await this.orm
      .select({ id: smServiceAccounts.id, n: count(smSecrets.id) })
      .from(smServiceAccounts)
      .leftJoin(
        smSecrets,
        and(
          eq(smSecrets.orgId, smServiceAccounts.orgId),
          isNull(smSecrets.deletedAt),
          or(exists(directPolicy), exists(readableProject)),
        ),
      )
      .where(eq(smServiceAccounts.orgId, orgId))
      .groupBy(smServiceAccounts.id);
    return new Map(rows.map((row) => [row.id, row.n]));
  }

  async serviceAccountCounts(account: SmServiceAccount, access: SmAccess) {
    const counts = { projects: 0, people: 0, accessTokens: 0, object: 'serviceAccountCounts' };
    if (access === 'none') return counts;
    const [[projects], [members], [groups], [accessTokens]] = await this.orm.batch([
      this.orm
        .select({ n: count() })
        .from(smServiceAccountProjects)
        .innerJoin(
          smProjects,
          and(eq(smProjects.id, smServiceAccountProjects.projectId), eq(smProjects.orgId, account.orgId)),
        )
        .where(
          and(eq(smServiceAccountProjects.serviceAccountId, account.id), eq(smServiceAccountProjects.readAccess, 1)),
        ),
      this.orm
        .select({ n: count() })
        .from(smServiceAccountMembers)
        .where(eq(smServiceAccountMembers.serviceAccountId, account.id)),
      this.orm
        .select({ n: count() })
        .from(smServiceAccountGroups)
        .where(eq(smServiceAccountGroups.serviceAccountId, account.id)),
      this.orm.select({ n: count() }).from(smAccessTokens).where(eq(smAccessTokens.serviceAccountId, account.id)),
    ]);
    return { ...counts, projects: projects.n, people: members.n + groups.n, accessTokens: accessTokens.n };
  }

  async readPeoplePolicies(kind: SmPeopleTarget, id: string) {
    const { member, group } = peoplePolicyTables[kind];
    const policies = (grant: typeof member | typeof group) =>
      this.orm
        .select({ id: grant.grantee, write_access: grant.writeAccess })
        .from(grant.table)
        .where(eq(grant.target, id));
    const [users, groups] = await this.orm.batch([policies(member), policies(group)]);
    return { users: accessByGrantee(users), groups: accessByGrantee(groups) };
  }

  async replacePeoplePolicies(
    kind: SmPeopleTarget,
    id: string,
    users: Map<string, SmAccess>,
    groups: Map<string, SmAccess>,
  ): Promise<{ users: Map<string, SmAccess>; groups: Map<string, SmAccess> }> {
    const { member, group } = peoplePolicyTables[kind];
    const clear = (grant: typeof member | typeof group) =>
      this.orm
        .delete(grant.table)
        .where(eq(grant.target, id))
        .returning({ id: grant.grantee, write_access: grant.writeAccess });
    const insert = (grant: typeof member | typeof group, policies: Map<string, SmAccess>) =>
      chunkRows([...policies], columnCount(grant.table)).map((chunk) =>
        this.orm
          .insert(grant.table)
          .values(chunk.map(([granteeId, access]) => grant.row(id, granteeId, access === 'write' ? 1 : 0))),
      );
    const [previousUsers, previousGroups] = await this.orm.batch([
      clear(member),
      clear(group),
      ...insert(member, users),
      ...insert(group, groups),
    ]);
    return { users: accessByGrantee(previousUsers), groups: accessByGrantee(previousGroups) };
  }

  policyDiffStatements(
    kind: SmMachinePolicy,
    id: string,
    current: ReadonlyMap<string, SmAccess>,
    requested: ReadonlyMap<string, SmAccess>,
  ): BatchItem<'sqlite'>[] {
    const { table, target, grantee, row, read } = machinePolicyTables[kind];
    const { created, updated, deleted } = diffPolicies(current, requested);
    const writeAccess = (granteeId: string) => (requested.get(granteeId) === 'write' ? 1 : 0);
    const policy = (granteeId: string) => and(eq(target, id), eq(grantee, granteeId));
    return [
      ...deleted.map((granteeId) => this.orm.delete(table).where(policy(granteeId))),
      ...updated.map((granteeId) =>
        this.orm
          .update(table)
          .set({ writeAccess: writeAccess(granteeId), ...(read ? { readAccess: 1 } : {}) })
          .where(policy(granteeId)),
      ),
      ...chunkRows(created, columnCount(table)).map((chunk) =>
        this.orm.insert(table).values(chunk.map((granteeId) => row(id, granteeId, writeAccess(granteeId)))),
      ),
    ];
  }

  async readProjectMachinePolicies(orgId: string, id: string) {
    return this.orm
      .select({
        id: smServiceAccounts.id,
        name: smServiceAccounts.name,
        write_access: smServiceAccountProjects.writeAccess,
      })
      .from(smServiceAccountProjects)
      .innerJoin(
        smServiceAccounts,
        and(eq(smServiceAccounts.id, smServiceAccountProjects.serviceAccountId), eq(smServiceAccounts.orgId, orgId)),
      )
      .where(and(eq(smServiceAccountProjects.projectId, id), eq(smServiceAccountProjects.readAccess, 1)));
  }

  async readGrantedProjects(orgId: string, id: string) {
    return this.orm
      .select({ id: smProjects.id, name: smProjects.name, write_access: smServiceAccountProjects.writeAccess })
      .from(smServiceAccountProjects)
      .innerJoin(smProjects, and(eq(smProjects.id, smServiceAccountProjects.projectId), eq(smProjects.orgId, orgId)))
      .where(and(eq(smServiceAccountProjects.serviceAccountId, id), eq(smServiceAccountProjects.readAccess, 1)));
  }

  async readSecretMachinePolicies(orgId: string, id: string) {
    return this.orm
      .select({
        id: smServiceAccounts.id,
        name: smServiceAccounts.name,
        write_access: smSecretServiceAccounts.writeAccess,
      })
      .from(smSecretServiceAccounts)
      .innerJoin(
        smServiceAccounts,
        and(eq(smServiceAccounts.id, smSecretServiceAccounts.serviceAccountId), eq(smServiceAccounts.orgId, orgId)),
      )
      .where(eq(smSecretServiceAccounts.secretId, id));
  }

  async getAccessTokenWithAccount(id: string): Promise<(SmAccessToken & { orgId: string }) | null> {
    const [row] = await this.orm
      .select({ token: smAccessTokens, orgId: smServiceAccounts.orgId })
      .from(smAccessTokens)
      .innerJoin(smServiceAccounts, eq(smServiceAccounts.id, smAccessTokens.serviceAccountId))
      .where(eq(smAccessTokens.id, id))
      .limit(1);
    return row ? { ...mapAccessToken(row.token), orgId: row.orgId } : null;
  }

  async changeSecretsTrash(orgId: string, ids: string[], restore: boolean): Promise<string[]> {
    if (!ids.length) return [];
    const now = new Date().toISOString();
    const change = (chunk: string[]) => {
      const where = and(eq(smSecrets.orgId, orgId), inArray(smSecrets.id, chunk), isNotNull(smSecrets.deletedAt));
      return restore
        ? this.orm
            .update(smSecrets)
            .set({ deletedAt: null, updatedAt: now })
            .where(where)
            .returning({ id: smSecrets.id })
        : this.orm.delete(smSecrets).where(where).returning({ id: smSecrets.id });
    };
    const statements = statementChunks(ids, change).map(change);
    const [, ...results] = await this.orm.batch([this.bumpServiceAccounts(orgId, now), ...statements]);
    return results.flat().map((row) => row.id);
  }

  async purgeSecretsTrash(now = Date.now()): Promise<void> {
    await this.orm.batch([
      this.orm.delete(smSecrets).where(lt(smSecrets.deletedAt, new Date(now - 30 * 24 * 60 * 60 * 1000).toISOString())),
    ]);
  }
}

export const smRepo = repository(SecretRepository);
