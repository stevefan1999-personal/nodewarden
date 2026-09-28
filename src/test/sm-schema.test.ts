import assert from 'node:assert/strict';
import test from 'node:test';

import { eq, getTableName, type Table } from 'drizzle-orm';

import { getOrm } from '../db/client';
import {
  orgGroups,
  organizationMemberships,
  smAccessTokens,
  smProjectGroups,
  smProjectMembers,
  smProjects,
  smSecretGroups,
  smSecretMembers,
  smSecretProjects,
  smSecrets,
  smSecretServiceAccounts,
  smServiceAccountGroups,
  smServiceAccountMembers,
  smServiceAccountProjects,
  smServiceAccounts,
} from '../db/schema';
import * as orgRepo from '../services/storage-org-repo';
import { createTestEnv, seedUser } from './support/env';

const { createOwnedOrganization } = await import('../handlers/organizations');
import { ENCRYPTED_FIELD, TEST_ORG_KEY } from './support/sm';

// The seed puts exactly one row in each, so a cascade shows up as a table dropping to zero.
const SEEDED_TABLES: Table[] = [
  organizationMemberships,
  orgGroups,
  smProjects,
  smSecrets,
  smServiceAccounts,
  smAccessTokens,
  smSecretProjects,
  smServiceAccountProjects,
  smProjectMembers,
  smProjectGroups,
  smSecretMembers,
  smSecretGroups,
  smSecretServiceAccounts,
  smServiceAccountMembers,
  smServiceAccountGroups,
];

interface SeededIds {
  membershipId: string;
  groupId: string;
  projectId: string;
  secretId: string;
  serviceAccountId: string;
}

// Every FK cascades, so no handler has to clean up policies. Every other seeded row stays, so a
// deleted project's secret survives with no project, as upstream.
const CASCADES = [
  {
    parent: organizationMemberships,
    id: 'membershipId',
    cascaded: [smProjectMembers, smSecretMembers, smServiceAccountMembers],
  },
  { parent: orgGroups, id: 'groupId', cascaded: [smProjectGroups, smSecretGroups, smServiceAccountGroups] },
  {
    parent: smProjects,
    id: 'projectId',
    cascaded: [smSecretProjects, smServiceAccountProjects, smProjectMembers, smProjectGroups],
  },
  {
    parent: smSecrets,
    id: 'secretId',
    cascaded: [smSecretProjects, smSecretMembers, smSecretGroups, smSecretServiceAccounts],
  },
  {
    parent: smServiceAccounts,
    id: 'serviceAccountId',
    cascaded: [
      smAccessTokens,
      smServiceAccountProjects,
      smSecretServiceAccounts,
      smServiceAccountMembers,
      smServiceAccountGroups,
    ],
  },
] satisfies Array<{ parent: Table; id: keyof SeededIds; cascaded: Table[] }>;

for (const { parent, id, cascaded } of CASCADES) {
  test(`deleting a row from ${getTableName(parent)} empties ${cascaded.map(getTableName).join(', ')} and nothing else`, async () => {
    // An org whose only member, group, project, secret and machine account hold one policy in every
    // policy table, plus the secret's project link, the machine account's project grant and a token.
    const env = await createTestEnv();
    const owner = await seedUser(env);
    const { id: orgId } = await createOwnedOrganization(env.DB, owner, { name: 'Acme', key: TEST_ORG_KEY });
    const membership = await orgRepo.getMembershipByUserAndOrg(env.DB, owner.id, orgId);
    assert.ok(membership);
    const [groupId, projectId, secretId, serviceAccountId] = Array.from({ length: 4 }, () => crypto.randomUUID());
    const ids: SeededIds = { membershipId: membership.id, groupId, projectId, secretId, serviceAccountId };
    const now = new Date().toISOString();
    const orm = getOrm(env.DB);
    await orm.batch([
      orm.insert(orgGroups).values({ id: groupId, orgId, name: 'Group', createdAt: now, updatedAt: now }),
      orm.insert(smProjects).values({ id: projectId, orgId, name: ENCRYPTED_FIELD, createdAt: now, updatedAt: now }),
      orm.insert(smSecrets).values({
        id: secretId,
        orgId,
        key: ENCRYPTED_FIELD,
        value: ENCRYPTED_FIELD,
        note: ENCRYPTED_FIELD,
        createdAt: now,
        updatedAt: now,
      }),
      orm
        .insert(smServiceAccounts)
        .values({ id: serviceAccountId, orgId, name: ENCRYPTED_FIELD, createdAt: now, updatedAt: now }),
      orm.insert(smAccessTokens).values({
        id: crypto.randomUUID(),
        serviceAccountId,
        name: ENCRYPTED_FIELD,
        encryptedPayload: ENCRYPTED_FIELD,
        key: ENCRYPTED_FIELD,
        clientSecretHash: 'hash',
        createdAt: now,
      }),
      orm.insert(smSecretProjects).values({ secretId, projectId }),
      orm.insert(smServiceAccountProjects).values({ serviceAccountId, projectId }),
      orm.insert(smProjectMembers).values({ projectId, membershipId: membership.id }),
      orm.insert(smProjectGroups).values({ projectId, groupId }),
      orm.insert(smSecretMembers).values({ secretId, membershipId: membership.id }),
      orm.insert(smSecretGroups).values({ secretId, groupId }),
      orm.insert(smSecretServiceAccounts).values({ secretId, serviceAccountId }),
      orm.insert(smServiceAccountMembers).values({ serviceAccountId, membershipId: membership.id }),
      orm.insert(smServiceAccountGroups).values({ serviceAccountId, groupId }),
    ]);
    await orm.delete(parent).where(eq(parent.id, ids[id]));
    const emptied: Table[] = [parent, ...cascaded];
    assert.deepEqual(
      Object.fromEntries(
        await Promise.all(SEEDED_TABLES.map(async (table) => [getTableName(table), await orm.$count(table)])),
      ),
      Object.fromEntries(SEEDED_TABLES.map((table) => [getTableName(table), emptied.includes(table) ? 0 : 1])),
    );
  });
}
