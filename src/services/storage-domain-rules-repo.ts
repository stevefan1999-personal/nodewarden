import { eq } from 'drizzle-orm';
import { z } from 'zod';

import { Repository, repository } from '../db/client';
import { domainSettings } from '../db/schema';
import type { UserDomainSettings } from '../types';
import { normalizeCustomEquivalentDomains, normalizeEquivalentDomains } from './domain-rules';
import { revisionRepo } from './storage-revision-repo';

// Rules are normalized on write, so a missing or corrupt stored value reads as no rules instead of failing sync.
function parseStored(raw: string | null | undefined): unknown {
  try {
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

const StoredTypes = z.array(z.int()).catch([]);

export class DomainRulesRepository extends Repository {
  async getUserDomainSettings(userId: string): Promise<UserDomainSettings> {
    const [row] = await this.orm.select().from(domainSettings).where(eq(domainSettings.userId, userId)).limit(1);
    const equivalentDomains = normalizeEquivalentDomains(parseStored(row?.equivalentDomains));
    const storedCustomEquivalentDomains = normalizeCustomEquivalentDomains(parseStored(row?.customEquivalentDomains));
    const customEquivalentDomains = storedCustomEquivalentDomains.length
      ? storedCustomEquivalentDomains
      : normalizeCustomEquivalentDomains(equivalentDomains);

    return {
      userId,
      equivalentDomains,
      customEquivalentDomains,
      excludedGlobalEquivalentDomains: StoredTypes.parse(parseStored(row?.excludedGlobalEquivalentDomains)),
      updatedAt: row?.updatedAt || null,
    };
  }

  async saveUserDomainSettings(
    userId: string,
    equivalentDomains: string[][],
    customEquivalentDomains: UserDomainSettings['customEquivalentDomains'],
    excludedGlobalEquivalentDomains: number[],
  ): Promise<void> {
    const values = {
      userId,
      equivalentDomains: JSON.stringify(equivalentDomains),
      customEquivalentDomains: JSON.stringify(customEquivalentDomains),
      excludedGlobalEquivalentDomains: JSON.stringify(excludedGlobalEquivalentDomains),
      updatedAt: new Date().toISOString(),
    };
    await this.orm
      .insert(domainSettings)
      .values(values)
      .onConflictDoUpdate({
        target: domainSettings.userId,
        set: {
          equivalentDomains: values.equivalentDomains,
          customEquivalentDomains: values.customEquivalentDomains,
          excludedGlobalEquivalentDomains: values.excludedGlobalEquivalentDomains,
          updatedAt: values.updatedAt,
        },
      });
    await revisionRepo(this.db).updateRevisionDate(userId);
  }
}

export const domainRulesRepo = repository(DomainRulesRepository);
