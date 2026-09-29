import { eq } from 'drizzle-orm';

import { Repository, repository } from '../db/client';
import { config } from '../db/schema';

const REGISTERED_KEY = 'registered';

export class ConfigRepository extends Repository {
  async getConfigValue(key: string): Promise<string | null> {
    const [row] = await this.orm.select({ value: config.value }).from(config).where(eq(config.key, key)).limit(1);
    return typeof row?.value === 'string' ? row.value : null;
  }

  async setConfigValue(key: string, value: string): Promise<void> {
    await this.orm.insert(config).values({ key, value }).onConflictDoUpdate({ target: config.key, set: { value } });
  }

  async setRegistered(): Promise<void> {
    await this.setConfigValue(REGISTERED_KEY, 'true');
  }
}

export const configRepo = repository(ConfigRepository);
