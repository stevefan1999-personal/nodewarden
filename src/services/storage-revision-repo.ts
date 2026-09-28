import { eq } from 'drizzle-orm';

import { Repository, repository } from '../db/client';
import { userRevisions } from '../db/schema';

export class RevisionRepository extends Repository {
  async getRevisionDate(userId: string): Promise<string> {
    const [row] = await this.orm
      .select({ revisionDate: userRevisions.revisionDate })
      .from(userRevisions)
      .where(eq(userRevisions.userId, userId))
      .limit(1);
    if (row?.revisionDate) return row.revisionDate;

    const date = new Date().toISOString();
    await this.orm
      .insert(userRevisions)
      .values({ userId, revisionDate: date })
      .onConflictDoNothing({ target: userRevisions.userId });
    return date;
  }

  async updateRevisionDate(userId: string): Promise<string> {
    const date = new Date().toISOString();
    await this.orm
      .insert(userRevisions)
      .values({ userId, revisionDate: date })
      .onConflictDoUpdate({
        target: userRevisions.userId,
        set: { revisionDate: date },
      });
    return date;
  }
}

export const revisionRepo = repository(RevisionRepository);
