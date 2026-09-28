import { test } from 'node:test';
import { is } from 'drizzle-orm';
import { SQLiteTable } from 'drizzle-orm/sqlite-core';

import { createSqliteD1 } from '../test/support/d1-sqlite';
import { getOrm } from './client';
import * as schema from './schema';

// drizzle's select() names every declared column, so a table or column the migrations lack fails its query: the
// guard against a schema.ts change without its generated migration.
test('the migrations create every table and column the schema declares', async () => {
  const orm = getOrm(await createSqliteD1());
  for (const table of Object.values(schema).filter((value) => is(value, SQLiteTable)))
    await orm.select().from(table).limit(0);
});
