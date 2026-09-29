import { and, eq, exists, getColumns, type SQL, type Table } from 'drizzle-orm';
import { drizzle, type DrizzleD1Database } from 'drizzle-orm/d1';

import { users } from './schema';
import { SINGLE_ROW, caseWhen, changes, json } from './sql';

export type Orm = DrizzleD1Database;

// D1 rejects any statement that binds more than this many parameters.
export const D1_MAX_BOUND_PARAMETERS = 100;

export function columnCount(table: Table): number {
  return Object.keys(getColumns(table)).length;
}

// Splits multi-row INSERT values so each statement stays within D1's bound-parameter limit, less
// any parameters every chunk's statement binds besides the rows.
export function chunkRows<T>(rows: T[], columnsPerRow: number, fixedParameters = 0): T[][] {
  const size = Math.floor((D1_MAX_BOUND_PARAMETERS - fixedParameters) / columnsPerRow);
  return Array.from({ length: Math.ceil(rows.length / size) }, (_, index) =>
    rows.slice(index * size, (index + 1) * size),
  );
}

// Splits items into chunks small enough that statement(chunk) stays within D1's bound-parameter limit.
// Rendering the statement for one and for two items measures what each item and everything else binds
// (JSON paths, literals, NULLs in SET, bound expressions left of IN), which hand counts kept getting wrong.
// Multi-row inserts keep chunkRows(rows, columnCount(table)): which columns bind varies with each row.
export function statementChunks<T>(items: T[], statement: (chunk: T[]) => { toSQL(): { params: unknown[] } }): T[][] {
  if (items.length < 2) return items.length ? [items] : [];
  const [one, two] = [1, 2].map((size) => statement(items.slice(0, size)).toSQL().params.length);
  if (two === one) throw new Error('statementChunks: the statement binds nothing per item');
  return chunkRows(items, two - one, 2 * one - two);
}

// Reuse one driver per database binding within a Worker isolate.
const ormByBinding = new WeakMap<D1Database, Orm>();

export function getOrm(d1: D1Database): Orm {
  const existing = ormByBinding.get(d1);
  if (existing) return existing;

  const orm = drizzle(d1);
  ormByBinding.set(d1, orm);
  return orm;
}

// A repository groups one table family's queries around its D1 binding and that binding's orm.
export abstract class Repository {
  protected readonly orm: Orm;

  constructor(protected readonly db: D1Database) {
    this.orm = getOrm(db);
  }
}

// A repository's accessor: one instance per D1 binding, built on first use and kept, as getOrm keeps the orm. Its
// state is the binding and the orm, so an isolate can reuse it for every request on that database.
export function repository<T extends Repository>(Class: new (db: D1Database) => T): (db: D1Database) => T {
  const instances = new WeakMap<D1Database, T>();
  return (db) => {
    const existing = instances.get(db);
    if (existing) return existing;
    const created = new Class(db);
    instances.set(db, created);
    return created;
  };
}

// D1 batches have no conditional rollback. Appending this select after a guarded write aborts the whole
// batch when that write matched no rows: json() of a non-JSON string raises, and D1 rolls the batch back.
export function abortUnlessChanged(orm: Orm, reason: string) {
  return orm.select({ abort: caseWhen(eq(changes(), 0), json(reason)) }).from(SINGLE_ROW);
}

// EXISTS the user's row, narrowed by conditions (undefined ones are skipped). In a WHERE clause it guards a
// write to another table against a concurrent change to that user, such as a rotated security stamp.
export function userRowMatches(orm: Orm, userId: string, ...conditions: (SQL | undefined)[]) {
  return exists(
    orm
      .select({ id: users.id })
      .from(users)
      .where(and(eq(users.id, userId), ...conditions)),
  );
}

// drizzle ends a failed query's message with every bound value (password hashes, keys, one-time codes), its stack
// repeats the message, and a Durable Object's failure crosses RPC as a plain Error carrying the same text.
const BOUND_VALUES = /\nparams: [\s\S]*$/;

// What may be logged of an error: every error down its cause chain keeps its statement text and driver error but
// loses drizzle's bound values, and each rebuilt error gets a fresh stack.
export function withoutQueryParams(error: unknown, seen: ReadonlySet<unknown> = new Set()): unknown {
  if (!(error instanceof Error)) return error;
  if (seen.has(error)) return undefined;
  const cause = withoutQueryParams(error.cause, new Set([...seen, error]));
  const message = error.message.replace(BOUND_VALUES, '');
  if (message === error.message && cause === error.cause) return error;
  return Object.assign(cause === undefined ? new Error(message) : new Error(message, { cause }), { name: error.name });
}
