import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import Database from 'better-sqlite3';

type SqliteConnection = InstanceType<typeof Database>;

interface ExecutedStatement {
  columns: string[];
  rows: unknown[][];
  changes: number;
  lastRowId: number;
}

// Production D1 rejects statements above this; SQLite alone allows thousands, so enforce it
// here to catch unchunked queries before they reach a real database.
export const D1_MAX_BOUND_PARAMETERS = 100;

// Object rows are built from positional ones, so duplicate column names resolve the way D1's
// all()/first() resolve them: the last column wins.
function toD1Result({ columns, rows, changes, lastRowId }: ExecutedStatement): D1Result<Record<string, unknown>> {
  return {
    success: true,
    results: rows.map((row) => Object.fromEntries(columns.map((column, index) => [column, row[index]]))),
    meta: {
      duration: 0,
      size_after: 0,
      rows_read: rows.length,
      rows_written: changes,
      last_row_id: lastRowId,
      changed_db: changes > 0,
      changes,
    },
  };
}

class SqliteD1Statement {
  constructor(
    private readonly connection: SqliteConnection,
    private readonly query: string,
    private readonly bindings: unknown[] = [],
  ) {}

  // D1 statements are immutable: drizzle prepares a query once and re-binds it per call.
  // D1 also validates bindings eagerly: undefined is a type error, and booleans and integral numbers
  // bind as INTEGER. better-sqlite3 rejects booleans and binds every number as REAL (a TEXT column
  // would store 1 as '1.0'), so pass integers as bigint, which it binds as INTEGER.
  bind(...values: unknown[]): SqliteD1Statement {
    return new SqliteD1Statement(
      this.connection,
      this.query,
      values.map((value) => {
        if (value === undefined) throw new Error("D1_TYPE_ERROR: Type 'undefined' not supported for value 'undefined'");
        const scalar = typeof value === 'boolean' ? Number(value) : value;
        return Number.isSafeInteger(scalar) ? BigInt(scalar as number) : scalar;
      }),
    );
  }

  // D1 compiles lazily, so SQL errors (including "already exists", which the schema bootstrap
  // tolerates) surface when the statement runs rather than at prepare().
  execute(): ExecutedStatement {
    try {
      if (this.bindings.length > D1_MAX_BOUND_PARAMETERS) {
        throw new Error(`too many SQL variables: ${this.bindings.length} > ${D1_MAX_BOUND_PARAMETERS}`);
      }
      const statement = this.connection.prepare(this.query);
      if (!statement.reader) {
        const { changes, lastInsertRowid } = statement.run(...this.bindings);
        return { columns: [], rows: [], changes, lastRowId: Number(lastInsertRowid) };
      }
      const rows = statement.raw(true).all(...this.bindings) as unknown[][];
      // A row-returning write (INSERT ... RETURNING) still reports its changes, as D1 does: one returned row
      // per changed row.
      const changes = statement.readonly ? 0 : rows.length;
      return {
        columns: statement.columns().map((column: { name: string }) => column.name),
        rows,
        changes,
        lastRowId: 0,
      };
    } catch (error) {
      throw new Error(`D1_ERROR: ${error instanceof Error ? error.message : String(error)}`, { cause: error });
    }
  }

  async first(column?: string): Promise<unknown> {
    const [row] = toD1Result(this.execute()).results;
    if (column === undefined) return row ?? null;
    if (row && !(column in row)) throw new Error(`D1_COLUMN_NOTFOUND: Column not found (${column})`);
    return row?.[column] ?? null;
  }

  async all(): Promise<D1Result<Record<string, unknown>>> {
    return toD1Result(this.execute());
  }

  async run(): Promise<D1Result<Record<string, unknown>>> {
    return toD1Result(this.execute());
  }

  async raw(options?: { columnNames?: boolean }): Promise<unknown[]> {
    const { columns, rows } = this.execute();
    return options?.columnNames ? [columns, ...rows] : rows;
  }
}

export type StatementWrapper = (query: string, statement: D1PreparedStatement) => D1PreparedStatement;

export type FailingWrite = {
  table: string;
  event: 'INSERT' | 'UPDATE' | 'DELETE';
  column?: string;
  rowId?: string;
};

class SqliteD1Database {
  private readonly wrappers = new Set<StatementWrapper>();

  constructor(private readonly connection: SqliteConnection) {}

  prepare(query: string): D1PreparedStatement {
    const statement = new SqliteD1Statement(this.connection, query) as unknown as D1PreparedStatement;
    return [...this.wrappers].reduce((wrapped, wrap) => wrap(query, wrapped), statement);
  }

  // Test seam: every statement prepared from now on passes through wrap, which may read its SQL text, fail it by
  // throwing, or return a wrapped statement. Returns the undo.
  wrapStatements(wrap: StatementWrapper): () => void {
    this.wrappers.add(wrap);
    return () => this.wrappers.delete(wrap);
  }

  // Test fault injection: SQLite aborts a matching write with `message`, so it fails inside its statement or batch
  // exactly as a failing D1 statement would and the whole batch rolls back; `rowId` narrows it to one row. A
  // trigger is the only per-row hook SQLite has, and this class is the tests' SQL driver. Returns the undo.
  failWrites({ table, event, column, rowId }: FailingWrite, message: string): () => void {
    const name = `abort_${crypto.randomUUID().replaceAll('-', '')}`;
    const literal = (value: string) => `'${value.replaceAll("'", "''")}'`;
    const when = column ? `${event} OF "${column}"` : event;
    const onRow = rowId === undefined ? '' : ` WHEN ${event === 'DELETE' ? 'OLD' : 'NEW'}.id = ${literal(rowId)}`;
    this.connection.exec(
      `CREATE TRIGGER ${name} BEFORE ${when} ON "${table}"${onRow} BEGIN SELECT RAISE(ABORT, ${literal(message)}); END`,
    );
    return () => this.connection.exec(`DROP TRIGGER ${name}`);
  }

  // D1 runs a batch as one implicit transaction: a failing statement rolls back all of them.
  async batch(statements: SqliteD1Statement[]): Promise<D1Result<Record<string, unknown>>[]> {
    return this.connection.transaction(() => statements.map((statement) => toD1Result(statement.execute())))();
  }
}

// The stand-in behind a test env's DB binding, for its test seams.
export function sqliteD1(db: D1Database): SqliteD1Database {
  if (!(db instanceof SqliteD1Database)) throw new Error('Not a SQLite-backed test database');
  return db;
}

// Every drizzle-kit migration's SQL, in the order wrangler applies them to D1.
const MIGRATIONS_DIR = join(import.meta.dirname, '../../../migrations');
export const MIGRATIONS = readdirSync(MIGRATIONS_DIR)
  .toSorted()
  .map((folder) => readFileSync(join(MIGRATIONS_DIR, folder, 'migration.sql'), 'utf8'));

// A fresh in-memory database per call, migrated the way wrangler migrates D1, which enforces foreign keys.
export async function createSqliteD1(): Promise<D1Database> {
  const connection = new Database(':memory:');
  connection.pragma('foreign_keys = ON');
  for (const migration of MIGRATIONS) connection.exec(migration);
  return new SqliteD1Database(connection) as unknown as D1Database;
}
