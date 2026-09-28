import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { registerHooks } from 'node:module';
import { getTableName, type Table } from 'drizzle-orm';
import type { SQLiteColumn } from 'drizzle-orm/sqlite-core';

import { LIMITS } from '../../config/limits';
import { AuthService } from '../../services/auth';
import type { Env, User } from '../../types';
import { waitUntil } from './cloudflare-workers';
import './workers-crypto';
import { createSqliteD1, sqliteD1, type StatementWrapper } from './d1-sqlite';
import * as userRepo from '../../services/storage-user-repo';

export const TEST_ORIGIN = 'https://vault.example.test';
// Cloudflare always sets CF-Connecting-IP, and public routes refuse to rate-limit without it.
// RFC 5737 documentation address.
const TEST_CLIENT_IP = '203.0.113.10';
const TEST_JWT_SECRET = 'nodewarden-test-jwt-secret-'.padEnd(LIMITS.auth.jwtSecretMinLength, '0');
const PBKDF2_KDF_TYPE = 0;

// Workers-only globals. The Cache API (sync responses) is a Map keyed by
// cache name and URL that ignores Cache-Control, so a handler that forgets to bump the revision
// date is served its stale entry. fetch is blocked so tests stay hermetic: the Worker's first
// request would otherwise register a real push installation with Bitwarden.
const cachedResponses = new Map<string, Response>();
const namedCache = (cacheName: string) => ({
  async match(request: RequestInfo | URL): Promise<Response | undefined> {
    return cachedResponses.get(`${cacheName} ${new Request(request).url}`)?.clone();
  },
  async put(request: RequestInfo | URL, response: Response): Promise<void> {
    cachedResponses.set(`${cacheName} ${new Request(request).url}`, response);
  },
});
// The [[ratelimits]] bindings wrangler.toml declares, counting every call per key in fixed windows of
// their period.
const rateLimitCounts = new Map<string, number>();
const rateLimitBindings = Object.fromEntries(
  [
    ...readFileSync(resolve(import.meta.dirname, '../../../wrangler.toml'), 'utf8').matchAll(
      /name = "(\w+)"\s+namespace_id = "\d+"\s+simple = \{ limit = (\d+), period = (\d+) \}/g,
    ),
  ].map(([, name, limit, period]): [string, RateLimit] => [
    name,
    {
      async limit({ key }) {
        const counter = `${name} ${key} ${Math.floor(Date.now() / 1000 / Number(period))}`;
        const count = (rateLimitCounts.get(counter) ?? 0) + 1;
        rateLimitCounts.set(counter, count);
        return { success: count <= Number(limit) };
      },
    },
  ]),
);

// workerd's pass-through stream that promises a byte count, which R2 needs to store a stream: like workerd's, it
// errors when the bytes through it are more or fewer.
class FixedLengthStream extends TransformStream<Uint8Array, Uint8Array> {
  constructor(expectedLength: number | bigint) {
    let seen = 0;
    super({
      transform(chunk, controller) {
        seen += chunk.byteLength;
        if (seen > Number(expectedLength)) throw new Error('FixedLengthStream received more bytes than promised');
        controller.enqueue(chunk);
      },
      flush() {
        if (seen !== Number(expectedLength)) throw new Error('FixedLengthStream received fewer bytes than promised');
      },
    });
  }
}

Object.assign(globalThis, {
  FixedLengthStream,
  caches: { default: namedCache('default') },
  async fetch(input: RequestInfo | URL): Promise<Response> {
    throw new Error(`Outbound fetch blocked in tests: ${new Request(input).url}`);
  },
});

// src/durable/notifications-hub.ts imports `cloudflare:workers`, which Node cannot resolve.
// Static imports link before this module body runs, so the Worker entry loads dynamically.
const cloudflareWorkersStandIn = new URL('./cloudflare-workers.ts', import.meta.url).href;
registerHooks({
  resolve: (specifier, context, nextResolve) =>
    specifier === 'cloudflare:workers'
      ? { url: cloudflareWorkersStandIn, shortCircuit: true }
      : nextResolve(specifier, context),
});
const { default: worker } = await import('../../index');
const { BackupTransferRunner } = await import('../../durable/backup-transfer-runner');

const executionContext = { waitUntil, passThroughOnException: () => {} } as unknown as ExecutionContext;

// Realtime notifications go to the NotificationsHub Durable Object; tests only need them accepted.
const acceptingDurableObjectNamespace = {
  idFromName: (name: string) => name,
  get: () => ({ fetch: async () => new Response(null, { status: 204 }) }),
} as unknown as DurableObjectNamespace;

// src/index.ts registers the push installation and syncs administrator roles once per isolate. Spend that on a
// throwaway deployment, so it never runs against a test's database.
await worker.fetch(new Request(`${TEST_ORIGIN}/api/alive`), await createTestEnv(), executionContext);

// Every env is a fresh deployment: its own database, an empty edge cache and fresh rate limiters, so rate-limit
// budgets keyed by the shared test client IP never leak between tests.
export async function createTestEnv(overrides: Partial<Env> = {}): Promise<Env> {
  cachedResponses.clear();
  rateLimitCounts.clear();
  const env = {
    DB: await createSqliteD1(),
    JWT_SECRET: TEST_JWT_SECRET,
    NOTIFICATIONS_HUB: acceptingDurableObjectNamespace,
    BACKUPS: memoryR2().binding,
    ...rateLimitBindings,
    ...overrides,
  } as Env;
  // The deployment's one backup runner, its lease kept in Durable Object storage held in memory.
  if (!env.BACKUP_TRANSFER_RUNNER) {
    const stored = new Map<string, unknown>();
    const storage = {
      get: async (key: string) => stored.get(key),
      put: async (key: string, value: unknown) => void stored.set(key, value),
      delete: async (key: string) => stored.delete(key),
    };
    const runner = new BackupTransferRunner({ storage } as unknown as DurableObjectState, env);
    env.BACKUP_TRANSFER_RUNNER = {
      idFromName: (name: string) => name,
      get: () => runner,
    } as unknown as Env['BACKUP_TRANSFER_RUNNER'];
  }
  return env;
}

export function memoryKv(): { binding: KVNamespace; values: Map<string, string> } {
  const values = new Map<string, string>();
  const binding = {
    get: async (key: string) => values.get(key) ?? null,
    // Blob reads ask for bytes, which a restore may have stored as a Uint8Array; the metadata a put carries is not kept.
    getWithMetadata: async (key: string) => {
      const value = values.get(key);
      return { value: value === undefined ? null : await new Response(value).arrayBuffer(), metadata: null };
    },
    // Reads a stream to its end, as KV does; values are text, as every blob the tests store is.
    put: async (key: string, value: string | ReadableStream | ArrayBuffer | ArrayBufferView) => {
      values.set(key, typeof value === 'string' ? value : await new Response(value).text());
    },
    delete: async (key: string) => {
      values.delete(key);
    },
  } as KVNamespace;
  return { binding, values };
}

export interface StoredR2Object {
  bytes: Uint8Array;
  uploaded: Date;
  contentType: string | undefined;
}

// An R2 bucket in memory with the calls backups make: range reads, listing keys in order a page at a time, and
// multipart uploads held to R2's part rules, so a writer that breaks them fails here as it would in production.
export function memoryR2(): { binding: R2Bucket; objects: Map<string, StoredR2Object> } {
  const LIST_PAGE_KEYS = 1000;
  const MIN_PART_BYTES = 5 * 1024 * 1024;
  const objects = new Map<string, StoredR2Object>();
  const describe = (key: string, { bytes, uploaded, contentType }: StoredR2Object) => ({
    key,
    size: bytes.byteLength,
    uploaded,
    httpMetadata: { contentType },
  });
  const binding = {
    async put(key: string, value: BodyInit, options?: R2PutOptions) {
      const httpMetadata = options?.httpMetadata;
      const stored = {
        bytes: new Uint8Array(await new Response(value).arrayBuffer()),
        uploaded: new Date(),
        contentType: httpMetadata instanceof Headers ? undefined : httpMetadata?.contentType,
      };
      objects.set(key, stored);
      return describe(key, stored);
    },
    async get(key: string, options?: R2GetOptions) {
      const stored = objects.get(key);
      if (!stored) return null;
      const range = options?.range as { offset: number; length: number } | undefined;
      const bytes = range ? stored.bytes.slice(range.offset, range.offset + range.length) : stored.bytes;
      return {
        ...describe(key, stored),
        body: new Response(bytes).body,
        arrayBuffer: async () => bytes.slice().buffer,
      };
    },
    async createMultipartUpload(key: string, options?: R2MultipartOptions) {
      const parts = new Map<number, Uint8Array>();
      return {
        key,
        uploadId: crypto.randomUUID(),
        async uploadPart(partNumber: number, value: BodyInit) {
          parts.set(partNumber, new Uint8Array(await new Response(value).arrayBuffer()));
          return { partNumber, etag: String(partNumber) };
        },
        async complete(uploaded: R2UploadedPart[]) {
          const ordered = uploaded
            .toSorted((a, b) => a.partNumber - b.partNumber)
            .map(({ partNumber }) => parts.get(partNumber)!);
          const [first, ...rest] = ordered;
          if (rest.some((part, index) => index < rest.length - 1 && part.byteLength !== first.byteLength))
            throw new Error('R2 multipart parts before the last must share one size');
          if (ordered.slice(0, -1).some((part) => part.byteLength < MIN_PART_BYTES))
            throw new Error('R2 multipart parts before the last must be at least 5 MiB');
          const bytes = new Uint8Array(ordered.reduce((sum, part) => sum + part.byteLength, 0));
          ordered.reduce((offset, part) => (bytes.set(part, offset), offset + part.byteLength), 0);
          const httpMetadata = options?.httpMetadata;
          const stored = {
            bytes,
            uploaded: new Date(),
            contentType: httpMetadata instanceof Headers ? undefined : httpMetadata?.contentType,
          };
          objects.set(key, stored);
          return describe(key, stored);
        },
        async abort() {
          parts.clear();
        },
      };
    },
    async head(key: string) {
      const stored = objects.get(key);
      return stored ? describe(key, stored) : null;
    },
    async list(options: R2ListOptions = {}) {
      const keys = [...objects.keys()].filter((key) => key.startsWith(options.prefix ?? '')).toSorted();
      const start = Number(options.cursor ?? 0);
      const page = keys.slice(start, start + (options.limit ?? LIST_PAGE_KEYS));
      const next = start + page.length;
      return {
        objects: page.map((key) => describe(key, objects.get(key)!)),
        truncated: next < keys.length,
        cursor: String(next),
        delimitedPrefixes: [],
      };
    },
    async delete(keys: string | string[]) {
      for (const key of [keys].flat()) objects.delete(key);
    },
  } as unknown as R2Bucket;
  return { binding, objects };
}

export async function seedUser(env: Env, overrides: Partial<User> = {}): Promise<User> {
  const id = overrides.id ?? crypto.randomUUID();
  const now = new Date().toISOString();
  const user: User = {
    id,
    email: `${id}@example.test`,
    emailVerified: true,
    name: 'Test User',
    masterPasswordHint: null,
    masterPasswordHash: 'test-master-password-hash',
    key: '2.dGVzdA==|dGVzdA==|dGVzdA==',
    privateKey: null,
    publicKey: null,
    kdfType: PBKDF2_KDF_TYPE,
    kdfIterations: LIMITS.auth.defaultKdfIterations,
    securityStamp: crypto.randomUUID(),
    role: 'user',
    status: 'active',
    totpSecret: null,
    totpRecoveryCode: null,
    twoFactorEmail: null,
    yubikeyKey1: null,
    yubikeyKey2: null,
    yubikeyKey3: null,
    yubikeyKey4: null,
    yubikeyKey5: null,
    yubikeyNfc: false,
    apiKey: null,
    userKeyId: null,
    createdAt: now,
    updatedAt: now,
    ...overrides,
  };
  await userRepo.createUser(env.DB, user);
  return user;
}

export interface WorkerRequest {
  method?: string;
  path: string;
  // JSON-encoded, except URLSearchParams, which is sent form-encoded as /identity expects, and
  // FormData, which is sent multipart as official web uploads files.
  body?: unknown;
  // Omit for an anonymous request.
  userId?: string;
  headers?: HeadersInit;
}

// Calls the real Worker fetch handler, so routing, auth and CORS all run.
export async function authedFetch(
  env: Env,
  { method = 'GET', path, body, userId, headers }: WorkerRequest,
): Promise<Response> {
  const requestHeaders = new Headers({ 'CF-Connecting-IP': TEST_CLIENT_IP });
  if (userId) {
    const user = await userRepo.getUserById(env.DB, userId);
    if (!user) throw new Error(`authedFetch: no user ${userId}`);
    requestHeaders.set('Authorization', `Bearer ${await new AuthService(env).generateAccessToken(user)}`);
  }
  const isForm = body instanceof URLSearchParams || body instanceof FormData;
  if (body !== undefined && !isForm) requestHeaders.set('Content-Type', 'application/json');
  new Headers(headers).forEach((value, name) => requestHeaders.set(name, value));

  const request = new Request(new URL(path, TEST_ORIGIN), {
    method,
    headers: requestHeaders,
    body: body === undefined || isForm ? body : JSON.stringify(body),
  });
  return worker.fetch(request, env, executionContext);
}

export const MAILABLE_DOMAIN = 'stevefan1999.tech';
export type SentEmail = Parameters<NonNullable<Env['EMAIL']>['send']>[0];

export function captureEmail(): { overrides: Partial<Env>; sent: SentEmail[] } {
  const sent: SentEmail[] = [];
  return {
    sent,
    overrides: {
      EMAIL: {
        async send(message) {
          sent.push(message);
          return { messageId: crypto.randomUUID() };
        },
      },
      EMAIL_FROM: `noreply@${MAILABLE_DOMAIN}`,
      WEB_VAULT_ORIGINS: 'https://web.example.test',
    },
  };
}

export function failingEmail(code: string): NonNullable<Env['EMAIL']> {
  return {
    async send() {
      throw Object.assign(new Error('x'), { code });
    },
  };
}
export { drainWaitUntil } from './cloudflare-workers';

export function portalFetch(
  env: Env,
  {
    method = 'GET',
    path,
    form,
    cookie,
    headers,
  }: { method?: string; path: string; form?: Record<string, string>; cookie?: string; headers?: HeadersInit },
): Promise<Response> {
  const requestHeaders = new Headers(headers);
  if (method === 'POST' && !requestHeaders.has('Origin')) requestHeaders.set('Origin', TEST_ORIGIN);
  if (cookie) requestHeaders.set('Cookie', cookie);
  return authedFetch(env, {
    method,
    path,
    body: form ? new URLSearchParams(form) : undefined,
    headers: requestHeaders,
  });
}

export async function signInToAdminPortal(env: Env, email: string): Promise<{ cookie: string; csrf: string }> {
  const { parseAdminDirectory, createAdminSession, adminCookie, ADMIN_COOKIE } =
    await import('../../services/admin-portal-auth');
  const directory = parseAdminDirectory(env);
  if (directory.kind !== 'enabled' || !directory.admins.has(email))
    throw new Error('Test administrator is not configured');
  const session = await createAdminSession(env, email, directory.admins.get(email)!);
  return { cookie: adminCookie(ADMIN_COOKIE, session.token, LIMITS.admin.sessionTtlSeconds), csrf: session.csrf };
}

// Every statement drizzle prepares from now on passes through wrap (see SqliteD1Database.wrapStatements).
export function wrapStatements(env: Env, wrap: StatementWrapper): () => void {
  return sqliteD1(env.DB).wrapStatements(wrap);
}

// Runs `before` right before the first statement matching `pattern` executes, so a test can slip a
// competing request into the window between a handler's read and its guarded write.
export function interceptStatement(env: Env, pattern: RegExp, before: () => Promise<void>): void {
  let pending = true;
  const intercept = (statement: D1PreparedStatement): D1PreparedStatement =>
    new Proxy(statement, {
      get(target, property) {
        const value = Reflect.get(target, property);
        if (property === 'bind') return (...values: unknown[]) => intercept(target.bind(...values));
        if (typeof value !== 'function') return value;
        if (!['run', 'first', 'all', 'raw'].includes(String(property))) return value.bind(target);
        return async (...args: unknown[]) => {
          if (pending) {
            pending = false;
            await before();
          }
          return value.apply(target, args);
        };
      },
    });
  wrapStatements(env, (query, statement) => (pattern.test(query) ? intercept(statement) : statement));
}

export type FailingWrite =
  | { table: Table; event: 'INSERT' | 'DELETE'; rowId?: string }
  | { table: Table; event: 'UPDATE'; column?: SQLiteColumn; rowId?: string };

// Makes a matching write fail with `message` inside its statement or batch, so the whole batch rolls back
// (see SqliteD1Database.failWrites); `rowId` narrows it to one row. Returns the undo for tests that retry.
export async function abortWrites(env: Env, write: FailingWrite, message: string): Promise<() => Promise<void>> {
  const undo = sqliteD1(env.DB).failWrites(
    {
      table: getTableName(write.table),
      event: write.event,
      column: write.event === 'UPDATE' ? write.column?.name : undefined,
      rowId: write.rowId,
    },
    message,
  );
  return async () => undo();
}
