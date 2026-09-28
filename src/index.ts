import { pruneEvents } from './services/events';
import { purgeExpiredEmailOtps } from './services/email-otp';
import { purgeSecretsTrash } from './services/storage-secret-repo';
import { purgeExpiredSends, purgeOldTrash } from './services/retention';
import { syncVaultAdminRoles } from './services/vault-admin-role';
import { ensurePushInstallationCredentials } from './services/push-relay';
import { Env } from './types';
import { NotificationsHub } from './durable/notifications-hub';
import { BackupTransferRunner } from './durable/backup-transfer-runner';
import { app } from './router';
import { applyCors, applySecurityHeaders, jsonResponse } from './utils/response';
import { runScheduledBackupIfDue } from './handlers/backup';
import { approveExpiredEmergencyAccess, remindPendingEmergencyAccess } from './handlers/emergency-access';
import { isBackendRequestPath } from './web-vault-visibility';
import { withoutQueryParams } from './db/client';

let dbInitialized = false;
let dbInitError: string | null = null;
let dbInitPromise: Promise<void> | null = null;

async function ensureDatabaseInitialized(env: Env): Promise<void> {
  if (dbInitialized) return;

  if (!dbInitPromise) {
    dbInitPromise = (async () => {
      await ensurePushInstallationCredentials(env.DB);
      try {
        await syncVaultAdminRoles(env);
      } catch {
        console.error('Vault administrator role sync failed during initialization');
      }
      dbInitialized = true;
      dbInitError = null;
    })()
      .catch((error: unknown) => {
        const loggable = withoutQueryParams(error);
        console.error('Failed to initialize database:', loggable);
        // Logged again on every request and cron run, so it keeps only the scrubbed message.
        dbInitError = loggable instanceof Error ? loggable.message : 'Unknown database initialization error';
      })
      .finally(() => {
        dbInitPromise = null;
      });
  }

  await dbInitPromise;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    // Trailing slashes are trimmed so routes match either form.
    const url = new URL(request.url);
    const normalizedPathname = url.pathname.length <= 1 ? url.pathname : url.pathname.replace(/\/+$/, '');
    let normalizedRequest = request;
    if (normalizedPathname !== url.pathname) {
      url.pathname = normalizedPathname;
      normalizedRequest = new Request(url.toString(), request);
    }

    if (
      env.ASSETS &&
      (normalizedRequest.method === 'GET' || normalizedRequest.method === 'HEAD') &&
      !isBackendRequestPath(url.pathname)
    ) {
      const assetResponse = await env.ASSETS.fetch(normalizedRequest);
      const contentType = String(assetResponse.headers.get('Content-Type') || '').toLowerCase();
      const shouldNoIndex = url.pathname === '/robots.txt' || contentType.includes('text/html');
      if (!shouldNoIndex) return applyCors(normalizedRequest, assetResponse, env);
      const headers = new Headers(assetResponse.headers);
      headers.set('X-Robots-Tag', 'noindex, nofollow, noarchive, nosnippet');
      return applyCors(
        normalizedRequest,
        new Response(assetResponse.body, {
          status: assetResponse.status,
          statusText: assetResponse.statusText,
          headers,
        }),
        env,
      );
    }

    await ensureDatabaseInitialized(env);
    if (dbInitError) {
      // Log full error server-side, return generic message to client.
      console.error('DB init error (not forwarded to client):', dbInitError);
      const resp = jsonResponse(
        {
          error: 'Database not initialized',
          error_description: 'Database initialization failed. Check server logs for details.',
          ErrorModel: {
            Message: 'Service temporarily unavailable',
            Object: 'error',
          },
        },
        500,
      );
      return applyCors(normalizedRequest, resp, env);
    }

    return applySecurityHeaders(normalizedRequest, await app.fetch(normalizedRequest, env, ctx));
  },

  async scheduled(controller: ScheduledController, env: Env): Promise<void> {
    void controller;
    await ensureDatabaseInitialized(env);
    if (dbInitError) throw new Error(`Scheduled jobs skipped: database initialization failed: ${dbInitError}`);
    // Every job runs even when another fails. Each failure is logged, then fails the invocation, so it shows
    // in the Worker's cron history instead of reading as success.
    const jobs = {
      'event cleanup': () => pruneEvents(env.DB),
      'email code cleanup': () => purgeExpiredEmailOtps(env.DB),
      'scheduled backup': () => runScheduledBackupIfDue(env),
      'Secrets Manager trash purge': () => purgeSecretsTrash(env.DB),
      'emergency access timeouts': () => approveExpiredEmergencyAccess(env),
      'emergency access reminders': () => remindPendingEmergencyAccess(env),
      'expired Send purge': () => purgeExpiredSends(env),
      'trash purge': () => purgeOldTrash(env),
    };
    const outcomes = await Promise.allSettled(Object.values(jobs).map((job) => job()));
    const failed = Object.keys(jobs).filter((name, index) => {
      const outcome = outcomes[index];
      if (outcome.status === 'rejected')
        console.error(`Scheduled job failed: ${name}`, withoutQueryParams(outcome.reason));
      return outcome.status === 'rejected';
    });
    if (failed.length) throw new Error(`Scheduled jobs failed: ${failed.join(', ')}`);
  },
};

export { NotificationsHub };
export { BackupTransferRunner };
