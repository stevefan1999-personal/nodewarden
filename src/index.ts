import { runMaintenance } from './services/maintenance';
import { syncVaultAdminRoles } from './services/vault-admin-role';
import { ensurePushInstallationCredentials } from './services/push-relay';
import { Env } from './types';
import { NotificationsHub } from './durable/notifications-hub';
import { BackupTransferRunner } from './durable/backup-transfer-runner';
import { app } from './router';
import { applyCors, applySecurityHeaders } from './utils/response';
import { isBackendRequestPath } from './web-vault-visibility';
import { withoutQueryParams } from './db/client';
import { readEnvConfig } from './config/env';
import { constantTimeEquals } from './utils/api-key';
import { z } from 'zod';

const GatewayOrigin = z
  .url()
  .regex(/^https?:\/\/[^/?#\\@\s]+\/?$/i)
  .transform((origin) => new URL(origin));

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
    const settings = readEnvConfig(env);
    // Trailing slashes are trimmed so routes match either form.
    const url = new URL(request.url);
    const normalizedPathname = url.pathname.length <= 1 ? url.pathname : url.pathname.replace(/\/+$/, '');
    let normalizedRequest = request;
    if (normalizedPathname !== url.pathname) {
      url.pathname = normalizedPathname;
      normalizedRequest = new Request(url.toString(), request);
    }
    const isMaintenance = normalizedRequest.method === 'POST' && url.pathname === '/api/internal/maintenance';

    if (settings.NODEWARDEN_DEPLOYMENT === null) {
      return applyCors(
        normalizedRequest,
        Response.json({ error: 'Invalid deployment configuration' }, { status: 503 }),
        env,
      );
    }
    if (settings.PLATFORM_REQUIRE_GATEWAY !== '0' && !isMaintenance) {
      if (
        settings.PLATFORM_REQUIRE_GATEWAY === null ||
        !settings.PLATFORM_INTERNAL_SECRET ||
        !constantTimeEquals(
          normalizedRequest.headers.get('X-CloudWarden-Gateway-Secret') || '',
          settings.PLATFORM_INTERNAL_SECRET,
        )
      ) {
        return applyCors(normalizedRequest, Response.json({ error: 'Forbidden' }, { status: 403 }), env);
      }
      const forwardedOrigin = normalizedRequest.headers.get('X-CloudWarden-Original-Origin');
      if (forwardedOrigin !== null) {
        const parsed = GatewayOrigin.safeParse(forwardedOrigin);
        if (!parsed.success || !settings.WEB_VAULT_ORIGINS.includes(parsed.data.origin)) {
          return applyCors(normalizedRequest, Response.json({ error: 'Forbidden' }, { status: 403 }), env);
        }
        url.protocol = parsed.data.protocol;
        url.hostname = parsed.data.hostname;
        url.port = parsed.data.port;
      }
    }
    if (
      normalizedRequest.headers.has('X-CloudWarden-Gateway-Secret') ||
      normalizedRequest.headers.has('X-CloudWarden-Original-Origin')
    ) {
      // Keep the vault's bearer token and body; platform capabilities never reach handlers or assets.
      normalizedRequest = new Request(url.toString(), normalizedRequest);
      normalizedRequest.headers.delete('X-CloudWarden-Gateway-Secret');
      normalizedRequest.headers.delete('X-CloudWarden-Original-Origin');
    }
    if (settings.PLATFORM_SUBSCRIPTION_STATUS !== 'active' && !isMaintenance) {
      return applyCors(
        normalizedRequest,
        Response.json(
          {
            error:
              settings.PLATFORM_SUBSCRIPTION_STATUS === 'suspended'
                ? 'Subscription suspended'
                : 'Invalid subscription configuration',
          },
          { status: settings.PLATFORM_SUBSCRIPTION_STATUS === 'suspended' ? 402 : 503 },
        ),
        env,
      );
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
      // Outside the Hono app, so no context answers it.
      const resp = Response.json(
        {
          error: 'Database not initialized',
          error_description: 'Database initialization failed. Check server logs for details.',
          ErrorModel: {
            Message: 'Service temporarily unavailable',
            Object: 'error',
          },
        },
        { status: 500 },
      );
      return applyCors(normalizedRequest, resp, env);
    }

    return applySecurityHeaders(normalizedRequest, await app.fetch(normalizedRequest, env, ctx));
  },

  async scheduled(controller: ScheduledController, env: Env): Promise<void> {
    void controller;
    await ensureDatabaseInitialized(env);
    if (dbInitError) throw new Error(`Scheduled jobs skipped: database initialization failed: ${dbInitError}`);
    await runMaintenance(env);
  },
};

export { NotificationsHub };
export { BackupTransferRunner };
