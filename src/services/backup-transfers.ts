import { AwsClient } from 'aws4fetch';

import { readEnvConfig } from '../config/env';
import type { Env } from '../types';

// Long enough to start a transfer of any size, short enough that a leaked link soon stops working: R2 checks the
// expiry when a transfer starts, not while it runs.
export const BACKUP_TRANSFER_TTL_SECONDS = 15 * 60;
const MS_PER_SECOND = 1000;

// The S3 settings a presigned archive URL is signed with, or null while any is missing.
function transferSettings(env: Env) {
  const { R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, BACKUPS_BUCKET_NAME } = readEnvConfig(env);
  return R2_ACCOUNT_ID && R2_ACCESS_KEY_ID && R2_SECRET_ACCESS_KEY && BACKUPS_BUCKET_NAME
    ? {
        accountId: R2_ACCOUNT_ID,
        accessKeyId: R2_ACCESS_KEY_ID,
        secretAccessKey: R2_SECRET_ACCESS_KEY,
        bucket: BACKUPS_BUCKET_NAME,
      }
    : null;
}

export function backupTransfersConfigured(env: Env): boolean {
  return transferSettings(env) !== null;
}

// A presigned URL that moves one archive straight between the administrator and the BACKUPS bucket, so no Worker
// limit applies to its size: GET downloads it as a file, PUT uploads it. Query signing covers only the host header,
// so a PUT may carry any body until the URL expires.
export async function presignBackupTransfer(
  env: Env,
  method: 'GET' | 'PUT',
  key: string,
  now: Date = new Date(),
): Promise<{ url: string; expiresAt: string }> {
  const settings = transferSettings(env);
  if (!settings) throw new Error('Presigned backup transfers need R2 S3 credentials');
  const objectPath = key.split('/').map(encodeURIComponent).join('/');
  const url = new URL(`https://${settings.accountId}.r2.cloudflarestorage.com/${settings.bucket}/${objectPath}`);
  url.searchParams.set('X-Amz-Expires', String(BACKUP_TRANSFER_TTL_SECONDS));
  if (method === 'GET')
    url.searchParams.set('response-content-disposition', `attachment; filename="${key.split('/').at(-1)}"`);
  const client = new AwsClient({
    accessKeyId: settings.accessKeyId,
    secretAccessKey: settings.secretAccessKey,
    service: 's3',
    region: 'auto',
  });
  const signed = await client.sign(url.toString(), {
    method,
    aws: { signQuery: true, datetime: now.toISOString().replace(/[:-]|\.\d{3}/g, '') },
  });
  return {
    url: signed.url,
    expiresAt: new Date(now.getTime() + BACKUP_TRANSFER_TTL_SECONDS * MS_PER_SECOND).toISOString(),
  };
}
