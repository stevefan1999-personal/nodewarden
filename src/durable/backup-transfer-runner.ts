import { DurableObject } from 'cloudflare:workers';
import type { Env } from '../types';
import {
  BACKUP_SCHEDULER_WINDOW_MINUTES,
  hasBackupSlotBetween,
  isBackupDueNow,
  loadBackupSchedule,
  loadBackupStatus,
} from '../services/backup-config';
import type { BackupImportResultBody } from '../services/backup-import';
import * as backupRuns from '../services/backup-runs';
import { withoutQueryParams } from '../db/client';

const BACKUP_JOB_STATE_KEY = 'backup.job.state.v1';
const BACKUP_JOB_LEASE_MS = 30 * 60 * 1000;

interface BackupJobState {
  token: string;
  reason: string;
  acquiredAt: string;
  expiresAtMs: number;
}

export interface BackupRunRequest {
  actorUserId: string;
  auditMetadata: Record<string, unknown> | null;
}

export interface BackupRestoreRequest {
  actorUserId: string;
  auditMetadata: Record<string, unknown> | null;
  key: string;
  replaceExisting: boolean;
}

// Backup and restore jobs serialize through a storage-backed lease on the named runner instance: a job method
// returns null while another job holds it. A job that dies without releasing it blocks others until the lease
// expires. ponytail: the lease is fixed, so a job running past it could overlap the next; renew it between archive
// entries if runs ever take that long.
export class BackupTransferRunner extends DurableObject<Env> {
  private async withJob<T>(reason: string, job: () => Promise<T>): Promise<T | null> {
    const nowMs = Date.now();
    const current = await this.ctx.storage.get<BackupJobState>(BACKUP_JOB_STATE_KEY);
    if (current && current.expiresAtMs > nowMs) return null;
    const token = crypto.randomUUID();
    await this.ctx.storage.put<BackupJobState>(BACKUP_JOB_STATE_KEY, {
      token,
      reason,
      acquiredAt: new Date(nowMs).toISOString(),
      expiresAtMs: nowMs + BACKUP_JOB_LEASE_MS,
    });
    try {
      return await job();
    } finally {
      if ((await this.ctx.storage.get<BackupJobState>(BACKUP_JOB_STATE_KEY))?.token === token)
        await this.ctx.storage.delete(BACKUP_JOB_STATE_KEY);
    }
  }

  async runBackup(request: BackupRunRequest): Promise<backupRuns.BackupArchiveInfo | null> {
    return this.withJob(`manual:${request.actorUserId}`, () =>
      backupRuns.runBackup(this.env, 'manual', request.actorUserId, request.auditMetadata),
    );
  }

  // A run that is due now runs once; a slot that comes due while it runs gets another. A failed run is recorded
  // in the backup status and waits for the next slot instead of retrying.
  async runScheduledBackups(): Promise<void> {
    await this.withJob('scheduled', async () => {
      let checkedAt = new Date();
      let due = isBackupDueNow(
        await loadBackupSchedule(this.env.DB),
        await loadBackupStatus(this.env.DB),
        checkedAt,
        BACKUP_SCHEDULER_WINDOW_MINUTES,
      );
      while (due) {
        await backupRuns
          .runBackup(this.env, 'scheduled', null)
          .catch((error: unknown) => console.error('Scheduled backup failed', withoutQueryParams(error)));
        const now = new Date();
        due = hasBackupSlotBetween(
          await loadBackupSchedule(this.env.DB),
          await loadBackupStatus(this.env.DB),
          checkedAt,
          now,
        );
        checkedAt = now;
      }
    });
  }

  async restoreBackup(request: BackupRestoreRequest): Promise<BackupImportResultBody | null> {
    return this.withJob(`restore:${request.actorUserId}`, () =>
      backupRuns.restoreBackup(
        this.env,
        request.key,
        request.actorUserId,
        request.replaceExisting,
        request.auditMetadata,
      ),
    );
  }
}
