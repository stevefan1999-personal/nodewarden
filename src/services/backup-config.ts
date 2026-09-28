import { z } from 'zod';

import { jsonText } from './org-types';
import * as configRepo from './storage-config-repo';

// The instance's one backup schedule travels in its archives; the status of its runs stays with the instance.
export const BACKUP_SCHEDULE_CONFIG_KEY = 'backup.schedule';
export const BACKUP_STATUS_CONFIG_KEY = 'backup.status';
// Rows the WebDAV and S3 destinations left: the drop-retired-backup-config migration deletes them, and export and
// restore skip them in archives from before it.
export const RETIRED_BACKUP_CONFIG_KEYS: readonly string[] = [
  'backup.settings.v1',
  'backup.runtime.v1',
  'backup.runner.lock.v1',
];
export const BACKUP_SCHEDULER_WINDOW_MINUTES = 5;

const MAX_INTERVAL_HOURS = 99;
const MAX_RETENTION_COUNT = 1000;

const intervalHoursError = `Backup interval hours must be between 1 and ${MAX_INTERVAL_HOURS}`;
const retentionError = `Backup retention count must be between 1 and ${MAX_RETENTION_COUNT}`;

// Runs start at startTime local time and then every intervalHours that day. A null retention count keeps every
// archive a run made.
export const BackupScheduleSchema = z.object({
  enabled: z.boolean(),
  intervalHours: z
    .int({ error: intervalHoursError })
    .min(1, { error: intervalHoursError })
    .max(MAX_INTERVAL_HOURS, { error: intervalHoursError }),
  startTime: z.string().regex(/^([01]\d|2[0-3]):[0-5]\d$/, { error: 'Backup start time must be in HH:mm format' }),
  // Intl refuses a zone it does not know.
  timezone: z.string().refine(
    (timezone) => {
      try {
        return !!new Intl.DateTimeFormat('en-US', { timeZone: timezone });
      } catch {
        return false;
      }
    },
    { error: 'Invalid backup timezone' },
  ),
  retentionCount: z
    .int({ error: retentionError })
    .min(1, { error: retentionError })
    .max(MAX_RETENTION_COUNT, { error: retentionError })
    .nullable(),
  includeAttachments: z.boolean(),
});
export type BackupSchedule = z.infer<typeof BackupScheduleSchema>;

export const DEFAULT_BACKUP_SCHEDULE: BackupSchedule = {
  enabled: false,
  intervalHours: 24,
  startTime: '03:00',
  timezone: 'UTC',
  retentionCount: 30,
  includeAttachments: true,
};

const BackupStatusSchema = z.object({
  lastAttemptAt: z.string().nullable(),
  lastSuccessAt: z.string().nullable(),
  lastErrorAt: z.string().nullable(),
  lastErrorMessage: z.string().nullable(),
  lastArchiveKey: z.string().nullable(),
  lastArchiveBytes: z.number().nullable(),
});
export type BackupStatus = z.infer<typeof BackupStatusSchema>;

const EMPTY_BACKUP_STATUS: BackupStatus = {
  lastAttemptAt: null,
  lastSuccessAt: null,
  lastErrorAt: null,
  lastErrorMessage: null,
  lastArchiveKey: null,
  lastArchiveBytes: null,
};

// An absent or unreadable row reads as the default.
export async function loadBackupSchedule(db: D1Database): Promise<BackupSchedule> {
  return jsonText
    .pipe(BackupScheduleSchema)
    .catch(DEFAULT_BACKUP_SCHEDULE)
    .parse((await configRepo.getConfigValue(db, BACKUP_SCHEDULE_CONFIG_KEY)) ?? '');
}

export async function saveBackupSchedule(db: D1Database, schedule: BackupSchedule): Promise<void> {
  await configRepo.setConfigValue(db, BACKUP_SCHEDULE_CONFIG_KEY, JSON.stringify(schedule));
}

export async function loadBackupStatus(db: D1Database): Promise<BackupStatus> {
  return jsonText
    .pipe(BackupStatusSchema)
    .catch(EMPTY_BACKUP_STATUS)
    .parse((await configRepo.getConfigValue(db, BACKUP_STATUS_CONFIG_KEY)) ?? '');
}

export async function updateBackupStatus(db: D1Database, change: Partial<BackupStatus>): Promise<BackupStatus> {
  const next = { ...(await loadBackupStatus(db)), ...change };
  await configRepo.setConfigValue(db, BACKUP_STATUS_CONFIG_KEY, JSON.stringify(next));
  return next;
}

function getDateTimeParts(
  date: Date,
  timezone: string,
): { year: string; month: string; day: string; hour: string; minute: string } {
  const formatter = new Intl.DateTimeFormat('en-CA', {
    timeZone: timezone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23',
  });
  const parts = formatter.formatToParts(date);
  const pick = (type: string): string => parts.find((part) => part.type === type)?.value || '';
  return {
    year: pick('year'),
    month: pick('month'),
    day: pick('day'),
    hour: pick('hour'),
    minute: pick('minute'),
  };
}

function getBackupLocalDateKey(date: Date, timezone: string): string {
  const parts = getDateTimeParts(date, timezone);
  return `${parts.year}-${parts.month}-${parts.day}`;
}

function getUtcDateForLocalTime(
  timezone: string,
  year: number,
  month: number,
  day: number,
  hour: number,
  minute: number,
): Date {
  const utcGuess = Date.UTC(year, month - 1, day, hour, minute, 0, 0);
  const actual = getDateTimeParts(new Date(utcGuess), timezone);
  const actualUtc = Date.UTC(
    Number(actual.year),
    Number(actual.month) - 1,
    Number(actual.day),
    Number(actual.hour),
    Number(actual.minute),
    0,
    0,
  );
  const desiredUtc = Date.UTC(year, month - 1, day, hour, minute, 0, 0);
  return new Date(utcGuess - (actualUtc - desiredUtc));
}

function getBackupSlotStartsForLocalDay(
  dateKey: string,
  timezone: string,
  startTime: string,
  intervalHours: number,
): Date[] {
  const dateMatch = String(dateKey || '').match(/^(\d{4})-(\d{2})-(\d{2})$/);
  const parsedTime = startTime.split(':').map((value) => Number(value));
  if (!dateMatch || parsedTime.length !== 2) return [];

  const [year, month, day] = dateMatch.slice(1).map(Number);
  const [hour, minute] = parsedTime;
  const firstSlot = getUtcDateForLocalTime(timezone, year, month, day, hour, minute);
  const nextLocalDay = new Date(Date.UTC(year, month - 1, day, 0, 0, 0, 0));
  nextLocalDay.setUTCDate(nextLocalDay.getUTCDate() + 1);
  const nextDay = getUtcDateForLocalTime(
    timezone,
    nextLocalDay.getUTCFullYear(),
    nextLocalDay.getUTCMonth() + 1,
    nextLocalDay.getUTCDate(),
    0,
    0,
  );
  const intervalMs = intervalHours * 60 * 60 * 1000;
  const slots: Date[] = [];

  for (let slotMs = firstSlot.getTime(); slotMs < nextDay.getTime(); slotMs += intervalMs) {
    slots.push(new Date(slotMs));
  }
  return slots;
}

export function hasBackupSlotBetween(
  schedule: BackupSchedule,
  status: BackupStatus,
  startInclusive: Date,
  endExclusive: Date,
): boolean {
  if (!schedule.enabled) return false;
  const startMs = startInclusive.getTime();
  const endMs = endExclusive.getTime();
  if (!Number.isFinite(startMs) || !Number.isFinite(endMs) || endMs <= startMs) return false;

  const lastSuccessAt = status.lastSuccessAt ? new Date(status.lastSuccessAt) : null;
  const lastSuccessMs =
    lastSuccessAt && Number.isFinite(lastSuccessAt.getTime()) ? lastSuccessAt.getTime() : Number.NEGATIVE_INFINITY;

  const dayCursor = new Date(startMs);
  dayCursor.setUTCHours(0, 0, 0, 0);
  const endDay = new Date(endMs);
  endDay.setUTCHours(0, 0, 0, 0);
  const checkedLocalDateKeys = new Set<string>();

  while (dayCursor.getTime() <= endDay.getTime() + 24 * 60 * 60 * 1000) {
    const localDateKey = getBackupLocalDateKey(dayCursor, schedule.timezone);
    if (!checkedLocalDateKeys.has(localDateKey)) {
      checkedLocalDateKeys.add(localDateKey);
      const slotStarts = getBackupSlotStartsForLocalDay(
        localDateKey,
        schedule.timezone,
        schedule.startTime,
        schedule.intervalHours,
      );
      for (const slotStart of slotStarts) {
        const slotStartMs = slotStart.getTime();
        if (slotStartMs < startMs || slotStartMs >= endMs) continue;
        if (lastSuccessMs >= slotStartMs) continue;
        return true;
      }
    }
    dayCursor.setUTCDate(dayCursor.getUTCDate() + 1);
  }

  return false;
}

export function isBackupDueNow(
  schedule: BackupSchedule,
  status: BackupStatus,
  now: Date,
  windowMinutes: number = BACKUP_SCHEDULER_WINDOW_MINUTES,
): boolean {
  if (!schedule.enabled) return false;
  const toleranceMs = Math.max(1, windowMinutes) * 60 * 1000;
  const lastSuccessAt = status.lastSuccessAt ? new Date(status.lastSuccessAt) : null;
  const lastSuccessMs =
    lastSuccessAt && Number.isFinite(lastSuccessAt.getTime()) ? lastSuccessAt.getTime() : Number.NEGATIVE_INFINITY;
  const localDateKey = getBackupLocalDateKey(now, schedule.timezone);
  const slotStarts = getBackupSlotStartsForLocalDay(
    localDateKey,
    schedule.timezone,
    schedule.startTime,
    schedule.intervalHours,
  );

  for (const slotStart of slotStarts) {
    const slotStartMs = slotStart.getTime();
    if (now.getTime() < slotStartMs || now.getTime() >= slotStartMs + toleranceMs) continue;
    if (lastSuccessMs >= slotStartMs) return false;
    return true;
  }
  return false;
}
