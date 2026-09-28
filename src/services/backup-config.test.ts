import assert from 'node:assert/strict';
import { test } from 'node:test';

import { createSqliteD1 } from '../test/support/d1-sqlite';
import {
  BACKUP_SCHEDULE_CONFIG_KEY,
  BackupScheduleSchema,
  DEFAULT_BACKUP_SCHEDULE,
  type BackupSchedule,
  type BackupStatus,
  hasBackupSlotBetween,
  isBackupDueNow,
  loadBackupSchedule,
  saveBackupSchedule,
} from './backup-config';
import { configRepo } from './storage-config-repo';

const neverRun: BackupStatus = {
  lastAttemptAt: null,
  lastSuccessAt: null,
  lastErrorAt: null,
  lastErrorMessage: null,
  lastArchiveKey: null,
  lastArchiveBytes: null,
};
// 03:00 in Hong Kong (UTC+8, no daylight saving) is 19:00 UTC the day before.
const daily: BackupSchedule = { ...DEFAULT_BACKUP_SCHEDULE, enabled: true, timezone: 'Asia/Hong_Kong' };

test('a missing or unreadable schedule row reads as the defaults, and a saved one round-trips', async () => {
  const db = await createSqliteD1();
  assert.deepEqual(await loadBackupSchedule(db), DEFAULT_BACKUP_SCHEDULE);
  for (const stored of ['{not json', JSON.stringify({ ...daily, intervalHours: 0 })]) {
    await configRepo(db).setConfigValue(BACKUP_SCHEDULE_CONFIG_KEY, stored);
    assert.deepEqual(await loadBackupSchedule(db), DEFAULT_BACKUP_SCHEDULE);
  }
  await saveBackupSchedule(db, daily);
  assert.deepEqual(await loadBackupSchedule(db), daily);
});

test('the schedule schema names the field that is out of range', () => {
  const cases: Array<[Partial<BackupSchedule>, string]> = [
    [{ intervalHours: 0 }, 'Backup interval hours must be between 1 and 99'],
    [{ startTime: '3:00' }, 'Backup start time must be in HH:mm format'],
    [{ timezone: 'Mars/Olympus_Mons' }, 'Invalid backup timezone'],
    [{ retentionCount: 0 }, 'Backup retention count must be between 1 and 1000'],
  ];
  for (const [change, message] of cases) {
    const parsed = BackupScheduleSchema.safeParse({ ...daily, ...change });
    assert.equal(parsed.success ? null : parsed.error.issues[0].message, message);
  }
});

test('a slot is due inside its window, in the schedule timezone, until a run after it succeeds', () => {
  assert.equal(isBackupDueNow(daily, neverRun, new Date('2026-09-28T19:02:00Z')), true);
  assert.equal(isBackupDueNow(daily, neverRun, new Date('2026-09-28T19:06:00Z')), false);
  assert.equal(isBackupDueNow(daily, neverRun, new Date('2026-09-28T18:59:00Z')), false);
  assert.equal(
    isBackupDueNow(daily, { ...neverRun, lastSuccessAt: '2026-09-28T19:01:00Z' }, new Date('2026-09-28T19:02:00Z')),
    false,
  );
  assert.equal(isBackupDueNow({ ...daily, enabled: false }, neverRun, new Date('2026-09-28T19:02:00Z')), false);
});

test('a slot that starts while a run is in progress is found once, and never after a success past it', () => {
  const twiceDaily = { ...daily, intervalHours: 12 };
  // 15:00 in Hong Kong is 07:00 UTC.
  const [start, end] = [new Date('2026-09-29T06:50:00Z'), new Date('2026-09-29T07:20:00Z')];
  assert.equal(hasBackupSlotBetween(twiceDaily, neverRun, start, end), true);
  assert.equal(
    hasBackupSlotBetween(twiceDaily, { ...neverRun, lastSuccessAt: '2026-09-29T07:10:00Z' }, start, end),
    false,
  );
  assert.equal(hasBackupSlotBetween(daily, neverRun, start, end), false);
});
