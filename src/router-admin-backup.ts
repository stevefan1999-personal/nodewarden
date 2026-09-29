import { jsonBody } from './utils/response';
import { Hono } from 'hono';
import {
  handleDeleteAdminBackupArchive,
  handleDownloadAdminBackupArchive,
  handleGetAdminBackupSettings,
  handleListAdminBackupArchives,
  handleRestoreAdminBackupArchive,
  handleRunAdminBackup,
  handleUpdateAdminBackupSettings,
  handleUploadAdminBackupArchive,
  BackupSettingsBody,
  BackupRunBody,
  BackupRestoreBody,
  BackupDownloadBody,
  BackupUploadBody,
  BackupDeleteBody,
} from './handlers/backup';
import type { AppEnv } from './router';

export const adminBackupRoutes = new Hono<AppEnv>();

adminBackupRoutes.get('/api/admin/backup/settings', handleGetAdminBackupSettings);
adminBackupRoutes.put('/api/admin/backup/settings', jsonBody(BackupSettingsBody), handleUpdateAdminBackupSettings);
adminBackupRoutes.post('/api/admin/backup/run', jsonBody(BackupRunBody), handleRunAdminBackup);
adminBackupRoutes.get('/api/admin/backup/archives', handleListAdminBackupArchives);
adminBackupRoutes.post(
  '/api/admin/backup/archives/restore',
  jsonBody(BackupRestoreBody),
  handleRestoreAdminBackupArchive,
);
adminBackupRoutes.post(
  '/api/admin/backup/archives/download',
  jsonBody(BackupDownloadBody),
  handleDownloadAdminBackupArchive,
);
adminBackupRoutes.post('/api/admin/backup/archives/upload', jsonBody(BackupUploadBody), handleUploadAdminBackupArchive);
adminBackupRoutes.delete('/api/admin/backup/archives', jsonBody(BackupDeleteBody), handleDeleteAdminBackupArchive);
