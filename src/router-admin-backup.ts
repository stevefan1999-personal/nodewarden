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
} from './handlers/backup';
import type { AppEnv } from './router';

export const adminBackupRoutes = new Hono<AppEnv>();

adminBackupRoutes.get('/api/admin/backup/settings', handleGetAdminBackupSettings);
adminBackupRoutes.put('/api/admin/backup/settings', handleUpdateAdminBackupSettings);
adminBackupRoutes.post('/api/admin/backup/run', handleRunAdminBackup);
adminBackupRoutes.get('/api/admin/backup/archives', handleListAdminBackupArchives);
adminBackupRoutes.post('/api/admin/backup/archives/restore', handleRestoreAdminBackupArchive);
adminBackupRoutes.post('/api/admin/backup/archives/download', handleDownloadAdminBackupArchive);
adminBackupRoutes.post('/api/admin/backup/archives/upload', handleUploadAdminBackupArchive);
adminBackupRoutes.delete('/api/admin/backup/archives', handleDeleteAdminBackupArchive);
