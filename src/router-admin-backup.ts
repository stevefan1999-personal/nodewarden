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

adminBackupRoutes.get('/api/admin/backup/settings', (c) =>
  handleGetAdminBackupSettings(c.req.raw, c.env, c.get('currentUser')),
);
adminBackupRoutes.put('/api/admin/backup/settings', (c) =>
  handleUpdateAdminBackupSettings(c.req.raw, c.env, c.get('currentUser')),
);
adminBackupRoutes.post('/api/admin/backup/run', (c) => handleRunAdminBackup(c.req.raw, c.env, c.get('currentUser')));
adminBackupRoutes.get('/api/admin/backup/archives', (c) =>
  handleListAdminBackupArchives(c.req.raw, c.env, c.get('currentUser')),
);
adminBackupRoutes.post('/api/admin/backup/archives/restore', (c) =>
  handleRestoreAdminBackupArchive(c.req.raw, c.env, c.get('currentUser')),
);
adminBackupRoutes.post('/api/admin/backup/archives/download', (c) =>
  handleDownloadAdminBackupArchive(c.req.raw, c.env, c.get('currentUser')),
);
adminBackupRoutes.post('/api/admin/backup/archives/upload', (c) =>
  handleUploadAdminBackupArchive(c.req.raw, c.env, c.get('currentUser')),
);
adminBackupRoutes.delete('/api/admin/backup/archives', (c) =>
  handleDeleteAdminBackupArchive(c.req.raw, c.env, c.get('currentUser')),
);
