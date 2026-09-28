import { Hono } from 'hono';
import {
  handleAdminExportBackup,
  handleAdminImportBackup,
  handleDeleteAdminBackupArchive,
  handleDownloadAdminBackupAttachment,
  handleGetAdminBackupSettings,
  handleListAdminBackupArchives,
  handleRestoreAdminBackupArchive,
  handleRunAdminBackup,
  handleUpdateAdminBackupSettings,
} from './handlers/backup';
import { errorResponse } from './utils/response';
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
adminBackupRoutes.delete('/api/admin/backup/archives', (c) =>
  handleDeleteAdminBackupArchive(c.req.raw, c.env, c.get('currentUser')),
);
adminBackupRoutes.post('/api/admin/backup/export', (c) =>
  handleAdminExportBackup(c.req.raw, c.env, c.get('currentUser')),
);
// POST only: this endpoint requires master-password verification, and a GET
// could only carry that credential in the query string, where it would leak
// into request logs, proxy logs, browser history and Referer headers.
// The credential is the same value clients send to /identity/connect/token,
// so a leaked copy is enough to sign in as this admin.
adminBackupRoutes.post('/api/admin/backup/blob', (c) =>
  handleDownloadAdminBackupAttachment(c.req.raw, c.env, c.get('currentUser')),
);
adminBackupRoutes.get('/api/admin/backup/blob', () =>
  errorResponse('Use POST with a JSON body for this endpoint. Credentials must not be sent in the URL.', 405),
);
adminBackupRoutes.post('/api/admin/backup/import', (c) =>
  handleAdminImportBackup(c.req.raw, c.env, c.get('currentUser')),
);
