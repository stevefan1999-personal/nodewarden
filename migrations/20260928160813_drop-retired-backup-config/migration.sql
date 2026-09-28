-- The WebDAV and S3 backup destinations are gone: their settings (with encrypted credentials), their run state
-- and their runner lock.
DELETE FROM `config` WHERE `key` IN ('backup.settings.v1', 'backup.runtime.v1', 'backup.runner.lock.v1');
