import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readEnvConfig } from './env';

test('env config keeps each variable degrading to its historical default', () => {
  const defaults = readEnvConfig({});
  assert.deepEqual(defaults.JWT_SECRET, { kind: 'missing' });
  assert.equal(defaults.SSO_SIGNUPS, true);
  assert.equal(defaults.SSO_SCOPES, 'openid profile email');
  assert.deepEqual(readEnvConfig({ JWT_SECRET: ' short ' }).JWT_SECRET, { kind: 'too_short' });
  for (const [value, enabled] of [
    [' 1 ', true],
    ['true', false],
    ['0', false],
  ] as const) {
    assert.equal(readEnvConfig({ ALLOW_OPEN_REGISTRATION: value }).ALLOW_OPEN_REGISTRATION, enabled, value);
  }
  for (const [value, enabled] of [
    ['0', false],
    ['false', true],
    ['', true],
  ] as const) {
    assert.equal(readEnvConfig({ SSO_SIGNUPS: value }).SSO_SIGNUPS, enabled, value);
  }
  const listed = readEnvConfig({
    WEB_VAULT_ORIGINS: ' https://a.example/x, bad, https://a.example ',
    SSO_AUTHORITY: 'https://idp.example//',
  });
  assert.deepEqual(listed.WEB_VAULT_ORIGINS, ['https://a.example']);
  assert.equal(listed.SSO_AUTHORITY, 'https://idp.example');
});

test('hosted settings distinguish absent defaults from invalid security configuration', () => {
  const defaults = readEnvConfig({});
  assert.equal(defaults.NODEWARDEN_DEPLOYMENT, 'standalone');
  assert.equal(defaults.TENANT_OWNER_EMAIL, undefined);
  assert.equal(defaults.PLATFORM_INTERNAL_SECRET, undefined);
  assert.equal(defaults.PLATFORM_SUBSCRIPTION_STATUS, 'active');
  assert.equal(defaults.PLATFORM_REQUIRE_GATEWAY, '0');
  const configured = readEnvConfig({
    NODEWARDEN_DEPLOYMENT: 'dispatch',
    TENANT_OWNER_EMAIL: ' Owner@Example.com ',
    PLATFORM_INTERNAL_SECRET: 'platform-test-secret-'.repeat(2),
  });
  assert.equal(configured.NODEWARDEN_DEPLOYMENT, 'dispatch');
  assert.equal(configured.TENANT_OWNER_EMAIL, 'owner@example.com');
  assert.ok(configured.PLATFORM_INTERNAL_SECRET);
  const invalid = readEnvConfig({
    NODEWARDEN_DEPLOYMENT: 'disptach',
    TENANT_OWNER_EMAIL: '',
    PLATFORM_INTERNAL_SECRET: 'short',
    PLATFORM_SUBSCRIPTION_STATUS: 'enabled',
    PLATFORM_REQUIRE_GATEWAY: 'true',
  });
  assert.equal(invalid.NODEWARDEN_DEPLOYMENT, null);
  assert.equal(invalid.TENANT_OWNER_EMAIL, null);
  assert.equal(invalid.PLATFORM_INTERNAL_SECRET, undefined);
  assert.equal(invalid.PLATFORM_SUBSCRIPTION_STATUS, null);
  assert.equal(invalid.PLATFORM_REQUIRE_GATEWAY, null);
});
