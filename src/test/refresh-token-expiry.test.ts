import assert from 'node:assert/strict';
import test from 'node:test';

import { sessionRepo } from '../services/storage-session-repo';
import { createTestEnv, seedUser } from './support/env';

test('extending a refresh token never moves its expiry past the absolute expiry stored with it', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env);
  const now = Date.now();
  const absoluteExpiresAt = now + 10_000;
  await sessionRepo(env.DB).saveRefreshToken(
    'refresh-token',
    user.id,
    now + 1_000,
    null,
    null,
    null,
    null,
    absoluteExpiresAt,
  );
  const extendTo = async (requestedExpiresAt: number) => {
    assert.equal(await sessionRepo(env.DB).extendRefreshTokenExpiry('refresh-token', requestedExpiresAt, now), true);
    return (await sessionRepo(env.DB).getRefreshTokenRecord('refresh-token'))?.expiresAt;
  };
  assert.equal(await extendTo(absoluteExpiresAt + 5_000), absoluteExpiresAt);
  assert.equal(await extendTo(absoluteExpiresAt - 5_000), absoluteExpiresAt - 5_000);
});
