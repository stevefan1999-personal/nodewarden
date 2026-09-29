import assert from 'node:assert/strict';
import test from 'node:test';
import '../test/support/workers-crypto';
import { createRecoveryCode, recoveryCodeEquals } from './recovery-code';

test('recovery codes map all byte values to the same grouped alphabet and compare normalized input', (context) => {
  let block = 0;
  context.mock.method(crypto, 'getRandomValues', (bytes: Uint8Array) => {
    assert.equal(bytes.length, 32);
    bytes.set(Array.from({ length: 32 }, (_, index) => block * 32 + index));
    return bytes;
  });
  const expected = 'ABCD EFGH IJKL MNOP QRST UVWX YZ23 4567';
  for (; block < 8; block++) assert.equal(createRecoveryCode(), expected);
  assert.equal(recoveryCodeEquals(expected.toLowerCase().replaceAll(' ', '-'), expected), true);
  assert.equal(recoveryCodeEquals(`B${expected.slice(1)}`, expected), false);
  assert.equal(recoveryCodeEquals(expected, null), false);
});
