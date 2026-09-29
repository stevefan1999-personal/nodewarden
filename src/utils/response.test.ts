import assert from 'node:assert/strict';
import { test } from 'node:test';

import { Hono } from 'hono';
import { z } from 'zod';

import type { AppEnv } from '../router';
import { errorResponse, jsonBody } from './response';

// Official clients (web-v2026.9.0 error.response.ts) read top-level Message and
// ValidationErrors for every non-identity call; the CLI prints the raw JSON when
// both are missing. Upstream ErrorResponseModel names the shape.
test('error body carries the upstream top-level message next to the legacy fields', async () => {
  const message = 'Secret not found.';
  const body = await errorResponse(message, 404).json();
  assert.deepEqual(body, {
    message,
    validationErrors: null,
    object: 'error',
    error: message,
    error_description: message,
    ErrorModel: { Message: message, Object: 'error' },
  });
});

test('error body carries the validation errors map when one is passed', async () => {
  const validationErrors = { ProjectIds: ['Only one project assignment is supported.'] };
  const response = errorResponse('The model state is invalid.', 400, {}, validationErrors);
  assert.equal(response.status, 400);
  const body = (await response.json()) as { message: string; validationErrors: unknown };
  assert.equal(body.message, 'The model state is invalid.');
  assert.deepEqual(body.validationErrors, validationErrors);
});

// One route validating its body with jsonBody and answering what the handler read.
const post = (schema: z.ZodType, body: string, contentType = 'application/json') =>
  new Hono<AppEnv>()
    .post('/', jsonBody(schema), (c) => Response.json(c.req.valid('json')))
    .request('/', { method: 'POST', body, headers: { 'Content-Type': contentType } });
const passwordBody = z.object({
  masterPasswordHash: z.string().min(8, 'At least 8 characters.').regex(/\d/, 'Needs a digit.'),
  key: z.string('Key is required.'),
});
const errorBody = async (response: unknown) => {
  assert.ok(response instanceof Response);
  assert.equal(response.status, 400);
  return (await response.json()) as { message: string; validationErrors: Record<string, string[]> | null };
};

test('jsonBody validates the camelCase keys official clients may send in PascalCase', async () => {
  const response = await post(passwordBody, '{"MasterPasswordHash":"hunter22","Key":"2.a|b|c","Extra":1}');
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { masterPasswordHash: 'hunter22', key: '2.a|b|c' });
});

test('jsonBody reads only a body labelled as JSON', async () => {
  const body = await errorBody(await post(passwordBody, '{"masterPasswordHash":"hunter22","key":"k"}', 'text/plain'));
  assert.deepEqual(Object.keys(body.validationErrors!), ['masterPasswordHash', 'key']);
});

test('jsonBody answers invalid fields in the Bitwarden error shape, grouped by dotted path', async () => {
  const body = await errorBody(await post(passwordBody, '{"masterPasswordHash":"short"}'));
  assert.equal(body.message, 'At least 8 characters.');
  assert.deepEqual(body.validationErrors, {
    masterPasswordHash: ['At least 8 characters.', 'Needs a digit.'],
    key: ['Key is required.'],
  });
  assert.deepEqual(Object.keys((await errorBody(await post(passwordBody, '[]'))).validationErrors!), ['']);
  const nested = z.object({ folders: z.array(z.object({ name: z.string('Name is required.') })) });
  assert.deepEqual((await errorBody(await post(nested, '{"folders":[{"name":"a"},{}]}'))).validationErrors, {
    'folders.1.name': ['Name is required.'],
  });
  // Keys an attacker picks can collide with Object.prototype members.
  const counts = z.record(z.string(), z.number('Must be a number.'));
  assert.deepEqual((await errorBody(await post(counts, '{"constructor":"x","toString":"y"}'))).validationErrors, {
    constructor: ['Must be a number.'],
    toString: ['Must be a number.'],
  });
});
