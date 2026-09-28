#!/usr/bin/env node
/**
 * Make `deploy:kv` idempotent across repeated builds.
 *
 * KV namespaces are referenced in wrangler config by account-scoped `id`, not
 * by name. The template ships without an id so fresh accounts can provision one
 * on first deploy. In non-interactive builds, wrangler may try to create the
 * same namespace again on later builds and fail with code 10014.
 *
 * It also creates the D1 database on the first build: `deploy:kv` applies the
 * migrations before `wrangler deploy`, which would otherwise provision it, and
 * both find it by `database_name`.
 */
const { execSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const CONFIG = path.resolve(__dirname, '..', 'wrangler.kv.toml');
const BINDING = 'ATTACHMENTS_KV';

const wrangler = (args) => execSync(`npx wrangler ${args}`, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] });

const toml = fs.readFileSync(CONFIG, 'utf8');
const databaseName = ((toml.match(/\[\[d1_databases\]\][^[]*/) || [''])[0].match(/database_name\s*=\s*"([^"]+)"/) ||
  [])[1];
if (!databaseName) throw new Error('[ensure-kv] wrangler.kv.toml has no D1 database_name');
if (JSON.parse(wrangler('d1 list --json')).some((database) => database.name === databaseName)) {
  console.log(`[ensure-kv] D1 database "${databaseName}" exists`);
} else {
  wrangler(`d1 create "${databaseName}"`);
  console.log(`[ensure-kv] created D1 database "${databaseName}"`);
}

const bindingBlock = (toml.match(/\[\[kv_namespaces\]\][^[]*/g) || []).find((entry) =>
  new RegExp(`binding\\s*=\\s*"${BINDING}"`).test(entry),
);
if (bindingBlock && /^\s*id\s*=/m.test(bindingBlock)) {
  console.log(`[ensure-kv] ${BINDING} already pinned in wrangler.kv.toml; nothing to do`);
} else {
  const workerName = (toml.match(/^\s*name\s*=\s*"([^"]+)"/m) || [])[1] || 'worker';
  const title = `${workerName}-${BINDING.toLowerCase().replace(/_/g, '-')}`;

  // Reuse the namespace an earlier build created (by exact title, else any *attachments-kv), or create it.
  const namespaces = JSON.parse(wrangler('kv namespace list'));
  const existing =
    namespaces.find((namespace) => namespace.title === title) ||
    namespaces.find((namespace) => typeof namespace.title === 'string' && namespace.title.endsWith('attachments-kv'));
  let id;
  if (existing) {
    console.log(`[ensure-kv] reusing existing namespace "${existing.title}" (${existing.id})`);
    id = existing.id;
  } else {
    const createOutput = wrangler(`kv namespace create "${title}"`);
    id = (createOutput.match(/id\s*=\s*"([0-9a-fA-F]{32})"/) || [])[1];
    if (!id) throw new Error(`[ensure-kv] could not parse new namespace id from:\n${createOutput}`);
    console.log(`[ensure-kv] created namespace "${title}" (${id})`);
  }

  fs.writeFileSync(
    CONFIG,
    toml.replace(new RegExp(`(\\[\\[kv_namespaces\\]\\]\\s*\\n\\s*binding\\s*=\\s*"${BINDING}")`), `$1\nid = "${id}"`),
  );
  console.log('[ensure-kv] pinned id into wrangler.kv.toml for this build');
}
