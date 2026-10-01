import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { cpSync, globSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { basename, extname, join, relative, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { experimental_readRawConfig } from 'wrangler';

// Only release-owned bindings belong here. The private provisioner supplies each tenant's
// D1/R2, verified owner, origins, restricted email sender, and secrets at upload time.
// Rate-limit namespace IDs are templates: the provider assigns stable, tenant-specific IDs.
export function tenantDeployMetadata(config, headers) {
  return {
    compatibilityDate: config.compatibility_date,
    compatibilityFlags: config.compatibility_flags,
    assetConfig: {
      html_handling: config.assets.html_handling,
      not_found_handling: config.assets.not_found_handling,
      // A suspended or gateway-only tenant must enforce its gate before any static file is served.
      run_worker_first: true,
      _headers: headers,
    },
    staticBindings: [
      { type: 'assets', name: config.assets.binding },
      ...config.durable_objects.bindings.map(({ name, class_name }) => ({
        type: 'durable_object_namespace',
        name,
        class_name,
      })),
      ...config.ratelimits.map(({ name, namespace_id, simple }) => ({
        type: 'ratelimit',
        name,
        namespace_id,
        simple,
      })),
    ],
    exports: Object.fromEntries(
      config.durable_objects.bindings.map(({ class_name }) => [
        class_name,
        { type: 'durable-object', storage: 'sqlite' },
      ]),
    ),
    observability: { enabled: false },
  };
}

export function buildTenantArtifact(root = resolve(import.meta.dirname, '..')) {
  const out = join(root, 'dist/tenant-artifact');
  const { rawConfig: config } = experimental_readRawConfig({ config: join(root, 'wrangler.toml') });
  execFileSync('npm', ['run', 'build:admin'], { cwd: root, stdio: 'inherit' });
  execFileSync('npm', ['run', 'build:assets'], { cwd: root, stdio: 'inherit' });
  rmSync(out, { recursive: true, force: true });
  mkdirSync(out, { recursive: true });

  // A local dry run resolves Wrangler's actual module graph. This config contains no account
  // resources or tenant secrets and never passes --dispatch-namespace or creates a Worker.
  const buildConfig = join(out, 'wrangler.json');
  writeFileSync(
    buildConfig,
    JSON.stringify(
      {
        name: 'cloudwarden-tenant',
        main: resolve(root, config.main),
        compatibility_date: config.compatibility_date,
        compatibility_flags: config.compatibility_flags,
        workers_dev: false,
        assets: { ...config.assets, directory: resolve(root, config.assets.directory), run_worker_first: true },
        durable_objects: config.durable_objects,
        migrations: config.migrations,
        ratelimits: config.ratelimits,
        vars: { NODEWARDEN_DEPLOYMENT: 'dispatch', ALLOW_OPEN_REGISTRATION: '0' },
        observability: { enabled: false },
      },
      null,
      2,
    ),
  );
  const moduleDir = join(out, 'modules');
  execFileSync(
    process.execPath,
    [
      join(root, 'node_modules/wrangler/bin/wrangler.js'),
      'deploy',
      '--dry-run',
      '--config',
      buildConfig,
      '--outdir',
      moduleDir,
    ],
    { cwd: root, stdio: 'inherit', env: { ...process.env, WRANGLER_SEND_METRICS: 'false' } },
  );

  const entrypoint = basename(config.main).replace(/\.[^.]+$/, '.js');
  const modules = readdirSync(moduleDir, { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile() && !entry.name.endsWith('.map') && entry.name !== 'README.md')
    .map((entry) => relative(moduleDir, join(entry.parentPath, entry.name)))
    .toSorted((left, right) => Number(right === entrypoint) - Number(left === entrypoint) || left.localeCompare(right))
    .map((name) => ({
      name,
      key: `modules/${name}`,
      contentType:
        {
          '.js': 'application/javascript+module',
          '.mjs': 'application/javascript+module',
          '.wasm': 'application/wasm',
          '.sql': 'text/plain',
        }[extname(name)] || 'application/octet-stream',
    }));
  if (modules[0]?.name !== entrypoint) throw new Error('Wrangler did not emit the tenant entrypoint');

  const assetDir = resolve(root, config.assets.directory);
  cpSync(assetDir, join(out, 'assets'), { recursive: true });
  const assets = readdirSync(assetDir, { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile() && !['_headers', '_redirects', '.assetsignore'].includes(entry.name))
    .map((entry) => {
      const path = relative(assetDir, join(entry.parentPath, entry.name));
      const bytes = readFileSync(join(assetDir, path));
      return {
        path: `/${path}`,
        key: `assets/${path}`,
        hash: createHash('sha256').update(bytes).digest('hex').slice(0, 32),
        size: bytes.byteLength,
      };
    })
    .toSorted((left, right) => left.path.localeCompare(right.path));
  const migrations = globSync('*/migration.sql', { cwd: join(root, 'migrations') })
    .toSorted()
    .map((name) => {
      const key = `migrations/${name}`;
      const target = join(out, key);
      mkdirSync(resolve(target, '..'), { recursive: true });
      cpSync(join(root, key), target);
      return { name, key };
    });
  const manifest = {
    ...tenantDeployMetadata(config, readFileSync(join(assetDir, '_headers'), 'utf8')),
    modules,
    assets,
    migrations,
  };
  const identity = createHash('sha256').update(JSON.stringify(manifest));
  for (const { key } of [...modules, ...migrations]) identity.update(readFileSync(join(out, key)));
  const version = identity.digest('hex').slice(0, 16);
  // Manifest last: an interrupted build can never advertise a complete release.
  writeFileSync(join(out, 'manifest.json'), JSON.stringify({ version, ...manifest }, null, 2));
  console.log(`Built tenant artifact ${version} in ${out}`);
  return out;
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) buildTenantArtifact();
