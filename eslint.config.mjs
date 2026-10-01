import { defineConfig } from 'eslint/config';
import prettierRecommended from 'eslint-plugin-prettier/recommended';
import svelte from 'eslint-plugin-svelte';
import ts from 'typescript';
import tseslint from 'typescript-eslint';

// String-SQL entry points on the Cloudflare bindings: D1 and Durable Object SQLite storage. Drizzle's
// database object (getOrm(db), drizzle-orm/durable-sqlite) is a different type, so its builders and its
// batch() stay allowed.
const RAW_SQL_METHODS = new Map([
  ['D1Database', new Set(['prepare', 'exec', 'batch', 'dump', 'withSession'])],
  ['D1DatabaseSession', new Set(['prepare', 'batch'])],
  ['SqlStorage', new Set(['exec'])],
]);
// Reading one of these as a value (env.DB.prepare.bind(env.DB), passing it along) hands out the raw entry
// point just like calling it. Installing a wrapper over it (a test seam) stays allowed, and so does forwarding
// batch, which only accepts statements that prepare already produced.
const RAW_SQL_ENTRY_POINTS = new Set(['prepare', 'exec', 'dump', 'withSession']);
// Drizzle database methods that execute a whole hand-written statement: they take a sql`...` value or a
// plain string (SQLWrapper | string). Passing a query builder to them stays allowed.
const DRIZZLE_STATEMENT_EXECUTORS = new Set(['run', 'all', 'get', 'values']);
const DRIZZLE_DATABASES = new Set(['DrizzleD1Database', 'BaseSQLiteDatabase', 'DrizzleSqliteDODatabase']);

const noRawSql = {
  meta: {
    type: 'problem',
    docs: { description: 'Forbid string SQL against D1 and Durable Object storage; build queries with drizzle.' },
    messages: {
      binding:
        '{{type}}.{{method}}() runs hand-written SQL. Use the drizzle query builder through getOrm(db) (drizzle-orm/durable-sqlite in Durable Objects).',
      statement:
        '{{method}}() on the drizzle database runs a hand-written statement. Build it with the drizzle query builder instead.',
      sqlRaw: 'sql.raw() splices unescaped text into SQL. Use sql`...` parameters or the query builder.',
      entryPoint:
        '{{type}}.{{method}} read as a value hands out the raw SQL entry point. Build queries with drizzle; tests observe statements through wrapStatements (src/test/support/env.ts).',
    },
    schema: [],
  },
  create(context) {
    const services = context.sourceCode.parserServices;
    const checker = services.program.getTypeChecker();
    // Type-aware, so RegExp#exec, Map#get('key') or an unrelated prepare() never trips the rule.
    const typeParts = (node) => {
      const flatten = (type) => (type.isUnion() || type.isIntersection() ? type.types.flatMap(flatten) : [type]);
      return flatten(checker.getNonNullableType(services.getTypeAtLocation(node)));
    };
    const typeNames = (node) => typeParts(node).map((part) => part.getSymbol()?.getName());
    const rawSqlOwner = (object, method) => typeNames(object).find((name) => RAW_SQL_METHODS.get(name)?.has(method));
    const memberName = (member) =>
      member.computed ? member.property.type === 'Literal' && member.property.value : member.property.name;
    const isHandWrittenStatement = (query, receiver) =>
      typeNames(query).includes('SQL') ||
      (typeParts(query).every((part) => part.flags & ts.TypeFlags.StringLike) &&
        typeNames(receiver).some((name) => DRIZZLE_DATABASES.has(name)));
    return {
      CallExpression(node) {
        const { callee } = node;
        if (callee.type !== 'MemberExpression') return;
        const method = memberName(callee);
        if (method === 'raw' && callee.object.type === 'Identifier' && callee.object.name === 'sql') {
          context.report({ node, messageId: 'sqlRaw' });
        } else if (
          DRIZZLE_STATEMENT_EXECUTORS.has(method) &&
          node.arguments[0] &&
          isHandWrittenStatement(node.arguments[0], callee.object)
        ) {
          context.report({ node, messageId: 'statement', data: { method } });
        } else {
          const type = rawSqlOwner(callee.object, method);
          if (type) context.report({ node, messageId: 'binding', data: { type, method } });
        }
      },
      MemberExpression(node) {
        const method = memberName(node);
        if (!RAW_SQL_ENTRY_POINTS.has(method)) return;
        const { parent } = node;
        if (
          (parent.type === 'CallExpression' && parent.callee === node) ||
          (parent.type === 'AssignmentExpression' && parent.left === node)
        )
          return;
        const type = rawSqlOwner(node.object, method);
        if (type) context.report({ node, messageId: 'entryPoint', data: { type, method } });
      },
    };
  },
};

const FUNCTION_VALUES = new Set(['ArrowFunctionExpression', 'FunctionExpression']);

// A module-local function referenced from exactly one place is a named detour: inline it there.
// Exported functions are the module's API (routers, other modules and tests call them), so only their
// own callers decide whether they earn a name.
const noSingleUseFunction = {
  meta: {
    type: 'suggestion',
    docs: { description: 'Forbid module-local functions that are referenced only once; inline them at the call site.' },
    messages: { singleUse: '{{name}} is only used once. Inline it at its single call site.' },
    schema: [],
  },
  create(context) {
    const exportedNames = new Set();
    const functionBody = (definition) => {
      if (definition.type === 'FunctionName' && definition.node.type === 'FunctionDeclaration') return definition.node;
      if (
        definition.type === 'Variable' &&
        definition.parent.kind === 'const' &&
        FUNCTION_VALUES.has(definition.node.init?.type)
      ) {
        return definition.node.init;
      }
      return null;
    };
    const isExported = (definition) => {
      const declaration = definition.type === 'FunctionName' ? definition.node : definition.parent;
      return ['ExportNamedDeclaration', 'ExportDefaultDeclaration'].includes(declaration.parent?.type);
    };
    return {
      ExportSpecifier(node) {
        exportedNames.add(node.local.name);
      },
      'Program:exit'() {
        for (const scope of context.sourceCode.scopeManager.scopes) {
          for (const variable of scope.variables) {
            const definition = variable.defs.find(functionBody);
            if (!definition || isExported(definition) || exportedNames.has(variable.name)) continue;
            const body = functionBody(definition);
            const insideBody = ({
              identifier: {
                range: [start, end],
              },
            }) => start >= body.range[0] && end <= body.range[1];
            // A recursive function needs its name to call itself, so it cannot be inlined.
            if (variable.references.some(insideBody)) continue;
            if (variable.references.length === 1)
              context.report({ node: definition.name, messageId: 'singleUse', data: { name: variable.name } });
          }
        }
      },
    };
  },
};

// A caught error can be a drizzle failure whose message and stack list every bound value, so a console call may
// use it only through withoutQueryParams() (src/db/client.ts); its typeof is harmless.
const noRawErrorLog = {
  meta: {
    type: 'problem',
    docs: { description: 'Log caught errors only through withoutQueryParams(), which strips bound query values.' },
    messages: { rawError: 'Pass {{name}} through withoutQueryParams() before logging it.' },
    schema: [],
  },
  create(context) {
    const consoleCalls = [];
    return {
      'CallExpression[callee.type="MemberExpression"][callee.object.name="console"]'(node) {
        consoleCalls.push(node);
      },
      'Program:exit'() {
        // Every reference to a catch-clause binding or to the first parameter of a promise's .catch() callback.
        const caught = new Set(
          context.sourceCode.scopeManager.scopes
            .flatMap((scope) => scope.variables)
            .filter((variable) =>
              variable.defs.some(
                (definition) =>
                  definition.type === 'CatchClause' ||
                  (definition.type === 'Parameter' &&
                    definition.node.parent?.type === 'CallExpression' &&
                    definition.node.parent.callee.property?.name === 'catch' &&
                    definition.node.params[0] === definition.name),
              ),
            )
            .flatMap((variable) => variable.references.map((reference) => reference.identifier)),
        );
        const leaks = (node) => {
          if (caught.has(node)) return [node];
          if (node.type === 'CallExpression' && node.callee.name === 'withoutQueryParams') return [];
          if (node.type === 'UnaryExpression' && node.operator === 'typeof') return [];
          return (context.sourceCode.visitorKeys[node.type] ?? []).flatMap((key) =>
            [node[key]].flat().filter(Boolean).flatMap(leaks),
          );
        };
        for (const call of consoleCalls)
          for (const leak of call.arguments.flatMap(leaks))
            context.report({ node: leak, messageId: 'rawError', data: { name: leak.name } });
      },
    };
  },
};

export default defineConfig([
  // The admin portal's build output and SvelteKit's generated files.
  { ignores: ['admin/build/**', 'admin/.svelte-kit/**'] },
  {
    files: ['**/*.{ts,mts,js,mjs,cjs,svelte}'],
    linterOptions: { reportUnusedDisableDirectives: 'error' },
    plugins: {
      '@typescript-eslint': tseslint.plugin,
      cloudwarden: {
        rules: {
          'no-raw-sql': noRawSql,
          'no-single-use-function': noSingleUseFunction,
          'no-raw-error-log': noRawErrorLog,
        },
      },
    },
    rules: {
      // Rest siblings are how a field is dropped from a copy ({ secret: _omitted, ...rest }).
      '@typescript-eslint/no-unused-vars': ['error', { ignoreRestSiblings: true }],
      '@typescript-eslint/no-unused-expressions': 'error',
      'cloudwarden/no-single-use-function': 'error',
      // Hand-written SQL lives only in src/db/sql.ts as typed helpers; everything else composes drizzle.
      'no-restricted-imports': [
        'error',
        {
          paths: ['drizzle-orm', 'drizzle-orm/sql'].map((name) => ({
            name,
            importNames: ['sql'],
            message:
              'Build queries with drizzle operators or the typed helpers in src/db/sql.ts; sql templates are not allowed elsewhere.',
          })),
        },
      ],
    },
  },
  { files: ['**/*.{ts,mts,js,mjs,cjs}'], languageOptions: { parser: tseslint.parser } },
  {
    // Production code only: tests may print whole errors to debug a failure.
    files: ['src/**/*.ts', 'admin/**/*.ts'],
    ignores: ['src/test/**', '**/*.test.ts'],
    rules: { 'cloudwarden/no-raw-error-log': 'error' },
  },
  // The admin portal's components: Svelte's recommended rules, with TypeScript in their scripts.
  ...svelte.configs.recommended,
  {
    files: ['**/*.svelte'],
    languageOptions: { parserOptions: { parser: tseslint.parser, extraFileExtensions: ['.svelte'] } },
  },
  {
    files: ['src/db/sql.ts'],
    rules: { 'no-restricted-imports': 'off' },
  },
  {
    // Type-aware, over tests and tooling too: tsconfig.eslint.json adds what the Worker build excludes, and the
    // Playwright specs use e2e/tsconfig.json, whose DOM types cover their in-page callbacks.
    files: ['**/*.ts'],
    languageOptions: {
      parserOptions: {
        project: ['./tsconfig.eslint.json', './e2e/tsconfig.json'],
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: { 'cloudwarden/no-raw-sql': 'error' },
  },
  {
    // The portal type-checks against its own SvelteKit tsconfig, which knows its generated $types and $lib.
    files: ['admin/**/*.ts'],
    languageOptions: { parserOptions: { project: './admin/tsconfig.json', tsconfigRootDir: import.meta.dirname } },
  },
  // Formatting belongs to Prettier (.prettierrc.json): drift is a lint error, and the stylistic rules that
  // would fight it are off.
  prettierRecommended,
]);
