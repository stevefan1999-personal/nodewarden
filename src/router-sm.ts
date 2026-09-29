import { Hono } from 'hono';
import {
  handleMachinePolicies,
  handlePotentialMachines,
  handleSecretPolicies,
  handlePeoplePolicies,
  handlePotentialPeople,
} from './handlers/sm-access-policies';
import {
  handleCreateAccessToken,
  handleCreateProject,
  handleProject,
  handleDeleteProjects,
  handleCreateSecret,
  handleCreateServiceAccount,
  handleServiceAccount,
  handleDeleteServiceAccounts,
  handleRevokeAccessTokens,
  handleSmCounts,
  handleSmEvents,
  handleDeleteSecrets,
  handleGetSecret,
  handleProjectSecrets,
  handleSecretsByIds,
  handleListAccessTokens,
  handleListProjects,
  handleListSecrets,
  handleListServiceAccounts,
  handleUpdateSecret,
  handleSecretsSync,
  handleSecretsTrash,
} from './handlers/secrets-manager';
import type { AppEnv } from './router';

// The subset of Secrets Manager routes a machine access token may call.
export function isMachineAllowedRoute(path: string, method: string): boolean {
  return (
    ((method === 'GET' || method === 'POST') && /^\/api\/organizations\/[a-f0-9-]+\/(projects|secrets)$/.test(path)) ||
    ((method === 'GET' || method === 'PUT') && /^\/api\/(projects|secrets)\/[a-f0-9-]+$/.test(path)) ||
    (method === 'POST' && /^\/api\/(projects\/delete|secrets\/(delete|get-by-ids))$/.test(path)) ||
    (method === 'GET' && /^\/api\/projects\/[a-f0-9-]+\/secrets$/.test(path)) ||
    (method === 'GET' && /^\/api\/organizations\/[a-f0-9-]+\/secrets\/sync$/.test(path))
  );
}

export const secretsManagerRoutes = new Hono<AppEnv>();

const secret = '/api/secrets/:secretId{[a-f0-9-]+}';
const project = '/api/projects/:projectId{[a-f0-9-]+}';
const serviceAccount = '/api/service-accounts/:serviceAccountId{[a-f0-9-]+}';
const org = '/api/organizations/:orgId{[a-f0-9-]+}';

secretsManagerRoutes.get(`${secret}/trash`, (c) => handleSecretsTrash(c, c.req.param('secretId'), undefined));
secretsManagerRoutes.post(`${secret}/trash/:action{(?:empty|restore)}`, (c) =>
  handleSecretsTrash(c, c.req.param('secretId'), c.req.param('action') as 'empty' | 'restore'),
);
secretsManagerRoutes.get(`${secret}/access-policies`, (c) => handleSecretPolicies(c, c.req.param('secretId')));
secretsManagerRoutes.on(['GET', 'PUT'], `${project}/access-policies/service-accounts`, (c) =>
  handleMachinePolicies(c, 'project', c.req.param('projectId')),
);
secretsManagerRoutes.on(['GET', 'PUT'], `${serviceAccount}/granted-policies`, (c) =>
  handleMachinePolicies(c, 'serviceAccount', c.req.param('serviceAccountId')),
);
secretsManagerRoutes.on(['GET', 'PUT'], `${project}/access-policies/people`, (c) =>
  handlePeoplePolicies(c, 'project', c.req.param('projectId')),
);
secretsManagerRoutes.on(['GET', 'PUT'], `${serviceAccount}/access-policies/people`, (c) =>
  handlePeoplePolicies(c, 'serviceAccount', c.req.param('serviceAccountId')),
);
secretsManagerRoutes.get(
  '/api/organization/:orgId{[a-f0-9-]+}/:kind{(?:projects|secrets|service-account)}/:id{[a-f0-9-]+}/events',
  (c) =>
    handleSmEvents(
      c,
      c.req.param('kind') as 'projects' | 'secrets' | 'service-account',
      c.req.param('id'),
      c.req.param('orgId'),
    ),
);
secretsManagerRoutes.get('/api/sm/events/service-accounts/:serviceAccountId{[a-f0-9-]+}', (c) =>
  handleSmEvents(c, 'service-account', c.req.param('serviceAccountId')),
);

secretsManagerRoutes.post('/api/service-accounts/delete', handleDeleteServiceAccounts);
secretsManagerRoutes.on(['GET', 'PUT'], serviceAccount, (c) =>
  handleServiceAccount(c, c.req.param('serviceAccountId'), false),
);
secretsManagerRoutes.get(`${serviceAccount}/sm-counts`, (c) =>
  handleServiceAccount(c, c.req.param('serviceAccountId'), true),
);
secretsManagerRoutes.post(`${serviceAccount}/access-tokens/revoke`, (c) =>
  handleRevokeAccessTokens(c, c.req.param('serviceAccountId')),
);
secretsManagerRoutes.post('/api/projects/delete', handleDeleteProjects);
secretsManagerRoutes.post('/api/secrets/get-by-ids', handleSecretsByIds);
secretsManagerRoutes.get(`${project}/secrets`, (c) => handleProjectSecrets(c, c.req.param('projectId')));
secretsManagerRoutes.on(['GET', 'PUT'], project, (c) => handleProject(c, c.req.param('projectId'), false));
secretsManagerRoutes.get(`${project}/sm-counts`, (c) => handleProject(c, c.req.param('projectId'), true));
secretsManagerRoutes.post('/api/secrets/delete', handleDeleteSecrets);
secretsManagerRoutes.get(secret, (c) => handleGetSecret(c, c.req.param('secretId')));
secretsManagerRoutes.put(secret, (c) => handleUpdateSecret(c, c.req.param('secretId')));
secretsManagerRoutes.get(`${serviceAccount}/access-tokens`, (c) =>
  handleListAccessTokens(c, c.req.param('serviceAccountId')),
);
secretsManagerRoutes.post(`${serviceAccount}/access-tokens`, (c) =>
  handleCreateAccessToken(c, c.req.param('serviceAccountId')),
);

secretsManagerRoutes.get(`${org}/access-policies/service-accounts/potential-grantees`, (c) =>
  handlePotentialMachines(c, c.req.param('orgId'), 'serviceAccounts'),
);
secretsManagerRoutes.get(`${org}/access-policies/projects/potential-grantees`, (c) =>
  handlePotentialMachines(c, c.req.param('orgId'), 'projects'),
);
secretsManagerRoutes.get(`${org}/access-policies/people/potential-grantees`, (c) =>
  handlePotentialPeople(c, c.req.param('orgId')),
);
secretsManagerRoutes.get(`${org}/sm-counts`, (c) => handleSmCounts(c, c.req.param('orgId')));
secretsManagerRoutes.get(`${org}/secrets`, (c) => handleListSecrets(c, c.req.param('orgId')));
secretsManagerRoutes.post(`${org}/secrets`, (c) => handleCreateSecret(c, c.req.param('orgId')));
secretsManagerRoutes.get(`${org}/secrets/sync`, (c) => handleSecretsSync(c, c.req.param('orgId')));
secretsManagerRoutes.get(`${org}/projects`, (c) => handleListProjects(c, c.req.param('orgId')));
secretsManagerRoutes.post(`${org}/projects`, (c) => handleCreateProject(c, c.req.param('orgId')));
secretsManagerRoutes.get(`${org}/service-accounts`, (c) => handleListServiceAccounts(c, c.req.param('orgId')));
secretsManagerRoutes.post(`${org}/service-accounts`, (c) => handleCreateServiceAccount(c, c.req.param('orgId')));
