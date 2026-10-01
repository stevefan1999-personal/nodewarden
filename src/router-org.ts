import { Hono } from 'hono';
import { errorResponse, jsonBody } from './utils/response';
import {
  handleAcceptInvite,
  handleBulkConfirmMembers,
  handleBulkMemberAction,
  handleBulkReinviteMembers,
  handleConfirmMember,
  handleCreateOrgCollection,
  handleCreateOrganization,
  handleDeleteGroup,
  handleDeleteOrgCollection,
  handleDeleteOrganization,
  handleEditMember,
  handleEnableSecretsManager,
  handleGetAutoEnrollStatus,
  handleGetMember,
  handleGetOrganization,
  handleGetOrganizationKeys,
  handleGetOrgCollectionDetails,
  handleGetPlans,
  handleGetPolicy,
  handleInviteMembers,
  handleLeaveOrganization,
  handleListGroups,
  handleListMemberMiniDetails,
  handleListMemberPublicKeys,
  handleListMembers,
  handleListOrgCollectionDetails,
  handleListOrgCollectionUsers,
  handleListOrgCollections,
  handleListPolicies,
  handleOrgApiKey,
  handlePostOrganizationKeys,
  handlePutPolicy,
  handleReinviteMember,
  handleMemberAction,
  handleRotateScimKey,
  handleSaveGroup,
  handleUpdateOrgCollection,
  handleUpdateOrganization,
  CreateOrganizationRequest,
  UpdateOrganizationBody,
  OrganizationKeysRequest,
  CreateOrgCollectionBody,
  CollectionRequest,
  MemberInviteRequest,
  AcceptInviteBody,
  BulkIdsRequest,
  ConfirmMemberBody,
  BulkConfirmMembersBody,
  MemberUpdateRequest,
  SaveGroupBody,
  SavePolicyRequest,
  SecretVerificationRequest,
} from './handlers/organizations';
import {
  enterpriseLicenseFileResponse,
  handleCreateSelfHostedOrganizationLicense,
  handleUpdateSelfHostedOrganizationLicense,
  LicenseJsonRequest,
} from './handlers/licenses';
import type { AppEnv } from './router';

export const organizationRoutes = new Hono<AppEnv>();

organizationRoutes.on(
  'POST',
  ['/api/organizations', '/organizations'],
  jsonBody(CreateOrganizationRequest),
  handleCreateOrganization,
);
organizationRoutes.on('GET', ['/api/plans', '/plans'], handleGetPlans);
organizationRoutes.on(
  'GET',
  [
    '/api/licenses/cloudwarden-enterprise.json',
    '/licenses/cloudwarden-enterprise.json',
    '/api/licenses/nodewarden-enterprise.json',
    '/licenses/nodewarden-enterprise.json',
  ],
  (c) => enterpriseLicenseFileResponse(c.get('currentUser')),
);
organizationRoutes.on(
  'POST',
  ['/api/organizations/licenses/self-hosted', '/organizations/licenses/self-hosted'],
  jsonBody(LicenseJsonRequest),
  handleCreateSelfHostedOrganizationLicense,
);
const license = '/organizations/licenses/self-hosted/:orgId{[a-f0-9-]+}';
organizationRoutes.on('POST', [`/api${license}/sync`, `${license}/sync`], (c) =>
  handleUpdateSelfHostedOrganizationLicense(c, c.req.param('orgId')),
);
organizationRoutes.on('POST', [`/api${license}`, license], (c) =>
  handleUpdateSelfHostedOrganizationLicense(c, c.req.param('orgId')),
);

const org = '/api/organizations/:orgId{[a-f0-9-]+}';
organizationRoutes.get(org, (c) => handleGetOrganization(c, c.req.param('orgId')));
organizationRoutes.on(['PUT', 'POST'], org, jsonBody(UpdateOrganizationBody), (c) =>
  handleUpdateOrganization(c, c.req.param('orgId')),
);
organizationRoutes.delete(org, (c) => handleDeleteOrganization(c, c.req.param('orgId')));
organizationRoutes.post(`${org}/delete`, (c) => handleDeleteOrganization(c, c.req.param('orgId')));
organizationRoutes.post(`${org}/leave`, (c) => handleLeaveOrganization(c, c.req.param('orgId')));
organizationRoutes.post(`${org}/keys`, jsonBody(OrganizationKeysRequest), (c) =>
  handlePostOrganizationKeys(c, c.req.param('orgId')),
);
organizationRoutes.on('GET', [`${org}/keys`, `${org}/public-key`], (c) =>
  handleGetOrganizationKeys(c, c.req.param('orgId')),
);
organizationRoutes.get(`${org}/auto-enroll-status`, (c) => handleGetAutoEnrollStatus(c, c.req.param('orgId')));
organizationRoutes.get(`${org}/billing/metadata`, (c) => c.json({ object: 'list', data: [], continuationToken: null }));
organizationRoutes.get(`${org}/billing/vnext/warnings`, (c) =>
  c.json({ freeTrial: null, inactiveSubscription: null, resellerRenewal: null, taxId: null }),
);
organizationRoutes.get(`${org}/billing/vnext/self-host/metadata`, (c) =>
  c.json({ isOnSecretsManagerStandalone: true, organizationOccupiedSeats: 0 }),
);

organizationRoutes.get(`${org}/collections/details`, (c) => handleListOrgCollectionDetails(c, c.req.param('orgId')));
organizationRoutes.get(`${org}/collections`, (c) => handleListOrgCollections(c, c.req.param('orgId')));
organizationRoutes.on(
  'POST',
  [`${org}/collections`, `${org}/collections/details`],
  jsonBody(CreateOrgCollectionBody),
  (c) => handleCreateOrgCollection(c, c.req.param('orgId')),
);
const collection = `${org}/collections/:collectionId{[a-f0-9-]+}`;
organizationRoutes.on(['PUT', 'POST'], collection, jsonBody(CollectionRequest), (c) =>
  handleUpdateOrgCollection(c, c.req.param('orgId'), c.req.param('collectionId')),
);
organizationRoutes.on(
  'DELETE',
  [collection, `${collection}/delete`, `${collection}/details`, `${collection}/users`],
  (c) => handleDeleteOrgCollection(c, c.req.param('orgId'), c.req.param('collectionId')),
);
organizationRoutes.post(`${collection}/delete`, (c) =>
  handleDeleteOrgCollection(c, c.req.param('orgId'), c.req.param('collectionId')),
);
organizationRoutes.get(`${collection}/details`, (c) =>
  handleGetOrgCollectionDetails(c, c.req.param('orgId'), c.req.param('collectionId')),
);
organizationRoutes.get(`${collection}/users`, (c) =>
  handleListOrgCollectionUsers(c, c.req.param('orgId'), c.req.param('collectionId')),
);

organizationRoutes.put(`${org}/users/enable-secrets-manager`, (c) =>
  handleEnableSecretsManager(c, c.req.param('orgId')),
);
organizationRoutes.get(`${org}/users`, (c) =>
  handleListMembers(c, c.req.param('orgId'), c.req.query('includeGroups') === 'true'),
);
organizationRoutes.get(`${org}/users/mini-details`, (c) => handleListMemberMiniDetails(c, c.req.param('orgId')));
organizationRoutes.post(`${org}/users/invite`, jsonBody(MemberInviteRequest), (c) =>
  handleInviteMembers(c, c.req.param('orgId')),
);
organizationRoutes.post(`${org}/users/public-keys`, jsonBody(BulkIdsRequest), (c) =>
  handleListMemberPublicKeys(c, c.req.param('orgId')),
);
organizationRoutes.post(`${org}/users/confirm`, jsonBody(BulkConfirmMembersBody), (c) =>
  handleBulkConfirmMembers(c, c.req.param('orgId')),
);
organizationRoutes.post(`${org}/users/reinvite`, jsonBody(BulkIdsRequest), (c) =>
  handleBulkReinviteMembers(c, c.req.param('orgId')),
);
organizationRoutes.delete(`${org}/users`, jsonBody(BulkIdsRequest), (c) =>
  handleBulkMemberAction(c, c.req.param('orgId'), 'remove'),
);
organizationRoutes.post(`${org}/users/remove`, jsonBody(BulkIdsRequest), (c) =>
  handleBulkMemberAction(c, c.req.param('orgId'), 'remove'),
);
organizationRoutes.on(['PUT', 'PATCH'], `${org}/users/revoke`, jsonBody(BulkIdsRequest), (c) =>
  handleBulkMemberAction(c, c.req.param('orgId'), 'revoke'),
);
organizationRoutes.on(['PUT', 'PATCH'], `${org}/users/restore`, jsonBody(BulkIdsRequest), (c) =>
  handleBulkMemberAction(c, c.req.param('orgId'), 'restore'),
);
const member = `${org}/users/:memberId{[a-f0-9-]+}`;
organizationRoutes.post(`${member}/accept`, jsonBody(AcceptInviteBody), (c) =>
  handleAcceptInvite(c, c.req.param('orgId'), c.req.param('memberId')),
);
organizationRoutes.post(`${member}/confirm`, jsonBody(ConfirmMemberBody), (c) =>
  handleConfirmMember(c, c.req.param('orgId'), c.req.param('memberId')),
);
organizationRoutes.post(`${member}/reinvite`, (c) =>
  handleReinviteMember(c, c.req.param('orgId'), c.req.param('memberId')),
);
organizationRoutes.on(['PUT', 'PATCH'], `${member}/revoke`, (c) =>
  handleMemberAction(c, c.req.param('orgId'), c.req.param('memberId'), 'revoke'),
);
organizationRoutes.on(['PUT', 'PATCH'], [`${member}/restore`, `${member}/restore/vnext`], (c) =>
  handleMemberAction(c, c.req.param('orgId'), c.req.param('memberId'), 'restore'),
);
organizationRoutes.get(member, (c) => handleGetMember(c, c.req.param('orgId'), c.req.param('memberId')));
organizationRoutes.on(['PUT', 'POST'], member, jsonBody(MemberUpdateRequest), (c) =>
  handleEditMember(c, c.req.param('orgId'), c.req.param('memberId')),
);
organizationRoutes.on(
  'DELETE',
  [
    member,
    `${member}/accept`,
    `${member}/confirm`,
    `${member}/reinvite`,
    `${member}/revoke`,
    `${member}/restore`,
    `${member}/restore/vnext`,
  ],
  (c) => handleMemberAction(c, c.req.param('orgId'), c.req.param('memberId'), 'remove'),
);

organizationRoutes.on('GET', [`${org}/groups`, `${org}/groups/details`], (c) =>
  handleListGroups(c, c.req.param('orgId')),
);
organizationRoutes.post(`${org}/groups`, jsonBody(SaveGroupBody), (c) => handleSaveGroup(c, c.req.param('orgId')));
const group = [`${org}/groups/:groupId{[a-f0-9-]+}`, `${org}/groups/:groupId{[a-f0-9-]+}/delete`] as const;
organizationRoutes.on(['POST', 'PUT'], [...group], jsonBody(SaveGroupBody), (c) =>
  handleSaveGroup(c, c.req.param('orgId'), c.req.param('groupId')),
);
organizationRoutes.on('DELETE', [...group], (c) => handleDeleteGroup(c, c.req.param('orgId'), c.req.param('groupId')));

organizationRoutes.get(`${org}/policies`, (c) => handleListPolicies(c, c.req.param('orgId')));
const policy = [`${org}/policies/:type{[0-9]+}`, `${org}/policies/:type{[0-9]+}/vnext`] as const;
organizationRoutes.on('PUT', [...policy], jsonBody(SavePolicyRequest), (c) =>
  handlePutPolicy(c, c.req.param('orgId'), Number(c.req.param('type'))),
);
organizationRoutes.on('GET', [...policy], (c) => handleGetPolicy(c, c.req.param('orgId'), Number(c.req.param('type'))));

organizationRoutes.post(`${org}/api-key`, jsonBody(SecretVerificationRequest), (c) =>
  handleOrgApiKey(c, c.req.param('orgId'), false),
);
organizationRoutes.post(`${org}/rotate-api-key`, jsonBody(SecretVerificationRequest), (c) =>
  handleOrgApiKey(c, c.req.param('orgId'), true),
);
organizationRoutes.on('POST', [`${org}/scim-key`, `${org}/rotate-scim-key`], (c) =>
  handleRotateScimKey(c, c.req.param('orgId')),
);

// Anything else under a well-formed organization id is unknown rather than an empty list.
organizationRoutes.on('ALL', [org, `${org}/*`], (c) => errorResponse(c, 'Not found', 404));
