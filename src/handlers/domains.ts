import type { AppContext } from '../router';
import { z } from 'zod';
import {
  buildDomainsResponse,
  customRulesToActiveEquivalentDomains,
  normalizeCustomEquivalentDomains,
  normalizeEquivalentDomains,
  normalizeExcludedGlobalTypes,
} from '../services/domain-rules';
import { errorResponse, jsonResponse, normalizeJsonKeys } from '../utils/response';
import { domainRulesRepo } from '../services/storage-domain-rules-repo';

// CONTRACT:
// This route accepts both camelCase and PascalCase Bitwarden-compatible payloads.
// It stores custom rules, then derives equivalentDomains from the non-excluded
// custom rules. Keep this behavior aligned with backup import/export and
// src/services/storage-domain-rules-repo.ts.
// A field that is present, even as null, replaces the stored rules; an absent one keeps them. The
// normalizers drop malformed entries, so a body that is not a JSON object changes nothing.
const DomainsBody = z.record(z.string(), z.unknown()).catch({});

export async function handleGetDomains(c: AppContext): Promise<Response> {
  const { userId } = c.var;
  const settings = await domainRulesRepo(c.env.DB).getUserDomainSettings(userId);
  return jsonResponse(
    buildDomainsResponse(
      settings.equivalentDomains,
      settings.customEquivalentDomains,
      settings.excludedGlobalEquivalentDomains,
    ),
  );
}

export async function handleUpdateDomains(c: AppContext): Promise<Response> {
  const { userId } = c.var;
  const payload = DomainsBody.parse(normalizeJsonKeys(await c.req.raw.json().catch(() => null)));
  const current = await domainRulesRepo(c.env.DB).getUserDomainSettings(userId);
  const customEquivalentDomains =
    payload.customEquivalentDomains !== undefined
      ? normalizeCustomEquivalentDomains(payload.customEquivalentDomains)
      : payload.equivalentDomains !== undefined
        ? normalizeCustomEquivalentDomains(normalizeEquivalentDomains(payload.equivalentDomains))
        : current.customEquivalentDomains;
  const equivalentDomains = customRulesToActiveEquivalentDomains(customEquivalentDomains);
  // Some older compatible clients send the excluded type list as globalEquivalentDomains.
  const excludedTypes =
    payload.excludedGlobalEquivalentDomains !== undefined
      ? payload.excludedGlobalEquivalentDomains
      : payload.globalEquivalentDomains;
  const excludedGlobalEquivalentDomains =
    excludedTypes === undefined ? current.excludedGlobalEquivalentDomains : normalizeExcludedGlobalTypes(excludedTypes);

  await domainRulesRepo(c.env.DB).saveUserDomainSettings(
    userId,
    equivalentDomains,
    customEquivalentDomains,
    excludedGlobalEquivalentDomains,
  );

  const settings = await domainRulesRepo(c.env.DB).getUserDomainSettings(userId);
  if (!settings) {
    return errorResponse('Domain settings unavailable', 500);
  }
  return jsonResponse(
    buildDomainsResponse(
      settings.equivalentDomains,
      settings.customEquivalentDomains,
      settings.excludedGlobalEquivalentDomains,
    ),
  );
}
