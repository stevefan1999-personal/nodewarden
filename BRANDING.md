# CloudWarden rename and upgrade compatibility

CloudWarden names both the open-source core and the managed service. The core remains derived from NodeWarden by shuaiplus, under its existing LGPL-3.0 license. The official Bitwarden web vault and clients retain their own branding.

The inspection covered application pages, mail, authentication, WebAuthn, SSO, licenses, archives, resource bindings, build tooling, documentation and the hosted provisioner. A text replacement across the repository would break several existing contracts.

| Area | Rename or preservation |
| --- | --- |
| Visible branding | Core admin/connector titles, mail subjects/body/footer/default sender, passkey relying-party display name, license display name, package/build metadata, logos and managed-service FAQ use CloudWarden. |
| License download | `/api/licenses/cloudwarden-enterprise.json` and `/licenses/cloudwarden-enterprise.json` are canonical. Both former `nodewarden-enterprise.json` routes remain aliases, with the existing `nodewarden-enterprise` license identifier and Bitwarden-compatible filename. |
| Backups | New scheduled/manual archives use `cloudwarden_backup_...zip`. Retention recognizes both strict prefixes. Old archives still restore/download/delete; uploads and unrelated ZIPs retain their existing treatment. Archive contents and table formats are unchanged. |
| Tokens | The `nodewarden` JWT issuer, six purpose-specific issuers and `nodewarden.account-passkey.challenge.v2` token type remain exact. Outstanding sessions, invitations and scoped challenges keep their existing validation. No issuer aliases or broader token acceptance were added. |
| Cookies and headers | `nodewarden_web_refresh`, `X-NodeWarden-Web-Session`, `X-NodeWarden-Web` and `X-NodeWarden-Acting-Device-Id` remain wire identifiers. Refresh revocation, cipher repair and notification device exclusion continue to use the same trust paths. |
| Passkeys and SSO | Only the relying-party display name changes. Hostname RP IDs, allowed origins, credentials, challenge formats, operator-configured SSO client IDs, callbacks and the `nodewarden-sso` prevalidation subject remain unchanged. |
| Deployment and storage | `NODEWARDEN_DEPLOYMENT`, existing Worker/D1/R2 names, database/bucket IDs, bindings, secrets, migration tags and Durable Object classes remain stable. The rename does not move data or create replacement resources. |
| Other compatibility values | The sync cache namespace, diagnostic `E_NODEWARDEN_*` codes, existing equivalent-domain group and Bitwarden push installation placeholder remain unchanged. They affect cache variants, monitoring, autofill or an external integration; a new unowned CloudWarden domain is not substituted. |
| Source attribution | The actual repository URL remains `stevefan1999-personal/nodewarden`. Upstream release/wiki/community/contributor/sponsor links are explicitly identified as NodeWarden upstream links. Original logo assets remain available; new markup uses standalone CloudWarden SVGs. |

Changing a Worker name or origin also changes its deployment identity and may change its WebAuthn relying-party ID. Existing self-hosts should update their code while keeping their configured names, origins and secrets. Fresh installations may choose their own names explicitly.

Hosted tenants pin an immutable core release. Updating the storefront alone does not update those vaults. Existing tenants receive a release through the authenticated, lease-fenced upgrade operation, which reuses their resources, preserves their current billing gate, and reasserts the latest plan after deployment. Dev/UAT billing remains Creem TEST; this rename does not authorize production billing.

The focused upgrade checks cover canonical and legacy license downloads, mixed-prefix backup retention and legacy restore, existing authentication formats, connector assets, and suspended-tenant upgrades. Full validation and actual dev/UAT readbacks are recorded with the private acceptance evidence.
