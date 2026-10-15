# Disposable Pages authorization request — NOT GRANTED

G-11 **BLOCKED**. This document requests a possible future, separate bounded
authorization. It neither records consent nor creates a repository, credential,
Pages site or publication. No production access is requested.

## Exact scope the operator must complete and approve

| Field | Required operator value; currently unset |
| --- | --- |
| Owner and repository | One exact `OWNER/ro-psop-disposable-SUFFIX`, physically separate from Ro-Repo, ID != `1159460821` |
| Repository identity | Numeric ID and node ID verified after creation; if creation itself is authorized, name/owner first, then confirm returned IDs before publication |
| Source branch | One exact `psop-disposable-SUFFIX`; source path `/` |
| Public project origin | Exact `https://owner.github.io/ro-psop-disposable-SUFFIX`, including case-sensitive repository path |
| Marker | Description exactly `RO PSOP DISPOSABLE ACCEPTANCE ONLY` |
| Operator / independent reviewer | Named human IDs and signed decision; neither is assigned here |
| Start / expiry | UTC time window, with separate read authorization maximum 24 hours per existing `ExternalScope` |
| Payload / workload | Exact test-only source/result/descriptor/inventory digests, bounded file count/bytes, expected number of deployments and deliberately invalid cases |
| Custody / cleanup | Dedicated single-repository test credential custodian, expiry, removal/revocation and retained-evidence location |

Do not substitute production `repo.ro-asd.org`, `Project-Ro-ASD/Ro-Repo`,
`pages-storage`, DNS, Cloudflare or another existing origin. Do not attach any
production signing role. Use disposable test keys, preserving `publishable=false`.

## Separate permissions, each requiring explicit consent

1. **Setup:** create only the named test repository/branch if it does not exist;
   set only its marker and legacy branch Pages `/` source; enable HTTPS there if
   available. No custom domain or organization-wide setting changes.
2. **Test publication:** upload only approved test objects and non-force commits
   on the named branch, request only enumerated Pages builds if necessary, and
   create only the corresponding test deployment/run metadata needed by the
   reviewed harness. Fixed bounds and purposes must be filled above. API-specific
   token permissions must be minimized and recorded; no production repository
   selection, wildcard scope or workflow capable of arbitrary remote writes.
3. **Observation:** GET only the exact repo/branch/commit/tree/blob/build/
   deployment/status/run and origin paths, with independent public pins and
   purpose `read-only-psop-disposable-acceptance`. This does not authorize steps
   1 or 2; the existing verifier itself is GET-only.
4. **Teardown:** stop future test ingress, reconcile outstanding requests, revoke
   test credentials, disable only this test Pages site and archive the repository
   if explicitly authorized. Repository deletion is a distinct destructive action
   requiring explicit consent; retain evidence first.

Operators may grant a subset. Missing setup/publication permission keeps external
execution BLOCKED even if public GET access is technically possible. A JSON
inventory is not human consent. No secret values belong in this request or audit.

Acceptance procedure and required retained artifacts are in
[DISPOSABLE-PAGES-ACCEPTANCE-PLAN.md](DISPOSABLE-PAGES-ACCEPTANCE-PLAN.md).
