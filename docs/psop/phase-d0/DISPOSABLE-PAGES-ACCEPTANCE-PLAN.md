# Future disposable GitHub Pages acceptance

**Not executed; G-11 BLOCKED.** No target is currently authorized or selected.
Follow the separate [authorization request](DISPOSABLE-PAGES-AUTHORIZATION-REQUEST.md).

## Existing code and missing publication path

`psop_pages.ExternalScope` enforces the independent repository naming, numeric/node
ID, branch, exact project origin, human operator, purpose and <=24h read window.
`GHRead` exposes a fixed GET allowlist. `verify_external` uses unchanged
`GitHubStorage` reads and `BranchPagesIdentity`, brackets full client verification
with exact provider identities, compares every signed inventory member and
publication to Git blobs and records response digests. `HTTPSReader` rejects
redirects/proxies/cross-origin requests and bounds bytes. Its origin handling
includes the GitHub project path, which must remain in all signed URLs.

The external CLI requires authorization inventory, independently distributed public
client pins, descriptor, commit, build ID, deployment ID and run ID. With no
authorization it emits BLOCKED/zero requests. It cannot set up or publish the
fixture. A future separately reviewed test provisioning/publication harness or
operator procedure must create provider-bound test receipts/descriptors: a local
bare-Git receipt OID cannot simply be asserted to be an unrelated remote commit.
Neither copying test result metadata nor the read inventory grants remote writes.

## Acceptance sequence after explicit authorization

| Step | Exact action | Evidence / rejection criterion |
| --- | --- | --- |
| 1 Inventory | Verify authorized repo IDs, marker, branch source `/`, project origin, credential selection and independent test key pins | Reject alias/rename, production ID/origin, alternate Pages build type or credential with other repo scope |
| 2 Prepare | Freeze test-only signed result, all RPM/SRPM/repodata/key/manifest bytes and full tree; preserve previous immutable generation | SHA256 inventory, exact source/tests and signature-role pins; no production keys |
| 3 Publish | Authorized harness records expected head, deterministic target and request before bounded non-force mutation | Exact parent/tree/commit and approval evidence; ambiguous response stays UNKNOWN |
| 4 Join provider facts | Resolve build ID and successful build commit; deployment ID with same SHA, successful status/environment URL; run ID with correct repo, head SHA, completed/success and Pages workflow identity | Retain raw GETs, IDs, timestamps and joins; wrong or missing linkage rejects even if all APIs report success |
| 5 Public observation | GET descriptor/publication and **every** signed inventory path through real HTTPS at exact project origin | Verify descriptor/root/signatures, RPM signatures/header identity, metadata internal hashes and byte parity with exact Git blobs; preserve signed descriptor bytes and independently pinned key inputs |
| 6 Bracket | Repeat exact Git/build/deployment/run identity checks after final byte | Changed identity or HEAD rejects; store all hashes/status/timing/coverage; no latest claim |
| 7 Client | Execute verified frozen bytes in disposable Fedora 44 DNF5 installroot/VM; compare installed set to exact target | Distinguish public HTTPS acquisition from DNF frozen transport and genuine application runtime |
| 8 Close | Reconcile outstanding requests, stop test ingress under granted scope, revoke credential, disable only test Pages if authorized | Record cleanup IDs/outcomes; preserve immutable evidence before archive/deletion |

Descriptor and receipt ordering must be specified before execution: the publication
commit cannot contain a receipt requiring its own commit hash. Keep the final
descriptor/receipt in the separately pinned evidence channel accepted by the test
client, bound to the observed publication commit. Test-specific adapter work must
not relax existing production denies.

## Fault matrix

| Scenario | Required observation and expected result |
| --- | --- |
| Successful API, absent public files | Public verifier fails; no client success/authority |
| Old build completes after new one | Observe a real separately authorized old/new deployment sequence where feasible; bracket identities and require exact candidate. Never claim the provider guarantees ordering |
| Delayed/stale CDN | Repeated timed reads from named regions; old valid full generation reported as old/UNVERIFIED latest; wrong expected candidate rejected |
| Mixed payload | Swap one metadata/RPM/publication member in a dedicated negative test commit; hash/signature mismatch rejects before DNF |
| Missing member / bad signature / wrong key | Remove one signed path or replace signature/test key; full verifier fails with previous client pointer unchanged |
| Wrong build/deployment/run/commit or project path | Valid bytes do not override incorrect provider join; reject |
| Identity changes during probe | Reject and retain before/after GETs; no partial PASS |

Real CDN delay and provider ordering cannot be forced deterministically. If they
do not occur, report those real-provider scenarios UNVERIFIED and retain separate
deterministic proxy/model fault results; do not label injected local faults real
GitHub observations. Public full-byte PASS means one bounded observation scope,
not continuous availability, global freshness or production gate completion.

Retain authorization, source/run/tool version, request and provider facts, exact
Git tree/inventory, all public response bytes or content-addressed immutable copies,
signed roots/descriptors, hashes, observation regions/times, negative outcomes,
DNF logs and teardown record. Independently sign/checkpoint the evidence index;
an unsigned SHA256 index only detects accidental change relative to its trusted
copy. Test artifacts stay test-only; production G-11 additionally requires the
exact separately authorized production deployment and complete observation.
