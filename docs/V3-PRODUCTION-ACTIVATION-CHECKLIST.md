# V3 production activation checklist

Overall acceptance: **BLOCKED**. Completing this document cannot enable this PR's
production adapters or the eleven disabled jobs. Activation requires another
maintainer-approved PR, actual independent acceptance and a reviewed writer cutover.

## Ordered maintainer configuration

1. Independently provision source-attestor, authenticated beta-history observer,
   test-runner, human-approval, protected-environment-witness, publication and audit
   public trust roots. Record exact public bytes and SHA256 pins; keep private roles
   separate. Approval, witness, publication and audit must use distinct canonical
   keys. Reuse the existing separate RPM/metadata GPG roles and never re-sign RPMs.
2. Pin Ro-Repo immutable repository ID `1159460821`, owner ID `248876122`, each
   producer's repository identity and exact source commits. Reconfirm IDs before
   activation. Pin approved publisher/reusable signer workflow code SHAs, ref,
   event, runner class, actor IDs, exact environment, audience and subject. Provision
   the subject verbatim; GitHub's 2026 subject format can incorporate immutable IDs.
   Implement independently authenticated JWKS pin refresh/revocation and bounded
   cache age. `verify_oidc` does not fetch or trust keys supplied by the JWT.
3. Configure protected environment required reviewers, prevent self-review,
   restrict deployment branches, remove administrative bypass where available,
   and pin a digest of this configuration. Deploy an independent witness that
   signs the exact human approval, candidate/base/result/policy/evidence/reason,
   attempt, workload token hash, environment and run attempt. An API approval
   actor or OIDC environment claim alone is insufficient.
4. Provision a UTF8 PostgreSQL authority shared by all future stable writers with
   TLS/server identity, restricted credentials, serializable transactions,
   append-only audit permissions, durable backups and restore procedures. Operate
   a separate immutable monotonic checkpoint service and audit signing custody.
   Perform external failover/restore and multi-runner tests. This PR connects only
   to loopback `ro_v3_test_*` databases; extending that guard needs explicit review.
5. Implement the live durable deployment outbox/lease, idempotent staging upload,
   Git CAS, deployment identity witness and recovery reconciliation. Resolve a
   crash after DB advertisement intent but before external Git/deployment completion.
   Preserve PUBLISHED/FAILED and last-known-good history until independent post
   verification; never report a local CAS as a successful remote rollback.
6. Verify Pages storage/domain ownership and enforce HTTPS. Stage immutable views
   and publication records without replacing historical bytes. Perform independent
   HTTPS reads of every approved path, signed advertisement and deployment binding
   before and after advertisement. Test partial visibility and multiple CDN PoPs.
   Do not assert atomic mutable Pages/CDN updates.
7. Prepare a separately reviewed client `.repo` migration to exact
   `https://repo.ro-asd.org/v3/views/<digest>/rpm/$basearch` URLs. Preserve beta's
   production behavior and the two-channel model. Existing mutable stable URLs
   cannot be used as proof that versioned-view consistency is active.
8. Independently pin official Fedora 44 repomd/metadata provenance, RPM public
   root, complete immutable package cache and exact NEVRAs. If repomd is unsigned,
   use the independently authenticated metadata pin contract rather than setting
   `repo_gpgcheck=1` for a nonexistent signature. Install/test Zstandard decoder if
   required; zchunk-only primary remains BLOCKED until its decoder is implemented
   and exercised. Run DNF exclusively against frozen explicitly allowed repos.
9. Acquire actual complete released artifacts for Ro-Assist, Control, Installer,
   Dolphin and applicable release/keyring/repos/defaults groups. Run native or
   accurately labelled emulated x86_64/aarch64 clean installs and full upgrades;
   verify noarch propagation, SRPM linkage, retained byte identity, dependency
   closure, file conflicts, config preservation and `.rpmnew`. Authenticate logs
   and runner identities. Unknown or missing required tests block approval.
10. Provide pinned raw VM images, exact QEMU executor, firmware and approved
    read-only media plus an authenticated `vm-inputs` attestation. Images must
    contain genuine acceptance cases at `/usr/libexec/ro-repo-v3/acceptance` for
    real Plasma login/integration, boot/reboot/recovery/upgrade and applicable
    Ro-Store GUI. Execute and attest results. This PR does not supply producer
    application code, ready VM images or image-specific guest tests.
11. Follow the V2 migration plan, verify live inventory/history and client rollback
    criteria, retire the whole-beta stable writer through review, and verify every
    stable writer shares the same authority/CAS boundary before enabling V3.
12. Obtain exact result-bound protected promotion authorization, exercise remote
    staging/post checks and fresh signed recovery under these real roots. Only
    then review production job wiring and adapter guards in the activation PR.

## Exact code gaps / activation entry points

| Reference | Acceptance | Required work |
| --- | --- | --- |
| `v3_immutable_view.production_publish` | BLOCKED | Intentionally unconditional rejection; no live publisher exists |
| `v3_backend_ledger.PostgreSQLAdapter.__init__/transaction` | UNVERIFIED | External TLS/HA configuration and independently checkpointed provider deployment; current connections are test-only |
| `v3_backend_evidence.verify_protected` | BLOCKED | Real protected-environment witness service and provisioned exact-result approval roots |
| `v3_backend_trust.verify_oidc` | UNVERIFIED | Real publisher/reusable workflow identity, JWKS lifecycle and workload execution |
| `v3_publication_backend.Backend.publish`, `v3_pages_backend.IsolatedGitStore.advertise` | BLOCKED | Production outbox/lease and cross-provider deployment/reconciliation; these are isolated implementations |
| `v3_immutable_view.HTTPSReader/verify_remote` | UNVERIFIED | Real authenticated Pages deployments, advertisement and CDN probes; transport implements read-only verification |
| `v3_migration.rehearse/writer_gate` | BLOCKED | Authenticated live V2 import and reviewed writer/client cutover; no live adoption operation is supplied |
| `v3_real_acceptance.execute` | UNVERIFIED | Actual released applications and independently pinned official upstream inputs |
| `v3_vm_acceptance.run/Agent.execute` | UNVERIFIED | Pinned real images and genuine guest cases, including cross-component Ro-Store acceptance |
| `v3_pinned_upstream.primary_inventory` | BLOCKED | zchunk-only primary decoder; Zstandard decoder is implemented but real feed execution remains UNVERIFIED |
| `.github/workflows/v3-stable-promotion-disabled.yml` | BLOCKED | All eleven jobs remain `${{ false }}`; no user input can enable them |

The code accepts only closed contracts, verified capabilities and actual
cryptographic bindings. These tests exercise the protocol with disposable keys;
they are not protected production authorizations. PASS for an isolated subsystem
does not change any UNVERIFIED or BLOCKED activation gate.
