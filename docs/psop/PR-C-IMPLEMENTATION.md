# PR-C client and acceptance integration

Base main `9284bdc04b7ed7f0b2c1ec6a34942eb7e36317c3`, feature branch
`codex/psop-phase3-client-acceptance`. No production activation capability is added.

| File/API | Integration |
| --- | --- |
| `tools/psop_client.py:issue_descriptor` | Requires current COMPLETE PR-B SignedResult/approval/receipt, exact target tree, unexpired authority and contiguous signed descriptor lineage. Signs only PSOP test domain with existing context publication role. |
| `schemas/psop-client-descriptor-v1.schema.json` | Closed descriptor, nested receipt/inventory/key contracts, bounded times, result and previous-generation identities, rollback_authority=false and production BLOCKED. |
| `tools/psop_client.py:Client.verify` | Independently pinned public roots; PSOP envelope/receipt/publication/review/result joins; complete immutable HTTPS inventory; actual metadata/RPM signatures; role fingerprints, repomd/primary checksums and exact RPM inventory. External URLs/XML base/path overrides rejected. |
| `Client.update`, `active` | Reuses unchanged V3 Client `locked`, `_atomic` and disposable command-root validation. One fsynced `active.json` pointer selects a prepared repo/state slot atomically. Exact pending descriptor/operation/packages blocks switching after DNF/process failure. Explicit same-view resume only. |
| `Client._dnf` | Constructs a fixed install/upgrade/makecache command, private installroot/cache/logs, no plugins/host config or caller flags; all four verification options are required. Frozen checked payload avoids a second CDN selection. Exact installed NEVRA verified after a real transaction. |
| `tools/psop_pages.py:HTTPSReader` | Exact loopback HTTPS or explicitly authorized separate project origin; independent CA/system TLS verification; bounded reads, no proxies/redirects/credentials or mutable Stable fallback. |
| `ExternalScope`, `GHRead`, `verify_external` | Explicit operator inventory, exact GET allowlist; reuses unchanged `GitHubStorage` read-only object verification and `BranchPagesIdentity` build/deployment/run joins. Full public/Git parity bracketed by identity checks. No setup, dispatch, push or settings API. |
| `tests/psop_client_support.py` | Real GPG/Git/ledger client models (model RPM bytes explicitly mocked only in unit tests); local TLS fixture without host CA edits. |
| `tests/psop_acceptance_support.py` | Hooks into PR-B's real signed RPM fixture and actual publisher, then descriptor/HTTPS/client/DNF. Separate contiguous chain tests a real version upgrade. Official Fedora dependency base is observed in a separate private root before PSOP overlay. |
| `tests/psop_evidence.py` | Exact source inventory/hash/modes, local commit/dirty state and allowlisted non-secret GitHub run context. Runtime receipts never become production execution authority. |
| `tests/test_psop_client.py`, `test_psop_provider_faults.py` | Closed-domain/trust/lineage/downgrade/expiry, real client process death/restart, pointer/journal recovery, writer UNKNOWN/expiry authority joins, every-member faults and out-of-order Pages identity models. PR #78 test code is not copied. |
| `tests/psop-fedora44-dnf5-e2e.py`, `psop-pages-disposable-acceptance.py` | Native container-only DNF and separate local HTTPS entry points; external mode without human authorization emits BLOCKED with zero requests. |
| `.github/workflows/psop-acceptance-tests.yml` | Additional Fedora 44 disposable job; contents-read only, checkout credentials disabled, no environment/secrets/dispatch/publishing. Required native/official-upstream failures fail CI; no skip/allow-failure. Existing eight jobs/workflows unchanged. |
| `tools/psop_audit.py` | Exact eleven named PR-C additions, including only the one test workflow; original 234 baseline/pin and PR-B allowlist unchanged. Existing PR-B fixture adds an optional observer only; default three-flow behavior remains. |

The state commit and RPM transaction cannot be one distributed atomic action.
Journal recovery acknowledges this: old active repo/state stays selected on
failure while pending authority prevents silent fallback; installed RPMDB may need
inspection/repair. A valid old descriptor can be accepted by a first client, so
global latest is always UNVERIFIED. Replay/known rollback and package downgrades
are rejected. Expired pending authority remains blocked; this test-only API does
not mint a production renewal/repair capability.

Actual HTTPS acquisition and DNF's frozen-file transport are reported separately.
All payload signatures and metadata hashes are verified before DNF; DNF also
enforces repository/RPM signatures on the frozen copy. Official Fedora base
metadata follows Fedora's observed metalink model, not a claimed PSOP OpenPGP
metadata signature. Its downloaded RPM/metadata/root hashes are retained; it is
not an independently attested production upstream snapshot.

See [readiness](READINESS-REPORT.md), [operator runbook](OPERATOR-RUNBOOK.md) and
[exact acceptance evidence](../evidence/psop-phase3/README.md). Existing production
workflows, V2 direct writers, public roots/registry, original baseline and Strict
V3 lock remain unchanged. All tested publications stay in local disposable Git;
external Pages is BLOCKED until a separately authorized target exists.
