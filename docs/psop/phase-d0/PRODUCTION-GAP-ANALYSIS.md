# Phase D-0 production gap analysis

Production activation **BLOCKED**. Documentation and read-only audit only, dated
2026-10-15. No production authority is created by this design.

The [15 MSC rules](../MINIMUM-SECURITY-CONTRACT.md),
[14 gates](../ACTIVATION-GATES.md) and [R-01..R-09](../RISK-ACCEPTANCE.md)
remain normative. D-0 does not replace their requirements. Statuses below are
production statuses; implementation/test success is a separate fact.

## Evidence classes and pins

| Class | Evidence | What it establishes / limit |
| --- | --- | --- |
| Current GitHub GET observation | [API capture](../../evidence/psop-phase-d0/github-observations.json), [additional reads](../../evidence/psop-phase-d0/github-additional.json) | Timestamped settings/run/ref response; neither signed approval nor enduring enforcement proof |
| Exact code | main `65409834e8c1b66b954f2d610971f8d407e1e79e`; [source inventory](../../evidence/psop-phase-d0/source-inventory.json), [guard](../../evidence/psop-phase-d0/source-audit.json) | Existing implementation and protected bytes; no deployed-service attestation |
| Signed public bytes | storage `097ba6ba7ab73d87c36f7ec9829b017b083b1883`; [signature audit](../../evidence/psop-phase-d0/public-signing.json), [legacy records](../../evidence/psop-phase-d0/public-history-signatures.json) | Original metadata/RPM integrity; no authenticated first-public availability or human authorization |
| Historical execution observations | [PR-C evidence](../../evidence/psop-phase3/README.md), [real-world evidence](../../evidence/v3-real-world-20261012/README.md) | Bounded prior test results; synthetic claims and test roots never become production execution authority |
| Proposed contract | Other files in this directory | Unimplemented design, unassigned operator roles and ungranted permissions |

Current main matches the requested base. PR #78 is OPEN/DRAFT at
`7a979ab0dffa4654c32ae8c5c0b1a05940180c3a`; D-0 must not modify it.
The storage Git commit is unsigned according to GitHub; its separately signed
publication/snapshot objects verify. These are different integrity statements.

## Missing production boundaries

| Existing interface | Verified current boundary | Production dependency |
| --- | --- | --- |
| `psop_context.Context` | Private temporary directory, `.invalid` origin and test keys; `publishable=false` | Independently provisioned production identity, root pins and deployment configuration |
| `psop_authorization.verify_approval` | Authenticated synthetic issuer/actor/run binding | Real workload issuer, independent human approval and exact signed-result release authorization |
| `psop_signing.MetadataSigner` | Disposable subkey-only home, production fingerprints rejected | Separate production signer service, role/custody and recovery ceremony |
| `psop_ledger.Ledger`, `psop_outbox.Outbox` | SQLite/V3 transactions, durable local nonce/intent/checkpoint | Production durable service, independently retained monotonic checkpoint, backup/restore and split-brain exclusion |
| `psop_storage_gateway.Gateway` | Literal local bare-Git ref; local flock/epoch drain | Exclusive real branch custody and exact expected-head protocol; no parallel direct writer |
| `psop_history` / `psop_genesis` | Original legacy signatures accepted; synthetic availability/genesis only | Trusted production availability coverage and explicit genesis/import decision |
| `psop_pages.verify_external` | GET-only external observer, explicit independent disposable scope | Authorized setup/publication outside this API, followed by real Git/build/deployment/run/HTTPS acceptance |
| `psop_client.Client` | Test descriptor, atomic pointer/pending journal, same-view resume | Production renewal, fresh expired-pending authority, RPMDB reconciliation, downgrade and trust-update protocols |

Changing a domain, removing `test=true`, or copying a `publishable=false` result
is forbidden. Production needs new typed, closed schemas and separately reviewed
modules, retaining all test and Strict V3 denials.

## Security and runtime findings

[Current policy audit](GITHUB-SECURITY-AUDIT.md) makes G-04 **FAIL**: required
independent review and self-review prevention are not enforced; storage lacks
exclusive-writer protection. Nine successful checks do not mean nine required
checks. No setting was changed.

[Runtime inventory](RUNTIME-ACCEPTANCE.md) separates genuine Ro-ASD packages from
synthetic PR-C RPMs. Available historical x86_64 DNF observations do not close
native aarch64, Plasma/login, installer, VM/boot/reboot or production execution
authority. No candidate is selected or authorized here.

## MSC and risk coverage

| Requirement | Closure design / remaining acceptance |
| --- | --- |
| MSC-01, MSC-08 | [Production API](PRODUCTION-API-CONTRACT.md): fresh domains, issuer, exact two-stage approval and atomic replay consumption |
| MSC-02..MSC-05 | [Runtime](RUNTIME-ACCEPTANCE.md), [history](HISTORY-GENESIS-EVIDENCE.md): provenance, full selected/retained closure, independent roots, native tests and dwell |
| MSC-06 | Production signer role/subkey separation and external custody evidence |
| MSC-07, MSC-09, MSC-10 | [Custody migration](WRITER-CUSTODY-MIGRATION.md): append-only immutable paths, V2 equivalence, exclusive admission, CAS and UNKNOWN |
| MSC-11 | [Disposable plan](DISPOSABLE-PAGES-ACCEPTANCE-PLAN.md): exact provider identity and every public byte; later exact production observation still required |
| MSC-12, MSC-13 | [Client contract](CLIENT-RENEWAL-REPAIR-ROLLBACK.md): roots, immutable transport, monotonic state and transaction repair |
| MSC-14 | Durable audit/intent/restore/witness interfaces and independent recovery drill |
| MSC-15 | Existing disabled Strict V3 source/workflow and baseline unchanged |

R-01 deadline, R-02 Pages ordering and R-03 CDN/first-client freshness remain
provider limitations requiring named bounded acceptance. R-04 additionally needs
Beta outage acceptance. R-05 policy failure needs controls and independent review;
R-06 missing runtime needs execution evidence; R-07 history gaps need preserved
legacy bytes plus availability evidence; R-08 unreachable history needs an honest
coverage/genesis decision; R-09 custody needs external ceremony/restore/rotation
evidence. All nine remain pending/unverified: no risk acceptance was signed here.
No risk disposition can waive an MSC floor.
