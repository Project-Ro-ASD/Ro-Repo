# Fourteen production gates and closure roadmap

Production activation **BLOCKED**. PASS requires exact executed production evidence
and independent review, never just code or a design. FAIL means an observed unmet
control; UNVERIFIED means insufficient actual evidence; BLOCKED means an explicit
missing prerequisite/authorization. All three keep the gate closed.

Evidence shorthand: API = [current GETs](../../evidence/psop-phase-d0/github-observations.json);
SIG = [public signatures](../../evidence/psop-phase-d0/public-signing.json);
HIST = [reachable history](../../evidence/psop-phase-d0/history.json);
C = [PR-C test evidence](../../evidence/psop-phase3/README.md).
PR labels below are proposed work packages, not existing/authorized PRs.

| Gate / status | Current evidence | Missing evidence and remedy | Expected PR / dependency | Operator authority | Acceptance test |
| --- | --- | --- | --- | --- | --- |
| G-01 UNVERIFIED | Exact main/storage/#78 API pins; original guard PASS; D-0 docs | Independent final review of actual production implementation and fresh pins | D1..D8, then final re-audit | Named review and deployment scope | Reproduce full source/root/policy inventory; reject drift and unreviewed head |
| G-02 BLOCKED | Four direct V2 writers; local-only C gateway; App/PAT/manual incomplete | Complete capabilities, revoke old ingress, actual pending-request drain/fence, sole custody | D3 then D7 after D1/D2/D4/D6 | Explicit live custody window + admin/token authority | Deny every old route; stale queue/response loss blocks whole realm; independently prove request disposition |
| G-03 UNVERIFIED | V2 regression/source preserved; C local equivalence | Real migration Beta output/history/rollback parity and R-04 acceptance | D3/D6 before D7 | Beta operator acceptance of shared UNKNOWN outage | Full-tree byte comparison, no-op, Beta rollback, concurrent snapshot/Stable; no successor under UNKNOWN |
| G-04 FAIL | API: main review count 0, self-review allowed, storage effective rules empty | Enforce independent review, self-review denial, check/source/ingress policy; enumerate bypass | D7 policy stage, designed in D1/D3 | Repository/org admin settings authority | Before/after GETs + rejected self/untrusted ref/missing checks/direct writer attempts |
| G-05 UNVERIFIED | SIG five snapshot RPM/metadata sets + six publications; public pins preserved | Production subkey custody, role separation, backup/restore/revocation/rotation attestations | D1 signing boundary then D7 ceremony | Signing custodian + independent reviewer, explicit provisioning | Wrong-role/primary-secret rejection; isolated restore, rotation/revocation and real final byte verification |
| G-06 BLOCKED | HIST: 300 trees, no Stable hits; SIG legacy integrity; no trusted dwell | Recover real coverage or new prospective dwell; explicit bound genesis/import approval | D4, before D8 candidate | Authoritative observer provisioning and genesis decision | Reject 404-only genesis, fabricated timestamps, gaps, changed source/base/result and duplicate genesis |
| G-07 UNVERIFIED | C synthetic DNF; genuine inventory and prior x86_64 observations | Exact candidate selected+retained closure, trusted executed required tests, independently pinned upstream | D4/D6 then D8 | Execution authority/runner identity and candidate review | Full RPM/header/SRPM/noarch/provenance checks; exact full-set install/upgrade, missing dependency/test rejection |
| G-08 UNVERIFIED | Native aarch64/GUI/VM coverage absent; signed packages != runtime | Real per-risk native, Plasma/login, boot/reboot/recovery/installer evidence | D6 runtime per group/arch | Lab hardware/VM/runner permission; no real user installation | Required test receipt for each target; reject emulation or CLI as native/GUI success |
| G-09 UNVERIFIED | C exact synthetic approval/replay transactions | Real issuer and independent human event; final-result binding, durable restore/witness acceptance | D1/D2 | Production broker identity/protected environment provisioning | Actor/run substitution, self-review, expired/replayed nonce, postapproval byte drift and restore replay rejection |
| G-10 UNVERIFIED | C local/model CAS/crash/UNKNOWN tests | Actual sole gateway, provider exact CAS, independent recovery/restore and drain evidence | D2/D3/D6 then D7 | Real custody/provider mutation authority only in later stage | Response-loss/crash at all boundaries; exact target reconciliation; unknown noncommit cannot unlock |
| G-11 BLOCKED | C local HTTPS + external GET verifier; no authorized separate target | Explicit disposable scope and real acceptance; later exact production observation | D6 external test then D8 production | Separate repository/origin/write/cleanup grant; later live deployment grant | Exact Git/build/deployment/run and every public member parity; API-success/public-failure rejects |
| G-12 UNVERIFIED | C monotonic test client/pending and DNF negatives | Production roots, renewal/repair/rollback/trust protocols, real client canary | D5a/b/c then D8 | Root distribution and explicit bounded client rollout | Expired renewal/pending, RPMDB partial state, stale first view, downgrade and root rollback matrix |
| G-13 BLOCKED | R-01..R-09 remain pending/unverified | Named signed bounded dispositions + Beta impact, complete nonwaivable controls | D7 review packet after rehearsals | Risk owners + independent acceptance | Verify exact policy/result/attempt/expiry/actors; reject risk waiver of MSC floor |
| G-14 BLOCKED | This task explicitly forbids activation | All prior gates accepted and separate exact production activation instruction | D8 only after G-01..13 | Explicit operator activation + independent review | Deny absent/changed/expired deployment/cohort/origin scope; Strict V3 stays locked |

No production gate is PASS in D-0: **0 PASS / 1 FAIL / 8 UNVERIFIED / 5 BLOCKED**.

## Small reviewable stages

| Proposed stage | Deliverable and stop boundary | Dependencies |
| --- | --- | --- |
| D1a / D1b | Closed production identity/approval schemas, then signer service interfaces and negative fixtures; no live credentials | D-0 design review |
| D2a / D2b | Durable production ledger/outbox adapter, then independent checkpoint/backup/restore/split-brain tests in disposable infrastructure | D1 schemas |
| D3a / D3b | Credentialless worker ingress and fixed-realm gateway, then V2 operation adapters with exact Beta byte/no-op/rollback regression | D1/D2; sole-custody design required, production writes denied |
| D4a / D4b | Legacy/history provenance adapter + prospective observer/test authority contract; then exact genesis/import verification | D1, canonical risk policy; no invented historical dwell |
| D5a / D5b / D5c | Descriptor renewal; RPMDB-aware repair; higher-generation rollback and trust rotation, each separate PR | D1/D2; disposable DNF fixtures |
| D6a / D6b | Independently pinned genuine candidate/upstream runtime receipts; separate authorized external Pages provisioning harness/acceptance | D1..D5 as relevant; separate external test grant |
| D7a / D7b | Operator security/custody/keys ceremony and request drain; then bounded all-writer cutover with independent evidence and Beta acceptance | D1..D6 accepted, explicit admin/custody grants; unresolved drain prevents cutover |
| D8 | Fresh complete gate review, explicit genesis/result approval, narrowly authorized production canary/observation/client cohort | Every prior gate, complete dwell/tests/risk dispositions and separate activation instruction |

D1..D5 and offline D6 harness/tests can be developed as isolated denied-by-default
code without granting live authority. They are future proposals, not implementation
authorized by this documentation-only task. Any source guard change in those PRs
requires a deliberate reviewed contract while retaining MSC-15 and test boundaries.
Do not combine all production changes into one activation PR.

New permissions are required for disposable creation/Pages settings/writes,
production service/key/witness provisioning, admin policies, old capability
revocation, writer freeze/drain/cutover, authoritative genesis, production publish
and client rollout. Authorization is exact and stage-specific; approving code or
disposable tests grants none of these operations. In particular D-0 may push only
its documentation feature branch and create its single open unmerged PR.
