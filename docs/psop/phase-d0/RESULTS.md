# Phase D-0 results

**Production activation BLOCKED.** This change contains only new documentation
and non-secret audit evidence. It does not change PR-A/B/C code, workflows, source
guards, production settings, signing/custody, storage or clients.

Pinned base main: `65409834e8c1b66b954f2d610971f8d407e1e79e`.
Pinned Pages storage: `097ba6ba7ab73d87c36f7ec9829b017b083b1883`.
PR #78: OPEN/DRAFT, `7a979ab0dffa4654c32ae8c5c0b1a05940180c3a`.
Delivery branch: `codex/psop-phase-d0-readiness`. The exact final delivery HEAD and
its CI links are recorded in the single PR delivery report; this source document
does not attempt to contain its own enclosing Git commit hash.

## Gate result

| G-01 | G-02 | G-03 | G-04 | G-05 | G-06 | G-07 |
| --- | --- | --- | --- | --- | --- | --- |
| UNVERIFIED | BLOCKED | UNVERIFIED | FAIL | UNVERIFIED | BLOCKED | UNVERIFIED |

| G-08 | G-09 | G-10 | G-11 | G-12 | G-13 | G-14 |
| --- | --- | --- | --- | --- | --- | --- |
| UNVERIFIED | UNVERIFIED | UNVERIFIED | BLOCKED | UNVERIFIED | BLOCKED | BLOCKED |

Each gate's existing/missing evidence, remedy, PR, authorization and acceptance
test is in [GATE-CLOSURE-ROADMAP.md](GATE-CLOSURE-ROADMAP.md).
No production gate passes merely because preparation code/tests/design exist.

## Three decisions

1. **Real writer gateway:** safe only after complete App/PAT/manual/workflow
   capability inventory, actual old-request completion/drain/fence, exclusive
   credential and server-policy custody, durable witnessed replay/outbox recovery,
   exact CAS, Beta output/history/rollback equivalence and explicit R-04 outage
   acceptance. An unresolvable old provider request keeps all successors blocked.
   The migration plan supplies no native GitHub deadline fence.
2. **First Stable and dwell:** original signed history verifies, but timestamps,
   300 trees without Stable and zero accessible named Stable runs are insufficient
   genesis/availability authority. Recover trustworthy contemporaneous evidence;
   otherwise start a new independently witnessed prospective dwell window. Require
   a separate exact source/policy/storage/result/evidence-bound genesis or import
   decision by a named operator and independent reviewer. Never backdate coverage.
3. **Authority boundary:** isolated denied-by-default identity/ledger/gateway/
   history/client code and offline tests can be proposed in later small PRs.
   Disposable repository/Pages publication, production keys/services/settings,
   capability revocation/custody cutover, authoritative genesis and activation/
   client rollout each require their own explicit exact grant. No such grant is
   supplied by this audit; G-11 and G-14 remain BLOCKED.

## Validation and audit limits

The unchanged original source guard passes. The unrestricted local full discovery
passes **679/679, zero skips**; no test was added, skipped or changed. Initial
sandbox discovery was unsuccessful because disposable GPG/socket fixtures could
not initialize; retain that failed attempt separately, never count it as PASS.
Current main has nine completed successful checks at the pinned main SHA in the
GET evidence. Delivery CI must also be checked at the exact final PR head/merge
candidate, not inferred from main or historical PR-C logs.

The [security audit](GITHUB-SECURITY-AUDIT.md) finds G-04 FAIL: independent review
is not required, environment self-review is allowed, and storage has no effective
branch rules. Two checks are required by the ruleset, while nine pass in observed
CI. Installation/App/PAT/manual visibility remains incomplete. No policy was changed.

The [history audit](HISTORY-GENESIS-EVIDENCE.md) and public signing audit establish
original byte integrity, not first availability. The [runtime inventory](RUNTIME-ACCEPTANCE.md)
documents genuine packages and missing native/GUI/boot/installer authority;
synthetic DNF5 success is separate. No external disposable Pages test was executed,
no remote publication or client installation occurred, and no production secret
value was read. Read-only API observations and an unsigned evidence digest index
are not independently signed operator approvals.
