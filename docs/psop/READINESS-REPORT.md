# PR-C readiness report

**Production activation BLOCKED.** This report distinguishes implementation/test
acceptance from production gate acceptance. Base main:
`9284bdc04b7ed7f0b2c1ec6a34942eb7e36317c3`. Pages:
`097ba6ba7ab73d87c36f7ec9829b017b083b1883`. PR #78 remains Draft at
`7a979ab0dffa4654c32ae8c5c0b1a05940180c3a`.

The normative gate requirements remain in [ACTIVATION-GATES.md](ACTIVATION-GATES.md).
Its Phase-A status text is historical; current PR-C evidence is mapped below.
No production private key/custody/settings, publication or client rollout was
used to obtain these results. Synthetic signed claims remain synthetic authority.

## Acceptance scope

| Scope | Status | Evidence / limit |
| --- | --- | --- |
| PR-B source/publisher + existing 652 tests | PASS_REGRESSION | 679/679 full discovery, zero skips (652 + 27 new); default three real local publication flows PASS. [Phase-3 evidence](../evidence/psop-phase3/README.md). |
| Descriptor/client/recovery | PASS_TEST_ONLY | Exact signed result/publication/receipt, preinstalled role pins, closed schemas, expiry/lineage, full inventory/GPG/RPM, atomic selection and durable same-view resume. Actual process death before/after pointer commit tested. |
| Fedora 44 x86_64 DNF5 | PASS_TEST_ONLY | Real install, selected+retained dependency solve and 1.0→2.0 upgrade, exact installed NEVRA. DNF executes frozen verified bytes after HTTPS verification. Test RPMs are synthetic, not real application acceptance. |
| DNF negative defenses | PASS_REJECTION | Real DNF rejects wrong metadata/RPM keys, broken metadata signature, unsigned RPM and missing dependency. Separate invalid fixtures never receive client success authority. Actual client DNF failure preserves old active state and blocks fallback. |
| Official Fedora upstream | PASS_OBSERVATION | 44-package public Fedora gzip dependency base resolved/installed in a private installroot before PSOP overlay; exact RPM/repomd/root hashes recorded. This is an observed runtime base, not independently attested/pinned production upstream or all Ro application's dependency closure. Offline runs explicitly remain UNVERIFIED. |
| Local HTTPS | PASS_TEST_ONLY | Real TLS/full client checks; missing/hash/mixed generation, untrusted CA, trusted wrong-host certificate, signed wrong result, expiry/replay. No host trust store change. |
| External disposable Pages | BLOCKED | No pre-existing explicitly authorized target. Tool/GET collector and exact identity/full Git/HTTPS-byte verification are implemented and model-tested; no external observation was executed. |
| Provider fault behavior | PASS_MODEL / PASS_LOCAL | Delayed/expired CAS, response loss, repeated reconcile, UNKNOWN successor block, restart/race/process death, late old build and mixed/stale/missing members. See exact test matrix in evidence. No native GitHub guarantees inferred. |
| Beta/Strict V3 | PASS_REGRESSION | Original 234-file byte/mode baseline, public roots, workflows and Strict V3 hard deny unchanged. Actual V2 writer custody migration remains UNVERIFIED. |
| Native aarch64 / GUI / VM / boot | UNVERIFIED | x86_64 DNF and noarch views do not satisfy these runtime gates. |
| Current open implementation FAIL | None at accepted final runs | Development/environment failures, if any, are excluded from PASS evidence. Exact final-head CI is verified in PR checks/delivery, not inferred from local logs. |

## Fourteen production gates

| Gate | Production status | PR-C evidence and remaining prerequisite |
| --- | --- | --- |
| G-01 Scope/re-audit | UNVERIFIED | Exact base/Pages/policy/public pins and protected source audited; isolated implementation exists. Independent final review and exact production implementation/binding are still required. |
| G-02 Writer custody | BLOCKED | Four real direct V2 writers/manual/App/PAT custody are not migrated. Simulated common gateway does not establish exclusive production custody or old-request drain. |
| G-03 Beta equivalence | UNVERIFIED | Existing byte/history/rollback tests pass locally/CI. No real custody migration/window/UNKNOWN impact acceptance was performed. |
| G-04 Repository/environment policy | UNVERIFIED | PR-A historical observations are not fresh independent approval of required-review/self-review/bypass/environment policies. No settings changed. |
| G-05 Signing/trust | UNVERIFIED | Public production pins preserved; actual test subkey and DNF verification pass. Production private custody, role isolation, rotation and restore require independent operator evidence. |
| G-06 History/genesis | BLOCKED | Legacy integrity adapter preserved; real first-availability/coverage/dwell and explicit production genesis/import approval remain missing. Test genesis gives no production authority. |
| G-07 Candidate/test authority | UNVERIFIED | Real synthetic Fedora DNF and observed official dependency base pass; actual production candidate's complete native/runtime tests, independent upstream and authenticated execution authority remain unproven. |
| G-08 Risk-class runtime | UNVERIFIED | Native aarch64, Plasma/login/VM/boot/reboot/recovery were not executed. Relevant groups remain blocked. |
| G-09 Approval/replay | UNVERIFIED | Real test signatures, atomic durable nonce/intent and restart rejection pass. Production identity/reviewer/issuer and independent restore/witness acceptance remain missing. |
| G-10 Publishing recovery | UNVERIFIED | Local/model faults pass; sole real writer custody, independently witnessed backup/restore and real unresolved-request handling remain unaccepted. Local epoch is not a GitHub deadline/drain guarantee. |
| G-11 Pages observation | BLOCKED | Local HTTPS only. External disposable target unauthorized; no exact external/production PSOP Git/build/deployment/run + complete public-byte observation. |
| G-12 Client acceptance | UNVERIFIED | Disposable native client/negative/recovery tests pass. No production public-root provisioning/rollout/canary. Production descriptor renewal and expired-pending fresh-authority repair protocol are not supplied by this test-only issuer. |
| G-13 Risk acceptance | BLOCKED | R-01..R-09 named signed dispositions and Beta incident impact acceptance are outstanding. Provider limitations cannot be converted to strict guarantees. |
| G-14 Separate activation | BLOCKED | This work explicitly forbids live activation. No explicit authorization for an exact production deployment exists. |

PR-C completion does not pass these production gates, authorize a token/custody
cutover or unlock Strict V3. Follow the [runbook](OPERATOR-RUNBOOK.md) for evidence
and incident boundaries; any live transition is a separate reviewed operator stage.
