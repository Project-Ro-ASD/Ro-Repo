# Ro-Repo V3: Component-Scoped Promotion Contract (Draft)

Status: **proposal / documentation only**. No V2 code paths, production workflows, signing keys, or published channels are changed by this document.

Tracking: [V3 roadmap #44](https://github.com/Project-Ro-ASD/Ro-Repo/issues/44).

## 1. Goals and boundaries

- Public channels remain **beta** and **stable**, at `rpm/fedora/44/{beta,stable}/{x86_64,aarch64,source}/`.
- Production releases continue using accepted/attested, signed RPMs and immutable, signed repository snapshots.
- The stable **promotion decision** is scoped to one producer-registry `promotion_group`, not the entire current beta snapshot.
- Each stable publication represents a **complete, independently verifiable repository view**; promotion of one group must not silently promote unrelated beta RPMs.
- A beta refresh containing an identical signed artifact set **must not reset** that group's waiting time.
- Both normal and fast-track require version/digest-bound evidence and explicit protected authorization. Fast-track waives **only waiting time**.
- No QA repository or extra production channel is added. Development testing uses Fedora 44 machines, VMs, and local RPM fixtures.

## 2. Identity of a candidate

Promotion unit: `promotion_group` from `config/producers-v2.json`.

Candidate identity binds:
1. Fedora major release (44) and each target architecture;
2. producer repository + component + source release identity and immutable provenance;
3. source RPM and **complete binary RPM closure produced by that source release**, subject to registry architecture policy;
4. each signed RPM's SHA-256, not a mutable tag or latest lookup;
5. immutable beta snapshot(s) proving publication of that exact artifact set;
6. a separately recorded first-public-beta timestamp for that candidate identity.

Subpackages are indivisible within a candidate: `dolphin`, `dolphin-libs`, `dolphin-devel` and the corresponding SRPM must move together, including the required architecture variants. Missing, unexpected or mismatched items fail closed.

Changing the candidate artifact set, architecture, provenance or source release starts a new candidate identity. Re-publishing the **same** verified artifact set in later beta snapshots preserves its first-seen date. A package's unrelated beta snapshot timestamp is never its candidate first-seen timestamp.

## 3. Promotion policy

| Risk class | Normal minimum beta dwell | Mandatory checks |
| --- | --- | --- |
| `normal-app` | 7 days | registry baseline test profile |
| `critical-desktop` | 7 days | registry baseline + real Plasma integration and login-session |
| `critical-system` | 14 days | registry baseline + relevant boot/reboot/recovery/QEMU tests as policy demands |

The producer registry (or a versioned policy derived from it) **must become the single authoritative test-profile source**. Existing local/remote policy divergence is a migration blocker.

### Normal mode

1. Find the immutable candidate's first published beta record.
2. Verify completed minimum dwell; verify exact candidate evidence, source/trust chain and compatible dependency closure.
3. Require explicit authorized approval for that candidate and resulting stable content digest.
4. Build, validate, sign and publish the stable candidate.

### Fast-track mode

Same flow, except an authorized fast-track request with an auditable **non-empty reason** may waive **dwell only**. Required test evidence, signing, dependencies, approval and verification cannot be waived. Approval cannot be reused for another digest, component group, target stable base or publication attempt.

Missing evidence, wrong arch, policy mismatch, invalid signature, baseline mismatch or incompatible resulting stable dependency graph **block both modes**.

## 4. Stable repository composition

Given a verified current stable manifest (or empty first stable bootstrap) and one approved promotion candidate:

1. Copy the exact stable package identities and signed bytes forward.
2. Identify the existing selected `promotion_group` from **persistent provenance**, not heuristic filename substring matching.
3. Remove only superseded package variants from that group; install the whole new candidate (including its SRPM and target architectures).
4. Reject collisions, missing required binary/source members, same package name duplicated for an architecture, downgrades unless explicitly authorized, and unexpected cross-group replacement.
5. Validate DNF installability of the **entire resulting stable set**, not just the promoted group, for each supported architecture; run explicit clean-install and upgrade regressions where applicable.
6. Generate new repository metadata for the stable set, sign metadata with the production role, and create a **new immutable stable snapshot**. Reuse existing signed RPM bytes, never rebuild an RPM to promote it.
7. Bind the protected publication approval and audit evidence to the exact candidate digest, previous stable publication, and new stable snapshot manifest digest.
8. Publish only after verification; preserve the prior stable publication and all its immutable artifacts for rollback.

The channel `publication-v1.json` pointer and published `repodata/repomd.xml` must never advertise an incomplete upload. The implementation must account for the limitations of GitHub Pages multi-file deployment and must verify the **remote** publication byte-for-byte before reporting success.

### Example

Beta has `ro-assist 0.2.5`, `dolphin 26.08.1`, `ro-installer 2.4.4`.

When **only** `ro-assist` is approved, the first stable snapshot contains **ro-assist** (plus any separately approved required dependencies), **not** Dolphin or Installer. A future approved Dolphin promotion produces a new stable snapshot that retains Ro-Assist byte-for-byte.

## 5. Evidence and trust

Versioned V3 evidence must distinguish:
- acceptance / attestation provenance;
- exact candidate ID, package/SRPM digests and first beta publication record;
- test outcomes and environments per architecture (including real KDE session for desktop-critical);
- policy version, risk class, required and actually passed tests;
- normal/fast-track decision, actor, reason if fast-track and approval timestamp;
- previous and resulting stable snapshot IDs and digests;
- signing run, publication run and independent remote verification run.

Do not copy or reinterpret a V2 `ro-assist`-only validation report as a V3 group validation. All inputs must be pinned and tamper evident.

## 6. Feature rollout and regression criteria

**PR-01:** architecture and interface contract, dry-run design only; no modifications to `pages-storage` or V2 workflows.

**PR-02:** candidate identity/first-seen ledger and normal/fast-track policies, tested offline. Explicitly reject modified digests and stale approvals.

**PR-03:** isolated stable set composer, including empty stable bootstrap, retained unrelated groups, all architectures and deterministic diffs; no live publish.

**PR-04:** reusable group validator, remove `ro-assist`-only assumptions, real Fedora 44 DNF and Plasma tests, repair current compatibility CI script.

**PR-05:** guarded dispatch/signing/publication and remote checks with pinned evidence; disable obsolete whole-beta-snapshot promotion path only after V3 acceptance.

**PR-06:** deterministic rollback, partial/deployment failure handling, historical manifest persistence and negative/replay/security tests.

**PR-07:** real Ro-Assist stable bootstrap + subsequent fast-track stable-to-stable upgrade exercised through Ro-Store's DNF5 integration.

### Required negative cases

- A new Dolphin beta release must not extend an unchanged Ro-Assist candidate's dwell.
- Approving Ro-Assist must never copy unrelated unapproved beta packages to stable.
- Missing Dolphin subpackages or mismatch to Dolphin SRPM fails closed.
- Fast-track without reason or approved actor fails closed; incomplete tests cannot be waived.
- A failed stable composition/publish attempt cannot alter the last working stable channel.
- Existing stable packages cannot disappear or be changed except by an explicitly approved superseding group operation.
- Running the same approved proposal twice must not produce conflicting publication results.
- Signed artifact substitution, stale beta validation or wrong architecture must be rejected.

## 7. Ro-Store contract

Ro-Store reads DNF5's **effective enabled repositories** and does not have any promotion privileges. For a stable-only test, only stable is enabled; for beta-only, only beta is enabled. If both are enabled, package choice follows DNF5's configured priority/version semantics and the UI must not mislabel an update as stable-only. No QA channel is required.
