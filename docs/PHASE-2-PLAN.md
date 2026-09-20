# Ro-Repo V2 Phase 2 Plan

Status: IN PROGRESS
Started: 2026-09-20

## Phase 2 goal

Phase 1 established the local trust chain and policy model. Phase 2 turns that
local model into the real remote Ro-ASD repository service without weakening
the existing fail-closed guarantees.

Canonical public endpoint:

- https://repo.ro-asd.org

Initial publication backend:

- GitHub Pages

Cloudflare R2, S3-compatible object storage, and self-hosted storage are not
required for Phase 2. They remain future backend options behind the same public
`repo.ro-asd.org` interface.

## Existing Phase 1 foundation that must be reused

Phase 2 must extend, not replace, the following already implemented contracts:

- exact producer/tag/commit/release/workflow acceptance
- producer registry and package policy validation
- central RPM signing command and exact signing-subkey enforcement
- repository-snapshot-v1
- publication-v1
- promotion-manifest-v1
- local beta/stable publication
- atomic publication rollback
- dwell and promotion policy
- Fedora 44 local E2E validation
- immutable snapshot semantics

No mutable `latest` identity and no direct publication from a producer is
allowed.

## Phase 2 work sequence

1. Structured Acceptance Report v1
2. Production signing CI wiring
3. Remote snapshot publication contract
4. GitHub Pages publication backend
5. `repo.ro-asd.org` custom-domain binding
6. Remote beta publication
7. Remote beta rollback
8. Stable promotion of the exact beta snapshot
9. Remote Fedora 44 DNF E2E validation
10. Negative security tests and Phase 2 closeout audit

## Acceptance Report v1

Acceptance must remain fail-closed, but failures must be diagnosable.

A rejected producer release must produce a structured report that identifies:

- result: accepted or rejected
- producer repository
- release tag
- source commit
- numeric GitHub release ID
- failed stage/check
- stable machine-readable error code
- human-readable error message
- expected value when safe and useful
- received value when safe and useful
- remediation hint when one can be given safely
- timestamp
- workflow/run identity when available

Examples of stable error categories include:

- PRODUCER_NOT_ALLOWLISTED
- TAG_COMMIT_MISMATCH
- RELEASE_ID_MISMATCH
- MANIFEST_IDENTITY_MISMATCH
- ARTIFACT_SET_MISMATCH
- SHA256SUMS_INVALID
- ARTIFACT_DIGEST_MISMATCH
- RPM_HEADER_MISMATCH
- FEDORA_RELEASE_MISMATCH
- ARCHITECTURE_DENIED
- SRPM_MISSING
- FEDORA_PACKAGE_COLLISION
- PROVENANCE_MISMATCH
- ACCEPTANCE_OBJECT_EXISTS
- INTERNAL_ACCEPTANCE_ERROR

The report must never include secrets, tokens, private-key material, passphrases,
or other credential values.

On success, the existing `acceptance-evidence-v1.json` remains the canonical
trust-chain evidence. Acceptance Report v1 is operational/developer-facing
diagnostic output and must not silently weaken or replace evidence validation.

On rejection, no accepted object may be created.

GitHub Actions should upload the report even when acceptance fails, using an
`if: always()` style final reporting/upload step while preserving the failed
job conclusion.

## Publication lifecycle

The producer release does not go directly to beta.

Canonical lifecycle:

```text
producer GitHub Release
  -> Ro-Repo exact acceptance
  -> accepted artifact set
  -> production RPM signing
  -> repository snapshot construction
  -> metadata signing
  -> immutable candidate snapshot
  -> validation
  -> beta publication
  -> dwell + evidence
  -> stable promotion of the exact same snapshot
```

A beta incident does not mutate the snapshot. The beta publication may be
atomically rolled back to an earlier snapshot, while a corrected producer
release creates a new snapshot. Clients that already installed a bad higher
NEVRA are not automatically downgraded by repository rollback; the normal fix
path is a forward hotfix release.

## Security invariants

- No direct push to `main`.
- All Phase 2 changes use branch -> PR -> required CI -> review -> merge.
- Existing `unit-policy` and `fedora44-e2e` required checks must not be weakened.
- Production primary private key never enters CI.
- RPM and metadata signing use separate subkey-only secrets.
- Exact signing subkey fingerprints are required.
- Producer repositories never receive production signing secrets.
- Published snapshots are immutable.
- Beta and stable are mutable publication views over immutable snapshots.
- Stable promotion must not rebuild or re-sign the tested beta snapshot.
- Errors remain fail-closed.
