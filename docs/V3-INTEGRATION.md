# V3 integrated proposal and isolated acceptance

The public channels remain `beta` and `stable`. V2 beta workflows and producer
acceptance behavior are unchanged. The V3 production workflow is unconditionally
disabled; this implementation cannot publish or roll back a live channel.

## Entry points and reuse

`tools/v3_integration.py` is the integrated local entry point. `prepare` verifies
frozen GPG-signed beta/stable manifests and signed snapshot-build evidence,
derives policy from `config/producers-v2.json`, checks all registered candidate
architectures, calls the existing stable composer, verifies every resulting RPM
against a pinned public key and checks complete archive/API history through the
existing evidence bridge. An optional signed result binds its **complete file
inventory**, including signatures and repodata, rather than only its packages.

```bash
python3 tools/v3_integration.py \
  --beta ARCHIVE/snapshots/fedora/44/BETA_SNAPSHOT \
  --stable ARCHIVE/snapshots/fedora/44/STABLE_SNAPSHOT \
  --registry config/producers-v2.json --group ro-assist \
  --publications ARCHIVE/publications/fedora/44/beta \
  --snapshots ARCHIVE/snapshots/fedora/44 --collection actions-collection.json \
  --metadata-key metadata-public.asc --metadata-key-sha256 METADATA_KEY_SHA256 \
  --rpm-key rpm-public.asc --rpm-key-sha256 RPM_KEY_SHA256 \
  --now UTC_TIMESTAMP --output NEW_OUTPUT
```

Omit `--stable` only for an empty bootstrap. These CLI inputs are caller pins,
**not independently authenticated authority**. An absent result or test claim
remains `UNVERIFIED`. `--mode fast-track --reason REASON` requests a dwell
exception; it does not grant approval or waive tests.

The programmatic `prepare_live` entry point composes source/GPG key pins,
exact-main registry binding, pinned Pages metadata, complete expected remote
byte parity, live completed runtime/ZIP receipt verification and integrated
proposal construction. Stable channel existence and pointer/signature bytes are
checked against the pinned Git tree; locally deleted or replaced tracked files
are rejected. It rechecks refs/blobs after the operation and rejects a bootstrap
over an existing stable channel or a different signed stable base. Signed result
verification uses a frozen private copy, binds its initial inventory and checks
both that inventory and its parent/base relationship before producing a proposal.
It never dispatches workflows. This acquisition path still cannot prove
OIDC identity, independently trusted pins, protected environment authorization,
historical public availability or remote unlisted-file absence.

## Policy and candidate identity

`v3_policy_profile.profile` derives a versioned profile exclusively from the
registry. The V3 contract adds BASE tests, real Plasma/login for desktop risk,
and boot/reboot/recovery/QEMU for system risk. Missing risk tests in the V2
registry are handled as V3 floors, without changing V2 production acceptance.
Supplied alternate profiles must equal the derived profile exactly.
Registered architecture/package-name closure is required for every selected and
retained group in the resulting set, even when a prior V2 snapshot was partial.

The integrated candidate binds group, Fedora release, architectures, complete
binary/SRPM bytes, immutable producer manifest digests, source commit/release,
producer and signing runs, policy version, canonical registry digest and test
profile. Its legacy artifact-set digest links to the existing signed beta
history. First-seen is a separate bound record, taken conservatively from the
matching `verify-remote-beta` job completion. Republishing the same artifacts
does not reset it. Signed timestamps and API consistency are not authenticated
historical-availability proof; that production gate remains `UNVERIFIED`.

`validate_claim` now covers architectures in the **whole resulting stable set**,
including retained groups. Claims are checked against full-set and candidate
digests and pinned baselines/environments. A consistent claim is never reported
as authenticated test execution. The integrated proposal uses strict versioned
schemas and explicitly sets `approval_granted: false`, `publishable: false`.

## Local authorization and recovery rehearsal

`v3_authorization.request` binds proposal, candidate, group, normal/fast-track
mode, reason, prior state, complete result, policy, evidence, first-seen and a
unique attempt. It rejects inadequate normal dwell, missing mandatory test
claims, empty fast-track reasons and unverified recovery targets. The resulting
`authorization-v3.json` must be signed by an independently pinned approval key;
`verify_signed` checks its detached GPG signature and an expiry of at most 24h.
This is **local rehearsal authorization**, never GitHub production approval.

`v3_publication_rehearsal` can initialize only a new disposable directory. It
contains no Git/HTTP write or deployment backend. It consumes approvals,
persists attempted/failed/completed receipts, stages immutable inventory-addressed
trees and checks them before atomically updating one local state file under an
exclusive lock. Stable-base comparison happens at begin **and** finish. Identical
completed attempts return the same receipt. Interrupted or failed attempts
need fresh authorization. A recovery needs a signed request bound to the current
base and an already verified historical target; both snapshots remain intact.

The audit chain detects inconsistent edits; it is not a signature or protection
against an attacker who can rewrite the entire local state. Production requires
an authenticated durable replay ledger and externally protected serialization.
Every locked operation checks the audit chain and all verified historical trees;
idempotent staged/completed responses also require the target bytes to match.

## Real Fedora validation and reproducibility

```bash
python3 -m unittest discover -s tests -v
bash tests/v3-integration-e2e.sh NEW_EVIDENCE_DIRECTORY
```

The integration E2E builds synthetic RPMs named Ro-Assist, Ro-Control and
Installer, uses ephemeral test-only signing roles, composes Ro-Assist-only
bootstrap, retains an independently approved Ro-Control fixture, and upgrades
the entire stable set using **real DNF5 transactions**. Candidate RPM signatures
and repodata signatures stay enforced. Separate effective stable-only and
beta-only views are queried. A locally modified configuration must survive with
a `.rpmnew` file. No producer application or Ro-Store source is changed.

`v3_full_set_dnf.validate` checks signed manifest/repodata/RPM inventory, actual
Fedora 44 architecture and DNF5, real full-set clean installation and baseline
installation/upgrade, installed EVR/architecture, retained-package file conflicts,
channel isolation and optional configuration paths. Baseline identity and result
parent must match the plan. Complete RPM preflight checks actual headers, RPM-role
signatures and SRPM linkage for every binary/source architecture in stable, beta
and baseline. Frozen private repository/key copies bind the tested bytes, with
final inventory rechecks. Only disposable installroots
are modified. Logs and receipts bind result/base inventory, full package set,
actual OS/DNF environment and byte digests. Root or a disposable container is
required for DNF installroots. Current fixtures are self-contained; real
application closure against independently pinned upstream Fedora repositories
remains an activation blocker.

The [PR #71 adversarial review](V3-PR71-SECURITY-REVIEW.md) records corrected
validation defects, isolated negative regressions and the limits of the evidence.

`v3_repository_metadata.generate` uses a fixed revision, single worker, SHA-256,
gzip, no database/zchunk and fixed input file timestamps. The signed preview
reuses every RPM byte and uses the snapshot date or explicit source-date epoch.
Unsigned repodata reproducibility is exercised across independent directories;
GPG signature creation timestamps are a separate nondeterministic envelope.

## Production activation and Pages limitations

`.github/workflows/v3-stable-promotion-disabled.yml` names all eleven production
stages, but **every job has `if: ${{ false }}`**, read-only permissions and only
`exit 1`. It has no inputs, secret references, signing commands, writable token
or deployment action. No branch variable or dispatch input can activate it.
The separate fixture workflow has read-only repository permissions and no
protected production environment.

Activation requires a separate reviewed backend and proven acceptance gates:
authenticated trust anchors, source attestations and immutable test artifacts;
complete historical/live beta evidence; real canonical x86_64/aarch64 application
closure; risk-specific graphical/system environments; OIDC/protected approval;
protected replay ledger and compare-and-swap; approved signing; independent
complete remote verification; actual Ro-Store stable-to-stable acceptance in a
separately authorized environment. Green fixture CI does not satisfy these.

An atomic local pointer or Git commit cannot guarantee atomic multi-file GitHub
Pages/CDN visibility. A deployment can expose mixed cached old/new objects;
the origin cannot enumerate or exclude unknown remote extra files. Future
publication must stage immutable URLs, advertise only a verified complete view,
bind the deployment identity and recheck every signed remote byte. This PR
provides no production atomicity guarantee, publication or actual rollback.
