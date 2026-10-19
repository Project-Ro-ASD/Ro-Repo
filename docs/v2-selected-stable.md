# V2 manual selected Stable promotion

This is a V2 `pages-storage` writer. No V3 service, PSOP, database, production
activation workflow, or RPM signing operation is involved.

## Operator setup

After reviewing and merging this change, keep both GitHub environments:

- `repo-production-signing`: existing metadata signing role, with
  `RO_REPO_METADATA_SIGNING_SUBKEY_B64` and
  `RO_REPO_METADATA_SIGNING_PASSPHRASE`. Use the existing isolated metadata
  secret subkey, never the primary private key or RPM signing secret.
- `repo-stable`: required reviewers and deployment branch restriction to `main`.
  Publishing uses the job's `GITHUB_TOKEN` with `contents: write`; no new PAT
  or secret is needed. Keep the existing `pages-storage` Pages deployment setup.

Also restrict the signing environment to trusted `main`. The two new workflows
reject dispatch from other refs. Required approvals remain operator actions.
Native `ubuntu-24.04` and `ubuntu-24.04-arm` runners must be available for the
Fedora 44 validation matrix.

## First promotion

Open Actions → **Promote selected V2 group to Stable** → Run workflow on `main`.
Enter these values, rechecking the current signed Beta publication first:

| Input | Example verified on 2026-10-19 |
| --- | --- |
| `promotion_group` | `ro-assist` |
| `beta_snapshot_id` | `repo-f44-20261009-001` |
| `beta_publication_run` | `37935890476` |
| `reason` | `Manual release of Ro-Assist after acceptance review` |

The group is a dropdown generated from the current V2 producer registry. Update
it when adding registry groups. Approve the existing signing environment when
requested. The candidate must pass real Fedora 44 DNF5 clean installs and,
when Stable exists, installation of previous Stable followed by upgrade to the
candidate on both native architectures. Approve `repo-stable` only after those
jobs pass. Dependency resolution uses only the composed Stable and official
Fedora/updates; unselected Beta dependencies are unavailable. Missing required
groups therefore fail closed and must be promoted independently first.

No 7/14-day dwell gate applies to this manual path. Normal promotion policy and
its evidence requirements remain unchanged.

## Package and publication contract

The tool verifies both signed channel records, their immutable snapshots,
metadata signatures, RPM digests, RPM signatures against the checked-in
production RPM public key, exact RPM headers, and complete file inventories.
Binary package names come exclusively from the selected registry group. All
registered subpackages and their available architectures must be present;
components requiring the full architecture set enforce that policy. Every
required SRPM is selected by the binary RPM's `SOURCERPM` header. Shared source
RPMs crossing group boundaries, mixed group versions and incomplete groups are
rejected. Noarch RPMs are copied into both binary repository trees.

The result is previous Stable minus the old selected group plus the selected
Beta group. Retained RPM bytes, selected RPM bytes, and original producer digest
fields are preserved. Same signed NEVRA set is a verified no-op. A NEVRA with
changed historical content is rejected. Version downgrades fail the DNF5 upgrade
verification rather than silently replacing a newer installed package.

A free `repo-f44-YYYYMMDD-NNN` snapshot ID is allocated under the shared writer
lock. All three repodata trees are rebuilt with `createrepo_c`; repomd, snapshot
manifest, catalog, publication and manual audit are signed by the existing
metadata role. The V2 catalog generator includes only curated applications
present in the composed snapshot. RPMs are never rebuilt or re-signed.

The signed artifact contains `selected-promotion.json` (reason, source Beta
identities, previous Stable publication and selected/retained package lists).
The final job re-verifies its signature and package inputs. It stores the audit
under `promotions/fedora/44/<snapshot>/<run>/`, the immutable snapshot under
`snapshots/fedora/44/`, and signed publication history under
`publications/fedora/44/stable/<run>/`.

All V2 Pages writers share `ro-repo-pages-storage` concurrency. A changed remote
Git tip is rejected before push; pushes are ordinary fast-forward operations.
An approval delay or external writer changing the base causes failure and
requires a fresh dispatch. A failed preparation/verification/push does not
publish the private checkout. The post-publish job waits for Pages and compares
every remote Stable file, including RPMs and metadata signatures, with the
committed tree, then verifies the publication signature.

## Rollback

Actions → **Roll back remote stable to signed history** on `main` accepts the
previous `target_publication_run` and a non-empty `reason`. Approve `repo-stable`.
The workflow verifies the target snapshot and production RPM signatures, restores
its exact signed publication and catalog without signing, commits a rollback
audit, and verifies the complete remote tree. It preserves newer immutable
snapshots/history. The first Stable publication has no prior Stable to restore;
rollback to an absent channel is intentionally unsupported.

A Pages propagation or remote verification failure after a successful Git push
cannot undo an already committed publication automatically. Use the verified
manual rollback to the previous publication. GitHub Pages/CDN is not a
transactional backend for clients already reading mutable URLs.

## Validation

- `python3 -m unittest tests.test_selected_stable -v`: group completeness,
  architecture/version checks, SRPM association, noarch and writer/workflow gates.
- `python3 tests/selected-stable-e2e.py`: native Fedora 44, real locally built
  signed RPM fixtures and temporary test keys; empty Stable, second independent
  group, Dolphin subpackages, noarch copies, exact byte preservation, no-op,
  update, native DNF5 install/upgrade, wrong source identities, missing/corrupt
  RPMs, invalid metadata signature, replacement failure preservation and rollback.
- `python3 -m unittest discover -s tests -q`: existing V2 and other unit regression
  suite. The existing `tests/e2e-local.sh` CI job is unchanged.

The new `selected-stable-fedora44` PR job runs the signed fixture integration
suite without production secrets. Actual production dispatch and native arm64
candidate validation require the authorized CI environments; local x86_64
fixtures do not establish arm64 runtime behavior or test application GUIs.

The pre-existing PSOP audit freezes historical V2 source hashes. Its original
phase-A evidence remains intact. `v2-selected-stable-source-contract.json` is a
separate, digest-pinned compatibility record for exactly the reviewed V2 files.
The audit still rejects mutations, missing files and extra writers; tests also
reject shortening this record. This is an offline audit adjustment and grants
no PSOP publication authority.
