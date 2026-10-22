# Phase D-0 non-secret evidence

Read-only audit on 2026-10-15. Base main
`65409834e8c1b66b954f2d610971f8d407e1e79e`, storage
`097ba6ba7ab73d87c36f7ec9829b017b083b1883`. Production activation BLOCKED.

| Artifact | Method / scope |
| --- | --- |
| `github-observations.json` | Timestamped `gh api --method GET` on each recorded endpoint; preserves success/access errors and complete response bodies; no secret endpoint/value reads |
| `github-additional.json` | Waiting/pending/requested queues, Pages builds and baseline main checks; GET only |
| `history.json` | `python3 tools/psop_audit.py history --commit 097ba6ba7ab73d87c36f7ec9829b017b083b1883`; all 300 reachable commits, no shallow boundary |
| `public-signing.json` | `git archive` of exact storage extracted only to `/tmp`; `python3 tools/psop_audit.py signing --pages-root /tmp/psop-d0-pages`; public root-pinned metadata and RPM verification in temporary GPG/RPM stores, no DNF installation |
| `public-history-signatures.json` | Existing `v3_signed_beta_history._keyring/_signature` and `signed_archive_bundle(..., legacy_compatibility=True)` against those exact extracted bytes; retains original signed records and digests, no rewriting |
| `candidate-inventory.json` | Exact snapshot manifest bytes/digests from storage, root RPM paths from Git tree, canonical `v3_policy_profile.profile` for every registry group; not candidate approval |
| `source-inventory.json` | All tracked base file Git mode/blob/SHA256 and comparison with current bytes; excludes new D-0 docs and generated untracked caches |
| `source-audit.json` | `python3 tools/psop_audit.py source`; original guard unchanged |
| `full-discovery.log.gz` | Unchanged full local test suite, 679 PASS / zero skips; temporary test key generation permitted outside filesystem/socket sandbox |
| `sandbox-unit.log.gz` | Unsuccessful first sandbox attempt (643 reported test cases, 78 errors); GPG/socket fixture restrictions; not accepted test evidence |
| `main-unit.log.gz` | `gh run view 38775956808 --job 116563528076 --log --repo Project-Ro-ASD/Ro-Repo`; provider job log of pinned baseline main |
| `validation.json` | Local validation summary and evidence limits; final PR CI is separately verified against delivery HEAD |
| `SHA256SUMS` | SHA256 of evidence files except itself; unsigned integrity index, not an independent witness/approval |

Pagination: environment/workflow/check and named writer run counts fit within 100
and returned counts were assessed. The Pages build endpoint returns the first 100
only; deployments are a bounded first page. These collections are not proof of
complete historic availability or deleted/unreachable history. All queue states
sampled returned zero at observation time; this is **not** provider request drain.
Installation GET 404 leaves App/PAT/manual scope UNVERIFIED. No inaccessible API
result is treated as absence of a writer or authorization to change settings.

Current observations are unsigned API responses and local audit outputs. Original
public publication/snapshot signatures are verified separately; the SHA256 index
does not authenticate a human approval, historic first availability or complete
global coverage. Previous PR-C and real-world evidence remains historical evidence
with its original limitations. No external disposable or production Pages
publication was performed. No production private key/token value was inspected.

The collectors used concurrent independent GETs, so timestamps define an
observation interval, not an atomic GitHub snapshot. Recheck mutable facts before
any future operator stage. The final PR report records final refs/#78 and delivery
CI after committing these files, avoiding a self-referential evidence hash.
