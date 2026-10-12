# Real-world public acceptance evidence

NON-PRODUCTION. Actual released RPMs were read-only inputs. Only fresh test
metadata/envelopes were signed; no released RPM was re-signed or published.
No private key, JWT, credentials, database backup or binary package cache is here.

Base main: `22e16af97d22d680e8e79298378ff9faaa0e2fad` (PR72 merged, seven checks passed).
Tested implementation: `b44995a`.
tools/tests/schemas/config inventory SHA256:
`9fdb8c241ea9fad1a4b4e30247f0fa03b2f6174df96475303a84b9a7902d9f58`.
Complete inventory: `released/acceptance.json` and `backend/rehearsal.json`.

Production input capture: Pages commit `097ba6ba7ab73d87c36f7ec9829b017b083b1883`,
Git tree `69fda4e20cf3082631228a5a7eca5b0ee3b2b0b1`. Git fsck and all268 API-vs-Git
blobs matched. Public HTTPS expected-file parity262/262, refs rechecked unchanged.
Current snapshot inventory SHA256:
`58d5a74b70360a4319069c6928671fb3ddf249cfa7cc1c2a0697e938ea470e97`.

The acquisition runner used HTTPS with official captured metalink SHA256 pins,
all metadata checksums and exact selected RPM primary checksums. Its mirrors are
recorded in `acquisition.json`; retries never changed the captured repomd pin.
Release264 and updates307 real RPMs were independently signature-checked against
Fedora44 fingerprint `36F612DCF27F7D1A48A835E4DBFCF71C6D9F90A6`.
Official metadata's local test attestation does not provision a production service.

Final released-package runner used a fresh Fedora44 container with network=none,
read-only /inputs and /upstream mounts, and a writable exact `git archive b44995a`
source copy. The rootless acquisition container used pasta; it could not be
detached with `podman network disconnect`, so it was not used as the final offline
transaction runner. Superseded draft runs are not final acceptance evidence.

Commands executed against the final archived source:

```bash
python3 -m unittest discover -s tests -v
python3 tests/v3-real-world-acceptance.py /inputs/pages/Project-Ro-ASD-Ro-Repo-097ba6b /upstream /tmp/real-final-acceptance /inputs/pages-tree.json
bash tests/v3-integration-e2e.sh /tmp/real-final-fedora-fixture
python3 tests/v3-upstream-url-e2e.py
python3 tests/v3-backend-postgres-e2e.py --dbname ro_v3_test_real_final --output /tmp/real-final-postgres.json
python3 tests/v3-backend-rehearsal.py --output /tmp/real-final-backend
RO_REPO_E2E_EVIDENCE=/tmp/real-final-v2.json bash tests/e2e-local.sh
```

Actual source acquisition/parity commands:

```bash
python3 tests/v3-real-upstream-acquire.py /tmp/real-upstream /path/to/pinned-pages
python3 tests/v3-real-world-source-audit.py /path/to/pinned-pages pages-tree.json remote-parity.json
```

These drivers deliberately pin this captured acceptance dataset. They do not
discover production authority or activate a channel. For future captures, record
and verify new source/feed snapshots rather than reusing old receipts as current.

| Evidence | Result / meaning |
| --- | --- |
| `unit.log` | 519 passed, no failure/error/skip; includes375 V3 tests |
| `released/` | 11 actual released-package x86_64 transaction scenarios passed, real source/candidate negatives; actual RPM artifact and input/source digests |
| `acquisition.json` | Exact official feeds, metadata hashes and571 cached RPM inventory; solver success alone is not transaction acceptance |
| `before-new-group-fix.json` | Genuine DNF failure for not-installed keyring/Dolphin/Installer upgrade arguments, preserved before correction |
| `fixture/`, `fixture.log` | Real signed **synthetic** fixtures, including new-group DNF regression, changed-config rpmnew and unsafe metadata/RPM negatives |
| `postgres.json`, `backend/`, `backend.log` | Real PG18.6/Git/RSA protocol, but **synthetic package/authority fixtures** |
| `immutable-view.json`, `immutable-view-dnf.log` | Actual Assist+keyring tree copied byte-identically to a digest-addressed view; signed DNF queryPASS; production authBLOCKED, HTTPS deploymentUNVERIFIED |
| `installer-loader-diagnostic.json`, related logs | Bare chroot lacks/proc and fails$ORIGIN; explicitLD_ORIGIN_PATH loads bundled Flutter then GTK rejects missing display. Packaging defect is not established; GUIUNVERIFIED |
| `v2-compatibility.json`, `v2.log` | Existing E2E exit0; rpmlint0errors/4fixturewarnings |
| `remote-parity.json`, `git-object-proof.json` | Read-only public/Git byte identity |
| configuration JSON | Read-only environment/branch/Pages state; not signed protected approval |

CLI probes are actual binaries in disposable installroots; an observation hook
calls the real RPMDB verifier first. DNF/RPMDB results are not mocked. CLI help or
offscreen version output is never GUI acceptance. Dolphin baseline's missing
binary is expected before the group exists; only installed target phases passed
the CLI probe. Installer raw failure is retained with its corrected environment
interpretation; no GUI PASS was invented.

Current source includes a configuration checker that correctly allows unchanged
packaged files to preserve local edits without requiring rpmnew. The actual Assist
config was unchanged; real changed-config rpmnew is UNVERIFIED for that release.
Synthetic fixture changed-config rpmnewPASS is separate.

One initial V2 manual subset-copy omitted fixtures and failed before testing. It
was replaced by the complete final Git archive; only that completed exit0 output
is labelled PASS. A metadata signer directory clash in a draft real driver was
fixed with a separate private test-signing home; no production secret was used.

Native aarch64, Plasma/login/installer/boot/recovery/Ro-Store VM, independently
authenticated first-public history and production roots/services remain
UNVERIFIED/BLOCKED. Existing stable was absent (Git inventory and HTTP404).
Production activation remains BLOCKED.
