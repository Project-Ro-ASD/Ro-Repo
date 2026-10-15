# PR-C exact acceptance evidence

**Local disposable acceptance only. External Pages and production activation are
BLOCKED.** Original 652 tests are preserved; final local full discovery is
**679/679 PASS, zero skips** (27 new tests; 71 PSOP tests in full discovery).

| File | Evidence |
| --- | --- |
| [tests.json](tests.json), [full-discovery.log.gz](full-discovery.log.gz) | Exact commands/counts, final 679-test output and execution scope. |
| [acceptance-summary.json](acceptance-summary.json) | Four native client outcomes, installed NEVRA/version, negative controls, upstream base and explicit limitations. |
| [native-dnf5.json.gz](native-dnf5.json.gz), [native-dnf5.log.gz](native-dnf5.log.gz) | Full actual Fedora 44 x86_64 DNF5/HTTPS records. Real install; selected+retained install; independent contiguous install/upgrade 1.0→2.0. Five actual DNF negative defenses and 17 client negative assertions. |
| [local-https.json.gz](local-https.json.gz), [local-https.log.gz](local-https.log.gz) | Separate network-disabled local HTTPS mode, four complete view verifications and 15 negative assertions. DNF is NOT_RUN/UNVERIFIED in this mode, including views named by the shared native harness. |
| [pr-b-baseline.json](pr-b-baseline.json), [pr-b-baseline.log.gz](pr-b-baseline.log.gz) | Unmodified default PR-B three-flow real RPM publication baseline; observer is not enabled in this run. |
| [external-pages.json](external-pages.json) | Actual external-mode refusal: BLOCKED, exit 2, zero requests, no authorized target. It is not a Pages PASS. |
| [fault-matrix.json](fault-matrix.json) | Exact executed test IDs for delayed CAS, expiry, race, lost response, process death, UNKNOWN, complete-member faults and wrong public receipts. |
| [source-inventory.json](source-inventory.json) | SHA256/mode inventory of all code/tests/schemas/config/public keys/workflows. Digest `6488aba7af22248d39d00f82363bd5e27f43673898e453d6404754df4ff79d5d`. |
| [source-audit.json](source-audit.json), [refs.json](refs.json) | Original 234-file protection and public pins unchanged; initial main/Pages/#78 references. Final remote checks are also recorded in PR delivery. |
| [pr78-reference.json](pr78-reference.json) | Read-only exact-head counterexample review; no merge/cherry-pick or copied test suite. |

Local real-runtime runs used the cached Fedora image
`1af38c532d564f256e338805615599f203d8f22895a07ce7d88d013cfda73105` with source
mounted read-only and only a temporary output mount. HTTPS-only and baseline runs
used `--network none`. The native upstream run accessed only public Fedora package
repositories, installed a 44-package gzip dependency base in a private client
installroot, then applied PSOP on that base. The parent container RPMDB remained
unchanged; the user's host root/RPMDB and CA trust store were never mounted or
modified. Fresh synthetic RPMs are not production Ro applications.

The native report includes exact downloaded Fedora RPM/repomd hashes and runtime
public-root pins. Fedora's observed metalink/default metadata model is not a
claimed OpenPGP metadata signature or independently attested production upstream.
PSOP's own `gpgcheck`, `repo_gpgcheck`, `sslverify` are 1 and
`skip_if_unavailable` is 0. DNF consumes a frozen verified file view after actual
TLS/complete-byte verification, avoiding a second mutable CDN read.

Source capture honestly records the local precommit main HEAD and dirty workspace.
The exact source inventory binds those executions to delivered code; it does not
pretend that a future commit SHA existed during a precommit test. GitHub runtime
artifacts separately record checkout/run context. Final-head CI (eight existing
jobs + the new Fedora acceptance job) is verified against the PR head and linked
in the PR description/delivery; these local logs do not attest GitHub success.

Repeat in a suitable disposable Fedora 44 runtime:

```bash
python3 -m unittest discover -s tests -v
python3 tests/psop-offline-e2e.py /tmp/baseline.json
python3 tests/psop-fedora44-dnf5-e2e.py /tmp/native.json --official-upstream
python3 tests/psop-pages-disposable-acceptance.py --mode local --output /tmp/https.json
```

The native tool refuses non-container/non-Fedora-44/non-x86_64 execution. Unit
client models use real cryptography but explicitly model RPM bytes; real RPM/DNF
claims come only from the native suite. No local/model observation proves global
freshness, Pages ordering, provider deadline fencing, native aarch64, GUI or
production authority. See [readiness](../../psop/READINESS-REPORT.md),
[runbook](../../psop/OPERATOR-RUNBOOK.md) and
[API map](../../psop/PR-C-IMPLEMENTATION.md).
