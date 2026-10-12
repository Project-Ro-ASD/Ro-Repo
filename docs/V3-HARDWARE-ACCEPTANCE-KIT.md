# Real hardware acceptance kit

Production activation: **BLOCKED**. No GUI, boot, hardware or aarch64 PASS is established by this kit. Preserve the actual acceptance report's 11/11 released-package result as prior evidence, not evidence for new code or machines.

Use Fedora 44 on a dedicated laptop, university test desktop, pinned genuine Ro-ASD QEMU image and suitable native/emulated aarch64 machine. Label native versus emulated execution and machine/image provenance. Record exact source commit, full package/SRPM digests, baseline/candidate/result view, upstream cache manifest and independent public roots before starting.

Collect read-only environment evidence before and after the session:

```bash
python3 tools/v3_hardware_kit.py --environment laptop-x86_64 --output /tmp/ro-v3-laptop-before
# alternatives: university-desktop, qemu-ro-asd, native-aarch64, emulated-aarch64
```

The collector records OS/architecture, boot ID, DNF version, installed NEVRAs, disk/mount inventory and cache-only enabled repos. Its machine-readable cases all begin UNVERIFIED. It never invokes a package transaction, GUI, reboot or disk operation. Preserve raw logs and hashes; an independent test-runner must attest actual observations under the existing `tests`/`acceptance-inputs` contracts.

## Transaction preparation

Freeze baseline, beta, composed stable and independently pinned Fedora cache into read-only input directories. Reuse `v3_pinned_upstream.verify_upstream`, `v3_real_acceptance.execute` and `v3_full_set_dnf.validate`; pass exact signed `real-acceptance-v3` spec, plan/registry digests and authenticated acquisition envelope. All DNF writes belong to newly created installroots. No fallback to a machine's mutable system repositories is allowed. Run separate Assist install and baseline-to-candidate upgrade, whole-set component promotion, retained package/file conflicts and config preservation with `.rpmnew` checks.

For a complete signed synthetic rehearsal on a disposable Fedora container:

```bash
bash tests/v3-integration-e2e.sh /tmp/ro-v3-synthetic-evidence
```

This exercises actual RPM/GPG/DNF mechanics, including HTTPS discovery and future updates. It is not real application/hardware acceptance. A ready producer image/cache is not supplied by this repository.

## Maintainer-operated real cases

| Case | Execute on dedicated test machine/guest | Required machine-readable evidence |
| --- | --- | --- |
| Ro-Assist | Install exact signed release, upgrade from a genuine earlier release, launch real runtime and exercise supported functions | Before/after NEVRAs, DNF logs, executable/runtime output, app logs/screenshots hashes and input digests |
| Dolphin/Plasma | Log into an actual Plasma session, open Dolphin, exercise Ro-ASD integration and upgrade the entire subpackage group | Session/desktop identity, real interaction observations, screenshots/logs, complete NEVRAs |
| Installer GUI | Launch the actual signed installer and exercise its GUI in a disposable VM | GUI interaction evidence, loader/runtime logs, package/source digests |
| Installer installation | Operator chooses a fresh VM disk or a dedicated test disk after examining `lsblk` output | Explicit target disk identity/authorization, installer journal and resulting filesystem/image evidence |
| Boot/reboot | Operator boots/reboots the test guest/machine and validates login and services | Distinct boot IDs, serial/journal logs, kernel/package identity and session observations |
| Isolation/upgrade | Query effective beta-only/stable-only sources, upgrade only the selected group while retaining other signed bytes | Effective repo configs, installed NEVRAs, complete view digest and retained/config hashes |
| Config/conflicts | Modify a known `%config(noreplace)` test config, upgrade and inspect original content and `.rpmnew`; include a known conflicting payload negative | Before/after hashes, rpmnew content, transaction rejection log for conflict |
| Recovery | Obtain fresh protected recovery authorization against current state; select previously POST_VERIFIED immutable history in the disposable environment | Current/target generation, authorization/witness/audit/remote receipts, actual package and application recovery observations |

No automatic format, repartition, dd, reboot or install-to-disk command is included. University machines require the institution's own test-machine authorization and backup procedure. Use genuine earlier signed Installer/Dolphin releases for upgrade acceptance; current releases alone cannot prove it.

## QEMU and aarch64

Reuse `v3_vm_acceptance.run` with a signed `vm-inputs` attestation and exact `vm-acceptance-v3` spec. Pin raw image, executor, firmware and read-only repository media. The executor copies the image into a private disposable root, disables network/host sharing and captures serial/QEMU/guest-agent logs. The actual guest must include `/usr/libexec/ro-repo-v3/acceptance` implementing genuine cases: login-session, plasma-integration, boot, reboot, recovery, qemu, upgrade and applicable ro-store-gui. Do not replace that guest helper with an echo/PASS script. Its absence is BLOCKED.

For native aarch64 run the same released-artifact transaction framework on Fedora 44 aarch64; for QEMU emulation label execution explicitly and provide real guest logs. A noarch RPM must be exercised on both actual target environments. Passing host protocol tests or signatures of aarch64 RPMs does not prove aarch64 execution.

Finish by collecting a new read-only observation directory, inventorying every evidence file with SHA256, and signing the exact logs/input/case manifest through the independently provisioned runner. Feed that capability into `verify_evidence`; unknown/missing mandatory cases block approval. No hand-edited checklist or synthetic screenshot grants a production PASS.
