# Genuine Ro-ASD package and runtime acceptance inventory

G-07/G-08 **UNVERIFIED**. This inventory installs nothing and selects no release.
[candidate-inventory.json](../../evidence/psop-phase-d0/candidate-inventory.json)
contains all five exact storage snapshot manifests/digests, tracked root RPM paths
and canonical group profiles derived from `config/producers-v2.json`.

Production snapshots are under `snapshots/fedora/44/<id>` at storage
`097ba6ba7ab73d87c36f7ec9829b017b083b1883`; current Beta publication run
`37935890476` selects `repo-f44-20261009-001`. Main's legacy root RPM directories
are another source inventory, not interchangeable accepted Stable input. Select
only exact accepted provenance/signatures/header identities, never a root filename
or mutable producer release alone. The production candidate signature audit passes
for the five snapshots; that establishes bytes, not application runtime success.

## First candidate requirements

| Group | Available latest snapshot package(s) | Canonical arch / dwell | Missing production evidence |
| --- | --- | --- | --- |
| ro-assist | 0.2.5-1.fc44, x86_64/aarch64 + SRPM | Both native arches / 7 days | Complete authenticated base tests on both native targets and trusted availability; lowest-risk candidate to evaluate, not an approved selection |
| ro-control | Not in latest snapshot | x86_64/aarch64 / 7 days | Accepted complete source/binary set, both native suites and dwell |
| desktop-theme | Not in latest snapshot | noarch / 7 days | Accepted source/binary, identical noarch bytes in both views, Plasma/login on both supported systems |
| ro-asd-branding, ro-asd-desktop-standard | 0.1.0-1.fc44 noarch + SRPM each | noarch / 7 days | Base tests plus canonical desktop floor: Plasma integration and login-session; both noarch deployment views |
| ro-asd-release | 0.1.2-1.fc44 noarch + SRPM | noarch / 14 days | Base tests plus boot/reboot/recovery/qemu on actual supported images |
| ro-asd-keyring, ro-asd-defaults, ro-asd-kernel-policy | 0.1.0-1.fc44 noarch + SRPM each | noarch / 14 days | Base and system floor, root/trust/update/recovery behavior where relevant |
| ro-asd-repos | 0.1.1-1.fc44 noarch + SRPM | noarch / 14 days | Base and system floor, repo trust/config and rollback behavior |
| ro-installer | 2.4.4-1.fc44 x86_64 + SRPM | x86_64 only / 14 days | Installer GUI, real install-to-disk VM, boot/reboot/recovery/qemu and full base suite; no implied aarch64 requirement outside registered scope |
| ro-kde-dolphin | dolphin, dolphin-libs, dolphin-devel 26.08.1-1.roasd1.fc44 + shared SRPM | x86_64 only, complete 3-package group / 7 days | Full base + Plasma/login; Fedora override closure/file conflicts; CLI/offscreen observations are insufficient |

Canonical BASE = dependency-solve, clean-install, upgrade, file-conflict, rpmlint,
smoke. DESKTOP adds plasma-integration/login-session; SYSTEM adds
boot/reboot/recovery/qemu even when the raw registry list only contains BASE
(`v3_policy_profile.profile` supplies the floor). Noarch's architecture label does
not waive runtime tests on supported binary views. Run exact selected **and
retained** Stable package closure, SRPM linkage, noarch parity and actual RPM
header/signature checks before accepting a complete result.

## Evidence gaps by execution target

| Execution | Existing evidence | Still missing |
| --- | --- | --- |
| x86_64 DNF5 | PR-C real DNF install/upgrade with synthetic fixture RPMs; historical 12-Oct genuine package/full-group DNF observations | Independently authenticated exact first candidate full-set production tests; synthetic success cannot transfer |
| Native aarch64 | Signed ro-assist package present; no native runtime acceptance established | Native hardware/VM identity, OS/image/upstream pins, install/upgrade/smoke and exact installed NEVRA |
| Plasma/login | Historical Dolphin CLI/offscreen only; GUI explicitly UNVERIFIED | Real graphical session/version, integration/login scenarios, evidence and failure checks |
| VM/boot/reboot/recovery | No qualifying first Stable bundle established | Exact bootable image/kernel/firmware/arch + VM logs, reboot and recovery result |
| Installer | Historical full-group dependency test, CLI exit 127 observations | Real interactive/install-to-disk path, resulting filesystem, boot/reboot and recovery |
| Risk-class tests | Existing policy and test harnesses | Every required test with successful executed result, trusted issuer, exact candidate/result/policy/evidence binding |

Historical real-world evidence under `docs/evidence/v3-real-world-20261012/`
includes Dolphin and installer full-group observations. It records its limitations;
do not turn a dependency solve or command availability into GUI/installer success.

## Fedora 44 exact upstream model

`fedora:44`, a metalink or a current mirror URL is not an immutable production pin.
Pin image digest, Fedora release/architecture, RPM/DNF/libdnf versions, base
RPMDB/package set, all enabled repository IDs and options, verified Fedora root
fingerprints/bytes, exact repomd bytes/digests and every referenced metadata/RPM
byte/digest/NEVRA/signature. Record resolved origins, fetch times and immutable
retention location; reject substitutions, missing members and unexpected repos.
Use `v3_pinned_upstream.py` as a reviewed interface reference, not evidence that a
production snapshot exists. Fedora's observed metalink trust model must not be
described as PSOP metadata OpenPGP signing.

Test clean install and upgrade from each supported prior state, offline frozen
replay, dependency/file conflicts and risk runtime against the **same** complete
upstream + Ro set. Execution receipt binds source/run/attempt, observer identity,
machine/image/arch, exact upstream inventory digest, command/options, exit code,
installed NEVRA and logs. Independent authority validates the runner provenance;
signed self-reported JSON alone is insufficient. PR-C's observed 44-package Fedora
dependency base does not pin all production dependencies. New upstream bytes
invalidate affected acceptance and require new review.
