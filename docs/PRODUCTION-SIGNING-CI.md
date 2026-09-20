# Ro-Repo V2 Production Signing CI

Status: DESIGN LOCKED FOR PHASE 2 IMPLEMENTATION
Branch: `phase2/production-signing-ci`

## Scope

This step wires the already-tested local RPM signing path into GitHub Actions
production CI.

This step signs accepted RPM/SRPM artifacts only.

It does not:

- publish GitHub Pages
- build or publish remote snapshots
- promote beta or stable
- use the metadata signing secret
- expose or import the offline primary private key

## Workflow shape

Production RPM signing is a second job in the existing exact-release acceptance
workflow.

```text
workflow_dispatch exact producer/tag/commit/release ID
  -> accept job
  -> accepted-component-<run_id> artifact
  -> sign job
       environment: repo-production-signing
       exact accepted artifact from the same workflow run
  -> signed-component-<run_id> artifact
```

The signing job must have `needs: accept` and therefore cannot run when
acceptance fails.

Using the same workflow run intentionally avoids adding another mutable signing
input such as "latest acceptance" or an arbitrary external run identifier.

## Protected environment

The signing job must reference:

```yaml
environment:
  name: repo-production-signing
```

The existing protected environment is the authorization boundary for production
RPM signing.

Environment approval and branch policy are security controls, not cosmetic
deployment metadata.

The job must use a single-concurrency signing group so two production signing
jobs cannot operate concurrently.

## Production secret contract

Only the RPM signing subkey is used in this step.

Environment secret names:

- `RO_REPO_RPM_SIGNING_SUBKEY_B64`
- `RO_REPO_RPM_SIGNING_PASSPHRASE`

The passphrase secret may be empty only when the provisioned subkey export is
intentionally unprotected. An encrypted export without its passphrase must fail
closed.

The expected RPM signing fingerprint is not a secret and must be read from:

`keys/production/production-fingerprints.txt`

Canonical value at the start of this work:

`38CB87F6FBD645309432A6E22E02DEE8828B769B`

The workflow must not accept a signing fingerprint from workflow input.

The offline primary secret key is forbidden in CI.

## Ephemeral key handling

The signing job must:

1. create a private temporary `GNUPGHOME` with restrictive permissions;
2. decode and import only the subkey-only CI export;
3. verify that the expected exact RPM signing subkey is present and signing-capable;
4. reject wrong-role, wrong-fingerprint, missing-key, or ambiguous key material;
5. use the exact fingerprint for signing;
6. clean the temporary keyring, passphrase material, and GPG agent state on exit.

Secret values must never be printed or passed as literal command-line
arguments.

If a passphrase file is required for GnuPG loopback mode, it must be temporary,
mode 0600, referenced by path only, and removed during cleanup.

## RPM 6 signing

Fedora 44 uses RPM 6.x. Production signing should use the RPM 6 unambiguous key
selection interface:

`rpmsign --addsign --key-id <exact fingerprint> ...`

Do not use short key IDs.

Do not rely on the legacy `%_gpg_name` selector for the production path.

The exact fingerprint remains additionally enforced by Ro-Repo validation.

## Accepted artifact revalidation

The signing job must not blindly sign every RPM found in a downloaded Actions
artifact.

Before signing it must revalidate the accepted object:

- acceptance evidence exists;
- acceptance evidence says exact GitHub attestation verification succeeded;
- evidence manifest digest matches the manifest;
- evidence release identity matches the manifest;
- RPM set exactly matches the manifest;
- every producer artifact SHA-256 still matches;
- filenames are safe and unique.

No rejected, unattested, mutated, extra, or missing artifact may reach
`rpmsign`.

## Canonical public-key verification

After signing, the produced RPMs must be verified against the canonical
repository public trust material, not merely against an ad-hoc key supplied by
workflow input.

Canonical public key:

`keys/production/ro-asd-rpm-signing-public.asc`

Wrong-role signatures must fail closed.

## Signing evidence

The job should emit a machine-readable `rpm-signing-evidence-v1.json`.

It must bind at least:

- schema version
- GitHub workflow run
- acceptance artifact identity
- accepted manifest digest
- RPM signing fingerprint
- timestamp
- each RPM filename
- producer artifact SHA-256
- signed artifact SHA-256

Signing evidence is not a replacement for the future repository snapshot
manifest. It is the auditable bridge between acceptance and snapshot creation.

## Output artifact

Successful signing uploads:

`signed-component-<github.run_id>`

containing the signed RPM/SRPM set plus signing evidence.

A signing failure must not upload an artifact that can be mistaken for a valid
signed component.

## Tests

Unit and Fedora 44 E2E coverage must include:

- exact expected signing subkey succeeds;
- wrong signing role fails;
- primary fingerprint is rejected as a role key;
- mutated accepted RPM is rejected before signing;
- extra or missing accepted RPM is rejected before signing;
- unattested production acceptance evidence is rejected;
- signing evidence validates against its schema;
- signed RPM verifies against the expected public key;
- no secret material appears in evidence;
- existing local snapshot and promotion tests remain green.

Production secrets are never required for pull-request CI. Tests use ephemeral
test-only keys.

## Manual provisioning after merge

After the workflow code is merged and reviewed, the maintainer will provision
the RPM subkey-only export and, if needed, its passphrase into the existing
`repo-production-signing` environment.

Secret values are never committed, pasted into PR discussion, or added to test
fixtures.
