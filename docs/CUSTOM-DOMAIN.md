# repo.ro-asd.org Custom Domain Binding

Status: PHASE 2 STEP 5 IMPLEMENTATION

## Scope

Step 5 binds the canonical public repository endpoint:

`https://repo.ro-asd.org`

to the existing GitHub Pages backend created in Step 4.

This step does not rebuild, re-sign, promote, or mutate any immutable snapshot.

## Required DNS record

For the `repo` subdomain, configure exactly one CNAME record:

```text
Type:  CNAME
Name:  repo
Value: project-ro-asd.github.io
```

Do not add A or AAAA records for `repo.ro-asd.org` while this CNAME is active.

## GitHub Pages custom domain

Repository:

`Project-Ro-ASD/Ro-Repo`

Set the Pages custom domain to:

`repo.ro-asd.org`

GitHub Pages should create or maintain the corresponding root-level `CNAME`
file in the Pages source branch. Because the Pages source is `pages-storage`,
the expected file content is exactly:

`repo.ro-asd.org`

## Security order

Recommended order:

1. verify ownership of `ro-asd.org` in the GitHub organization when available;
2. set the repository Pages custom domain;
3. create the DNS CNAME record;
4. wait for GitHub DNS verification and TLS certificate provisioning;
5. enable Enforce HTTPS;
6. run the remote domain verification workflow.

Do not delete the Pages custom-domain setting while DNS still points to GitHub
Pages. This avoids leaving a dangling DNS record that could create a takeover
risk.

## Automated closeout

Workflow:

`.github/workflows/verify-pages-domain.yml`

Input:

- exact immutable `snapshot_id`

The workflow verifies:

- `pages-storage/CNAME` equals `repo.ro-asd.org`;
- public DNS returns exactly `project-ro-asd.github.io.`;
- HTTPS succeeds;
- every file in the selected immutable snapshot is retrievable remotely;
- every remote file is byte-for-byte equal to the Pages storage copy;
- the remote repository snapshot manifest has a valid metadata signature;
- the remote signed snapshot identity equals the requested exact snapshot.

The verification workflow has read-only repository permissions and no secrets.

## Step 5 canary

Use:

```text
snapshot_id: repo-f44-20260920-001
```

Step 5 is closed only after the workflow succeeds against
`https://repo.ro-asd.org`.

## Next step

Step 6 creates the remote beta channel as a mutable view over an exact immutable
snapshot. It must reuse the already-published Step 4/5 bytes and must not
rebuild or re-sign packages or repository metadata.
