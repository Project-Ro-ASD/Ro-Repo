# Current GitHub security audit

G-04 **FAIL**. This is a read-only 2026-10-15 observation, not a settings change.
Exact timestamp, endpoint, response and access failures are retained in
[github-observations.json](../../evidence/psop-phase-d0/github-observations.json).

| Control | Observed value | Assessment |
| --- | --- | --- |
| Main effective rules | Active ruleset `22656730`, default branch; deletion/non-fast-forward restricted; PR required | Effective rules checked separately from legacy branch-protection endpoint |
| Independent reviewer | `required_approving_review_count=0`; CODEOWNERS false; last-push approval false; stale dismissal false | FAIL; a PR requirement alone supplies no independent approval |
| Required checks | Strict checks: `unit-policy`, `fedora44-e2e`, integration ID 15368 | These two are enforced; all nine are observed green, seven are not required by this ruleset |
| Ruleset bypass | `bypass_actors=[]`, `current_user_can_bypass=never` | No configured bypass in this observed ruleset; not proof of every App/PAT/admin capability |
| Storage protection | Branch reports `protected=false`; legacy endpoint 404 `Branch not protected`; effective rules `[]` | FAIL exclusive writer protection |
| Signing environment | `repo-production-signing`, reviewer team `release-engineering` ID 19418500; admins bypass false | Reviewer gate exists, but `prevent_self_review=false`: independence FAIL |
| Beta / Stable environments | Same reviewer team, self-review false prevention, admins bypass false | Same independence gap |
| Deployment source | Signing/Beta/Stable custom branch policy exactly `main` | Main-only policy observed for these environments; snapshot writer has no environment |
| Pages environment | Allows `main` and `pages-storage`, admins bypass true; no required reviewer | Cannot be described as main-only protected signing authority |
| Pages configuration | Legacy `pages-storage` at `/`, custom domain `repo.ro-asd.org`; `https_enforced=false` | GET observation; clients must enforce HTTPS. No DNS or Pages configuration changed |
| Workflow defaults | Read default; cannot approve PR reviews; all actions allowed, SHA pinning not globally required | Defaults do not revoke explicitly requested job `contents:write` |
| App/PAT/manual writers | Repository installation endpoint unavailable (404); account/org token and manual capability inventory incomplete | UNVERIFIED, never infer absence from access denial |

Legacy main `/protection` also returns 404. This does **not** mean main has no
protection: the effective rules and active ruleset above establish its actual
controls. Team identity is not proof of two different humans; membership and
actual approval identities need an operator-attested separation record.

Expected closure: separately authorized administrator stage to require independent
review, reject triggering actor/self-approval, bind trusted required checks and
source ref, restrict real storage ingress, enumerate every bypass/capability, and
test denied attempts using disposable resources. Retain before/after GET evidence
and named independent reviewer. Merely editing workflow YAML cannot enforce
repository-level App/PAT/manual exclusion. Admins able to change policy remain a
governance trust boundary and need monitored, independently reviewed changes.

GitHub's [environment documentation](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments)
describes self-review prevention as a separate option. The observed false value
must not be promoted to independent approval. No new credentials or policy grants
are requested by this audit.
