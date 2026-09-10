#!/usr/bin/env python3
"""
Bootstrap a Project-Ro-ASD repository with the repository security baseline.

The tool is deliberately conservative:
- it only targets Project-Ro-ASD by default;
- it never edits an unrelated existing ruleset;
- it reuses an organization-level Ro-ASD baseline when one already applies;
- repository-specific required CI checks are opt-in via repeated --check flags;
- producer and central-release extras are opt-in.

Authentication is delegated to GitHub CLI (`gh auth login`).
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import Any, Iterable

API_VERSION = "2026-03-10"
ORG_BASELINE_NAME = "Ro-ASD Baseline - Default Branch"
REPO_FALLBACK_NAME = "Ro-ASD Baseline - Repository Fallback"
REPO_CHECKS_NAME = "Ro-ASD Required CI - Default Branch"
EXPECTED_OWNER = "Project-Ro-ASD"

CENTRAL_ENVIRONMENTS = (
    "repo-beta",
    "repo-stable",
    "repo-production-signing",
)


class BootstrapError(RuntimeError):
    pass


@dataclass
class ApiResult:
    ok: bool
    status: int | None
    data: Any
    stderr: str = ""


class GhClient:
    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run

    def _run(
        self,
        method: str,
        endpoint: str,
        payload: dict[str, Any] | None = None,
        *,
        allow_failure: bool = False,
    ) -> ApiResult:
        if self.dry_run and method.upper() not in {"GET", "HEAD"}:
            print(f"[dry-run] {method.upper()} /{endpoint}")
            if payload is not None:
                print(json.dumps(payload, indent=2, sort_keys=True))
            return ApiResult(True, None, None)

        cmd = [
            "gh",
            "api",
            "--method",
            method.upper(),
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            f"X-GitHub-Api-Version: {API_VERSION}",
            f"/{endpoint}",
            "--include",
        ]
        stdin = None
        if payload is not None:
            cmd += ["--input", "-"]
            stdin = json.dumps(payload)

        proc = subprocess.run(
            cmd,
            input=stdin,
            text=True,
            capture_output=True,
            check=False,
        )
        status = self._parse_status(proc.stdout)
        body = self._strip_headers(proc.stdout)
        data: Any = None
        if body.strip():
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                data = body

        result = ApiResult(proc.returncode == 0, status, data, proc.stderr.strip())
        if not result.ok and not allow_failure:
            detail = result.stderr or body.strip() or "unknown GitHub API error"
            raise BootstrapError(
                f"{method.upper()} /{endpoint} failed"
                + (f" (HTTP {status})" if status else "")
                + f": {detail}"
            )
        return result

    @staticmethod
    def _parse_status(raw: str) -> int | None:
        for line in raw.splitlines():
            if line.startswith("HTTP/"):
                parts = line.split()
                if len(parts) >= 2 and parts[1].isdigit():
                    return int(parts[1])
        return None

    @staticmethod
    def _strip_headers(raw: str) -> str:
        # `gh api --include` emits one header block, a blank line, then body.
        parts = raw.split("\r\n\r\n", 1)
        if len(parts) == 2:
            return parts[1]
        parts = raw.split("\n\n", 1)
        return parts[1] if len(parts) == 2 else raw

    def get(self, endpoint: str, *, allow_failure: bool = False) -> ApiResult:
        return self._run("GET", endpoint, allow_failure=allow_failure)

    def post(
        self,
        endpoint: str,
        payload: dict[str, Any] | None = None,
        *,
        allow_failure: bool = False,
    ) -> ApiResult:
        return self._run("POST", endpoint, payload, allow_failure=allow_failure)

    def put(
        self,
        endpoint: str,
        payload: dict[str, Any] | None = None,
        *,
        allow_failure: bool = False,
    ) -> ApiResult:
        return self._run("PUT", endpoint, payload, allow_failure=allow_failure)

    def patch(
        self,
        endpoint: str,
        payload: dict[str, Any] | None = None,
        *,
        allow_failure: bool = False,
    ) -> ApiResult:
        return self._run("PATCH", endpoint, payload, allow_failure=allow_failure)


def parse_repo(value: str) -> tuple[str, str]:
    value = value.strip().strip("/")
    if value.startswith("https://github.com/"):
        value = value.removeprefix("https://github.com/").removesuffix(".git").strip("/")
    parts = value.split("/")
    if len(parts) != 2 or not all(parts):
        raise argparse.ArgumentTypeError("repository must be OWNER/REPO or a GitHub repository URL")
    return parts[0], parts[1]


def pull_request_rule() -> dict[str, Any]:
    return {
        "type": "pull_request",
        "parameters": {
            "required_approving_review_count": 0,
            "dismiss_stale_reviews_on_push": False,
            "require_code_owner_review": False,
            "require_last_push_approval": False,
            "required_review_thread_resolution": False,
            "allowed_merge_methods": ["merge", "squash", "rebase"],
        },
    }


def universal_rules() -> list[dict[str, Any]]:
    return [
        {"type": "deletion"},
        {"type": "non_fast_forward"},
        pull_request_rule(),
    ]


def status_check_rule(checks: Iterable[str]) -> dict[str, Any]:
    clean = dedupe_nonempty(checks)
    return {
        "type": "required_status_checks",
        "parameters": {
            "strict_required_status_checks_policy": True,
            "do_not_enforce_on_create": False,
            "required_status_checks": [{"context": check} for check in clean],
        },
    }


def ruleset_payload(name: str, rules: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "name": name,
        "target": "branch",
        "enforcement": "active",
        "conditions": {
            "ref_name": {
                "include": ["~DEFAULT_BRANCH"],
                "exclude": [],
            }
        },
        "rules": rules,
        "bypass_actors": [],
    }


def dedupe_nonempty(values: Iterable[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        value = value.strip()
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def find_named_ruleset(
    rulesets: list[dict[str, Any]],
    name: str,
    *,
    source_type: str | None = None,
) -> dict[str, Any] | None:
    for ruleset in rulesets:
        if ruleset.get("name") != name:
            continue
        if source_type is not None and ruleset.get("source_type") != source_type:
            continue
        return ruleset
    return None


class Bootstrapper:
    def __init__(
        self,
        api: GhClient,
        owner: str,
        repo: str,
        *,
        checks: list[str],
        producer: bool,
        central_release: bool,
        allow_other_owner: bool,
    ):
        self.api = api
        self.owner = owner
        self.repo = repo
        self.full = f"{owner}/{repo}"
        self.checks = dedupe_nonempty(checks)
        self.producer = producer
        self.central_release = central_release
        self.allow_other_owner = allow_other_owner
        self.manual_followups: list[str] = []

    def run(self) -> None:
        self._guard_owner()
        metadata = self._repo_metadata()
        self._require_default_branch_main(metadata)
        self._ensure_rules()
        self._ensure_security()
        if self.producer:
            self._enable_immutable_releases()
        if self.central_release:
            self._ensure_central_environments()

        print()
        print(f"Baseline complete for {self.full}.")
        if self.manual_followups:
            print("Manual follow-up:")
            for item in self.manual_followups:
                print(f"  - {item}")
        else:
            print("No manual follow-up detected.")

    def _guard_owner(self) -> None:
        if self.owner != EXPECTED_OWNER and not self.allow_other_owner:
            raise BootstrapError(
                f"refusing to modify {self.full}: expected owner {EXPECTED_OWNER}. "
                "Use --allow-other-owner only for intentional testing."
            )

    def _repo_metadata(self) -> dict[str, Any]:
        result = self.api.get(f"repos/{self.owner}/{self.repo}")
        if not isinstance(result.data, dict):
            raise BootstrapError("repository metadata response was not a JSON object")
        return result.data

    def _require_default_branch_main(self, metadata: dict[str, Any]) -> None:
        default_branch = metadata.get("default_branch")
        if default_branch != "main":
            raise BootstrapError(
                f"default branch is {default_branch!r}, not 'main'. "
                "Rename/create main deliberately before applying the Ro-ASD baseline."
            )
        print("[ok] default branch: main")

    def _rulesets(self) -> list[dict[str, Any]]:
        result = self.api.get(
            f"repos/{self.owner}/{self.repo}/rulesets?includes_parents=true"
        )
        if not isinstance(result.data, list):
            raise BootstrapError("ruleset response was not a JSON list")
        return result.data

    def _ensure_rules(self) -> None:
        existing = self._rulesets()
        org_baseline = find_named_ruleset(
            existing, ORG_BASELINE_NAME, source_type="Organization"
        )

        if org_baseline and org_baseline.get("enforcement") == "active":
            print(f"[ok] organization baseline applies: {ORG_BASELINE_NAME}")
        else:
            self._upsert_repo_ruleset(
                existing,
                REPO_FALLBACK_NAME,
                ruleset_payload(REPO_FALLBACK_NAME, universal_rules()),
            )

        if self.checks:
            # Status checks are intentionally repository-specific. Never bake them
            # into the organization-wide baseline.
            existing = self._rulesets()
            self._upsert_repo_ruleset(
                existing,
                REPO_CHECKS_NAME,
                ruleset_payload(REPO_CHECKS_NAME, [status_check_rule(self.checks)]),
            )
            print("[ok] required CI checks: " + ", ".join(self.checks))
        else:
            print("[info] no repository-specific required CI checks requested")

    def _upsert_repo_ruleset(
        self,
        existing: list[dict[str, Any]],
        name: str,
        payload: dict[str, Any],
    ) -> None:
        current = find_named_ruleset(existing, name, source_type="Repository")
        if current is None:
            self.api.post(f"repos/{self.owner}/{self.repo}/rulesets", payload)
            print(f"[ok] created repository ruleset: {name}")
            return

        ruleset_id = current.get("id")
        if not isinstance(ruleset_id, int):
            raise BootstrapError(f"existing ruleset {name!r} has no numeric id")
        self.api.put(
            f"repos/{self.owner}/{self.repo}/rulesets/{ruleset_id}",
            payload,
        )
        print(f"[ok] updated repository ruleset: {name}")

    def _ensure_security(self) -> None:
        # Secret scanning + push protection live in `security_and_analysis`.
        # If an org security configuration enforces them, PATCH may be rejected;
        # verify final state before deciding whether that is an error.
        patch = {
            "security_and_analysis": {
                "secret_scanning": {"status": "enabled"},
                "secret_scanning_push_protection": {"status": "enabled"},
            }
        }
        patch_result = self.api.patch(
            f"repos/{self.owner}/{self.repo}",
            patch,
            allow_failure=True,
        )
        if not patch_result.ok:
            current = self._repo_metadata()
            security = current.get("security_and_analysis") or {}
            secret_ok = (security.get("secret_scanning") or {}).get("status") == "enabled"
            push_ok = (
                security.get("secret_scanning_push_protection") or {}
            ).get("status") == "enabled"
            if not (secret_ok and push_ok):
                raise BootstrapError(
                    "could not enable secret scanning/push protection and the "
                    "repository does not report both as enabled"
                )
            print("[ok] secret scanning + push protection are organization-managed/enabled")
        else:
            print("[ok] secret scanning + push protection enabled")

        self.api.put(f"repos/{self.owner}/{self.repo}/vulnerability-alerts")
        print("[ok] Dependabot alerts enabled")

        self.api.put(f"repos/{self.owner}/{self.repo}/automated-security-fixes")
        print("[ok] Dependabot security updates enabled")

    def _enable_immutable_releases(self) -> None:
        result = self.api.put(
            f"repos/{self.owner}/{self.repo}/immutable-releases",
            allow_failure=True,
        )
        if result.ok or result.status == 409:
            print("[ok] immutable releases enabled")
            return
        raise BootstrapError(
            "failed to enable immutable releases"
            + (f" (HTTP {result.status})" if result.status else "")
        )

    def _ensure_central_environments(self) -> None:
        team = self.api.get(
            f"orgs/{self.owner}/teams/release-engineering",
            allow_failure=True,
        )
        team_id = None
        if team.ok and isinstance(team.data, dict):
            raw_id = team.data.get("id")
            if isinstance(raw_id, int):
                team_id = raw_id

        if team_id is None:
            self.manual_followups.append(
                "Could not resolve Project-Ro-ASD/release-engineering team via API; "
                "create/protect repo-beta, repo-stable and repo-production-signing manually."
            )
            return

        payload = {
            "wait_timer": 0,
            "prevent_self_review": False,
            "reviewers": [{"type": "Team", "id": team_id}],
            "deployment_branch_policy": {
                "protected_branches": False,
                "custom_branch_policies": True,
            },
        }
        for env in CENTRAL_ENVIRONMENTS:
            self.api.put(
                f"repos/{self.owner}/{self.repo}/environments/{env}",
                payload,
            )
            policy_result = self.api.post(
                f"repos/{self.owner}/{self.repo}/environments/{env}/deployment-branch-policies",
                {"name": "main", "type": "branch"},
                allow_failure=True,
            )
            if not policy_result.ok and policy_result.status != 422:
                raise BootstrapError(
                    f"failed to ensure main deployment branch policy for {env}"
                )
            print(f"[ok] protected environment: {env}")

        self.manual_followups.append(
            "Verify in the GitHub UI that administrator bypass remains disabled for "
            "repo-beta, repo-stable and repo-production-signing; that control is not "
            "reliably represented by the environment REST payload."
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Apply the Ro-ASD repository baseline using GitHub CLI."
    )
    parser.add_argument("repository", help="Project-Ro-ASD/REPO or GitHub repository URL")
    parser.add_argument(
        "--check",
        action="append",
        default=[],
        metavar="CONTEXT",
        help="repository-specific required status check; repeat as needed",
    )
    parser.add_argument(
        "--producer",
        action="store_true",
        help="enable immutable releases for an RPM/package producer repository",
    )
    parser.add_argument(
        "--central-release",
        action="store_true",
        help="configure Ro-Repo-style protected release environments",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="show write requests without sending them",
    )
    parser.add_argument(
        "--allow-other-owner",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    owner, repo = parse_repo(args.repository)

    if shutil.which("gh") is None:
        print("error: GitHub CLI (`gh`) is required", file=sys.stderr)
        return 2

    auth = subprocess.run(
        ["gh", "auth", "status"],
        text=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if auth.returncode != 0:
        print("error: `gh` is not authenticated; run `gh auth login` first", file=sys.stderr)
        return 2

    try:
        Bootstrapper(
            GhClient(dry_run=args.dry_run),
            owner,
            repo,
            checks=args.check,
            producer=args.producer,
            central_release=args.central_release,
            allow_other_owner=args.allow_other_owner,
        ).run()
    except BootstrapError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
