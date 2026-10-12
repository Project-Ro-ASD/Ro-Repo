"""Immutable digest-addressed repository views and complete byte verification.

The approved payload is already signed (RPMs and repository metadata). Signing
after authorization signs an external publication envelope, never changes that
payload. Git/Pages deployments do not imply atomic CDN visibility. DNF clients
must use the explicit immutable baseurl before production activation.
"""
import pathlib
import shutil
import tempfile
import urllib.parse
import urllib.request

from v3_backend_trust import (TOKEN, TestSigner, canonical, digest, require_attestation,
                              require_test_root, verify_envelope, key_identity)
from v3_integration import tree_inventory
from v3_policy_profile import sha
from v3_promotion_planner import PlanningError


class VerifiedResult:
    def __init__(self, source, inventory, receipt, plan_sha256, seal):
        if seal is not TOKEN:
            raise PlanningError("unverified complete result")
        self.source, self.inventory, self.receipt = pathlib.Path(source), inventory, receipt
        self.plan_sha256 = plan_sha256
        self.sha256 = sha(inventory)

    def check(self):
        if tree_inventory(self.source) != self.inventory:
            raise PlanningError("verified result changed")


def verify_attested_result(source, proposal, plan, attestation, *, now):
    inventory = tree_inventory(source)
    payload = require_attestation(attestation, "result-preflight")
    if (sha(inventory) != proposal["result_stable_sha256"] or
            payload.get("result_stable_sha256") != sha(inventory) or
            payload.get("stable_set_sha256") != proposal["stable_set_sha256"] or
            payload.get("plan_sha256") != sha(plan) or not payload["issued_at"] <= now < payload["expires_at"] or
            payload.get("proposal_sha256") != proposal["proposal_sha256"] or
            payload.get("rpm_signatures") != "PASS" or payload.get("srpm_closure") != "PASS" or
            payload.get("metadata_signatures") != "PASS"):
        raise PlanningError("authenticated full-result preflight required")
    return VerifiedResult(source, inventory, attestation.sha256, sha(plan), TOKEN)


def verify_result(source, proposal, plan, *, beta, baseline, registry, rpm_key, rpm_key_sha256,
                  metadata_key, metadata_key_sha256, operation="promote"):
    """Real frozen GPG/RPM/SRPM preflight, reusing the merged V3 validators."""
    from v3_full_set_dnf import _signed_view, _rpm_set_preflight
    from v3_signed_beta_history import _keyring
    from v3_integration import verify_proposal
    from v3_group_validation import stable_set_digest
    verify_proposal(proposal)
    before = tree_inventory(source)
    from v3_policy_profile import require_complete
    require_complete(plan, registry)
    if (plan["selected_group_packages"] != proposal["candidate_identity"]["packages"] or
            stable_set_digest(plan) != proposal["stable_set_sha256"] or
            (baseline is None) != (proposal["previous_stable_sha256"] is None) or
            (baseline is not None and sha(tree_inventory(baseline)) != proposal["previous_stable_sha256"])):
        raise PlanningError("canonical result/approved stable-base digest mismatch")
    if operation not in {"promote", "recover"}:
        raise PlanningError("invalid result operation")
    if sha(before) != proposal["result_stable_sha256"]:
        raise PlanningError("unapproved result inventory")
    with tempfile.TemporaryDirectory(prefix="v3-result-") as temp:
        work = pathlib.Path(temp)
        frozen = work / "snapshot" / pathlib.Path(source).name
        shutil.copytree(source, frozen, symlinks=True)
        if tree_inventory(frozen) != before:
            raise PlanningError("result changed while freezing")
        ring = _keyring(metadata_key, metadata_key_sha256, work)
        manifest = _signed_view(frozen, ring)
        input_trees = {pathlib.Path(p): tree_inventory(p) for p in (beta, baseline) if p is not None}
        inputs = {}
        for index, (path, inventory) in enumerate(input_trees.items()):
            target = work / ("input-" + str(index)) / path.name
            shutil.copytree(path, target, symlinks=True)
            if tree_inventory(target) != inventory:
                raise PlanningError("signed planner input changed while freezing")
            inputs[path] = _signed_view(target, ring)
        if operation == "promote":
            from v3_promotion_planner import plan as canonical_plan
            recomputed = canonical_plan(inputs[pathlib.Path(beta)], None if baseline is None else inputs[pathlib.Path(baseline)], registry, plan["promotion_group"])
            if recomputed != plan:
                raise PlanningError("plan changed unrelated groups or signed baseline bytes")
        if ((operation == "promote" and manifest["parent_snapshot"] != plan["stable_base_snapshot_id"]) or
                sorted(manifest["packages"], key=lambda p: p["nevra"]) != sorted(plan["resulting_stable_packages"], key=lambda p: p["nevra"])):
            raise PlanningError("result differs from complete approved plan")
        receipt = _rpm_set_preflight(frozen, manifest, rpm_key, rpm_key_sha256, work / "preflight")
        if tree_inventory(source) != before or tree_inventory(frozen) != before or any(tree_inventory(p) != expected for p, expected in input_trees.items()):
            raise PlanningError("result changed during cryptographic preflight")
    return VerifiedResult(source, before, sha(receipt), sha(plan), TOKEN)


def immutable_url(origin, result_digest, arch):
    parsed = urllib.parse.urlsplit(origin)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in {"", "/"} or parsed.port not in {None, 443}:
        raise PlanningError("independently pinned HTTPS origin required")
    from v3_backend_trust import HEX
    if not HEX.fullmatch(result_digest) or arch not in {"x86_64", "aarch64", "source"}:
        raise PlanningError("invalid immutable view identity")
    return origin.rstrip("/") + "/v3/views/" + result_digest + "/rpm/" + arch


class StagedView:
    def __init__(self, path, result, envelope, descriptor, seal):
        if seal is not TOKEN:
            raise PlanningError("unverified staging")
        self.path, self.result, self.envelope, self.descriptor = path, result, envelope, descriptor
        self.sha256 = result.sha256
        self.envelope_sha256 = digest(envelope)

    def check(self):
        if tree_inventory(self.path / "payload") != self.result.inventory or (self.path / "publication.json").is_symlink() or (self.path / "publication.json").read_bytes() != self.envelope:
            raise PlanningError("immutable staged view changed")


class IsolatedStore:
    def __init__(self, root):
        self.root = require_test_root(root)
        self.views = self.root / "views"
        self.views.mkdir(exist_ok=True)
        if self.views.is_symlink():
            raise PlanningError("unsafe view store")

    def stage(self, result, authorization, signer, *, origin, audit_key_sha256, now, inject=None):
        from v3_backend_evidence import Authorization
        if not isinstance(result, VerifiedResult) or not isinstance(authorization, Authorization) or not isinstance(signer, TestSigner):
            raise PlanningError("verified result, protected approval and isolated signer required")
        payload = authorization.payload
        if (now >= authorization.expiry or payload["request"]["result_stable_sha256"] != result.sha256 or
                signer.key_sha256 in {audit_key_sha256, payload["approval_key_sha256"], payload["witness_key_sha256"]}):
            raise PlanningError("expired/substituted approval or signing role collision")
        if key_identity(signer.public) in {payload["approval_key_identity"], payload["witness_key_identity"]}:
            raise PlanningError("canonical approval/publication key role collision")
        result.check()
        descriptor = {"schema_version": 3, "scope": "v3-immutable-publication-test-only", "publishable": False,
                      "result_stable_sha256": result.sha256, "inventory": result.inventory,
                      "authorization_sha256": authorization.sha256, "request": payload["request"],
                      "preflight_sha256": result.receipt, "signing_key_sha256": signer.key_sha256,
                      "signing_key_identity": key_identity(signer.public),
                      "baseurls": {arch: immutable_url(origin, result.sha256, arch) for arch in ("x86_64", "aarch64", "source")},
                      "issued_at": now, "expires_at": int(authorization.expiry)}
        from ro_repo import validate_schema
        validate_schema(descriptor, "immutable-publication-v3")
        envelope = signer.envelope("publication", descriptor)
        verify_envelope(envelope, role="publication", public_key=signer.public, key_sha256=signer.key_sha256,
                        expected={k: v for k, v in descriptor.items() if k not in {"issued_at", "expires_at"}}, now=now)
        target = self.views / (result.sha256 + "-" + payload["request"]["attempt_id"])
        if target.exists() or target.is_symlink():
            raise PlanningError("immutable view already exists")
        with tempfile.TemporaryDirectory(prefix=".stage-", dir=self.views) as temp:
            stage = pathlib.Path(temp) / "view"
            stage.mkdir()
            shutil.copytree(result.source, stage / "payload", symlinks=True)
            if tree_inventory(stage / "payload") != result.inventory:
                raise PlanningError("staged result differs from approved bytes")
            (stage / "publication.json").write_bytes(envelope)
            result.check()
            if inject:
                inject("before-stage-rename")
            stage.rename(target)
            if inject:
                inject("after-stage-rename")
        return StagedView(target, result, envelope, descriptor, TOKEN)

    def reopen(self, result, authorization, signer, *, now):
        """Recover a rename completed before ledger commit; no new signing."""
        from v3_backend_evidence import Authorization
        if not isinstance(result, VerifiedResult) or not isinstance(authorization, Authorization) or not isinstance(signer, TestSigner) or now >= authorization.expiry:
            raise PlanningError("fresh verified staging retry prerequisites required")
        result.check()
        target = self.views / (result.sha256 + "-" + authorization.payload["request"]["attempt_id"])
        if target.is_symlink() or not target.is_dir() or (target / "publication.json").is_symlink():
            raise PlanningError("missing safe staged view")
        raw = (target / "publication.json").read_bytes()
        from v3_backend_trust import strict_json
        descriptor = strict_json(raw)["payload"]
        from ro_repo import validate_schema, ContractError
        try:
            validate_schema(descriptor, "immutable-publication-v3")
        except ContractError as exc:
            raise PlanningError("invalid staging retry publication schema") from exc
        if (descriptor["authorization_sha256"] != authorization.sha256 or descriptor["inventory"] != result.inventory or
                descriptor["signing_key_sha256"] != signer.key_sha256 or descriptor["signing_key_identity"] != key_identity(signer.public) or
                descriptor["request"] != authorization.payload["request"] or descriptor["result_stable_sha256"] != result.sha256 or
                descriptor["preflight_sha256"] != result.receipt or descriptor["expires_at"] != int(authorization.expiry)):
            raise PlanningError("conflicting staging retry")
        verify_envelope(raw, role="publication", public_key=signer.public, key_sha256=signer.key_sha256,
                        expected={k: v for k, v in descriptor.items() if k not in {"issued_at", "expires_at"}}, now=now)
        view = StagedView(target, result, raw, descriptor, TOKEN)
        view.check()
        return view


class DirectoryReader:
    def __init__(self, view):
        self.view = view

    def read(self, path):
        self.view.check()
        return (self.view.path / "payload" / path).read_bytes()

    def publication(self):
        return (self.view.path / "publication.json").read_bytes()

    def inventory(self):
        return tree_inventory(self.view.path / "payload")

    def advertisement(self):
        return (self.view.path / "stable-advertisement.json").read_bytes()


class HTTPSReader:
    """Read-only bounded HTTPS transport, no redirects or implicit credentials."""
    def __init__(self, origin, result_digest, attempt, *, max_bytes=512 * 1024 * 1024):
        immutable_url(origin, result_digest, "x86_64")
        from v3_authorization import ID
        if not isinstance(attempt, str) or not ID.fullmatch(attempt):
            raise PlanningError("invalid publication identity")
        self.base = origin.rstrip("/") + "/v3/views/" + result_digest + "/"
        self.publication_url = origin.rstrip("/") + "/v3/publications/" + attempt + ".json"
        self.advertisement_url = origin.rstrip("/") + "/v3/stable.json"
        self.max_bytes = max_bytes

    def _get(self, path, url=None):
        if pathlib.PurePosixPath(path).is_absolute() or ".." in pathlib.PurePosixPath(path).parts or "\\" in path:
            raise PlanningError("unsafe remote member")
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                raise PlanningError("remote redirect rejected")
        request = urllib.request.Request(url or self.base + urllib.parse.quote(path, safe="/"), headers={"Cache-Control": "no-cache"})
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=30) as response:
            data = response.read(self.max_bytes + 1)
        if len(data) > self.max_bytes:
            raise PlanningError("remote object exceeds bound")
        return data

    def read(self, path):
        return self._get(path)

    def publication(self):
        return self._get("publication.json", self.publication_url)

    def advertisement(self):
        return self._get("stable.json", self.advertisement_url)


class RemoteVerification:
    def __init__(self, data, seal):
        if seal is not TOKEN:
            raise PlanningError("unverified remote view")
        self.data, self.sha256 = data, sha(data)


def verify_remote(view, reader, deployment, *, now, post_ledger=None,
                  advertisement_key=None, advertisement_key_sha256=None):
    payload = require_attestation(deployment, "deployment")
    view.check()
    if (not payload["issued_at"] <= now < payload["expires_at"] or
            payload.get("result_stable_sha256") != view.sha256 or
            payload.get("publication_sha256") != view.envelope_sha256 or
            not isinstance(payload.get("git_commit"), str) or len(payload["git_commit"]) != 40 or any(c not in "0123456789abcdef" for c in payload["git_commit"]) or
            not isinstance(payload.get("deployment_id"), str) or not payload["deployment_id"]):
        raise PlanningError("authenticated deployment identity required")
    try:
        if hasattr(reader, "check_deployment"):
            reader.check_deployment(payload["git_commit"])
        if reader.publication() != view.envelope:
            raise PlanningError("remote publication envelope differs")
        for item in view.result.inventory:
            if digest(reader.read(item["path"])) != item["sha256"]:
                raise PlanningError("partial/mixed/corrupt remote view")
        if hasattr(reader, "inventory") and reader.inventory() != view.result.inventory:
            raise PlanningError("unexpected remote files")
    except OSError as exc:
        raise PlanningError("incomplete remote view") from exc
    from v3_backend_ledger import Ledger
    if post_ledger is not None and not isinstance(post_ledger, Ledger):
        raise PlanningError("authenticated ledger required for post-verification")
    post = None if post_ledger is None else post_ledger.inspect(view.descriptor["request"]["attempt_id"])
    if post is not None and post["head"]["digest"] != view.sha256:
        raise PlanningError("advertisement differs from post-verified view")
    if post is not None:
        if advertisement_key_sha256 != view.descriptor["signing_key_sha256"]:
            raise PlanningError("independent advertisement key pin required")
        expected = {"result_stable_sha256": view.sha256, "publication_sha256": view.envelope_sha256,
                    "authorization_sha256": view.descriptor["authorization_sha256"],
                    "previous_stable_sha256": view.descriptor["request"]["previous_stable_sha256"],
                    "generation": post["head"]["generation"], "baseurls": view.descriptor["baseurls"],
                    "staged_git_commit": post["attempt"]["proofs"]["REMOTE_VERIFIED"]["verification"]["git_commit"],
                    "publishable": False}
        from v3_backend_trust import strict_json
        try:
            raw = reader.advertisement()
            verify_envelope(raw, role="stable-advertisement", public_key=advertisement_key,
                            key_sha256=advertisement_key_sha256, expected=expected, now=now)
        except (OSError, AttributeError) as exc:
            raise PlanningError("missing remote signed stable advertisement") from exc
    if hasattr(reader, "check_deployment"):
        reader.check_deployment(payload["git_commit"])
    return RemoteVerification({"result_stable_sha256": view.sha256, "publication_sha256": view.envelope_sha256,
                               "deployment_sha256": deployment.sha256, "deployment_id": payload["deployment_id"],
                               "git_commit": payload["git_commit"], "verified_at": now,
                               "phase": "pre" if post is None else "post",
                               "advertised_generation": None if post is None else post["head"]["generation"],
                               "advertisement_checkpoint": None if post is None else post["checkpoint"],
                               "coverage": "all-approved-paths", "publishable": False}, TOKEN)


def production_publish(*args, **kwargs):
    raise PlanningError("production activation BLOCKED; separate reviewed activation PR required")
