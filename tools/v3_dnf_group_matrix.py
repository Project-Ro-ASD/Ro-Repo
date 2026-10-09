"""Derive fail-closed Fedora DNF group targets from a V3 promotion plan.

This is an offline input contract, not a test execution report or approval.
"""
import argparse
import json
import pathlib
from v3_promotion_planner import PlanningError, _parse, _policies

BINARY_ARCHES = {"x86_64", "aarch64"}

def matrix(plan, registry, target_arch):
    if target_arch not in BINARY_ARCHES:
        raise PlanningError("unsupported target architecture")
    if not isinstance(plan, dict) or plan.get("publishable") is not False:
        raise PlanningError("input must be a non-publishable V3 plan")
    policies, owner = _policies(registry)
    group = plan.get("promotion_group")
    if group not in policies:
        raise PlanningError("unregistered group")
    selected = plan.get("selected_group_packages")
    final = plan.get("resulting_stable_packages")
    if not isinstance(selected, list) or not isinstance(final, list) or not selected:
        raise PlanningError("missing packages")
    relevant = {}
    for p in selected:
        name, epoch, ver, rel, arch = _parse(p)
        if owner.get(name) != group:
            raise PlanningError("cross-group package in candidate")
        if arch not in {target_arch, "noarch"}:
            continue
        if name in relevant:
            raise PlanningError("multiple candidate packages for name and architecture")
        relevant[name] = (p, epoch, ver, rel, arch)
    if not relevant:
        raise PlanningError("target architecture has no binary packages")
    all_final = {(p["nevra"],p["architecture"]) for p in final}
    for p, *_ in relevant.values():
        if (p["nevra"], p["architecture"]) not in all_final:
            raise PlanningError("candidate missing from resulting stable set")
    names = set(relevant)
    expected = policies[group]["names"]
    if names != expected:
        raise PlanningError("incomplete package group for target architecture")
    return {
        "scope": "offline-v3-dnf-matrix-untrusted",
        "promotion_group": group,
        "target_arch": target_arch,
        "candidate_sha256": plan.get("candidate_sha256"),
        "binary_packages": [
            {"name": name, "nevra": p["nevra"], "filename": p["filename"],
             "arch": arch, "epoch": epoch, "version": ver, "release": rel}
            for name, (p, epoch, ver, rel, arch) in sorted(relevant.items())
        ],
        "publishable": False,
        "dnf_executed": False
    }

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--plan",required=True)
    parser.add_argument("--registry",required=True)
    parser.add_argument("--arch",required=True)
    parser.add_argument("--output",required=True)
    args=parser.parse_args()
    result=matrix(json.loads(pathlib.Path(args.plan).read_text()),
                  json.loads(pathlib.Path(args.registry).read_text()),args.arch)
    output=pathlib.Path(args.output)
    if output.exists():
        raise PlanningError("matrix output already exists")
    output.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")

if __name__=="__main__":
    main()
