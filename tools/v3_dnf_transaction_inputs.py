"""Validate an atomic, architecture-specific V3 DNF transaction input.

Only prepares exact target/baseline arguments. Does not execute DNF or assert
that any package is installable. The DNF runner checks final installed EVRs.
"""
import argparse
import json
import pathlib
import re
import subprocess
from v3_promotion_planner import PlanningError

SAFE = re.compile(r"^[A-Za-z0-9_+.-]+$")
def rpm_header(path):
    if path.is_symlink() or not path.is_file():
        raise PlanningError("unsafe/missing baseline RPM")
    result = subprocess.run(["rpm","-qp","--qf","%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n",str(path)],capture_output=True,text=True)
    if result.returncode != 0:
        raise PlanningError("invalid baseline RPM")
    parts = result.stdout.strip().split("\t")
    if len(parts)!=5 or not all(SAFE.fullmatch(part) for part in parts):
        raise PlanningError("invalid baseline RPM header")
    return parts

def transaction_inputs(matrix,baseline_dir):
    if not isinstance(matrix,dict) or matrix.get("scope")!="offline-v3-dnf-matrix-untrusted" or matrix.get("publishable") is not False or matrix.get("dnf_executed") is not False:
        raise PlanningError("invalid matrix")
    arch=matrix.get("target_arch")
    if arch not in {"x86_64","aarch64"}:
        raise PlanningError("unsupported matrix architecture")
    packages=matrix.get("binary_packages")
    if not isinstance(packages,list) or not packages:
        raise PlanningError("empty transaction matrix")
    names={}
    for item in packages:
        if not isinstance(item,dict) or set(item)!={"name","nevra","filename","arch","epoch","version","release"}:
            raise PlanningError("malformed transaction item")
        name=item["name"]
        if not all(isinstance(item[k],str) and SAFE.fullmatch(item[k]) for k in ["name","filename","arch","epoch","version","release"]):
            raise PlanningError("unsafe RPM transaction item")
        if name in names or item["arch"] not in {arch,"noarch"}:
            raise PlanningError("duplicate name or wrong architecture")
        if item["filename"]!=f'{name}-{item["version"]}-{item["release"]}.{item["arch"]}.rpm' or item["nevra"]!=f'{name}-{item["epoch"]}:{item["version"]}-{item["release"]}.{item["arch"]}':
            raise PlanningError("RPM target identity mismatch")
        names[name]=item
    root=pathlib.Path(baseline_dir)
    if root.is_symlink() or not root.is_dir():
        raise PlanningError("unsafe baseline directory")
    entries=sorted(root.glob("*.rpm"))
    if len(entries)!=len(names):
        raise PlanningError("baseline RPM set must match group exactly")
    baseline={}
    for path in entries:
        name,epoch,ver,rel,rpmarch=rpm_header(path)
        if name not in names or name in baseline or rpmarch not in {arch,"noarch"}:
            raise PlanningError("unknown/duplicate baseline RPM or incompatible architecture")
        if (epoch,ver,rel)==(names[name]["epoch"],names[name]["version"],names[name]["release"]):
            raise PlanningError("baseline is same version as candidate")
        baseline[name]={"filename":path.name,"version":ver,"release":rel,"epoch":epoch,"arch":rpmarch}
    if set(baseline)!=set(names):
        raise PlanningError("baseline missing packages")
    return {"scope":"offline-v3-transaction-inputs","group":matrix["promotion_group"],"target_arch":arch,
            "names":sorted(names),"candidate_targets":[names[n]["nevra"] for n in sorted(names)],
            "expected_candidate_evr":{n:":".join([names[n]["epoch"],names[n]["version"]+"-"+names[n]["release"]]) for n in sorted(names)},
            "expected_baseline_evr":{n:":".join([baseline[n]["epoch"],baseline[n]["version"]+"-"+baseline[n]["release"]]) for n in sorted(names)},
            "baseline_files":[baseline[n]["filename"] for n in sorted(names)],
            "baseline_targets":[f'{n}-{baseline[n]["version"]}-{baseline[n]["release"]}.{baseline[n]["arch"]}' for n in sorted(names)],
            "publishable":False}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--matrix",required=True)
    p.add_argument("--baseline-dir",required=True)
    p.add_argument("--output",required=True)
    a=p.parse_args()
    result=transaction_inputs(json.loads(pathlib.Path(a.matrix).read_text()),a.baseline_dir)
    output=pathlib.Path(a.output)
    if output.exists():
        raise PlanningError("transaction inputs output already exists")
    output.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
if __name__=="__main__":
    main()
