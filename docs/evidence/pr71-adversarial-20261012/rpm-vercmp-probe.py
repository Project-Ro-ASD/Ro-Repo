"""Deterministic native RPM differential observation; no production authority."""
import json
import pathlib
import random
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
from v3_promotion_planner import version_compare

rng = random.Random(71)
# '-' is an EVR version/release delimiter for Lua rpm.vercmp and is rejected
# inside a version/release segment by the planner's _parse grammar.
alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.~^_+"
cases = [("1.9", "1.10"), ("1~rc", "1"), ("1", "1^git"),
         ("1^git", "1.1"), ("1a", "1.1"), ("1.01", "1.1")]
while len(cases) < 1500:
    cases.append(tuple("".join(rng.choice(alphabet) for _ in range(rng.randint(1, 24))) for _ in range(2)))
differences = []
for offset in range(0, len(cases), 100):
    batch = cases[offset:offset + 100]
    expressions = ["tostring(rpm.vercmp(" + json.dumps(a) + "," + json.dumps(b) + "))" for a, b in batch]
    macro = '%{lua:print(table.concat({' + ",".join(expressions) + '},","))}'
    observed = subprocess.check_output(["rpm", "--eval", macro], text=True).strip().split(",")
    assert len(observed) == len(batch)
    for (a, b), value in zip(batch, observed):
        actual, planned = int(value), version_compare(a, b)
        if actual != planned:
            differences.append({"a": a, "b": b, "rpm": actual, "planner": planned})
print(json.dumps({"scope": "native-rpm-differential-observation-test-only", "seed": 71,
                  "cases": len(cases), "rpm_version": subprocess.check_output(["rpm", "--version"], text=True).strip(),
                  "differences": differences, "production_authority": False}, sort_keys=True))
assert not differences
