#!/usr/bin/env python3
"""Native Fedora 44 PSOP client acceptance; refuses the user's host runtime."""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "tools"))
from psop_acceptance_support import exercise

if __name__ == "__main__":
    exercise(sys.argv[1], dnf=True, official_upstream="--official-upstream" in sys.argv[2:])
