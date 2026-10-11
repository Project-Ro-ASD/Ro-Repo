"""Reproducible unsigned repodata for isolated V3 composition/preview trees."""
import os
import pathlib
import subprocess

from v3_promotion_planner import PlanningError


def generate(repository, source_date_epoch):
    root = pathlib.Path(repository)
    if (root.is_symlink() or not root.is_dir() or type(source_date_epoch) is not int
            or source_date_epoch < 0 or source_date_epoch > 253402300799):
        raise PlanningError("invalid deterministic metadata input")
    if (root / "repodata").exists():
        raise PlanningError("immutable repository metadata already exists")
    for path in root.iterdir():
        if path.is_symlink() or not path.is_file() or path.suffix != ".rpm":
            raise PlanningError("unexpected repository input")
        os.utime(path, (source_date_epoch, source_date_epoch))
    subprocess.run(["createrepo_c", "--quiet", "--workers", "1", "--no-database",
                    "--general-compress-type", "gz", "--checksum", "sha256",
                    "--revision", str(source_date_epoch), "--set-timestamp-to-revision",
                    "--unique-md-filenames", str(root)], check=True, capture_output=True, text=True)
