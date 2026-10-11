"""Disposable pinned VM execution through QEMU Guest Agent, no host sharing.

Images must contain genuine image-specific acceptance cases at the fixed guest
path below. Missing cases fail closed; the orchestrator never invents GUI PASS.
See https://www.qemu.org/docs/master/interop/qemu-ga-ref.html.
"""
import base64
import pathlib
import platform
import shutil
import socket
import subprocess
import time

from v3_backend_trust import canonical, digest, require_attestation, require_test_root, strict_json
from v3_policy_profile import sha
from v3_promotion_planner import PlanningError
from v3_stable_composer import _sha256

CASES = {"login-session", "plasma-integration", "boot", "reboot", "recovery", "qemu", "ro-store-gui", "upgrade"}


class Agent:
    def __init__(self, path, timeout=30):
        self.path, self.timeout = str(path), timeout

    def call(self, command, arguments=None):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(self.timeout)
            connection.connect(self.path)
            connection.sendall(canonical({"execute": command, "arguments": arguments or {}}) + b"\n")
            data = bytearray()
            while b"\n" not in data:
                chunk = connection.recv(65536)
                if not chunk or len(data) + len(chunk) > 4 * 1024 * 1024:
                    raise PlanningError("invalid/bounded guest response")
                data.extend(chunk)
            result = strict_json(bytes(data).split(b"\n", 1)[0])
            if not isinstance(result, dict) or "error" in result or "return" not in result:
                raise PlanningError("guest agent command failed")
            return result["return"]

    def execute(self, case, timeout):
        if case not in CASES:
            raise PlanningError("unknown VM acceptance case")
        result = self.call("guest-exec", {"path": "/usr/libexec/ro-repo-v3/acceptance", "arg": [case], "capture-output": True})
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status = self.call("guest-exec-status", {"pid": result["pid"]})
            if status.get("exited"):
                if status.get("exitcode") != 0 or status.get("out-truncated") or status.get("err-truncated"):
                    raise PlanningError("real VM acceptance failed/truncated: " + case)
                try:
                    log = base64.b64decode(status.get("out-data", ""), validate=True)
                    report = strict_json(log)
                except ValueError as exc:
                    raise PlanningError("invalid guest acceptance output") from exc
                if (not isinstance(report, dict) or set(report) != {"case", "result", "observations"} or
                        report["case"] != case or report["result"] != "PASS" or not report["observations"]):
                    raise PlanningError("missing real guest observations")
                return log
            time.sleep(0.5)
        raise PlanningError("VM acceptance timeout")


def run(spec, image, qemu, media, root, attestation, *, firmware, now):
    from ro_repo import validate_schema
    validate_schema(spec, "vm-acceptance-v3")
    root = require_test_root(root)
    payload = require_attestation(attestation, "vm-inputs")
    if payload.get("spec_sha256") != sha(spec) or not payload["issued_at"] <= now < payload["expires_at"]:
        raise PlanningError("independent VM image/executor/media pin required")
    if not set(spec["cases"]) <= CASES:
        raise PlanningError("unknown VM case")
    inputs = ((image, "guest.raw", "image_sha256"), (qemu, "qemu", "qemu_sha256"),
              (media, "repo.iso", "media_sha256"), (firmware, "firmware", "firmware_sha256"))
    for file, _, key in inputs:
        path = pathlib.Path(file)
        if path.is_symlink() or not path.is_file() or _sha256(path) != spec[key]:
            raise PlanningError("VM input digest substitution")
    # A raw image has no external qcow2 backing files. Copying pins each input
    # before execution and isolates every guest write from the source image.
    for original, name, key in inputs:
        target = root / name
        if target.exists() or target.is_symlink():
            raise PlanningError("VM output already exists")
        shutil.copyfile(original, target)
        if _sha256(target) != spec[key] or _sha256(original) != spec[key]:
            raise PlanningError("VM input changed while freezing")
    (root / "qemu").chmod(0o700)
    arch = spec["architecture"]
    machine = "q35" if arch == "x86_64" else "virt"
    args = [str(root / "qemu"), "-machine", machine, "-accel", "tcg", "-m", "4096", "-smp", "2",
            "-bios", str(root / "firmware"), "-cpu", "max",
            "-drive", "file=" + str(root / "guest.raw") + ",format=raw,if=virtio",
            "-drive", "file=" + str(root / "repo.iso") + ",format=raw,media=cdrom,readonly=on",
            "-nic", "none", "-display", "none", "-monitor", "none", "-serial", "file:" + str(root / "serial.log"),
            "-chardev", "socket,path=" + str(root / "agent.sock") + ",server=on,wait=off,id=qga",
            "-device", "virtio-serial", "-device", "virtserialport,chardev=qga,name=org.qemu.guest_agent.0"]
    error_log = (root / "qemu-errors.log").open("wb")
    process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=error_log)
    try:
        agent = Agent(root / "agent.sock")
        deadline = time.monotonic() + spec["boot_timeout_seconds"]
        while True:
            if process.poll() is not None:
                raise PlanningError("QEMU terminated before acceptance")
            try:
                agent.call("guest-ping")
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise PlanningError("guest agent boot timeout")
                time.sleep(0.5)
        logs = {}
        for case in spec["cases"]:
            raw = agent.execute(case, spec["case_timeout_seconds"])
            (root / (case + ".json")).write_bytes(raw)
            logs[case] = digest(raw)
        return {"scope": "v3-vm-observation", "publishable": False, "spec_sha256": sha(spec),
                "architecture": arch, "execution": "emulated", "host_architecture": platform.machine(),
                "checks": {case: "PASS" for case in logs}, "logs_sha256": logs,
                "runner_attestation": "UNVERIFIED", "production_activation": "BLOCKED"}
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
        error_log.close()
