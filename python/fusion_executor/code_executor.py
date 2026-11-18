"""Sandboxed code-mode execution backend (issue #75).

Implements the harness ``CodeExecutor`` protocol (fusion-harness#50):
``execute(script, namespace) -> Any`` where ``namespace`` maps stub
names to real tool callables. The script (model-written Python) runs
in a sandboxed child process; stub calls round-trip to the parent via
a file bridge and are serviced against the real callables. The child
is spawned through ``FusionSandboxExecutor.run`` — security guard,
seatbelt (network/filesystem), rlimits, RSS watchdog, and timeout all
apply to the whole script run. On failure the pre-exec git snapshot is
rolled back where the backend supports it, and the child traceback is
raised so the harness error loop receives the full traceback payload
as its next model message. harness never executes code itself; this
backend never does prompt work.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shlex
import shutil
import tempfile
import time
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .models import RollbackPolicy, SandboxProfile

logger = logging.getLogger(__name__)

_STUB_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

_CHILD_TIMEOUT_GRACE_SEC = 5.0
_FINAL_POLL_SEC = 2.0
_RESP_POLL_SEC = 0.002
_REQ_POLL_SEC = 0.005

_SHIM_SOURCE = """import json, os, sys, time, traceback

def main():
    bridge, script_path = sys.argv[1], sys.argv[2]
    with open(os.path.join(bridge, "manifest.json")) as f:
        manifest = json.load(f)
    with open(script_path) as f:
        source = f.read()
    counter = [0]

    def make_stub(name):
        def stub(*args, **kwargs):
            counter[0] += 1
            req_id = counter[0]
            req_path = os.path.join(bridge, "req-%d.json" % req_id)
            resp_path = os.path.join(bridge, "resp-%d.json" % req_id)
            tmp = req_path + ".tmp"
            with open(tmp, "w") as f:
                json.dump({"name": name, "args": args, "kwargs": kwargs}, f)
            os.replace(tmp, req_path)
            deadline = time.monotonic() + manifest["call_timeout_sec"]
            while time.monotonic() < deadline:
                if os.path.exists(resp_path):
                    with open(resp_path) as f:
                        resp = json.load(f)
                    os.remove(resp_path)
                    if resp.get("ok"):
                        return resp.get("value")
                    raise RuntimeError("stub call %s failed: %s" % (name, resp.get("error", "")))
                time.sleep(0.002)
            raise RuntimeError("stub call %s timed out waiting for host response" % name)
        return stub

    namespace = {}
    for name in manifest["stubs"]:
        namespace[name] = make_stub(name)
    try:
        exec(compile(source, script_path, "exec"), namespace)
        result = namespace.get("result")
        payload = {"ok": True, "value": result}
    except BaseException:
        payload = {"ok": False, "traceback": traceback.format_exc(),
                   "error": "%s: %s" % (type(sys.exc_info()[1]).__name__, sys.exc_info()[1])}
    tmp = os.path.join(bridge, "final.json.tmp")
    with open(tmp, "w") as f:
        json.dump(payload, f)
    os.replace(tmp, os.path.join(bridge, "final.json"))
    sys.exit(0 if payload["ok"] else 1)

main()
"""


class CodeSandboxProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    timeout_sec: float = Field(default=30.0, description="whole-script wall clock cap (executor watchdog)")
    rss_limit_mb: int = Field(default=2048, description="per-task RSS cap (MB); 0 disables the watchdog")
    max_cpu_sec: int = Field(default=0, description="CPU seconds cap (RLIMIT_CPU); 0 = rely on timeout_sec")
    network: str = Field(default="deny", description="seatbelt network mode: deny (default) | allow")
    filesystem: str = Field(
        default="deny_write",
        description="seatbelt filesystem mode: deny_write (default) | deny | allow",
    )
    fail_if_unavailable: bool = Field(
        default=False,
        description="fail closed when sandbox-exec is unavailable instead of degrading",
    )
    rollback_on_failure: bool = Field(
        default=True,
        description=(
            "roll back the pre-exec git snapshot + sweep untracked files (git clean -fd) "
            "when the script fails or violates the profile. The workspace should be a "
            "dedicated scratch checkout: pre-existing untracked files are burned on rollback."
        ),
    )


class CodeExecutionError(RuntimeError):
    """Script failed, was blocked, or violated the profile.

    ``str(exc)`` carries the child's full traceback so the harness
    error loop can feed it back to the model verbatim as
    ``"CodeExecutionError: <traceback>"``.
    """


class SandboxedCodeExecutor:
    """Harness ``CodeExecutor`` backend: sandboxed subprocess execution
    of model-written scripts with a stub-call bridge to real tools."""

    def __init__(
        self,
        executor: Any,
        *,
        workspace: str | None = None,
        profile: CodeSandboxProfile | None = None,
        python_bin: str = "python3",
    ) -> None:
        if not hasattr(executor, "run"):
            raise TypeError("executor must expose FusionSandboxExecutor-compatible run()")
        self._executor = executor
        self._workspace = os.path.abspath(workspace) if workspace else os.getcwd()
        self._profile = profile or CodeSandboxProfile()
        self._python_bin = python_bin
        os.makedirs(self._workspace, exist_ok=True)
        logger.info(
            "sandboxed code executor ready workspace=%s timeout_sec=%.1f network=%s filesystem=%s rollback=%s",
            self._workspace,
            self._profile.timeout_sec,
            self._profile.network,
            self._profile.filesystem,
            self._profile.rollback_on_failure,
        )

    def execute(self, script: str, namespace: dict) -> Any:
        """Protocol method (fusion-harness#50 CodeExecutor).

        ``namespace`` maps stub names to callables. Returns the
        script's ``result`` variable (JSON round-trip; non-JSON values
        come back as their repr string). Raises ``CodeExecutionError``
        with the full child traceback on failure — the harness loop
        formats it as the next model message.
        """
        if not isinstance(script, str) or not script.strip():
            raise CodeExecutionError("empty script")
        stubs = self._validate_stubs(namespace)
        profile = self._profile
        bridge = Path(tempfile.mkdtemp(prefix="fe-code-bridge-", dir=self._workspace))
        run_id = uuid.uuid4().hex[:8]
        script_path = bridge / f"script-{run_id}.py"
        shim_path = bridge / "shim.py"
        try:
            manifest = {
                "stubs": sorted(stubs),
                "call_timeout_sec": profile.timeout_sec + _CHILD_TIMEOUT_GRACE_SEC,
            }
            (bridge / "manifest.json").write_text(json.dumps(manifest))
            shim_path.write_text(_SHIM_SOURCE)
            script_path.write_text(script)
            cmd = f"{shlex.quote(self._python_bin)} {shlex.quote(str(shim_path))} {shlex.quote(str(bridge))} {shlex.quote(str(script_path))}"
            result, final = self._run_and_service(cmd, bridge, stubs)
            # watchdog/seatbelt verdicts win over whatever the child managed to
            # write before being killed (SIGINT mid-script can still emit a
            # KeyboardInterrupt final.json)
            if getattr(result, "timed_out", False) or getattr(result, "blocked_by_security", False):
                final = self._final_from_result(result)
            else:
                final = final if final is not None else self._final_from_result(result)
            if final.get("ok"):
                logger.info(
                    "code script ok run_id=%s duration=%.3fs stubs=%s",
                    run_id,
                    result.duration_sec,
                    sorted(stubs),
                )
                return final.get("value")
            self._rollback(result)
            tb = final.get("traceback") or final.get("error") or "unknown code-mode failure"
            logger.warning(
                "code script failed run_id=%s exit=%s blocked=%s timed_out=%s rolled_back=%s err=%.200s",
                run_id,
                result.exit_code,
                result.blocked_by_security,
                result.timed_out,
                result.auto_rolled_back,
                tb.replace("\n", " | "),
            )
            raise CodeExecutionError(tb)
        finally:
            shutil.rmtree(bridge, ignore_errors=True)

    def _validate_stubs(self, namespace: dict) -> dict[str, Callable]:
        stubs: dict[str, Callable] = {}
        for name, fn in (namespace or {}).items():
            if not isinstance(name, str) or not _STUB_NAME_RE.match(name):
                raise CodeExecutionError(f"invalid stub name {name!r} (must be a Python identifier)")
            if not callable(fn):
                raise CodeExecutionError(f"stub {name!r} is not callable")
            stubs[name] = fn
        return stubs

    def _run_and_service(self, cmd: str, bridge: Path, stubs: dict) -> tuple[Any, dict | None]:
        seatbelt = SandboxProfile(
            network=self._profile.network,
            filesystem=self._profile.filesystem,
            fail_if_unavailable=self._profile.fail_if_unavailable,
        )
        policy = RollbackPolicy(file_damage_check=True) if self._profile.rollback_on_failure else None
        with ThreadPoolExecutor(max_workers=1) as pool:
            fut = pool.submit(
                self._executor.run,
                cmd,
                cwd=self._workspace,
                timeout_sec=self._profile.timeout_sec,
                rss_limit_mb=self._profile.rss_limit_mb,
                max_cpu_sec=self._profile.max_cpu_sec,
                seatbelt=True,
                sandbox=seatbelt,
                auto_rollback=policy,
            )
            self._service_bridge(bridge, stubs, fut)
            result = fut.result()
        final = self._read_final(bridge)
        return result, final

    def _service_bridge(self, bridge: Path, stubs: dict, fut: Any) -> None:
        serviced: set[str] = set()
        deadline = time.monotonic() + self._profile.timeout_sec + _CHILD_TIMEOUT_GRACE_SEC
        while time.monotonic() < deadline:
            if fut.done():
                break
            for req_path in sorted(bridge.glob("req-*.json")):
                key = req_path.name
                if key in serviced:
                    continue
                serviced.add(key)
                self._service_request(req_path, stubs)
            time.sleep(_REQ_POLL_SEC)
        # child may still emit one last request right before exiting; drain once
        for req_path in sorted(bridge.glob("req-*.json")):
            if req_path.name not in serviced:
                self._service_request(req_path, stubs)

    def _service_request(self, req_path: Path, stubs: dict) -> None:
        try:
            req = json.loads(req_path.read_text())
        except (OSError, ValueError) as exc:
            logger.warning("bridge request unreadable %s: %s", req_path.name, exc)
            return
        resp_id = req_path.name[len("req-") : -len(".json")]
        resp_path = req_path.parent / f"resp-{resp_id}.json"
        name = req.get("name", "")
        try:
            if name not in stubs:
                raise RuntimeError(f"unknown stub {name!r} (not in this turn's namespace)")
            value = stubs[name](*req.get("args", []), **req.get("kwargs", {}))
            try:
                payload = {"ok": True, "value": value}
                json.dumps(value)
            except (TypeError, ValueError):
                payload = {"ok": True, "value": repr(value)}
        except BaseException as exc:
            logger.info("stub call failed name=%s err=%s", name, exc)
            payload = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        tmp = resp_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload))
        os.replace(tmp, resp_path)
        logger.debug("bridge serviced req=%s name=%s ok=%s", resp_id, name, payload.get("ok"))

    def _read_final(self, bridge: Path) -> dict | None:
        final_path = bridge / "final.json"
        deadline = time.monotonic() + _FINAL_POLL_SEC
        while time.monotonic() < deadline:
            if final_path.exists():
                try:
                    return json.loads(final_path.read_text())
                except ValueError as exc:
                    logger.warning("final.json unreadable: %s", exc)
                    return None
            time.sleep(_RESP_POLL_SEC)
        logger.warning("final.json missing after run completion")
        return None

    def _final_from_result(self, result: Any) -> dict:
        if getattr(result, "blocked_by_security", False):
            reason = getattr(result, "security_reason", "") or "blocked by security policy"
            tb = (
                "Traceback (most recent call last):\n"
                f"  [sandbox] script blocked before execution\n"
                f"SecurityViolation: {reason}"
            )
            return {"ok": False, "error": f"SecurityViolation: {reason}", "traceback": tb}
        if getattr(result, "timed_out", False):
            return {
                "ok": False,
                "error": "TimeoutError: script exceeded the sandbox time limit",
                "traceback": (
                    "Traceback (most recent call last):\n"
                    "  [sandbox] killed by watchdog\n"
                    "TimeoutError: script exceeded the sandbox time limit"
                ),
            }
        tail = (getattr(result, "stdout", "") or getattr(result, "stderr", "")).strip()[-2000:]
        return {
            "ok": False,
            "error": f"RuntimeError: child exited with code {result.exit_code}",
            "traceback": tail or f"RuntimeError: child exited with code {result.exit_code}",
        }

    def _rollback(self, result: Any) -> None:
        if not self._profile.rollback_on_failure:
            return
        if getattr(result, "auto_rolled_back", False):
            logger.info("code script failure already auto-rolled-back snapshot=%s", result.snapshot_id)
        else:
            snapshot_id = getattr(result, "snapshot_id", None)
            if snapshot_id:
                try:
                    ok = self._executor.rollback(snapshot_id, cwd=self._workspace)
                except Exception as exc:
                    logger.warning("rollback attempt failed: %s", exc)
                    ok = False
                logger.info("code script rollback applied snapshot=%s ok=%s", snapshot_id, ok)
            else:
                logger.info("no snapshot available for rollback (side effects may remain in non-git workspace)")
        self._clean_untracked()

    def _clean_untracked(self) -> None:
        # git reset --hard leaves untracked files a hallucinated script created;
        # code-mode workspaces are dedicated scratch checkouts (profile doc), so
        # git clean -fd is the side-effect sweep. Non-git workspace: visible warning.
        clean = self._executor.run("git clean -fd", cwd=self._workspace, timeout_sec=15.0)
        if clean.exit_code != 0:
            logger.warning(
                "git clean failed (workspace may not be a git repo; untracked side effects remain) exit=%s out=%.200s",
                clean.exit_code,
                (clean.stdout or clean.stderr or "").strip(),
            )
            return
        logger.info("git clean swept untracked script side effects workspace=%s", self._workspace)


__all__ = ["CodeExecutionError", "CodeSandboxProfile", "SandboxedCodeExecutor"]
