from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from pydantic import BaseModel, Field

from .executor import FusionSandboxExecutor
from .models import SandboxProfile

logger = logging.getLogger(__name__)

DEFAULT_DEMO_WORKSPACE = os.path.join(os.path.expanduser("~"), ".fusion-executor", "demo")
DEFAULT_LLM_BASE_URL = "http://127.0.0.1:11432"
PROBE_TIMEOUT_SEC = 3.0
GIT_TIMEOUT_SEC = 300
PIP_TIMEOUT_SEC = 900
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")


class DemoEnvError(RuntimeError):
    pass


class DemoAppState(BaseModel):
    name: str
    repo_url: str
    shell_id: str
    started_at: float = Field(default_factory=time.time)
    llm_base_url: str
    llm_probe_ok: bool = False
    llm_probe_detail: str = ""


def _derive_name(repo_url: str) -> str:
    base = repo_url.rstrip("/").split("/")[-1]
    if base.endswith(".git"):
        base = base[:-4]
    if not NAME_RE.match(base):
        raise DemoEnvError(f"cannot derive a valid app name from the repo url ({base!r}); pass name= explicitly")
    return base


def _ssh_fallback(repo_url: str) -> str | None:
    m = re.match(r"^https?://([^/]+)/(.+?)(\.git)?/?$", repo_url)
    if not m:
        return None
    return f"git@{m.group(1)}:{m.group(2)}.git"


def _run_cmd(cmd: list[str], *, cwd: str | None = None, timeout: int, what: str) -> subprocess.CompletedProcess:
    logger.info("demo_env %s: %s (cwd=%s)", what, " ".join(cmd), cwd)
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        raise DemoEnvError(f"{what} timed out ({timeout}s): {e}") from e
    except OSError as e:
        raise DemoEnvError(f"{what} failed to start: {e}") from e
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "").strip()[-500:]
        raise DemoEnvError(f"{what} failed (exit {proc.returncode}): {tail}")
    return proc


def probe_llm_endpoint(base_url: str) -> tuple[bool, str]:
    for path in ("/healthz", "/v1/models"):
        url = base_url.rstrip("/") + path
        try:
            with urllib.request.urlopen(url, timeout=PROBE_TIMEOUT_SEC) as resp:
                if resp.status < 400:
                    return True, f"{path} -> {resp.status}"
        except urllib.error.URLError as e:
            logger.info("demo_env probe %s unreachable: %s", url, e.reason)
        except OSError as e:
            logger.info("demo_env probe %s unreachable: %s", url, e)
    return False, f"{base_url} both /healthz and /v1/models unreachable (informational, does not block startup)"


class DemoEnvRunner:
    """Demo/test environment sandbox runner (issue #64): a guest runs one ai-* app at a time,
    with heavy dependencies (LLM/inference) all routed through the host's fusion-gateway. Pure-Python
    orchestration layer — provision (git/venv/pip) uses its own subprocess (the runner is a trusted
    configuration action), the app process goes through shell_start + SandboxProfile (seatbelt isolation
    + env wiring to the host gateway)."""

    def __init__(
        self,
        *,
        host_llm_base_url: str = DEFAULT_LLM_BASE_URL,
        workspace_dir: str | None = None,
        executor: FusionSandboxExecutor | None = None,
        extra_env: dict[str, str] | None = None,
    ):
        self.llm_base_url = host_llm_base_url
        self.workspace = Path(workspace_dir or DEFAULT_DEMO_WORKSPACE)
        self.extra_env = dict(extra_env or {})
        self.workspace.mkdir(parents=True, exist_ok=True)
        if executor is None:
            # D3-6 4-layer: the app's own start.sh is not in the baseline allowlist — append the basename to
            # the whitelist + register the workspace as a trusted bin dir (start.sh must resolve inside the
            # workspace to be allowed, preventing poisoning).
            executor = FusionSandboxExecutor(
                extra_whitelist=["start.sh"],
                trusted_bin_dirs=[str(self.workspace)],
            )
        self.executor = executor
        logger.info("DemoEnvRunner init workspace=%s llm_base_url=%s", self.workspace, self.llm_base_url)

    @property
    def _state_path(self) -> Path:
        return self.workspace / "state.json"

    def _load_state(self) -> DemoAppState | None:
        if not self._state_path.exists():
            return None
        try:
            return DemoAppState.model_validate(json.loads(self._state_path.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, ValueError) as e:
            logger.warning("demo_env state.json corrupted, ignoring: %s", e)
            return None

    def _save_state(self, state: DemoAppState | None) -> None:
        if state is None:
            self._state_path.unlink(missing_ok=True)
        else:
            tmp = self._state_path.with_suffix(".json.tmp")
            tmp.write_text(state.model_dump_json(indent=2), encoding="utf-8")
            os.replace(tmp, self._state_path)

    def _is_running(self, state: DemoAppState) -> bool:
        try:
            out = self.executor.shell_output(state.shell_id)
        except RuntimeError as e:
            logger.info("demo_env shell_output query failed (treating as stopped): %s", e)
            return False
        return bool(out.running)

    def status(self) -> dict | None:
        state = self._load_state()
        if state is None:
            logger.info("demo_env status: no running app")
            return None
        running = self._is_running(state)
        tail = ""
        if running:
            out = self.executor.shell_output(state.shell_id)
            tail = out.output[-2000:]
        info = state.model_dump()
        info["running"] = running
        info["output_tail"] = tail
        logger.info("demo_env status: app=%s running=%s", state.name, running)
        return info

    def stop(self) -> dict:
        state = self._load_state()
        if state is None:
            logger.info("demo_env stop: no running app (idempotent no-op)")
            return {"ok": True, "stopped": None}
        ok = self.executor.kill_shell(state.shell_id)
        self._save_state(None)
        logger.info("demo_env stop: app=%s shell=%s killed=%s", state.name, state.shell_id, ok)
        return {"ok": bool(ok), "stopped": state.name}

    def _provision(self, repo_url: str, name: str) -> Path:
        app_dir = self.workspace / name
        if (app_dir / ".git").exists():
            _run_cmd(
                ["git", "-C", str(app_dir), "pull", "--ff-only"],
                timeout=GIT_TIMEOUT_SEC,
                what=f"git pull {name}",
            )
        else:
            clone_cmd = ["git", "clone", "--depth", "1", repo_url, str(app_dir)]
            try:
                _run_cmd(clone_cmd, timeout=GIT_TIMEOUT_SEC, what=f"git clone {name} (https)")
            except DemoEnvError:
                ssh_url = _ssh_fallback(repo_url)
                if ssh_url is None or app_dir.exists():
                    raise
                logger.warning("demo_env https clone failed, trying ssh fallback: %s", ssh_url)
                _run_cmd(
                    ["git", "clone", "--depth", "1", ssh_url, str(app_dir)],
                    timeout=GIT_TIMEOUT_SEC,
                    what=f"git clone {name} (ssh)",
                )
        if not app_dir.is_dir():
            raise DemoEnvError(f"app directory missing after clone: {app_dir}")
        venv_dir = self.workspace / ".venv"
        if not (venv_dir / "bin" / "python").exists():
            _run_cmd(
                [sys.executable, "-m", "venv", str(venv_dir)],
                timeout=GIT_TIMEOUT_SEC,
                what="venv create",
            )
        if (app_dir / "pyproject.toml").exists():
            _run_cmd(
                [
                    str(venv_dir / "bin" / "pip"),
                    "install",
                    "-e",
                    str(app_dir),
                ],
                cwd=str(app_dir),
                timeout=PIP_TIMEOUT_SEC,
                what=f"pip install -e {name}",
            )
        start_sh = app_dir / "start.sh"
        if not start_sh.exists():
            raise DemoEnvError(
                f"{name} has no start.sh — cannot auto-start (never silently skipped). "
                f"Start it manually: cd {app_dir} and follow that project's README, or skip this app."
            )
        if not os.access(start_sh, os.X_OK):
            start_sh.chmod(0o755)
            logger.info("demo_env start.sh missing the executable bit, chmod 755 applied: %s", start_sh)
        return app_dir

    def up(self, repo_url: str, *, name: str | None = None) -> dict:
        app_name = name or _derive_name(repo_url)
        if not NAME_RE.match(app_name):
            raise DemoEnvError(f"invalid app name (must match {NAME_RE.pattern}): {app_name!r}")
        existing = self._load_state()
        if existing is not None and self._is_running(existing):
            if existing.name == app_name and existing.repo_url == repo_url:
                logger.info("demo_env up: app=%s already running (idempotent, returning status)", app_name)
                return self.status()
            raise DemoEnvError(
                f"an app is already running: {existing.name} (single app per guest policy). stop it before up-ing a new app."
            )
        if existing is not None and existing.name != app_name:
            self._save_state(None)
            logger.info("demo_env up: cleared stopped old app state %s", existing.name)
        app_dir = self._provision(repo_url, app_name)
        start_sh = app_dir / "start.sh"
        probe_ok, probe_detail = probe_llm_endpoint(self.llm_base_url)
        if not probe_ok:
            logger.warning(
                "demo_env host gateway unreachable (informational, the app UI still starts; inference will fail): %s",
                probe_detail,
            )
        profile = SandboxProfile(network="allow", filesystem="deny_write")
        env_vars = {
            "FUSION_LLM_BASE_URL": self.llm_base_url,
            "FUSION_MLX_URL": self.llm_base_url,
            "VIRTUAL_ENV": str(self.workspace / ".venv"),
            **self.extra_env,
        }
        result = self.executor.shell_start(
            str(start_sh),
            cwd=str(app_dir),
            env_vars=env_vars,
            task_id=f"demo-{app_name}",
            seatbelt=True,
            inherit_env=True,
            sandbox=profile,
            max_idle_sec=0,
        )
        if not result.ok:
            raise DemoEnvError(
                f"start.sh start rejected: blocked_by_security={result.blocked_by_security}"
                f" reason={result.security_reason} error={result.error}"
            )
        state = DemoAppState(
            name=app_name,
            repo_url=repo_url,
            shell_id=result.shell_id,
            llm_base_url=self.llm_base_url,
            llm_probe_ok=probe_ok,
            llm_probe_detail=probe_detail,
        )
        self._save_state(state)
        logger.info("demo_env up: app=%s shell=%s probe_ok=%s", app_name, result.shell_id, probe_ok)
        return self.status()
