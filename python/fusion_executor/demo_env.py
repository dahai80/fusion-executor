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
        raise DemoEnvError(f"无法从 repo url 推导合法 app 名 ({base!r}); 请用 name= 显式指定")
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
        raise DemoEnvError(f"{what} 超时 ({timeout}s): {e}") from e
    except OSError as e:
        raise DemoEnvError(f"{what} 启动失败: {e}") from e
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "").strip()[-500:]
        raise DemoEnvError(f"{what} 失败 (exit {proc.returncode}): {tail}")
    return proc


def probe_llm_endpoint(base_url: str) -> tuple[bool, str]:
    for path in ("/healthz", "/v1/models"):
        url = base_url.rstrip("/") + path
        try:
            with urllib.request.urlopen(url, timeout=PROBE_TIMEOUT_SEC) as resp:
                if resp.status < 400:
                    return True, f"{path} -> {resp.status}"
        except urllib.error.URLError as e:
            logger.info("demo_env probe %s 不可达: %s", url, e.reason)
        except OSError as e:
            logger.info("demo_env probe %s 不可达: %s", url, e)
    return False, f"{base_url} /healthz 与 /v1/models 均不可达 (信息性, 不阻断启动)"


class DemoEnvRunner:
    """Demo/test 环境沙箱 runner (issue #64): guest 一次跑一个 ai-* app,
    重依赖 (LLM/推理) 全部走宿主机 fusion-gateway。纯 Python 编排层 —
    provision (git/venv/pip) 走自身 subprocess (runner 是受信配置动作),
    app 进程走 shell_start + SandboxProfile (seatbelt 隔离 + env 接线宿主网关)。"""

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
            # D3-6 4-layer: app 自带 start.sh 不在基线白名单 — 追加 basename 扩展 + 登记
            # workspace 为可信 bin 目录 (start.sh resolve 落在 workspace 内才放行, 防投毒)。
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
            logger.warning("demo_env state.json 损坏, 忽略: %s", e)
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
            logger.info("demo_env shell_output 查询失败 (视为已停): %s", e)
            return False
        return bool(out.running)

    def status(self) -> dict | None:
        state = self._load_state()
        if state is None:
            logger.info("demo_env status: 无运行中 app")
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
            logger.info("demo_env stop: 无运行中 app (幂等 no-op)")
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
                logger.warning("demo_env https clone 失败, 尝试 ssh fallback: %s", ssh_url)
                _run_cmd(
                    ["git", "clone", "--depth", "1", ssh_url, str(app_dir)],
                    timeout=GIT_TIMEOUT_SEC,
                    what=f"git clone {name} (ssh)",
                )
        if not app_dir.is_dir():
            raise DemoEnvError(f"clone 后 app 目录不存在: {app_dir}")
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
                f"{name} 无 start.sh — 无法自动启动 (不静默跳过)。"
                f"请手动启动: cd {app_dir} 后按该项目 README 启动, 或跳过该 app。"
            )
        if not os.access(start_sh, os.X_OK):
            start_sh.chmod(0o755)
            logger.info("demo_env start.sh 无执行位, 已 chmod 755: %s", start_sh)
        return app_dir

    def up(self, repo_url: str, *, name: str | None = None) -> dict:
        app_name = name or _derive_name(repo_url)
        if not NAME_RE.match(app_name):
            raise DemoEnvError(f"app 名非法 (须 {NAME_RE.pattern}): {app_name!r}")
        existing = self._load_state()
        if existing is not None and self._is_running(existing):
            if existing.name == app_name and existing.repo_url == repo_url:
                logger.info("demo_env up: app=%s 已在运行 (幂等, 直接返回状态)", app_name)
                return self.status()
            raise DemoEnvError(f"已有一个 app 在运行: {existing.name} (单 app per guest 策略)。先 stop 再 up 新 app。")
        if existing is not None and existing.name != app_name:
            self._save_state(None)
            logger.info("demo_env up: 清理已停的旧 app 状态 %s", existing.name)
        app_dir = self._provision(repo_url, app_name)
        start_sh = app_dir / "start.sh"
        probe_ok, probe_detail = probe_llm_endpoint(self.llm_base_url)
        if not probe_ok:
            logger.warning("demo_env 宿主网关不可达 (信息性, app UI 仍启动; 推理会失败): %s", probe_detail)
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
                f"start.sh 启动被拒: blocked_by_security={result.blocked_by_security}"
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
