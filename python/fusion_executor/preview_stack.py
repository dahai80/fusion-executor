from __future__ import annotations

import json
import logging
import os
import re
import shutil
import socket
import subprocess
import threading
import time
import urllib.request
from collections.abc import Callable
from pathlib import Path

from pydantic import BaseModel, Field

from fusion_executor.demo_env import _ssh_fallback

logger = logging.getLogger(__name__)

DEFAULT_PREVIEW_WORKSPACE = Path.home() / ".fusion-executor" / "preview"
GIT_TIMEOUT_SEC = 300.0
COMPOSE_TIMEOUT_SEC = 1800.0
HEALTH_POLL_INTERVAL_SEC = 2.0
NAME_RE = r"^[A-Za-z0-9][A-Za-z0-9_-]*$"


class PreviewError(RuntimeError):
    pass


class PreviewProject(BaseModel):
    name: str
    repo_url: str
    compose_dir: str = "."
    compose_files: list[str] = Field(min_length=1)
    profile: str | None = None
    host_port: int = Field(ge=1024, le=65535)
    service_port: int = Field(ge=1, le=65535)
    health_path: str = "/healthz"
    health_timeout_sec: float = 300.0
    seed_service: str | None = None
    seed_cmd: str | None = None
    ttl_min: int = Field(default=60, ge=1)

    def model_validate_name(self) -> None:
        if not re.match(NAME_RE, self.name):
            raise PreviewError(f"invalid preview name: {self.name!r} (must match {NAME_RE})")


class PreviewStackRunner:
    def __init__(
        self,
        workspace_dir: str | Path = DEFAULT_PREVIEW_WORKSPACE,
        notify: Callable[[dict], None] | None = None,
        extra_env: dict[str, str] | None = None,
    ) -> None:
        self.workspace = Path(workspace_dir).expanduser()
        self.apps_dir = self.workspace / "apps"
        self.notify = notify
        self.extra_env = dict(extra_env or {})
        self._timers: dict[str, threading.Timer] = {}
        self._lock = threading.Lock()
        self.workspace.mkdir(parents=True, exist_ok=True)
        logger.info("PreviewStackRunner initialized workspace=%s", self.workspace)

    def _ensure_docker(self) -> None:
        if shutil.which("docker") is None:
            raise PreviewError("docker not found on PATH — preview stacks require docker compose")

    def _state_path(self, name: str) -> Path:
        return self.workspace / f"{name}.json"

    def _load_state(self, name: str) -> dict | None:
        p = self.state_path_safe(name)
        if p is None or not p.exists():
            return None
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("preview state unreadable name=%s err=%s", name, e)
            return None

    def state_path_safe(self, name: str) -> Path | None:
        if not re.fullmatch(NAME_RE, name):
            return None
        return self._state_path(name)

    def _save_state(self, name: str, state: dict | None) -> None:
        p = self._state_path(name)
        if state is None:
            p.unlink(missing_ok=True)
            return
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, p)

    def _run(
        self, cmd: list[str], *, cwd: Path | None, timeout: float, what: str, extra_env: dict[str, str] | None = None
    ) -> str:
        logger.info("preview cmd what=%s cmd=%s cwd=%s", what, " ".join(cmd), cwd)
        try:
            env = {**os.environ, **self.extra_env, **(extra_env or {})}
            r = subprocess.run(
                cmd,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
            )
        except subprocess.TimeoutExpired as e:
            raise PreviewError(f"{what} timed out after {timeout}s") from e
        if r.returncode != 0:
            tail = (r.stderr or r.stdout or "").strip()[-800:]
            raise PreviewError(f"{what} failed (exit {r.returncode}): {tail}")
        return r.stdout

    def _compose_base(self, proj: PreviewProject, repo_dir: Path) -> list[str]:
        cdir = repo_dir / proj.compose_dir
        cmd = ["docker", "compose", "-p", proj.name]
        for f in proj.compose_files:
            cmd += ["-f", str(cdir / f)]
        if proj.profile:
            cmd += ["--profile", proj.profile]
        return cmd

    def _probe_port_free(self, host_port: int) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        try:
            s.bind(("127.0.0.1", host_port))
        except OSError as e:
            raise PreviewError(f"host port {host_port} already in use — pick another preview port") from e
        finally:
            s.close()

    def _wait_healthy(self, proj: PreviewProject) -> tuple[bool, str]:
        url = f"http://127.0.0.1:{proj.host_port}{proj.health_path}"
        deadline = time.monotonic() + proj.health_timeout_sec
        last = ""
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(url, timeout=3.0) as resp:
                    if resp.status == 200:
                        return True, f"200 {url}"
                    last = f"status {resp.status}"
            except Exception as e:
                last = f"{type(e).__name__}: {e}"
            time.sleep(HEALTH_POLL_INTERVAL_SEC)
        return False, f"health check timeout after {proj.health_timeout_sec}s ({last}) — url {url}"

    def _seed(self, proj: PreviewProject, repo_dir: Path) -> str:
        if not proj.seed_cmd:
            return "skipped (no seed_cmd configured)"
        if not proj.seed_service:
            raise PreviewError(
                "seed_cmd set but seed_service missing — synthetic data injection needs a target service"
            )
        cmd = [*self._compose_base(proj, repo_dir), "exec", "-T", proj.seed_service, "sh", "-c", proj.seed_cmd]
        self._run(cmd, cwd=repo_dir, timeout=COMPOSE_TIMEOUT_SEC, what="synthetic data seed")
        return f"seeded via {proj.seed_service}: {proj.seed_cmd}"

    def _expire(self, name: str) -> None:
        logger.info("preview TTL expired, tearing down name=%s", name)
        try:
            self.teardown(name)
        except PreviewError as e:
            logger.error("TTL teardown failed name=%s err=%s", name, e)
        if self.notify:
            self._safe_notify({"name": name, "event": "ttl_expired"})

    def _safe_notify(self, payload: dict) -> None:
        try:
            self.notify(payload)
        except Exception as e:
            logger.warning("notify hook failed err=%s", e)

    def _arm_ttl(self, name: str, ttl_min: int) -> None:
        with self._lock:
            old = self._timers.pop(name, None)
            if old:
                old.cancel()
            t = threading.Timer(ttl_min * 60.0, self._expire, args=(name,))
            t.daemon = True
            t.start()
            self._timers[name] = t

    def up(self, proj: PreviewProject) -> dict:
        self._ensure_docker()
        proj.model_validate_name()
        st = self._load_state(proj.name)
        if st and st.get("healthy"):
            logger.info("preview already up, idempotent return name=%s", proj.name)
            return st
        if st:
            logger.info("stale preview state found, re-uping name=%s", proj.name)
            self.teardown(proj.name)
        self._probe_port_free(proj.host_port)
        repo_dir = self.apps_dir / proj.name
        self._provision(proj.repo_url, proj.name, repo_dir)
        cmd = [*self._compose_base(proj, repo_dir), "up", "-d", "--build"]
        self._run(
            cmd,
            cwd=repo_dir,
            timeout=COMPOSE_TIMEOUT_SEC,
            what="docker compose up",
            extra_env={"PREVIEW_HOST_PORT": str(proj.host_port), "PREVIEW_SERVICE_PORT": str(proj.service_port)},
        )
        healthy, detail = self._wait_healthy(proj)
        seed_detail = "skipped (unhealthy stack)"
        if healthy:
            seed_detail = self._seed(proj, repo_dir)
        state = {
            "name": proj.name,
            "repo_url": proj.repo_url,
            "url": f"http://127.0.0.1:{proj.host_port}/",
            "host_port": proj.host_port,
            "health_path": proj.health_path,
            "compose_dir": proj.compose_dir,
            "compose_files": proj.compose_files,
            "profile": proj.profile,
            "healthy": healthy,
            "health_detail": detail,
            "seed_detail": seed_detail,
            "ttl_min": proj.ttl_min,
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        }
        self._save_state(proj.name, state)
        if healthy:
            self._arm_ttl(proj.name, proj.ttl_min)
            logger.info("preview stack healthy name=%s url=%s", proj.name, state["url"])
        else:
            logger.error("preview stack unhealthy after up, tearing down name=%s detail=%s", proj.name, detail)
            self.teardown(proj.name)
        if self.notify:
            self._safe_notify({**state, "event": "ready" if healthy else "unhealthy"})
        return state

    def _provision(self, repo_url: str, name: str, repo_dir: Path) -> None:
        if (repo_dir / ".git").exists():
            self._run(["git", "pull", "--ff-only"], cwd=repo_dir, timeout=GIT_TIMEOUT_SEC, what="git pull")
            return
        repo_dir.parent.mkdir(parents=True, exist_ok=True)
        clone_url = repo_url
        if repo_url.startswith("https://") and "@" not in repo_url:
            alt = _ssh_fallback(repo_url)
            try:
                self._run(
                    ["git", "clone", "--depth", "1", clone_url, str(repo_dir)],
                    cwd=None,
                    timeout=GIT_TIMEOUT_SEC,
                    what="git clone",
                )
                return
            except PreviewError:
                if alt is None:
                    raise
                logger.warning("https clone failed, falling back to ssh url=%s", alt)
                clone_url = alt
        self._run(
            ["git", "clone", "--depth", "1", clone_url, str(repo_dir)],
            cwd=None,
            timeout=GIT_TIMEOUT_SEC,
            what="git clone",
        )
        if not (repo_dir / "docker-compose.yml").exists() and not any(repo_dir.rglob("docker-compose*.y*ml")):
            raise PreviewError(f"no docker-compose file found in cloned repo {repo_dir}")

    def status(self, name: str) -> dict | None:
        st = self._load_state(name)
        if st is None:
            return None
        ok, detail = self._wait_healthy_quick(st["host_port"], st.get("health_path", "/healthz"))
        st["healthy"] = ok
        st["health_detail"] = detail
        return st

    def _wait_healthy_quick(self, host_port: int, health_path: str) -> tuple[bool, str]:
        url = f"http://127.0.0.1:{host_port}{health_path}"
        try:
            with urllib.request.urlopen(url, timeout=3.0) as resp:
                return resp.status == 200, f"200 {url}"
        except Exception as e:
            return False, f"{type(e).__name__}: {e}"

    def status_all(self) -> list[dict]:
        out = []
        for p in sorted(self.workspace.glob("*.json")):
            st = self._load_state(p.stem)
            if st:
                out.append(st)
        return out

    def teardown(self, name: str) -> dict:
        st = self._load_state(name)
        if st is None:
            return {"ok": True, "torn_down": None}
        repo_dir = self.apps_dir / name
        cmd = ["docker", "compose", "-p", name]
        for f in st.get("compose_files") or ["docker-compose.yml"]:
            cmd += ["-f", str(repo_dir / st.get("compose_dir", ".") / f)]
        if st.get("profile"):
            cmd += ["--profile", st["profile"]]
        cmd += ["down", "-v", "--remove-orphans"]
        self._run(cmd, cwd=repo_dir, timeout=COMPOSE_TIMEOUT_SEC, what="docker compose down")
        with self._lock:
            t = self._timers.pop(name, None)
            if t:
                t.cancel()
        self._save_state(name, None)
        logger.info("preview stack torn down name=%s", name)
        return {"ok": True, "torn_down": name}

    def teardown_all(self) -> list[str]:
        names = [p.stem for p in sorted(self.workspace.glob("*.json"))]
        out = []
        for n in names:
            if self.teardown(n)["torn_down"] is not None:
                out.append(n)
        return out

    def preview_url(self, name: str) -> str:
        st = self._load_state(name)
        if st is None:
            raise PreviewError(f"no preview state for {name!r} — up first")
        return st["url"]
