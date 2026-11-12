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
import uuid
from pathlib import Path

from pydantic import BaseModel, Field

from fusion_executor.preview_stack import PreviewError, PreviewProject, PreviewStackRunner

logger = logging.getLogger(__name__)

DEFAULT_SESSIONS_WORKSPACE = Path.home() / ".fusion-executor" / "demo-sessions"
DEMO_PORT_RANGE = (11600, 11669)
DEMO_LLM_BASE_URL = "http://127.0.0.1:11432"
IOS_TTL_MIN = 15
DISPATCH_INTERVAL_SEC = 5.0
SIMCTL_TIMEOUT_SEC = 300.0


class DemoSessionError(RuntimeError):
    pass


class DemoSessionConfig(BaseModel):
    sample_slug: str
    kind: str = "web"
    repo_url: str = ""
    compose_dir: str = "."
    compose_files: list[str] = Field(default_factory=lambda: ["docker-compose.demo.yml"])
    profile: str | None = None
    service_port: int = 80
    health_path: str = "/healthz"
    health_timeout_sec: float = 120.0
    scenarios: dict[str, str] = Field(default_factory=dict)
    llm_api_key: str = ""
    exec_service: str = "web"
    ttl_min: int = 30
    device_name: str = "iPhone 18 Pro"
    app_path: str = ""
    bundle_id: str = ""

    def validate_config(self) -> None:
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", self.sample_slug):
            raise DemoSessionError(f"invalid sample_slug: {self.sample_slug!r}")
        if self.kind not in ("web", "ios"):
            raise DemoSessionError(
                f"unsupported kind: {self.kind!r} (web|ios; android emulator container deferred, see follow-up issue)"
            )
        if self.kind == "web" and not self.repo_url:
            raise DemoSessionError("web session requires repo_url")
        if self.kind == "ios" and not self.bundle_id:
            raise DemoSessionError("ios session requires bundle_id")


class DemoSessionManager:
    def __init__(
        self,
        workspace_dir: str | Path = DEFAULT_SESSIONS_WORKSPACE,
        max_web: int = 8,
        max_ios: int = 2,
    ) -> None:
        self.workspace = Path(workspace_dir).expanduser()
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.max_web = max_web
        self.max_ios = max_ios
        self._timers: dict[str, threading.Timer] = {}
        self._lock = threading.RLock()
        self._stacks = PreviewStackRunner(workspace_dir=self.workspace / "stacks")
        self._dispatcher = threading.Thread(target=self._dispatch_loop, daemon=True)
        self._dispatcher.start()
        logger.info(
            "DemoSessionManager initialized workspace=%s max_web=%d max_ios=%d", self.workspace, max_web, max_ios
        )

    def _session_path(self, session_id: str) -> Path:
        return self.workspace / f"{session_id}.json"

    def _load(self, session_id: str) -> dict | None:
        p = self._session_path(session_id)
        if not p.exists():
            return None
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("session state unreadable id=%s err=%s", session_id, e)
            return None

    def _save(self, session_id: str, state: dict | None) -> None:
        p = self._session_path(session_id)
        if state is None:
            p.unlink(missing_ok=True)
            return
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, p)

    def _active_ids(self) -> list[str]:
        return sorted(p.stem for p in self.workspace.glob("*.json") if not p.stem.startswith("queue"))

    def _count_kind(self, kind: str) -> int:
        return sum(1 for sid in self._active_ids() if (self._load(sid) or {}).get("kind") == kind)

    def _free_port(self) -> int:
        lo, hi = DEMO_PORT_RANGE
        for port in range(lo, hi + 1):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.bind(("127.0.0.1", port))
                s.close()
                return port
            except OSError:
                s.close()
        raise DemoSessionError(f"demo port range {lo}-{hi} exhausted")

    def start_session(self, cfg: DemoSessionConfig) -> dict:
        cfg.validate_config()
        cap = self.max_web if cfg.kind == "web" else self.max_ios
        with self._lock:
            active = self._count_kind(cfg.kind)
            if active >= cap:
                position = self._enqueue(cfg)
                eta = position * (cfg.ttl_min / 2.0)
                logger.info("demo session queued kind=%s slug=%s position=%d", cfg.kind, cfg.sample_slug, position)
                return {"queued": True, "position": position, "eta_min": round(eta, 1)}
            return self._start_now(cfg)

    def _start_now(self, cfg: DemoSessionConfig) -> dict:
        session_id = f"{cfg.sample_slug}-{uuid.uuid4().hex[:8]}"
        if cfg.kind == "web":
            return self._start_web(session_id, cfg)
        return self._start_ios(session_id, cfg)

    def _start_web(self, session_id: str, cfg: DemoSessionConfig) -> dict:
        host_port = self._free_port()
        proj = PreviewProject(
            name=session_id,
            repo_url=cfg.repo_url,
            compose_dir=cfg.compose_dir,
            compose_files=cfg.compose_files,
            profile=cfg.profile,
            host_port=host_port,
            service_port=cfg.service_port,
            health_path=cfg.health_path,
            health_timeout_sec=cfg.health_timeout_sec,
            ttl_min=cfg.ttl_min,
        )
        llm_env = (
            {"FUSION_LLM_API_KEY": cfg.llm_api_key, "FUSION_LLM_BASE_URL": DEMO_LLM_BASE_URL}
            if cfg.llm_api_key
            else {"FUSION_LLM_BASE_URL": DEMO_LLM_BASE_URL}
        )
        try:
            st = self._stacks.up(proj, extra_env=llm_env)
        except PreviewError as e:
            raise DemoSessionError(f"demo stack up failed: {e}") from e
        state = {
            "session_id": session_id,
            "sample_slug": cfg.sample_slug,
            "kind": "web",
            "url": st["url"],
            "host_port": host_port,
            "healthy": st["healthy"],
            "health_path": cfg.health_path,
            "compose_dir": cfg.compose_dir,
            "compose_files": cfg.compose_files,
            "profile": cfg.profile,
            "exec_service": cfg.exec_service,
            "scenarios": cfg.scenarios,
            "llm_base_url": DEMO_LLM_BASE_URL,
            "llm_key_wired": bool(cfg.llm_api_key),
            "ttl_min": cfg.ttl_min,
            "started_at": st["started_at"],
        }
        self._save(session_id, state)
        self._arm_ttl(session_id, cfg.ttl_min)
        logger.info("demo web session up id=%s url=%s ttl=%dmin", session_id, st["url"], cfg.ttl_min)
        return {**state, "queued": False}

    def _run_simctl(self, args: list[str], what: str) -> str:
        logger.info("simctl what=%s args=%s", what, " ".join(args))
        try:
            r = subprocess.run(["xcrun", "simctl", *args], capture_output=True, text=True, timeout=SIMCTL_TIMEOUT_SEC)
        except subprocess.TimeoutExpired as e:
            raise DemoSessionError(f"{what} timed out after {SIMCTL_TIMEOUT_SEC}s") from e
        if r.returncode != 0:
            raise DemoSessionError(f"{what} failed (exit {r.returncode}): {(r.stderr or r.stdout).strip()[-500:]}")
        return r.stdout

    def _pick_device(self, device_name: str) -> str:
        out = self._run_simctl(["list", "devices", "available"], what="list devices")
        for line in out.splitlines():
            if device_name in line and "(Shutdown)" in line:
                m = re.search(r"\(([0-9A-F-]{36})\)", line)
                if m:
                    return m.group(1)
        raise DemoSessionError(f"no available shutdown simulator matching {device_name!r}")

    def _start_ios(self, session_id: str, cfg: DemoSessionConfig) -> dict:
        udid = self._pick_device(cfg.device_name)
        self._run_simctl(["boot", udid], what="boot simulator")
        deadline = time.monotonic() + 120.0
        booted = False
        while time.monotonic() < deadline:
            out = self._run_simctl(["list", "devices"], what="wait boot")
            if f"{udid}" in out and "(Booted)" in out:
                booted = True
                break
            time.sleep(2.0)
        if not booted:
            self._run_simctl(["shutdown", udid], what="shutdown after boot timeout")
            raise DemoSessionError(f"simulator {udid} failed to boot within 120s")
        if cfg.app_path:
            self._run_simctl(["install", udid, cfg.app_path], what="install app")
        self._run_simctl(["launch", udid, cfg.bundle_id], what="launch app")
        state = {
            "session_id": session_id,
            "sample_slug": cfg.sample_slug,
            "kind": "ios",
            "udid": udid,
            "device_name": cfg.device_name,
            "bundle_id": cfg.bundle_id,
            "healthy": True,
            "llm_base_url": DEMO_LLM_BASE_URL,
            "llm_key_wired": bool(cfg.llm_api_key),
            "ttl_min": IOS_TTL_MIN,
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        }
        self._save(session_id, state)
        self._arm_ttl(session_id, IOS_TTL_MIN)
        logger.info("demo ios session up id=%s device=%s ttl=%dmin", session_id, cfg.device_name, IOS_TTL_MIN)
        return {**state, "queued": False}

    def get_session(self, session_id: str) -> dict | None:
        st = self._load(session_id)
        if st is None:
            return None
        if st["kind"] == "web":
            ok, detail = self._stacks._wait_healthy_quick(st["host_port"], st.get("health_path", "/healthz"))
            st["healthy"] = ok
            st["health_detail"] = detail
        else:
            out = self._run_simctl(["list", "devices"], what="check device")
            st["healthy"] = st.get("udid", "") in out and "(Booted)" in out
        return st

    def inject_scenario(self, session_id: str, scenario_id: str) -> dict:
        st = self._load(session_id)
        if st is None:
            raise DemoSessionError(f"no such session: {session_id}")
        cmd = st.get("scenarios", {}).get(scenario_id)
        if not cmd:
            raise DemoSessionError(
                f"unknown scenario {scenario_id!r} for session {session_id} (stub pack: {sorted(st.get('scenarios', {}))})"
            )
        if st["kind"] != "web":
            raise DemoSessionError("scenario injection currently supported for web sessions only")
        repo_dir = self.workspace / "stacks" / "apps" / session_id
        compose_cmd = ["docker", "compose", "-p", session_id]
        for f in st.get("compose_files") or ["docker-compose.demo.yml"]:
            compose_cmd += ["-f", str(repo_dir / st.get("compose_dir", ".") / f)]
        if st.get("profile"):
            compose_cmd += ["--profile", st["profile"]]
        compose_cmd += ["exec", "-T", st.get("exec_service", "web"), "sh", "-c", cmd]
        try:
            self._stacks._run(compose_cmd, cwd=repo_dir, timeout=60.0, what="scenario injection")
        except PreviewError as e:
            raise DemoSessionError(f"scenario injection failed: {e}") from e
        # Hard rule: demo path never calls real third-party APIs — every injection is a recorded stub, logged for transparency.
        logger.info("[stub] %s -> %s (session=%s)", scenario_id, cmd, session_id)
        st["last_scenario"] = scenario_id
        self._save(session_id, st)
        return {"ok": True, "session_id": session_id, "scenario_id": scenario_id, "stub": True}

    def end_session(self, session_id: str) -> dict:
        st = self._load(session_id)
        if st is None:
            return {"ok": True, "ended": None}
        if st["kind"] == "web":
            try:
                self._stacks.teardown(session_id)
            except PreviewError as e:
                raise DemoSessionError(f"teardown failed: {e}") from e
        else:
            udid = st.get("udid")
            if udid:
                try:
                    self._run_simctl(["uninstall", udid, st.get("bundle_id", "")], what="uninstall app (burn data)")
                except DemoSessionError as e:
                    logger.warning("app uninstall failed id=%s err=%s", session_id, e)
                try:
                    self._run_simctl(["shutdown", udid], what="shutdown simulator")
                except DemoSessionError as e:
                    logger.warning("simulator shutdown failed id=%s err=%s", session_id, e)
        with self._lock:
            t = self._timers.pop(session_id, None)
            if t:
                t.cancel()
        self._save(session_id, None)
        logger.info("demo session ended, data burned id=%s kind=%s", session_id, st["kind"])
        return {"ok": True, "ended": session_id}

    def _arm_ttl(self, session_id: str, ttl_min: int) -> None:
        with self._lock:
            old = self._timers.pop(session_id, None)
            if old:
                old.cancel()
            t = threading.Timer(ttl_min * 60.0, self._expire, args=(session_id,))
            t.daemon = True
            t.start()
            self._timers[session_id] = t

    def _expire(self, session_id: str) -> None:
        logger.info("demo session TTL expired id=%s", session_id)
        try:
            self.end_session(session_id)
        except DemoSessionError as e:
            logger.error("TTL teardown failed id=%s err=%s", session_id, e)

    def rollup(self, sample_slug: str) -> dict:
        sessions = [self._load(sid) for sid in self._active_ids()]
        sessions = [s for s in sessions if s and s.get("sample_slug") == sample_slug]
        healthy = sum(1 for s in sessions if s.get("healthy"))
        active = len(sessions)
        badge = "healthy" if healthy > 0 else ("maintenance" if active > 0 else "unknown")
        return {"sample_slug": sample_slug, "healthy": healthy, "active": active, "badge": badge}

    def _queue_path(self) -> Path:
        return self.workspace / "queue.json"

    def _load_queue(self) -> list[dict]:
        p = self._queue_path()
        if not p.exists():
            return []
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return []

    def _save_queue(self, q: list[dict]) -> None:
        tmp = self._queue_path().with_suffix(".tmp")
        tmp.write_text(json.dumps(q, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, self._queue_path())

    def _enqueue(self, cfg: DemoSessionConfig) -> int:
        q = self._load_queue()
        q.append(cfg.model_dump())
        self._save_queue(q)
        return len(q)

    def _dispatch_loop(self) -> None:
        while True:
            time.sleep(DISPATCH_INTERVAL_SEC)
            try:
                q = self._load_queue()
                if not q:
                    continue
                head = DemoSessionConfig(**q[0])
                cap = self.max_web if head.kind == "web" else self.max_ios
                if self._count_kind(head.kind) < cap:
                    self._save_queue(q[1:])
                    self._start_now(head)
                    logger.info("queued demo session started slug=%s kind=%s", head.sample_slug, head.kind)
            except Exception as e:
                logger.error("queue dispatch failed err=%s", e)

    def shutdown_all(self) -> list[str]:
        ended = []
        for sid in self._active_ids():
            if self.end_session(sid)["ended"]:
                ended.append(sid)
        self._save_queue([])
        return ended

    def has_docker(self) -> bool:
        return shutil.which("docker") is not None
