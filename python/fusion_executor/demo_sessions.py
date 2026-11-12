from __future__ import annotations

import json
import logging
import os
import re
import shutil
import socket
import subprocess
import tempfile
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
ANDROID_BOOT_TIMEOUT_SEC = 600.0
KIND_CAP_ATTR = {"web": "max_web", "ios": "max_ios", "android": "max_android"}


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
    android_image: str = "redroid/redroid:14.0.0-latest"
    stream_path: str = ""

    def validate_config(self) -> None:
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", self.sample_slug):
            raise DemoSessionError(f"invalid sample_slug: {self.sample_slug!r}")
        if self.kind not in ("web", "ios", "android"):
            raise DemoSessionError(f"unsupported kind: {self.kind!r} (web|ios|android)")
        if self.kind == "web" and not self.repo_url:
            raise DemoSessionError("web session requires repo_url")
        if self.kind == "ios" and not self.bundle_id:
            raise DemoSessionError("ios session requires bundle_id")
        if self.kind == "android" and not self.bundle_id:
            raise DemoSessionError("android session requires bundle_id (app package to launch)")


class DemoSessionManager:
    def __init__(
        self,
        workspace_dir: str | Path = DEFAULT_SESSIONS_WORKSPACE,
        max_web: int = 8,
        max_ios: int = 2,
        max_android: int = 1,
    ) -> None:
        self.workspace = Path(workspace_dir).expanduser()
        self.workspace.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.workspace, 0o700)
        self.max_web = max_web
        self.max_ios = max_ios
        self.max_android = max_android
        self._streams: dict[str, threading.Thread] = {}
        self._stop_flags: dict[str, threading.Event] = {}
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
        cap = getattr(self, KIND_CAP_ATTR[cfg.kind])
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
        if cfg.kind == "android":
            return self._start_android(session_id, cfg)
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
            "llm_api_key": cfg.llm_api_key,
            "llm_key_wired": bool(cfg.llm_api_key),
            "stream_path": cfg.stream_path,
            "ttl_min": cfg.ttl_min,
            "started_at": st["started_at"],
        }
        if cfg.stream_path:
            state["stream_url"] = st["url"].rstrip("/") + "/" + cfg.stream_path.lstrip("/")
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
            "llm_api_key": cfg.llm_api_key,
            "llm_key_wired": bool(cfg.llm_api_key),
            "ttl_min": IOS_TTL_MIN,
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        }
        self._save(session_id, state)
        self._arm_ttl(session_id, IOS_TTL_MIN)
        logger.info("demo ios session up id=%s device=%s ttl=%dmin", session_id, cfg.device_name, IOS_TTL_MIN)
        return {**state, "queued": False}

    def _adb(self, args: list[str], what: str, timeout: float = 60.0) -> str:
        logger.info("adb what=%s args=%s", what, " ".join(args))
        try:
            r = subprocess.run(["adb", *args], capture_output=True, text=True, timeout=timeout)
        except FileNotFoundError as e:
            raise DemoSessionError("android sessions require adb (android platform-tools) on PATH") from e
        except subprocess.TimeoutExpired as e:
            raise DemoSessionError(f"{what} timed out after {timeout}s") from e
        if r.returncode != 0:
            raise DemoSessionError(f"{what} failed (exit {r.returncode}): {(r.stderr or r.stdout).strip()[-500:]}")
        return r.stdout

    def _start_android(self, session_id: str, cfg: DemoSessionConfig) -> dict:
        import platform

        if platform.system() != "Linux" or not Path("/dev/kvm").exists():
            # Visible failure, never a silent skip: the emulator container needs
            # Linux + KVM (redroid binderfs). Live verification is blocked on a
            # Linux demo host — see issue #69 acceptance notes.
            raise DemoSessionError(
                "android sessions require a Linux demo host with /dev/kvm "
                f"(got platform={platform.system()}, /dev/kvm={Path('/dev/kvm').exists()})"
            )
        if shutil.which("adb") is None:
            raise DemoSessionError("android sessions require adb (android platform-tools) on PATH")
        host_port = self._free_port()
        container = f"{session_id}-emu"
        try:
            self._stacks._run(
                [
                    "docker",
                    "run",
                    "-d",
                    "--rm",
                    "--name",
                    container,
                    "--privileged",
                    "-p",
                    f"127.0.0.1:{host_port}:5555",
                    cfg.android_image,
                ],
                cwd=self.workspace,
                timeout=180.0,
                what="android emulator container start",
            )
        except PreviewError as e:
            raise DemoSessionError(f"android emulator container start failed: {e}") from e
        serial = f"127.0.0.1:{host_port}"
        try:
            self._adb(["connect", serial], "adb connect")
            deadline = time.monotonic() + ANDROID_BOOT_TIMEOUT_SEC
            booted = False
            while time.monotonic() < deadline:
                out = self._adb(["-s", serial, "shell", "getprop", "sys.boot_completed"], "wait boot", timeout=30.0)
                if out.strip() == "1":
                    booted = True
                    break
                time.sleep(5.0)
            if not booted:
                raise DemoSessionError(f"android emulator {serial} failed to boot within {ANDROID_BOOT_TIMEOUT_SEC}s")
            if cfg.app_path:
                self._adb(["-s", serial, "install", "-r", "-t", cfg.app_path], "install apk", timeout=300.0)
            self._adb(
                ["-s", serial, "shell", "monkey", "-p", cfg.bundle_id, "-c", "android.intent.category.LAUNCHER", "1"],
                "launch app",
            )
        except DemoSessionError:
            try:
                self._stacks._run(
                    ["docker", "rm", "-f", container],
                    cwd=self.workspace,
                    timeout=30.0,
                    what="android emulator cleanup after failed start",
                )
            except PreviewError as e:
                logger.warning("android cleanup failed id=%s err=%s", session_id, e)
            raise
        state = {
            "session_id": session_id,
            "sample_slug": cfg.sample_slug,
            "kind": "android",
            "container": container,
            "adb_serial": serial,
            "host_port": host_port,
            "bundle_id": cfg.bundle_id,
            "healthy": True,
            "llm_base_url": DEMO_LLM_BASE_URL,
            "llm_api_key": cfg.llm_api_key,
            "llm_key_wired": bool(cfg.llm_api_key),
            "ttl_min": cfg.ttl_min,
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        }
        self._save(session_id, state)
        self._arm_ttl(session_id, cfg.ttl_min)
        logger.info("demo android session up id=%s serial=%s ttl=%dmin", session_id, serial, cfg.ttl_min)
        return {**state, "queued": False}

    def open_stream(self, session_id: str) -> dict:
        """Best-effort screen stream. iOS: MJPEG over HTTP (simctl screenshot loop).
        Web: demo-app-provided stream page (noVNC etc.) — URL probed and returned.
        NOTE: this is NOT the ~120ms WebRTC acceptance target from issue #69 —
        iOS touch injection has no public simctl API (needs XCTest stack); MJPEG
        latency is ~0.5-1s. Verified honestly as best-effort preview."""
        st = self._load(session_id)
        if st is None:
            raise DemoSessionError(f"no such session: {session_id}")
        if st["kind"] == "ios":
            if st.get("stream_port"):
                return {"ok": True, "stream_url": f"http://127.0.0.1:{st['stream_port']}/stream.mjpeg", "mode": "mjpeg"}
            port = self._free_port()
            stop = threading.Event()
            t = threading.Thread(target=self._mjpeg_loop, args=(st["udid"], port, stop), daemon=True)
            t.start()
            self._streams[session_id] = t
            self._stop_flags[session_id] = stop
            # Wait for the listener to bind before handing out the URL (the
            # server thread owns binding; a fast client would otherwise hit
            # connection-refused).
            ready = False
            for _ in range(50):
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        ready = True
                        break
                except OSError:
                    time.sleep(0.1)
            if not ready:
                stop.set()
                raise DemoSessionError(f"mjpeg stream server failed to bind port {port}")
            st["stream_port"] = port
            self._save(session_id, st)
            url = f"http://127.0.0.1:{port}/stream.mjpeg"
            logger.info("demo ios stream open id=%s url=%s (mjpeg best-effort, not WebRTC)", session_id, url)
            return {"ok": True, "stream_url": url, "mode": "mjpeg"}
        url = st.get("stream_url")
        if not url:
            raise DemoSessionError(
                "session has no stream configured (web demos opt in via stream_path; "
                "the demo app must provide the stream page, e.g. noVNC)"
            )
        try:
            import urllib.request

            with urllib.request.urlopen(url, timeout=5) as resp:
                code = resp.status
        except Exception as e:
            raise DemoSessionError(f"stream endpoint unreachable: {url} ({e})") from e
        logger.info("demo web stream verified id=%s url=%s status=%d", session_id, url, code)
        return {"ok": True, "stream_url": url, "mode": "demo-app"}

    def _mjpeg_loop(self, udid: str, port: int, stop: threading.Event) -> None:
        import http.server

        frames = {"jpg": b""}

        def snap() -> bytes:
            # simctl screenshot only writes to a file path (stdout "-" is
            # treated as a literal filename) — snapshot via temp file.
            tmp = Path(tempfile.gettempdir()) / f"fe-mjpeg-{udid[:8]}.jpg"
            try:
                r = subprocess.run(
                    ["xcrun", "simctl", "io", udid, "screenshot", "--type=jpeg", "--display", "1", str(tmp)],
                    capture_output=True,
                    timeout=30.0,
                )
            except subprocess.TimeoutExpired:
                return b""
            if r.returncode != 0:
                return b""
            try:
                return tmp.read_bytes()
            except OSError:
                return b""

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path != "/stream.mjpeg":
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Type", "multipart/x-mixed-replace; boundary=frame")
                self.end_headers()
                while not stop.is_set():
                    jpg = frames["jpg"]
                    if not jpg:
                        time.sleep(0.2)
                        continue
                    try:
                        self.wfile.write(
                            b"--frame\r\nContent-Type: image/jpeg\r\nContent-Length: "
                            + str(len(jpg)).encode()
                            + b"\r\n\r\n"
                            + jpg
                            + b"\r\n"
                        )
                        self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError):
                        return
                    time.sleep(0.5)

            def log_message(self, fmt, *args):
                logger.debug("mjpeg " + fmt, *args)

        server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
        server.daemon_threads = True

        def capture():
            while not stop.is_set():
                frames["jpg"] = snap()
                time.sleep(0.5)
            server.shutdown()

        threading.Thread(target=capture, daemon=True).start()
        logger.info("mjpeg stream server listening port=%d udid=%s", port, udid)
        server.serve_forever(poll_interval=0.2)
        server.server_close()
        logger.info("mjpeg stream server stopped port=%d", port)

    def get_session(self, session_id: str) -> dict | None:
        st = self._load(session_id)
        if st is None:
            return None
        if st["kind"] == "web":
            ok, detail = self._stacks._wait_healthy_quick(st["host_port"], st.get("health_path", "/healthz"))
            st["healthy"] = ok
            st["health_detail"] = detail
        elif st["kind"] == "android":
            try:
                out = self._adb(["-s", st["adb_serial"], "get-state"], "check emulator", timeout=15.0)
                st["healthy"] = out.strip() == "device"
            except DemoSessionError:
                st["healthy"] = False
        else:
            out = self._run_simctl(["list", "devices"], what="check device")
            st["healthy"] = st.get("udid", "") in out and "(Booted)" in out
        return st

    def session_cost(self, session_id: str) -> dict:
        """Read back per-session LLM metering from the gateway /v1/cost surface
        using the session's own fk- key (own-key scope — gateway-owned metering)."""
        st = self._load(session_id)
        if st is None:
            raise DemoSessionError(f"no such session: {session_id}")
        key = st.get("llm_api_key")
        if not key:
            raise DemoSessionError(f"session {session_id} has no llm_api_key wired; metering readback unavailable")
        import urllib.error
        import urllib.request

        req = urllib.request.Request(
            DEMO_LLM_BASE_URL.rstrip("/") + "/v1/cost",
            headers={"Authorization": f"Bearer {key}"},
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                summary = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            raise DemoSessionError(
                f"/v1/cost readback failed (HTTP {e.code}): {e.read().decode('utf-8', 'replace')[-300:]}"
            ) from e
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
            raise DemoSessionError(f"/v1/cost readback failed: {e}") from e
        logger.info("session cost readback id=%s ok=%s", session_id, bool(summary))
        return {"session_id": session_id, "cost_summary": summary}

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
        stop = self._stop_flags.pop(session_id, None)
        if stop:
            stop.set()
        self._streams.pop(session_id, None)
        if st["kind"] == "web":
            try:
                self._stacks.teardown(session_id)
            except PreviewError as e:
                raise DemoSessionError(f"teardown failed: {e}") from e
        elif st["kind"] == "android":
            try:
                self._stacks._run(
                    ["docker", "rm", "-f", st["container"]],
                    cwd=self.workspace,
                    timeout=60.0,
                    what="android emulator teardown (burn data)",
                )
            except (PreviewError, KeyError) as e:
                logger.warning("android teardown failed id=%s err=%s", session_id, e)
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
                cap = getattr(self, KIND_CAP_ATTR[head.kind])
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
