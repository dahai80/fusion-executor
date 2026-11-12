from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import urllib.request
from pathlib import Path

import pytest

from fusion_executor.demo_sessions import DemoSessionConfig, DemoSessionError, DemoSessionManager
from fusion_executor.preview_stack import PreviewStackRunner

DOCKER_AVAILABLE = (
    shutil.which("docker") is not None
    and subprocess.run(["docker", "info", "--format", "ok"], capture_output=True, text=True, timeout=15).returncode == 0
)

SIMCTL_AVAILABLE = shutil.which("xcrun") is not None


def _available_device_names() -> list[str]:
    try:
        # First simctl call on a fresh runner cold-starts daemons and can be slow.
        r = subprocess.run(
            ["xcrun", "simctl", "list", "devices", "available"], capture_output=True, text=True, timeout=120
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        logging.warning("simctl device discovery failed, skipping iOS live test: %s", e)
        return []
    if r.returncode != 0:
        logging.warning("simctl device discovery exited %d, skipping iOS live test", r.returncode)
        return []
    names: list[str] = []
    for line in r.stdout.splitlines():
        if "(Shutdown)" in line and "iPhone" in line:
            name = line.split("(")[0].strip()
            if name and name not in names:
                names.append(name)
    return names


def _make_demo_repo(repo_dir: Path, *, stream: bool = False, llm_env: bool = False) -> str:
    site = repo_dir / "site"
    site.mkdir(parents=True, exist_ok=True)
    (site / "index.html").write_text("<html>DEMO-SESSION-OK</html>\n")
    (site / "healthz").write_text("ok\n")
    if stream:
        (site / "vnc.html").write_text("<html>NOVNC-PLACEHOLDER</html>\n")
    env_block = ""
    if llm_env:
        env_block = "    environment:\n      - FUSION_LLM_API_KEY=${FUSION_LLM_API_KEY:-}\n"
    compose = repo_dir / "docker-compose.demo.yml"
    compose.write_text(
        "services:\n"
        "  web:\n"
        "    image: nginx:alpine\n"
        "    ports:\n"
        '      - "127.0.0.1:${PREVIEW_HOST_PORT:-11600}:80"\n'
        "    volumes:\n"
        "      - ./site:/usr/share/nginx/html:rw\n" + env_block
    )
    subprocess.run(["git", "init", "-q"], cwd=repo_dir, check=True)
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init", "--allow-empty"],
        cwd=repo_dir,
        check=True,
    )
    return str(repo_dir)


def _web_cfg(repo_url: str, slug: str = "tiny-todo", **kw) -> DemoSessionConfig:
    kw.setdefault("llm_api_key", "fk-test-session-key")
    kw.setdefault("scenarios", {"invoice-created": "echo INVOICE-STUB-EVENT > /usr/share/nginx/html/demo-data.txt"})
    return DemoSessionConfig(
        sample_slug=slug,
        kind="web",
        repo_url=repo_url,
        exec_service="web",
        ttl_min=5,
        **kw,
    )


def test_validate_config_slug_and_kind():
    with pytest.raises(DemoSessionError, match="invalid sample_slug"):
        DemoSessionConfig(sample_slug="Bad Slug").validate_config()
    with pytest.raises(DemoSessionError, match="bundle_id"):
        DemoSessionConfig(sample_slug="ok", kind="android").validate_config()
    with pytest.raises(DemoSessionError, match="repo_url"):
        DemoSessionConfig(sample_slug="ok", kind="web").validate_config()
    with pytest.raises(DemoSessionError, match="bundle_id"):
        DemoSessionConfig(sample_slug="ok", kind="ios").validate_config()
    DemoSessionConfig(sample_slug="tiny-todo", kind="web", repo_url="/tmp/x").validate_config()


def test_unknown_scenario_rejected(tmp_path):
    m = DemoSessionManager(workspace_dir=tmp_path / "ws")
    with pytest.raises(DemoSessionError, match="no such session"):
        m.inject_scenario("ghost-000", "s1")


def test_rollup_empty_is_unknown(tmp_path):
    m = DemoSessionManager(workspace_dir=tmp_path / "ws")
    r = m.rollup("tiny-todo")
    assert r == {"sample_slug": "tiny-todo", "healthy": 0, "active": 0, "badge": "unknown"}


def test_capacity_queue_reports_position(tmp_path):
    m = DemoSessionManager(workspace_dir=tmp_path / "ws", max_web=0)
    st = m.start_session(_web_cfg("/local/repo"))
    assert st["queued"] is True
    assert st["position"] == 1
    st2 = m.start_session(_web_cfg("/local/repo"))
    assert st2["position"] == 2
    assert len(m._load_queue()) == 2
    m._save_queue([])


def test_shutdown_all_clears(tmp_path):
    m = DemoSessionManager(workspace_dir=tmp_path / "ws")
    assert m.shutdown_all() == []
    m._save_queue([{}])
    m.shutdown_all()
    assert m._load_queue() == []


@pytest.mark.skipif(not DOCKER_AVAILABLE, reason="docker daemon not available")
class TestLiveWebSessions:
    def test_session_lifecycle_scenario_and_burn(self, tmp_path, caplog):
        repo = _make_demo_repo(tmp_path / "repo")
        m = DemoSessionManager(workspace_dir=tmp_path / "ws")
        st = m.start_session(_web_cfg(repo))
        sid = st["session_id"]
        try:
            assert st["queued"] is False
            assert st["healthy"] is True
            assert st["llm_key_wired"] is True
            assert st["llm_base_url"] == "http://127.0.0.1:11432"
            with urllib.request.urlopen(st["url"], timeout=5) as resp:
                assert b"DEMO-SESSION-OK" in resp.read()
            got = m.get_session(sid)
            assert got["healthy"] is True
            with caplog.at_level(logging.INFO, logger="fusion_executor.demo_sessions"):
                r = m.inject_scenario(sid, "invoice-created")
            assert r["stub"] is True
            assert "[stub] invoice-created" in caplog.text
            with urllib.request.urlopen(st["url"] + "demo-data.txt", timeout=5) as resp:
                assert b"INVOICE-STUB-EVENT" in resp.read()
            with pytest.raises(DemoSessionError, match="unknown scenario"):
                m.inject_scenario(sid, "no-such-scenario")
            ru = m.rollup("tiny-todo")
            assert ru["badge"] == "healthy" and ru["healthy"] == 1
        finally:
            m.end_session(sid)
        assert m.get_session(sid) is None
        assert m.rollup("tiny-todo")["active"] == 0
        st_b = m.start_session(_web_cfg(repo))
        sid_b = st_b["session_id"]
        try:
            burned = True
            try:
                urllib.request.urlopen(st_b["url"] + "demo-data.txt", timeout=5)
                burned = False
            except Exception:
                pass
            assert burned, "cross-session residue detected — data burn violated"
        finally:
            m.end_session(sid_b)

    def test_port_from_demo_range(self, tmp_path):
        repo = _make_demo_repo(tmp_path / "repo2")
        m = DemoSessionManager(workspace_dir=tmp_path / "ws")
        st = m.start_session(_web_cfg(repo, slug="invoice-tool"))
        try:
            assert 11600 <= st["host_port"] <= 11669
        finally:
            m.end_session(st["session_id"])


@pytest.mark.skipif(not SIMCTL_AVAILABLE, reason="xcrun simctl not available")
@pytest.mark.skipif(
    os.environ.get("GITHUB_ACTIONS") == "true",
    reason="headless CI runners boot simulators but app launch hangs without a GUI session",
)
class TestLiveIosSessions:
    def test_ios_boot_launch_shutdown_and_queue(self, tmp_path):
        devices = _available_device_names()
        if len(devices) < 3:
            pytest.skip(f"need 3 available iPhone simulators, found {len(devices)}: {devices}")
        m = DemoSessionManager(workspace_dir=tmp_path / "ws", max_ios=2)
        cfg_a = DemoSessionConfig(
            sample_slug="ios-demo-a", kind="ios", bundle_id="com.apple.mobilesafari", device_name=devices[0]
        )
        cfg_b = DemoSessionConfig(
            sample_slug="ios-demo-b", kind="ios", bundle_id="com.apple.mobilesafari", device_name=devices[1]
        )
        try:
            st_a = m.start_session(cfg_a)
            assert st_a["queued"] is False and st_a["healthy"] is True
            st_b = m.start_session(cfg_b)
            assert st_b["queued"] is False and st_b["healthy"] is True
            cfg_c = DemoSessionConfig(
                sample_slug="ios-demo-c", kind="ios", bundle_id="com.apple.mobilesafari", device_name=devices[2]
            )
            st_c = m.start_session(cfg_c)
            assert st_c["queued"] is True and st_c["position"] == 1
            m._save_queue([])
            got = m.get_session(st_a["session_id"])
            assert got["healthy"] is True
        finally:
            m.shutdown_all()
        assert m.rollup("ios-demo-a")["active"] == 0

    def test_ios_mjpeg_stream_serves_frames(self, tmp_path):
        import urllib.error
        import urllib.request

        devices = _available_device_names()
        if not devices:
            pytest.skip("no available iPhone simulator")
        m = DemoSessionManager(workspace_dir=tmp_path / "ws", max_ios=1)
        cfg = DemoSessionConfig(
            sample_slug="ios-stream", kind="ios", bundle_id="com.apple.mobilesafari", device_name=devices[0]
        )
        try:
            st = m.start_session(cfg)
            sid = st["session_id"]
            opened = m.open_stream(sid)
            assert opened["mode"] == "mjpeg"
            url = opened["stream_url"]
            again = m.open_stream(sid)
            assert again["stream_url"] == url
            with urllib.request.urlopen(url, timeout=10) as resp:
                ctype = resp.headers.get("Content-Type", "")
                assert "multipart/x-mixed-replace" in ctype
                chunk = resp.read(4096)
                assert b"image/jpeg" in chunk
            with pytest.raises(urllib.error.HTTPError) as ei:
                urllib.request.urlopen(url.replace("stream.mjpeg", "nope"), timeout=5)
            assert ei.value.code == 404
        finally:
            m.shutdown_all()


def test_preview_up_extra_env_passthrough(tmp_path):
    PreviewStackRunner(workspace_dir=tmp_path / "ws")
    import inspect

    sig = inspect.signature(PreviewStackRunner.up)
    assert "extra_env" in sig.parameters


def test_android_preflight_visible_error(tmp_path):
    import platform

    m = DemoSessionManager(workspace_dir=tmp_path / "ws")
    cfg = DemoSessionConfig(sample_slug="android-demo", kind="android", bundle_id="com.example.app")
    if platform.system() == "Linux" and Path("/dev/kvm").exists():
        pytest.skip("real Linux+KVM host — preflight would pass")
    with pytest.raises(DemoSessionError, match="Linux demo host with /dev/kvm"):
        m.start_session(cfg)


def test_android_capacity_queue(tmp_path):
    m = DemoSessionManager(workspace_dir=tmp_path / "ws", max_android=0)
    cfg = DemoSessionConfig(sample_slug="android-demo", kind="android", bundle_id="com.example.app")
    st = m.start_session(cfg)
    assert st["queued"] is True and st["position"] == 1
    m._save_queue([])


def test_session_cost_no_key_visible_error(tmp_path):
    m = DemoSessionManager(workspace_dir=tmp_path / "ws")
    sid = "tiny-todo-00000000"
    m._save(sid, {"session_id": sid, "sample_slug": "tiny-todo", "kind": "web", "llm_api_key": ""})
    with pytest.raises(DemoSessionError, match="no llm_api_key wired"):
        m.session_cost(sid)


def test_session_cost_bad_key_visible_error(tmp_path):
    m = DemoSessionManager(workspace_dir=tmp_path / "ws")
    sid = "tiny-todo-00000000"
    m._save(sid, {"session_id": sid, "sample_slug": "tiny-todo", "kind": "web", "llm_api_key": "fk-definitely-invalid"})
    with pytest.raises(DemoSessionError, match="/v1/cost readback failed"):
        m.session_cost(sid)


def test_web_stream_not_configured_visible_error(tmp_path):
    m = DemoSessionManager(workspace_dir=tmp_path / "ws")
    sid = "tiny-todo-00000000"
    m._save(sid, {"session_id": sid, "sample_slug": "tiny-todo", "kind": "web"})
    with pytest.raises(DemoSessionError, match="no stream configured"):
        m.open_stream(sid)


def test_open_stream_no_session(tmp_path):
    m = DemoSessionManager(workspace_dir=tmp_path / "ws")
    with pytest.raises(DemoSessionError, match="no such session"):
        m.open_stream("ghost-000")


@pytest.mark.skipif(not DOCKER_AVAILABLE, reason="docker daemon not available")
class TestLiveWebStreamAndMetering:
    def test_stream_url_issued_and_reachable(self, tmp_path):
        repo = _make_demo_repo(tmp_path / "repo", stream=True)
        m = DemoSessionManager(workspace_dir=tmp_path / "ws")
        st = m.start_session(_web_cfg(repo, slug="stream-demo", stream_path="vnc.html"))
        try:
            assert st["stream_url"].endswith("/vnc.html")
            got = m.open_stream(st["session_id"])
            assert got["ok"] is True and got["mode"] == "demo-app"
            with urllib.request.urlopen(got["stream_url"], timeout=5) as resp:
                assert b"NOVNC-PLACEHOLDER" in resp.read()
        finally:
            m.end_session(st["session_id"])

    def test_web_llm_env_reaches_container(self, tmp_path, caplog):
        repo = _make_demo_repo(tmp_path / "repo", llm_env=True)
        m = DemoSessionManager(workspace_dir=tmp_path / "ws")
        cfg = _web_cfg(
            repo,
            slug="llm-env-demo",
            llm_api_key="fk-container-env-probe",
            scenarios={"key-echo": 'echo -n "$FUSION_LLM_API_KEY" > /usr/share/nginx/html/key.txt'},
        )
        st = m.start_session(cfg)
        sid = st["session_id"]
        try:
            m.inject_scenario(sid, "key-echo")
            with urllib.request.urlopen(st["url"] + "key.txt", timeout=5) as resp:
                assert resp.read() == b"fk-container-env-probe"
        finally:
            m.end_session(sid)


def _gateway_up() -> bool:
    try:
        with urllib.request.urlopen("http://127.0.0.1:11432/healthz", timeout=3) as resp:
            return resp.status == 200
    except Exception:
        return False


def _gateway_master_key() -> str:
    key = os.environ.get("FUSION_GATEWAY_MASTER_KEY", "")
    if not key:
        p = Path("/tmp/fusion-gw-master.key")
        if p.exists():
            key = p.read_text(encoding="utf-8").strip()
    return key


GATEWAY_MASTER_KEY = _gateway_master_key()


@pytest.mark.skipif(
    not (_gateway_up() and GATEWAY_MASTER_KEY), reason="gateway down or FUSION_GATEWAY_MASTER_KEY unset"
)
class TestLiveMeteringE2E:
    def test_fk_key_usage_shows_in_v1_cost(self, tmp_path):
        import uuid as _uuid

        gw = "http://127.0.0.1:11432"
        key_name = f"demo-metering-test-{_uuid.uuid4().hex[:8]}"
        req = urllib.request.Request(
            gw + "/api/v1/keys",
            data=json.dumps({"name": key_name, "scopes": ["chat"]}).encode(),
            headers={"Authorization": f"Bearer {GATEWAY_MASTER_KEY}", "Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw_key = json.loads(resp.read().decode())["raw_key"]
        assert raw_key.startswith("fk-")
        repo = _make_demo_repo(tmp_path / "repo", llm_env=True)
        m = DemoSessionManager(workspace_dir=tmp_path / "ws")
        llm_cmd = (
            "curl -s -m 90 -X POST http://host.docker.internal:11432/v1/chat/completions "
            '-H "Content-Type: application/json" -H "Authorization: Bearer $FUSION_LLM_API_KEY" '
            '-d \'{"model":"mlx-community--Qwen3-0.6B-4bit","messages":[{"role":"user","content":"say ok"}],'
            '"max_tokens":8,"stream":true}\' > /usr/share/nginx/html/llm.txt; head -c 60 /usr/share/nginx/html/llm.txt'
        )
        cfg = _web_cfg(repo, slug="metering-demo", llm_api_key=raw_key, scenarios={"llm-call": llm_cmd})
        st = m.start_session(cfg)
        sid = st["session_id"]
        try:
            m.inject_scenario(sid, "llm-call")
            got = m.get_session(sid)
            assert got["healthy"] is True
            cost = m.session_cost(sid)
            summary = cost["cost_summary"]
            assert summary.get("total_requests", 0) >= 1, f"fk- key usage not metered: {summary}"
            assert summary.get("total_tokens", 0) > 0
            assert any("demo-metering-test" in k for k in summary.get("by_key", {}))
        finally:
            m.end_session(sid)
            revoke = urllib.request.Request(
                gw + f"/api/v1/keys/{key_name}",
                headers={"Authorization": f"Bearer {GATEWAY_MASTER_KEY}"},
                method="DELETE",
            )
            try:
                urllib.request.urlopen(revoke, timeout=10)
            except Exception as e:
                logging.warning("metering test key revoke failed name=%s err=%s", key_name, e)
