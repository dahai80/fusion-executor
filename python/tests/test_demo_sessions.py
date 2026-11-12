from __future__ import annotations

import logging
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
    r = subprocess.run(["xcrun", "simctl", "list", "devices", "available"], capture_output=True, text=True, timeout=30)
    names: list[str] = []
    for line in r.stdout.splitlines():
        if "(Shutdown)" in line and "iPhone" in line:
            name = line.split("(")[0].strip()
            if name and name not in names:
                names.append(name)
    return names


def _make_demo_repo(repo_dir: Path) -> str:
    site = repo_dir / "site"
    site.mkdir(parents=True, exist_ok=True)
    (site / "index.html").write_text("<html>DEMO-SESSION-OK</html>\n")
    (site / "healthz").write_text("ok\n")
    compose = repo_dir / "docker-compose.demo.yml"
    compose.write_text(
        "services:\n"
        "  web:\n"
        "    image: nginx:alpine\n"
        "    ports:\n"
        '      - "127.0.0.1:${PREVIEW_HOST_PORT:-11600}:80"\n'
        "    volumes:\n"
        "      - ./site:/usr/share/nginx/html:rw\n"
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
    return DemoSessionConfig(
        sample_slug=slug,
        kind="web",
        repo_url=repo_url,
        exec_service="web",
        scenarios={"invoice-created": "echo INVOICE-STUB-EVENT > /usr/share/nginx/html/demo-data.txt"},
        llm_api_key="fk-test-session-key",
        ttl_min=5,
        **kw,
    )


def test_validate_config_slug_and_kind():
    with pytest.raises(DemoSessionError, match="invalid sample_slug"):
        DemoSessionConfig(sample_slug="Bad Slug").validate_config()
    with pytest.raises(DemoSessionError, match="unsupported kind"):
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


def test_preview_up_extra_env_passthrough(tmp_path):
    PreviewStackRunner(workspace_dir=tmp_path / "ws")
    import inspect

    sig = inspect.signature(PreviewStackRunner.up)
    assert "extra_env" in sig.parameters
