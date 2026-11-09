from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

import pytest

from fusion_executor.preview_stack import PreviewError, PreviewProject, PreviewStackRunner

DOCKER_AVAILABLE = (
    shutil.which("docker") is not None
    and subprocess.run(["docker", "info", "--format", "ok"], capture_output=True, text=True, timeout=15).returncode == 0
)

PREVIEW_PORT = 18971


def _free_port() -> int:
    import socket

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _make_compose_repo(repo_dir: Path) -> str:
    site = repo_dir / "site"
    site.mkdir(parents=True, exist_ok=True)
    (site / "index.html").write_text("<html>PREVIEW-OK</html>\n")
    (site / "healthz").write_text("ok\n")
    compose = repo_dir / "docker-compose.yml"
    compose.write_text(
        "services:\n"
        "  web:\n"
        "    image: nginx:alpine\n"
        '    profiles: ["preview"]\n'
        "    ports:\n"
        '      - "127.0.0.1:${PREVIEW_HOST_PORT:-18971}:80"\n'
        "    volumes:\n"
        "      - ./site:/usr/share/nginx/html:rw\n"
    )
    overlay = repo_dir / "docker-compose.preview.yml"
    overlay.write_text('services:\n  web:\n    environment:\n      PREVIEW_MODE: "1"\n')
    subprocess.run(["git", "init", "-q"], cwd=repo_dir, check=True)
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init", "--allow-empty"],
        cwd=repo_dir,
        check=True,
    )
    return str(repo_dir)


def _proj(repo_url: str, name: str = "preview-fixture", host_port: int = PREVIEW_PORT) -> PreviewProject:
    return PreviewProject(
        name=name,
        repo_url=repo_url,
        compose_files=["docker-compose.yml", "docker-compose.preview.yml"],
        profile="preview",
        host_port=host_port,
        service_port=80,
        health_path="/healthz",
        health_timeout_sec=60.0,
        seed_service="web",
        seed_cmd="echo SYNTHETIC-DEMO-DATA-ONLY > /usr/share/nginx/html/demo-data.txt",
        ttl_min=1,
    )


def _notify_events(events: list):
    return lambda payload: events.append(payload)


def test_init_without_docker_path_ok(tmp_path):
    PreviewStackRunner(workspace_dir=tmp_path / "ws")
    assert (tmp_path / "ws").is_dir()


def test_invalid_name_rejected(tmp_path):
    r = PreviewStackRunner(workspace_dir=tmp_path / "ws")
    with pytest.raises(PreviewError, match="invalid preview name"):
        r.up(_proj("/local/repo", name="../evil"))


def test_port_in_use_fails_visibly(tmp_path):
    import socket

    port = _free_port()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", port))
    s.listen(1)
    try:
        r = PreviewStackRunner(workspace_dir=tmp_path / "ws")
        with pytest.raises(PreviewError, match="already in use"):
            r.up(_proj("/local/repo", host_port=port))
    finally:
        s.close()


def test_teardown_without_state_is_noop(tmp_path):
    r = PreviewStackRunner(workspace_dir=tmp_path / "ws")
    assert r.teardown("no-such") == {"ok": True, "torn_down": None}
    assert r.status("no-such") is None
    assert r.status_all() == []


def test_preview_url_without_state_raises(tmp_path):
    r = PreviewStackRunner(workspace_dir=tmp_path / "ws")
    with pytest.raises(PreviewError, match="no preview state"):
        r.preview_url("ghost")


def test_notify_hook_failure_does_not_break_up(tmp_path):
    r = PreviewStackRunner(
        workspace_dir=tmp_path / "ws", notify=lambda p: (_ for _ in ()).throw(RuntimeError("hook down"))
    )
    assert r.notify is not None


@pytest.mark.skipif(not DOCKER_AVAILABLE, reason="docker daemon not available")
class TestLivePreviewStack:
    def test_full_lifecycle(self, tmp_path):
        repo = _make_compose_repo(tmp_path / "repo")
        events: list = []
        port = _free_port()
        r = PreviewStackRunner(workspace_dir=tmp_path / "ws", notify=events.append)
        st = r.up(_proj(repo, host_port=port))
        try:
            assert st["healthy"] is True
            assert st["url"] == f"http://127.0.0.1:{port}/"
            import urllib.request

            with urllib.request.urlopen(st["url"], timeout=5) as resp:
                assert b"PREVIEW-OK" in resp.read()
            with urllib.request.urlopen(st["url"] + "demo-data.txt", timeout=5) as resp:
                assert b"SYNTHETIC-DEMO-DATA-ONLY" in resp.read()
            assert events and events[-1]["event"] == "ready"
            st2 = r.up(_proj(repo, host_port=port))
            assert st2["url"] == st["url"]
            live = r.status("preview-fixture")
            assert live["healthy"] is True
            assert r.preview_url("preview-fixture") == st["url"]
        finally:
            r.teardown("preview-fixture")
        time.sleep(0.5)
        assert r.status("preview-fixture") is None
        out = subprocess.run(
            ["docker", "ps", "--filter", "name=preview-fixture", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
        ).stdout.strip()
        assert out == ""

    def test_unhealthy_stack_auto_teardown(self, tmp_path):
        repo_dir = tmp_path / "repo-bad"
        repo_dir.mkdir(parents=True, exist_ok=True)
        compose = repo_dir / "docker-compose.yml"
        port = _free_port()
        compose.write_text(
            "services:\n"
            "  web:\n"
            "    image: nginx:alpine\n"
            "    ports:\n"
            '      - "127.0.0.1:${PREVIEW_HOST_PORT:-18972}:80"\n'
        )
        subprocess.run(["git", "init", "-q"], cwd=repo_dir, check=True)
        subprocess.run(["git", "add", "."], cwd=repo_dir, check=True)
        subprocess.run(
            ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init", "--allow-empty"],
            cwd=repo_dir,
            check=True,
        )
        r = PreviewStackRunner(workspace_dir=tmp_path / "ws")
        proj = _proj(str(repo_dir), name="preview-bad", host_port=port)
        proj = proj.model_copy(
            update={
                "health_timeout_sec": 8.0,
                "health_path": "/never-there",
                "compose_files": ["docker-compose.yml"],
                "profile": None,
                "seed_service": None,
                "seed_cmd": None,
            }
        )
        st = r.up(proj)
        assert st["healthy"] is False
        time.sleep(0.5)
        assert r.status("preview-bad") is None
        out = subprocess.run(
            ["docker", "ps", "-a", "--filter", "name=preview-bad", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
        ).stdout.strip()
        assert out == ""
