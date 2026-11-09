from __future__ import annotations

import subprocess
import time
from pathlib import Path

import pytest

from fusion_executor.demo_env import DemoEnvError, DemoEnvRunner, _derive_name, _ssh_fallback
from fusion_executor.models import SandboxProfile


def _make_repo(repo_dir: Path, *, with_start_sh: bool = True) -> str:
    repo_dir.mkdir(parents=True, exist_ok=True)
    if with_start_sh:
        start = repo_dir / "start.sh"
        start.write_text("#!/bin/bash\necho DEMO-APP-UP LLM=$FUSION_LLM_BASE_URL\nwhile true; do sleep 1; done\n")
        start.chmod(0o755)
    subprocess.run(["git", "init", "-q"], cwd=repo_dir, check=True)
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init", "--allow-empty"],
        cwd=repo_dir,
        check=True,
    )
    return str(repo_dir)


@pytest.fixture()
def runner(tmp_path):
    return DemoEnvRunner(
        host_llm_base_url="http://127.0.0.1:1",
        workspace_dir=str(tmp_path / "ws"),
    )


def test_derive_name_and_ssh_fallback():
    assert _derive_name("https://github.com/owner/ai-demo.git") == "ai-demo"
    assert _derive_name("https://github.com/owner/ai-demo") == "ai-demo"
    assert _derive_name("/local/path/my_app") == "my_app"
    with pytest.raises(DemoEnvError):
        _derive_name("https://host/x/not a name")
    assert _ssh_fallback("https://github.com/o/r.git") == "git@github.com:o/r.git"
    assert _ssh_fallback("/local/path") is None


def test_up_boots_app_and_reports_status(runner, tmp_path):
    repo = _make_repo(tmp_path / "repo-a")
    st = runner.up(repo)
    try:
        assert st["running"] is True
        assert st["name"] == "repo-a"
        assert st["llm_probe_ok"] is False
        time.sleep(1.5)
        st2 = runner.status()
        assert st2["running"] is True
        assert "DEMO-APP-UP" in st2["output_tail"]
        assert "LLM=http://127.0.0.1:1" in st2["output_tail"]
    finally:
        runner.stop()
    time.sleep(0.5)
    assert runner.status() is None


def test_up_idempotent_same_repo(runner, tmp_path):
    repo = _make_repo(tmp_path / "repo-b")
    st = runner.up(repo)
    try:
        st2 = runner.up(repo)
        assert st2["shell_id"] == st["shell_id"]
    finally:
        runner.stop()


def test_up_refuses_second_app_while_running(runner, tmp_path):
    repo_a = _make_repo(tmp_path / "repo-c")
    repo_b = _make_repo(tmp_path / "repo-d")
    runner.up(repo_a)
    try:
        with pytest.raises(DemoEnvError, match="单 app per guest"):
            runner.up(repo_b)
    finally:
        runner.stop()


def test_up_without_start_sh_fails_visibly(runner, tmp_path):
    repo = _make_repo(tmp_path / "repo-e", with_start_sh=False)
    with pytest.raises(DemoEnvError, match=r"无 start\.sh"):
        runner.up(repo)


def test_up_name_collision_stale_state_reused(runner, tmp_path):
    repo = _make_repo(tmp_path / "repo-f")
    runner.up(repo)
    runner.stop()
    st = runner.up(repo)
    try:
        assert st["running"] is True
    finally:
        runner.stop()


def test_stop_without_state_is_noop(runner):
    out = runner.stop()
    assert out == {"ok": True, "stopped": None}


def test_invalid_app_name_rejected(runner, tmp_path):
    repo = _make_repo(tmp_path / "ok-name")
    with pytest.raises(DemoEnvError, match="app 名非法"):
        runner.up(repo, name="../evil")


def test_probe_llm_endpoint_unreachable_is_informational(tmp_path):
    from fusion_executor.demo_env import probe_llm_endpoint

    ok, detail = probe_llm_endpoint("http://127.0.0.1:1")
    assert ok is False
    assert "不可达" in detail


def test_sandbox_profile_plumbed_through_shell_start():
    # issue #64 layer check: SandboxProfile param reaches the native shell path
    from fusion_executor import FusionSandboxExecutor

    e = FusionSandboxExecutor()
    r = e.shell_start("echo plumb", sandbox=SandboxProfile(network="allow"))
    try:
        assert r.ok
        time.sleep(0.5)
        out = e.shell_output(r.shell_id)
        assert "plumb" in out.output
    finally:
        e.kill_shell(r.shell_id)
