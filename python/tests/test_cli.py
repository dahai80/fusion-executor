from __future__ import annotations

import io
import json
from contextlib import redirect_stdout

import pytest

from fusion_executor import FusionSandboxExecutor, cli


def _run_main(argv: list[str]) -> tuple[int, str]:
    import sys

    old = sys.argv
    sys.argv = argv
    buf = io.StringIO()
    try:
        with redirect_stdout(buf):
            code = cli.main()
    finally:
        sys.argv = old
    return code, buf.getvalue()


def test_cli_main_runs_command():
    code, out = _run_main(["fusion-executor", "echo cli-ok"])
    assert code == 0
    data = json.loads(out)
    assert data["exit_code"] == 0
    assert "cli-ok" in data["stdout"]


def test_cli_main_no_command_prints_help():
    code, out = _run_main(["fusion-executor"])
    assert code == 0
    assert "usage:" in out.lower()


def test_cli_main_blocked_returns_nonzero():
    code, out = _run_main(["fusion-executor", "rm -rf /"])
    assert code == 1
    assert "blocked_by_security" in out


def test_cli_main_verbose_flag():
    code, out = _run_main(["fusion-executor", "echo v", "-v"])
    assert code == 0
    assert json.loads(out)["exit_code"] == 0


def test_run_async_echo():
    import asyncio

    ex = FusionSandboxExecutor()
    r = asyncio.run(ex.run_async("echo async-ok"))
    assert r.exit_code == 0
    assert "async-ok" in r.stdout


def test_rollback_without_cwd_raises():
    ex = FusionSandboxExecutor()
    with pytest.raises(ValueError, match="cwd"):
        ex.rollback("snap-id", cwd=None)


# ── T8 M-CLI-01: --serve flag + 退出码映射 ──


def test_cli_timeout_exit_code_124():
    # M-CLI-01: -124 超时映射 124 (旧版 -1/-124 全 → 1, 超时身份丢失)
    # D3-1: python3 -c 需 --allow-inline-interpreter opt-in (企业硬化默认拒内联解释器)
    code, out = _run_main(
        [
            "fusion-executor",
            "python3 -c 'import time; time.sleep(30)'",
            "--timeout-sec",
            "1",
            "--allow-inline-interpreter",
        ]
    )
    assert code == 124, f"超时应退 124, 得 {code}"
    data = json.loads(out)
    assert data["exit_code"] == -124
    assert data["timed_out"] is True


def test_cli_blocked_exit_code_1():
    # 已有 test_cli_main_blocked_returns_nonzero 覆盖 ==1; 此处显式断言语义
    code, _ = _run_main(["fusion-executor", "rm -rf /"])
    assert code == 1


def test_cli_env_flag_invalid_returns_2():
    # M-CLI-01: 参数错误 try/except → 退 2 (非裸 traceback)
    code, _ = _run_main(["fusion-executor", "echo hi", "--env", "NO_EQUALS_SIGN"])
    assert code == 2


def test_cli_env_flag_passes_value():
    # D3-1: python3 -c 需 --allow-inline-interpreter opt-in (企业硬化默认拒内联解释器)
    code, out = _run_main(
        [
            "fusion-executor",
            "python3 -c 'import os; print(os.environ.get(\"FE_FLAG\"))'",
            "--env",
            "FE_FLAG=on",
            "--allow-inline-interpreter",
        ]
    )
    assert code == 0
    assert "on" in json.loads(out)["stdout"]


def test_cli_m5_bad_cwd_exits_2():
    # M-5: --cwd 目录不存在 → 启动期 fail-fast sys.exit(2), 非延迟到首请求
    import pytest

    with pytest.raises(SystemExit) as ei:
        _run_main(["fusion-executor", "echo hi", "--cwd", "/nonexistent/m5/cwd/xyz"])
    assert ei.value.code == 2


def test_cli_m5_bad_sock_parent_exits_2():
    # M-5: --sock 父目录不存在 → serve 模式 fail-fast sys.exit(2)
    import pytest

    with pytest.raises(SystemExit) as ei:
        _run_main(["fusion-executor", "--serve", "--sock", "/nonexistent/m5/sock/parent/fe.sock"])
    assert ei.value.code == 2


def test_cli_serve_flag_starts_and_cleans_socket():
    # M-CLI-01 + C-PYO3-02: --serve 启 UDS server, SIGTERM 后 finally 清理 socket
    import os
    import socket
    import subprocess
    import sys
    import time

    sock_path = "/tmp/fe-test-serve-cli.sock"
    if os.path.exists(sock_path):
        os.unlink(sock_path)
    proc = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import sys; sys.argv=['fusion-executor','--serve','--sock','" + sock_path + "']; "
            "from fusion_executor.cli import main; main()",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        # 轮询 socket 出现 (serve 起来)
        deadline = time.time() + 8.0
        bound = False
        while time.time() < deadline:
            if os.path.exists(sock_path):
                # 确认可连 (可能 bind 中)
                try:
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                        s.settimeout(1.0)
                        s.connect(sock_path)
                    bound = True
                    break
                except OSError:
                    pass
            time.sleep(0.1)
        assert bound, "serve 应在 8s 内绑定 socket 并可连"
        # SIGTERM → Python signal handler 抛 KeyboardInterrupt → finally os.unlink
        proc.terminate()
        rc = proc.wait(timeout=8.0)
        assert rc in (0, -15, 1), f"serve SIGTERM 退出码异常: {rc}"
        assert not os.path.exists(sock_path), "serve 停机后应清理 socket"
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5.0)
        if os.path.exists(sock_path):
            os.unlink(sock_path)
