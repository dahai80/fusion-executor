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


# ── T8 M-CLI-01: --serve flag + exit-code mapping ──


def test_cli_timeout_exit_code_124():
    # M-CLI-01: -124 timeout maps to 124 (old version mapped -1/-124 all → 1, losing timeout identity)
    # D3-1: python3 -c requires --allow-inline-interpreter opt-in (enterprise hardening rejects inline interpreters by default)
    code, out = _run_main(
        [
            "fusion-executor",
            "python3 -c 'import time; time.sleep(30)'",
            "--timeout-sec",
            "1",
            "--allow-inline-interpreter",
        ]
    )
    assert code == 124, f"timeout should exit 124, got {code}"
    data = json.loads(out)
    assert data["exit_code"] == -124
    assert data["timed_out"] is True


def test_cli_blocked_exit_code_1():
    # test_cli_main_blocked_returns_nonzero already covers ==1; here we assert the semantics explicitly
    code, _ = _run_main(["fusion-executor", "rm -rf /"])
    assert code == 1


def test_cli_env_flag_invalid_returns_2():
    # M-CLI-01: argument errors go through try/except → exit 2 (no bare traceback)
    code, _ = _run_main(["fusion-executor", "echo hi", "--env", "NO_EQUALS_SIGN"])
    assert code == 2


def test_cli_env_flag_passes_value():
    # D3-1: python3 -c requires --allow-inline-interpreter opt-in (enterprise hardening rejects inline interpreters by default)
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
    # M-5: --cwd directory missing → startup fail-fast sys.exit(2), not deferred to the first request
    import pytest

    with pytest.raises(SystemExit) as ei:
        _run_main(["fusion-executor", "echo hi", "--cwd", "/nonexistent/m5/cwd/xyz"])
    assert ei.value.code == 2


def test_cli_m5_bad_sock_parent_exits_2():
    # M-5: --sock parent directory missing → serve mode fail-fast sys.exit(2)
    import pytest

    with pytest.raises(SystemExit) as ei:
        _run_main(["fusion-executor", "--serve", "--sock", "/nonexistent/m5/sock/parent/fe.sock"])
    assert ei.value.code == 2


def test_cli_serve_flag_starts_and_cleans_socket():
    # M-CLI-01 + C-PYO3-02: --serve starts a UDS server, finally cleans up the socket after SIGTERM
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
        # poll for the socket to appear (serve is up)
        deadline = time.time() + 8.0
        bound = False
        while time.time() < deadline:
            if os.path.exists(sock_path):
                # confirm connectable (may still be binding)
                try:
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                        s.settimeout(1.0)
                        s.connect(sock_path)
                    bound = True
                    break
                except OSError:
                    pass
            time.sleep(0.1)
        assert bound, "serve should bind the socket and be connectable within 8s"
        # SIGTERM → Python signal handler raises KeyboardInterrupt → finally os.unlink
        proc.terminate()
        rc = proc.wait(timeout=8.0)
        assert rc in (0, -15, 1), f"serve SIGTERM exit code unexpected: {rc}"
        assert not os.path.exists(sock_path), "serve should clean up the socket after shutdown"
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5.0)
        if os.path.exists(sock_path):
            os.unlink(sock_path)


def test_cli_serve_keyboard_interrupt_exits_1(monkeypatch):
    # D6-09: --serve receiving KeyboardInterrupt should exit 1 (not 0), distinguishing interrupt from normal shutdown.
    import os

    sock = "/tmp/fe-test-cli-kbi.sock"
    if os.path.exists(sock):
        os.unlink(sock)

    def _raise_keyboardinterrupt(self, path=None):
        raise KeyboardInterrupt

    monkeypatch.setattr(FusionSandboxExecutor, "serve", _raise_keyboardinterrupt)
    code, _ = _run_main(["fusion-executor", "--serve", "--sock", sock])
    assert code == 1, f"D6-09: serve KeyboardInterrupt should exit 1, got {code}"
    if os.path.exists(sock):
        os.unlink(sock)
