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
