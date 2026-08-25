"""Example 01 — Basic command execution.

Run a shell command, inspect the structured ExecutionResult.

    cd /Users/dahai/fusion && source .venv/bin/activate
    cd fusion-executor && maturin develop --release
    python examples/01_run_echo.py

Prerequisite: native extension built (`maturin develop --release`).
"""

import logging

from fusion_executor import FusionSandboxExecutor

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")


def main() -> None:
    ex = FusionSandboxExecutor()

    result = ex.run("echo 'hello fusion-executor'", task_id="demo-01")
    print(f"exit_code      = {result.exit_code}")
    print(f"stdout         = {result.stdout!r}")
    print(f"duration_sec   = {result.duration_sec}")
    print(f"task_id        = {result.task_id}")
    print(f"command        = {result.command}")
    print(f"timed_out      = {result.timed_out}")
    print(f"blocked        = {result.blocked_by_security}")

    if result.exit_code != 0:
        raise SystemExit(f"expected exit_code 0, got {result.exit_code}")


if __name__ == "__main__":
    main()
