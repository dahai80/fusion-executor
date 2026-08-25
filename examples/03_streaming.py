"""Example 03 — Live stdio streaming.

run_streaming() yields chunk strings as stdout arrives, then a final
ExecutionResult. The 4-layer path: fe-sandbox run_streaming (mpsc Chunk/Done)
-> fe-core execute_streaming -> fe-ipc NDJSON multi-frame -> fe-pyo3
NativeStreamIterator -> this Python generator.

    python examples/03_streaming.py

Contrast with run() (Example 01): run() returns only after the command
finishes; run_streaming() gives you output as it happens.
"""

import logging

from fusion_executor import FusionSandboxExecutor

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")


def main() -> None:
    ex = FusionSandboxExecutor()

    # A command that prints progressively — chunks arrive as lines flush.
    # (No command substitution: the Guard rejects $(...) / backticks to prevent
    # injection, so we use a plain python loop with literal output.)
    cmd = "python3 -c 'import sys,time\nfor i in range(1,6):\n    print(f\"line {i}\")\n    sys.stdout.flush()\n    time.sleep(0.2)'"

    print("--- streaming chunks ---")
    final = None
    for frame in ex.run_streaming(cmd, timeout_sec=10.0, enable_rollback_snapshot=False):
        if isinstance(frame, str):
            # chunk: partial stdout, print without trailing newline (chunk may bundle lines)
            print(f"  chunk: {frame!r}")
        else:
            # final ExecutionResult
            final = frame

    print("--- final result ---")
    if final is None:
        raise SystemExit("stream ended without a final ExecutionResult")
    print(f"exit_code    = {final.exit_code}")
    print(f"duration_sec = {final.duration_sec}")
    print(f"stdout       = {final.stdout!r}")

    if final.exit_code != 0:
        raise SystemExit(f"expected exit_code 0, got {final.exit_code}")


if __name__ == "__main__":
    main()
