"""Example 07 — Bidirectional IPC server-push subscription.

Start a UDS JSON-RPC server (serve()), then subscribe to a broadcast channel.
The server pushes notification frames (no `id`, method `executor.event`):
  telemetry  -> 10Hz TelemetrySample (CPU/mem)
  stdio      -> chunk/done from commands run by other connections
  screenshot -> periodic screen capture (needs TCC Screen Recording)

This example starts the server in a subprocess on a private socket, subscribes
to telemetry, prints a few pushed frames, then unsubscribes and stops the
server.

    python examples/07_subscribe.py
"""

import logging
import os
import signal
import socket
import subprocess
import sys
import time

from fusion_executor import FusionSandboxExecutor

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

SOCK = "/tmp/fusion-executor-demo.sock"


def wait_for_sock(path: str, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.exists(path):
            return
        time.sleep(0.05)
    raise SystemExit(f"server socket {path} did not appear in {timeout}s")


def main() -> None:
    # Clean any stale socket, start the server on a private path.
    try:
        os.unlink(SOCK)
    except FileNotFoundError:
        pass

    env = dict(os.environ, FUSION_EXECUTOR_SOCK=SOCK)
    proc = subprocess.Popen([sys.executable, "-c", "from fusion_executor import FusionSandboxExecutor; FusionSandboxExecutor().serve()"], env=env)
    try:
        wait_for_sock(SOCK)
        print(f"server up on {SOCK} (pid={proc.pid})")

        ex = FusionSandboxExecutor()
        sub = ex.subscribe(["telemetry"], sock_path=SOCK, interval_ms=100, idle_timeout=3.0)
        print(f"subscribed: {sub._sub_id}")

        print("--- pushed telemetry frames ---")
        seen = 0
        for _ in range(5):
            frame = next(sub)
            data = frame["data"]
            print(f"  #{seen + 1} channel={frame['channel']} cpu={data.get('cpu_pct')}% mem={data.get('mem_mb')}MB")
            seen += 1

        ok = sub.unsubscribe()
        print(f"unsubscribe ok={ok}, saw {seen} frames")
        if seen == 0:
            raise SystemExit("no push frames received")
    finally:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=5.0)
        try:
            os.unlink(SOCK)
        except FileNotFoundError:
            pass
        print("server stopped.")


if __name__ == "__main__":
    main()
