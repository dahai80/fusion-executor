"""Example 04 — Git snapshot + rollback.

Caller-driven rollback: snapshot_create() takes a git baseline, rollback()
restores it. The executor stays stateless per-task — your self-healing loop
owns the retry count and decides when to roll back.

This example builds a throwaway git repo in a temp dir, snapshots it,
corrupts a file via a failing command, then rolls back.

    python examples/04_rollback.py
"""

import logging
import subprocess
import tempfile
from pathlib import Path

from fusion_executor import FusionSandboxExecutor

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")


def git(cwd: Path, *args: str) -> str:
    out = subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, text=True, check=True)
    return out.stdout.strip()


def main() -> None:
    ex = FusionSandboxExecutor()

    with tempfile.TemporaryDirectory(prefix="fe-rollback-demo-") as td:
        repo = Path(td)
        git(repo, "init", "-q")
        git(repo, "config", "user.email", "demo@fusion.local")
        git(repo, "config", "user.name", "demo")
        app = repo / "app.py"
        app.write_text("def main():\n    return 1\n")
        git(repo, "add", "-A")
        git(repo, "commit", "-q", "-m", "init")

        print(f"repo: {repo}")
        print(f"before: {app.read_text()!r}")

        # Snapshot the clean baseline.
        snap = ex.snapshot_create(str(repo))
        print(f"snapshot_id: {snap}")

        # Corrupt the file (overwrite via a whitelisted python command), then fail.
        ex.run(
            f"python3 -c \"open('{app}', 'w').write('BROKEN')\"",
            cwd=str(repo),
            timeout_sec=5.0,
            enable_rollback_snapshot=False,
        )
        bad_cmd = "python3 -c 'raise SystemExit(1)'"
        result = ex.run(bad_cmd, cwd=str(repo), timeout_sec=5.0, enable_rollback_snapshot=False)
        print(f"corrupted: {app.read_text()!r}  (failing cmd exit={result.exit_code})")

        # Roll back to the snapshot.
        ok = ex.rollback(snap, cwd=str(repo))
        print(f"rollback ok={ok}")
        print(f"after: {app.read_text()!r}")

        if app.read_text() != "def main():\n    return 1\n":
            raise SystemExit("rollback did not restore the original file")


if __name__ == "__main__":
    main()
