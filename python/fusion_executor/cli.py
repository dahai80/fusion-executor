from __future__ import annotations

import argparse
import json
import logging
import sys

from .executor import FusionSandboxExecutor


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="fusion-executor",
        description="fusion-executor — 受控执行沙箱 + macOS 控制中枢",
    )
    parser.add_argument("command", nargs="?", help="要执行的命令")
    parser.add_argument("--cwd", default=None, help="工作目录")
    parser.add_argument("--timeout", type=float, default=30.0, help="超时秒")
    parser.add_argument("-v", "--verbose", action="store_true", help="调试日志")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    if not args.command:
        parser.print_help()
        return 0

    executor = FusionSandboxExecutor()
    result = executor.run(args.command, cwd=args.cwd, timeout=args.timeout)
    print(json.dumps(result.model_dump(), ensure_ascii=False, indent=2))
    return result.exit_code if result.exit_code >= 0 else 1


if __name__ == "__main__":
    sys.exit(main())
