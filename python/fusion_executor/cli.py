from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

from .executor import DEFAULT_SOCK, FusionSandboxExecutor, ensure_socket_dir
from .models import RollbackPolicy


def _validate_paths(cwd: str | None, sock: str | None, *, check_sock: bool = True) -> None:
    # M-5: startup fail-fast — a missing cwd / unwritable sock parent deferred to the first request is hard to locate
    if cwd is not None and not Path(cwd).is_dir():
        print(f"error: --cwd directory does not exist: {cwd}", file=sys.stderr)
        sys.exit(2)
    if check_sock:
        sock_path = sock or DEFAULT_SOCK
        # IMPL-1: the default socket lives in ~/.fusion-executor/ (HOME-private 0o700), which may not exist yet.
        # serve() would ensure_socket_dir; create it here first so the parent-writability check passes (avoid a false block on first start).
        ensure_socket_dir(sock_path)
        parent = Path(sock_path).parent
        if not parent.is_dir() or not os.access(parent, os.W_OK):
            print(f"error: socket parent directory is not writable: {parent}", file=sys.stderr)
            sys.exit(2)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fusion-executor",
        description="fusion-executor — controlled execution sandbox + macOS control hub",
    )
    # M-CLI-01: serve as a flag (not a subcommand), keeping bare-command mode the main path (Rule 11
    # compatible with the old usage `fusion-executor echo hi`). subcommand + bare positional argparse
    # is ambiguous (echo v parsed as a subcommand choice); a flag is unambiguous.
    parser.add_argument(
        "--serve", action="store_true", help="start the UDS JSON-RPC server (instead of executing a command)"
    )
    parser.add_argument(
        "--sock", default=None, help="serve-mode socket path (default ~/.fusion-executor/fe.sock, HOME-private 0o700)"
    )
    parser.add_argument("command", nargs="?", help="command to execute (ignored in serve mode)")
    parser.add_argument("--cwd", default=None, help="working directory")
    parser.add_argument("--timeout-sec", type=float, default=30.0, help="timeout seconds (timeout exit code -124)")
    parser.add_argument("--task-id", default=None, help="task id (passed through to the result)")
    parser.add_argument("--env", action="append", default=None, metavar="K=V", help="environment variable (repeatable)")
    parser.add_argument("--no-snapshot", action="store_true", help="disable the rollback snapshot")
    parser.add_argument("--auto-rollback", action="store_true", help="auto-rollback on failure + file damage")
    # D3-1 (audit 0827 product): inline-interpreter gateway opt-in. Default False (enterprise hardening rejects python -c / node -e /
    #   ruby -e / perl -e, preventing agent-driven arbitrary payloads from bypassing allowlist semantics); True keeps inline
    #   execution (test machines / local interaction rely on python3 -c).
    parser.add_argument(
        "--allow-inline-interpreter",
        action="store_true",
        help="allow inline interpreters (python -c / node -e / ruby -e / perl -e; enterprise hardening rejects by default)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    # Issue #64: demo/test environment sandbox runner (one ai-* app per guest, LLM via the host gateway)
    parser.add_argument(
        "--demo-up",
        default=None,
        metavar="REPO_URL",
        help="demo environment: provision + start one ai-* app (single app per guest, idempotent)",
    )
    parser.add_argument("--demo-status", action="store_true", help="demo environment: query running status")
    parser.add_argument("--demo-stop", action="store_true", help="demo environment: stop the running app")
    parser.add_argument("--demo-workspace", default=None, help="demo workspace (default ~/.fusion-executor/demo)")
    parser.add_argument(
        "--demo-llm-url",
        default=None,
        help="host LLM gateway (default http://127.0.0.1:11432; injected as FUSION_LLM_BASE_URL/FUSION_MLX_URL)",
    )
    parser.add_argument(
        "--demo-env", action="append", default=None, metavar="K=V", help="extra env var for the demo app (repeatable)"
    )
    return parser


def _parse_env(pairs: list[str] | None) -> dict[str, str] | None:
    if not pairs:
        return None
    out: dict[str, str] = {}
    for p in pairs:
        if "=" not in p:
            raise ValueError(f"--env format must be K=V, got {p!r}")
        k, v = p.split("=", 1)
        out[k] = v
    return out


def _run_demo(args: argparse.Namespace, log: logging.Logger) -> int:
    # Issue #64: demo environment submode — idempotent up/status/stop actions, JSON output for demo scripts
    from .demo_env import DemoEnvError, DemoEnvRunner

    try:
        runner = DemoEnvRunner(
            host_llm_base_url=args.demo_llm_url or "http://127.0.0.1:11432",
            workspace_dir=args.demo_workspace,
            extra_env=_parse_env(args.demo_env),
            executor=FusionSandboxExecutor(allow_inline_interpreter=args.allow_inline_interpreter),
        )
        if args.demo_up:
            info = runner.up(args.demo_up)
        elif args.demo_status:
            info = runner.status()
        else:
            info = runner.stop()
        print(json.dumps(info, ensure_ascii=False, indent=2))
        return 0
    except DemoEnvError as e:
        log.error("demo environment failed: %s", e)
        return 1
    except (TypeError, ValueError) as e:
        log.error("argument error: %s", e)
        return 2
    except Exception:
        log.exception("demo environment exception")
        return 2


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    log = logging.getLogger("fusion_executor")

    # M-CLI-01: serve mode
    if args.serve:
        # M-5: serve validates the sock parent writability (cwd uses the executor default, not validated)
        _validate_paths(None, args.sock)
        try:
            FusionSandboxExecutor(allow_inline_interpreter=args.allow_inline_interpreter).serve(args.sock)
        except KeyboardInterrupt:
            log.info("serve interrupted (KeyboardInterrupt)")
            return 1
        return 0

    # Issue #64: demo environment mode — flag-driven (same as --serve, avoiding subcommand + bare positional ambiguity)
    if args.demo_up or args.demo_status or args.demo_stop:
        return _run_demo(args, log)

    if not args.command:
        parser.print_help()
        return 0

    # M-5: execute mode validates cwd exists (sock is not the execute path, not validated)
    _validate_paths(args.cwd, None, check_sock=False)

    # M-CLI-01: wrap in try/except and exit 2 (old version dumped a bare traceback); -124→124 (old version mapped -1/-124 all → 1)
    try:
        env_vars = _parse_env(args.env)
        policy = RollbackPolicy() if args.auto_rollback else None
        executor = FusionSandboxExecutor(allow_inline_interpreter=args.allow_inline_interpreter)
        result = executor.run(
            args.command,
            cwd=args.cwd,
            timeout_sec=args.timeout_sec,
            task_id=args.task_id,
            env_vars=env_vars,
            enable_rollback_snapshot=not args.no_snapshot,
            auto_rollback=policy,
        )
        print(json.dumps(result.model_dump(), ensure_ascii=False, indent=2))
    except (TypeError, ValueError) as e:
        log.error("argument error: %s", e)
        return 2
    except Exception:
        log.exception("execution exception")
        return 2
    # M-CLI-01: -124 timeout maps to 124 (old version mapped -1/-124 all → 1, losing the timeout identity); -1 blocked → 1
    if result.exit_code == -124:
        return 124
    if result.exit_code < 0:
        return 1
    return result.exit_code


if __name__ == "__main__":
    sys.exit(main())
