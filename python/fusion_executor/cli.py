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
    # M-5: 启动期 fail-fast — cwd 不存在 / sock 父目录不可写推迟到首请求难定位
    if cwd is not None and not Path(cwd).is_dir():
        print(f"错误: --cwd 目录不存在: {cwd}", file=sys.stderr)
        sys.exit(2)
    if check_sock:
        sock_path = sock or DEFAULT_SOCK
        # IMPL-1: 默认 socket 在 ~/.fusion-executor/ (HOME 私有 0o700), 该目录可能不存在。
        # serve() 会 ensure_socket_dir 创建, 此处先建以让父目录可写校验通过 (避免误拦首次启动)。
        ensure_socket_dir(sock_path)
        parent = Path(sock_path).parent
        if not parent.is_dir() or not os.access(parent, os.W_OK):
            print(f"错误: socket 父目录不可写: {parent}", file=sys.stderr)
            sys.exit(2)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fusion-executor",
        description="fusion-executor — 受控执行沙箱 + macOS 控制中枢",
    )
    # M-CLI-01: serve 作为 flag (非 subcommand), 保持裸命令模式为主路径 (Rule 11
    # 兼容旧用法 `fusion-executor echo hi`)。subcommand + bare positional argparse
    # 歧义 (echo v 被当 subcommand choice), flag 无歧义。
    parser.add_argument("--serve", action="store_true", help="启动 UDS JSON-RPC server (替代执行命令)")
    parser.add_argument(
        "--sock", default=None, help="serve 模式 socket 路径 (默认 ~/.fusion-executor/fe.sock, HOME 私有 0o700)"
    )
    parser.add_argument("command", nargs="?", help="要执行的命令 (serve 模式忽略)")
    parser.add_argument("--cwd", default=None, help="工作目录")
    parser.add_argument("--timeout-sec", type=float, default=30.0, help="超时秒 (超时退出码 -124)")
    parser.add_argument("--task-id", default=None, help="任务 id (透传结果)")
    parser.add_argument("--env", action="append", default=None, metavar="K=V", help="环境变量 (可多次)")
    parser.add_argument("--no-snapshot", action="store_true", help="禁用回滚快照")
    parser.add_argument("--auto-rollback", action="store_true", help="失败+文件毁损自动回滚")
    # D3-1 (审计 0827 product): 内联解释器网关 opt-in。默认 False (企业硬化拒 python -c / node -e /
    #   ruby -e / perl -e, 防 agent-driven 任意 payload 绕白名单语义); True 保留内联执行能力 (测试机/
    #   本地交互依赖 python3 -c)。
    parser.add_argument(
        "--allow-inline-interpreter",
        action="store_true",
        help="允许内联解释器 (python -c / node -e / ruby -e / perl -e; 企业硬化默认拒)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="调试日志")
    # Issue #64: demo/test 环境沙箱 runner (guest 单 ai-* app, LLM 走宿主网关)
    parser.add_argument(
        "--demo-up",
        default=None,
        metavar="REPO_URL",
        help="demo 环境: provision + 启动一个 ai-* app (单 app per guest, 幂等)",
    )
    parser.add_argument("--demo-status", action="store_true", help="demo 环境: 查询运行状态")
    parser.add_argument("--demo-stop", action="store_true", help="demo 环境: 停止运行中的 app")
    parser.add_argument("--demo-workspace", default=None, help="demo 工作区 (默认 ~/.fusion-executor/demo)")
    parser.add_argument(
        "--demo-llm-url",
        default=None,
        help="宿主 LLM 网关 (默认 http://127.0.0.1:11432; 注入 FUSION_LLM_BASE_URL/FUSION_MLX_URL)",
    )
    parser.add_argument(
        "--demo-env", action="append", default=None, metavar="K=V", help="demo app 附加环境变量 (可多次)"
    )
    return parser


def _parse_env(pairs: list[str] | None) -> dict[str, str] | None:
    if not pairs:
        return None
    out: dict[str, str] = {}
    for p in pairs:
        if "=" not in p:
            raise ValueError(f"--env 格式须 K=V, 得 {p!r}")
        k, v = p.split("=", 1)
        out[k] = v
    return out


def _run_demo(args: argparse.Namespace, log: logging.Logger) -> int:
    # Issue #64: demo 环境子模式 — up/status/stop 幂等动作, JSON 输出供演示脚本消费
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
        log.error("demo 环境失败: %s", e)
        return 1
    except (TypeError, ValueError) as e:
        log.error("参数错误: %s", e)
        return 2
    except Exception:
        log.exception("demo 环境异常")
        return 2


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    log = logging.getLogger("fusion_executor")

    # M-CLI-01: serve 模式
    if args.serve:
        # M-5: serve 校验 sock 父目录可写 (cwd 用 executor 默认, 不校验)
        _validate_paths(None, args.sock)
        try:
            FusionSandboxExecutor(allow_inline_interpreter=args.allow_inline_interpreter).serve(args.sock)
        except KeyboardInterrupt:
            log.info("serve interrupted (KeyboardInterrupt)")
            return 1
        return 0

    # Issue #64: demo 环境模式 — flag 驱动 (同 --serve, 避免 subcommand + bare positional 歧义)
    if args.demo_up or args.demo_status or args.demo_stop:
        return _run_demo(args, log)

    if not args.command:
        parser.print_help()
        return 0

    # M-5: 执行模式校验 cwd 存在 (sock 非执行路径, 不校验)
    _validate_paths(args.cwd, None, check_sock=False)

    # M-CLI-01: 包 try/except 退 2 (旧版裸 traceback); -124→124 (旧版 -1/-124 全 → 1)
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
        log.error("参数错误: %s", e)
        return 2
    except Exception:
        log.exception("执行异常")
        return 2
    # M-CLI-01: -124 超时映射 124 (旧版 -1/-124 全 → 1, 超时身份丢失); -1 blocked → 1
    if result.exit_code == -124:
        return 124
    if result.exit_code < 0:
        return 1
    return result.exit_code


if __name__ == "__main__":
    sys.exit(main())
