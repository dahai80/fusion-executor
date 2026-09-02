from __future__ import annotations

import json
import os
import subprocess
import tempfile

import pytest

from fusion_executor import (
    EditResult,
    ExecutionResult,
    FusionSandboxExecutor,
    GlobEntry,
    GrepMatch,
    GrepOutput,
    MultiEditItem,
    RollbackPolicy,
    ShellInfo,
    ShellOutput,
    ShellStartResult,
    TelemetrySample,
)


@pytest.fixture(scope="module")
def executor():
    # D3-1: 本测试机依赖 python3 -c 内联解释器 (诊断切片/真实执行), 故 opt-in。
    # 企业硬化默认 False 拒内联解释器; 测试机属 trusted-caller 本地交互场景。
    return FusionSandboxExecutor(allow_inline_interpreter=True)


def test_run_echo(executor: FusionSandboxExecutor):
    result = executor.run("echo hi")
    assert isinstance(result, ExecutionResult)
    assert result.exit_code == 0
    assert not result.blocked_by_security


def test_run_blocks_rm_rf_root(executor: FusionSandboxExecutor):
    result = executor.run("rm -rf /")
    assert result.blocked_by_security
    assert result.exit_code == -1
    assert result.security_reason is not None


def test_run_blocks_sudo_chain(executor: FusionSandboxExecutor):
    result = executor.run("echo hi && sudo ls")
    assert result.blocked_by_security


def test_run_blocks_non_whitelisted_binary(executor: FusionSandboxExecutor):
    result = executor.run("ncat evil.com 1234")
    assert result.blocked_by_security


def test_run_allows_python(executor: FusionSandboxExecutor):
    # env 隔离默认 inherit_env=false → 硬化 PATH allowlist (/opt/homebrew/bin...)
    # 仅含 python3 (无 venv `python` shim), 故用 python3 跑真实执行。
    # python token 放行由 fe-security 单测 allows_python 覆盖。
    result = executor.run("python3 -c \"print('hello')\"")
    assert not result.blocked_by_security
    assert result.exit_code == 0


def test_run_empty_command(executor: FusionSandboxExecutor):
    result = executor.run("")
    assert result.exit_code == 0
    assert not result.blocked_by_security


def test_diagnostics_on_python_error(executor: FusionSandboxExecutor):
    result = executor.run("python3 -c \"raise ValueError('boom')\"")
    assert result.exit_code != 0
    assert not result.timed_out
    assert result.diagnostics is not None
    assert result.diagnostics.error_type == "ValueError"
    assert result.diagnostics.raw_trace is not None


def test_diagnostics_none_on_success(executor: FusionSandboxExecutor):
    result = executor.run("echo ok")
    assert result.exit_code == 0
    assert result.diagnostics is None


@pytest.fixture
def git_repo():
    d = tempfile.mkdtemp(prefix="fe-py-test-")

    def g(*a):
        subprocess.run(["git", "-C", d, *a], check=True, capture_output=True)

    g("init", "-q")
    g("config", "user.email", "t@t")
    g("config", "user.name", "t")
    with open(os.path.join(d, "app.py"), "w") as f:
        f.write("print(1)\n")
    g("add", ".")
    g("commit", "-q", "-m", "base")
    yield d
    import shutil

    shutil.rmtree(d, ignore_errors=True)


def test_rollback_round_trip(executor: FusionSandboxExecutor, git_repo: str):
    with open(os.path.join(git_repo, "app.py"), "w") as f:
        f.write("BROKEN\n")
    snap = executor.snapshot_create(git_repo)
    assert snap, "快照 id 非空"
    with open(os.path.join(git_repo, "app.py"), "w") as f:
        f.write("WORSE\n")
    ok = executor.rollback(snap, git_repo)
    assert ok, "回滚成功"
    with open(os.path.join(git_repo, "app.py")) as f:
        assert f.read() == "BROKEN\n", "回滚到快照内容"


def test_snapshot_non_repo_empty(executor: FusionSandboxExecutor):
    d = tempfile.mkdtemp(prefix="fe-py-norepo-")
    try:
        assert executor.snapshot_create(d) == ""
    finally:
        import shutil

        shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def uds_server():
    import sys
    import time

    fd, sp = tempfile.mkstemp(suffix=".sock", prefix="fe-tools-uds-")
    os.close(fd)
    os.unlink(sp)
    env = dict(os.environ, FUSION_EXECUTOR_SOCK=sp)
    proc = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "from fusion_executor import FusionSandboxExecutor; FusionSandboxExecutor(allow_inline_interpreter=True).serve()",
        ],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        deadline = time.time() + 10.0
        while time.time() < deadline:
            if os.path.exists(sp):
                break
            time.sleep(0.05)
        else:
            raise TimeoutError(f"socket 未出现: {sp}")
        yield sp
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        if os.path.exists(sp):
            os.unlink(sp)


def _consume_stream(executor: FusionSandboxExecutor, command: str, **kw):
    chunks: list[str] = []
    result = None
    for frame in executor.run_streaming(command, enable_rollback_snapshot=False, **kw):
        if isinstance(frame, ExecutionResult):
            result = frame
        else:
            chunks.append(frame)
    return chunks, result


def test_run_streaming_echo(executor: FusionSandboxExecutor):
    chunks, result = _consume_stream(executor, "echo hi")
    assert result is not None
    assert result.exit_code == 0
    assert not result.timed_out
    assert "hi" in "".join(chunks)
    assert "hi" in result.stdout


def test_run_streaming_blocked_single_result(executor: FusionSandboxExecutor):
    chunks, result = _consume_stream(executor, "rm -rf /")
    assert result is not None
    assert result.blocked_by_security
    assert result.exit_code == -1
    assert chunks == [], "拦截应无 chunk, 仅单帧 result"


def test_run_streaming_timeout(executor: FusionSandboxExecutor):
    _chunks, result = _consume_stream(executor, 'python3 -c "while True: pass"', timeout_sec=1.0)
    assert result is not None
    assert result.timed_out
    assert result.exit_code == -124


def test_run_streaming_diagnostics_on_error(executor: FusionSandboxExecutor):
    _chunks, result = _consume_stream(executor, "python3 -c \"raise ValueError('boom')\"")
    assert result is not None
    assert result.exit_code != 0
    assert result.diagnostics is not None
    assert result.diagnostics.error_type == "ValueError"


def test_seatbelt_fs_deny_is_best_effort(executor: FusionSandboxExecutor, tmp_path):
    # 0827 C-16/A-12: seatbelt 层删 DANGEROUS_BINS process-exec denylist (A-12 —
    # 黑名单不可枚举, rm 重命名/symlink 绕过; 二进制隔离由 fe-security Stage-2 allowlist 主导),
    # 改加定向 SENSITIVE_FS_PATHS file-write* deny (C-16 — best-effort, Darwin 25 全局
    # file-write* 失效但定向 literal 或可用, 失效退回无 FS 保护不误报)。
    # 本测试验证 A-12 后的隔离现状: seatbelt 不再 deny /bin/rm execve (denylist 已删),
    # 白名单二进制 (echo/python3) 正常执行 (allow default); rm 的毁灭性删除由 fe-security
    # 正则黑名单 + C-16 定向 FS deny 兜底, 非 seatbelt process-exec 层。
    probe = tmp_path / "probe.py"
    probe.write_text(
        "import os\n"
        "try:\n"
        '    os.execve("/bin/rm", ["rm", "/nonexistent_seatbelt_probe"], {})\n'
        "except OSError as e:\n"
        '    print(f"execve_attempted errno={e.errno} msg={e.strerror}")\n'
    )
    cmd = f"python3 {probe}; echo probe_exit=$?"
    r_off = executor.run(cmd, seatbelt=False)
    assert not r_off.blocked_by_security, "seatbelt off 不应被安全层拦"
    r_on = executor.run(cmd, seatbelt=True)
    assert not r_on.blocked_by_security, "seatbelt on 不应被安全层拦 (python3 白名单)"
    assert "probe_exit=" in r_on.stdout, "seatbelt on 白名单 python3 carrier 应正常执行 (allow default)"


def test_seatbelt_allows_whitelisted_echo(executor: FusionSandboxExecutor):
    # seatbelt=True 不影响白名单命令正常执行 (allow default)。
    result = executor.run("echo seatbelt_ok", seatbelt=True)
    assert result.exit_code == 0
    assert not result.blocked_by_security
    assert "seatbelt_ok" in result.stdout


def test_seatbelt_default_true_all_layers_no_drift():
    # D1-2/D2-3 (审计 0827 arch ARCH-1 + product): seatbelt 默认值 4 层须一致 True。
    # 历史 drift — models.py Pydantic 默认 False, 而 executor.run/run_async/shell_start 默认 True +
    # Rust serde default_true。任一层默认 False = 商用静默关隔离 (绕 ARCH-1)。此测试锁住统一。
    import inspect

    from fusion_executor.models import ExecutionRequest

    # 层 1: Pydantic ExecutionRequest 默认 True
    assert ExecutionRequest(command="x").seatbelt is True, "ExecutionRequest.seatbelt 默认须 True"

    # 层 2-3: FusionSandboxExecutor.run / run_streaming / shell_start 签名默认 True
    # (run_async 吸收 **kw 转发 run, 无独立 seatbelt 形参, 不入此检查)
    for name in ("run", "run_streaming", "shell_start"):
        fn = getattr(FusionSandboxExecutor, name)
        sig = inspect.signature(fn)
        param = sig.parameters.get("seatbelt")
        assert param is not None, f"{name} 须有 seatbelt 参数"
        assert param.default is True, f"{name} seatbelt 默认须 True, 实际 {param.default!r}"

    # 层 4: Rust serde default_true — Python ExecutionRequest 默认 True → 序列化含 seatbelt=true
    # (native 反序列化对齐; ARCH-1 health 已断言 seatbelt_default_on)。
    req = ExecutionRequest(command="echo drift_check")
    dumped = req.model_dump()
    assert dumped.get("seatbelt") is True, f"默认 request 序列化 seatbelt 须 True, 实际 {dumped.get('seatbelt')}"


def test_run_populates_schema_fields(executor: FusionSandboxExecutor):
    result = executor.run("echo hi", task_id="task-abc")
    assert result.task_id == "task-abc"
    assert result.command == "echo hi"
    assert result.duration_sec > 0.0


def test_run_blocked_preserves_task_id_and_command(executor: FusionSandboxExecutor):
    result = executor.run("rm -rf /", task_id="blocked-1")
    assert result.task_id == "blocked-1"
    assert result.command == "rm -rf /"
    assert result.blocked_by_security
    assert result.duration_sec == 0.0


def test_run_streaming_done_has_schema_fields(executor: FusionSandboxExecutor):
    _chunks, result = _consume_stream(executor, "echo hi", task_id="stream-1")
    assert result is not None
    assert result.task_id == "stream-1"
    assert result.command == "echo hi"
    assert result.duration_sec > 0.0


# ── M-OPS-06: trace_id 跨层关联 (auto-gen + forwarded + blocked + streaming) ──


def test_run_trace_id_auto_generated(executor: FusionSandboxExecutor):
    result = executor.run("echo t")
    assert result.trace_id is not None
    assert len(result.trace_id) == 36
    assert result.trace_id.count("-") == 4


def test_run_trace_id_forwarded(executor: FusionSandboxExecutor):
    result = executor.run("echo t", trace_id="caller-tid-999")
    assert result.trace_id == "caller-tid-999"


def test_run_trace_id_on_blocked(executor: FusionSandboxExecutor):
    result = executor.run("rm -rf /", trace_id="blk-tid-1")
    assert result.blocked_by_security
    assert result.trace_id == "blk-tid-1"


def test_run_streaming_trace_id(executor: FusionSandboxExecutor):
    _chunks, result = _consume_stream(executor, "echo s", trace_id="stream-tid-1")
    assert result is not None
    assert result.trace_id == "stream-tid-1"


# ── Issue #3: RLIMIT_NPROC/CPU 注入 (run + run_streaming 4-layer 端到端) ──
# Darwin RLIMIT_NPROC per-UID spread-limiter: 低值令 sh 自身 fork python3 EAGAIN,
# 故测可观测 rlimit (python resource.getrlimit 读回注入值), 确定性无 fork 依赖。


def test_run_injects_rlimits(executor: FusionSandboxExecutor):
    # 注入经 `ulimit -u/-t`; setrlimit 软上限不能超硬上限 — CI runner 硬上限可能 < 请求值 (如 1333),
    # 内核静默 clamp。断言观测值 ≤ 请求 且受内核硬限约束, 不写死 2048。
    probe = (
        "python3 -c 'import resource; "
        'print("NPROC", resource.getrlimit(resource.RLIMIT_NPROC)[0], resource.getrlimit(resource.RLIMIT_NPROC)[1]); '
        'print("CPU", resource.getrlimit(resource.RLIMIT_CPU)[0])\''
    )
    result = executor.run(probe, max_nproc=2048, max_cpu_sec=15)
    assert result.exit_code == 0, f"probe 应 exit 0, stdout={result.stdout}"
    nproc_line = next(ln for ln in result.stdout.splitlines() if ln.startswith("NPROC"))
    nproc_soft, nproc_hard = nproc_line.split()[1], nproc_line.split()[2]
    assert int(nproc_soft) <= 2048, f"软 NPROC 应 ≤ 请求 2048, 得 {nproc_soft}"
    assert int(nproc_soft) <= int(nproc_hard), f"软 NPROC 应 ≤ 硬上限, soft={nproc_soft} hard={nproc_hard}"
    assert int(nproc_soft) > 0, f"注入后 NPROC 应非零, 得 {nproc_soft}"
    assert "CPU 15" in result.stdout, f"应观测注入 CPU=15, stdout={result.stdout}"


def test_run_rlimits_default_zero_cpu(executor: FusionSandboxExecutor):
    probe = "python3 -c 'import resource; print(\"CPU\", resource.getrlimit(resource.RLIMIT_CPU)[0])'"
    result = executor.run(probe)
    assert result.exit_code == 0
    # 默认 max_cpu_sec=0 → RLIMIT_CPU 上限应是 unlimited (0 或大数, 非有限值如 15)
    cpu_val = result.stdout.split("CPU")[1].strip()
    assert cpu_val in ("0", "9223372036854775807", "-1"), f"默认 CPU 应不限, 得 {cpu_val}"


def test_run_rejects_negative_nproc(executor: FusionSandboxExecutor):
    try:
        executor.run("echo hi", max_nproc=-1)
        raise AssertionError("max_nproc<0 应抛 ValueError")
    except ValueError:
        pass


def test_run_streaming_injects_rlimits(executor: FusionSandboxExecutor):
    # 同 test_run_injects_rlimits: 软上限受内核硬限 clamp, 不写死 2048。
    probe = "python3 -c 'import resource; print(\"NPROC\", resource.getrlimit(resource.RLIMIT_NPROC)[0], resource.getrlimit(resource.RLIMIT_NPROC)[1])'"
    _chunks, result = _consume_stream(executor, probe, max_nproc=2048)
    assert result is not None
    assert result.exit_code == 0
    nproc_line = next(ln for ln in result.stdout.splitlines() if ln.startswith("NPROC"))
    nproc_soft, nproc_hard = nproc_line.split()[1], nproc_line.split()[2]
    assert int(nproc_soft) <= 2048, f"软 NPROC 应 ≤ 请求 2048, 得 {nproc_soft}"
    assert int(nproc_soft) <= int(nproc_hard), f"软 NPROC 应 ≤ 硬上限, soft={nproc_soft} hard={nproc_hard}"
    assert int(nproc_soft) > 0, f"注入后 NPROC 应非零, 得 {nproc_soft}"


# ── 原生文件工具 (fe-tools) ──


def test_file_edit_unique_replace(executor: FusionSandboxExecutor, tmp_path):
    fp = tmp_path / "app.py"
    fp.write_text("x = 1\ny = 2\n")
    r = executor.file_edit("app.py", "x = 1", "x = 99", cwd=str(tmp_path))
    assert isinstance(r, EditResult)
    assert r.ok
    assert r.matches == 1
    assert fp.read_text() == "x = 99\ny = 2\n"


def test_file_edit_ambiguous_rejected(executor: FusionSandboxExecutor, tmp_path):
    fp = tmp_path / "a.txt"
    fp.write_text("dup\ndup\n")
    r = executor.file_edit("a.txt", "dup", "one", cwd=str(tmp_path))
    assert not r.ok
    assert r.matches == 2
    assert fp.read_text() == "dup\ndup\n"


def test_glob_python_files(executor: FusionSandboxExecutor, tmp_path):
    (tmp_path / "a.py").write_text("")
    (tmp_path / "b.py").write_text("")
    (tmp_path / "c.txt").write_text("")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "d.py").write_text("")
    entries = executor.glob("**/*.py", cwd=str(tmp_path))
    paths = sorted(e.path for e in entries)
    assert paths == ["a.py", "b.py", "sub/d.py"]
    assert all(isinstance(e, GlobEntry) for e in entries)


def test_grep_matches_lines(executor: FusionSandboxExecutor, tmp_path):
    (tmp_path / "a.py").write_text("import os\nx = 1\nimport sys\n")
    ms = executor.grep(r"^import\s", ["a.py"], cwd=str(tmp_path))
    assert len(ms) == 2
    assert all(isinstance(m, GrepMatch) for m in ms)
    assert ms[0].line_number == 1
    assert ms[0].content == "import os"
    assert ms[1].line_number == 3


def test_grep_with_opts_files_with_matches(executor: FusionSandboxExecutor, tmp_path):
    (tmp_path / "a.py").write_text("TODO fix\n")
    (tmp_path / "b.py").write_text("nope\n")
    (tmp_path / "c.py").write_text("TODO again\n")
    out = executor.grep_with_opts("TODO", ["."], {"output_mode": "files_with_matches"}, cwd=str(tmp_path))
    assert isinstance(out, GrepOutput)
    assert out.output_mode == "files_with_matches"
    assert out.matches == []
    assert sorted(out.files) == ["a.py", "c.py"]


def test_grep_with_opts_count_mode(executor: FusionSandboxExecutor, tmp_path):
    (tmp_path / "a.py").write_text("todo\ntodo\ntodo\n")
    out = executor.grep_with_opts("todo", ["a.py"], {"output_mode": "count"}, cwd=str(tmp_path))
    assert len(out.counts) == 1
    assert out.counts[0].path == "a.py"
    assert out.counts[0].count == 3


def test_grep_with_opts_context(executor: FusionSandboxExecutor, tmp_path):
    (tmp_path / "a.py").write_text("l1\nl2\nl3\nMARK\nl5\nl6\nl7\n")
    out = executor.grep_with_opts("MARK", ["a.py"], {"before": 2, "after": 1}, cwd=str(tmp_path))
    assert len(out.matches) == 1
    m = out.matches[0]
    assert m.line_number == 4
    assert m.content == "MARK"
    assert m.context_before == ["l2", "l3"]
    assert m.context_after == ["l5"]


def test_grep_with_opts_multiline(executor: FusionSandboxExecutor, tmp_path):
    (tmp_path / "a.py").write_text("foo\nmiddle\nbar\n")
    out = executor.grep_with_opts("foo.*bar", ["a.py"], {"multiline": True}, cwd=str(tmp_path))
    assert len(out.matches) == 1
    assert out.matches[0].line_number == 1
    assert out.matches[0].content == "foo\nmiddle\nbar"


def test_grep_with_opts_glob_filter(executor: FusionSandboxExecutor, tmp_path):
    (tmp_path / "a.py").write_text("MARK\n")
    (tmp_path / "b.rs").write_text("MARK\n")
    (tmp_path / "c.txt").write_text("MARK\n")
    inc = executor.grep_with_opts(
        "MARK",
        ["."],
        {"output_mode": "files_with_matches", "glob_include": ["*.py"]},
        cwd=str(tmp_path),
    )
    assert inc.files == ["a.py"]
    exc = executor.grep_with_opts(
        "MARK",
        ["."],
        {"output_mode": "files_with_matches", "glob_exclude": ["*.rs"]},
        cwd=str(tmp_path),
    )
    assert sorted(exc.files) == ["a.py", "c.txt"]


def test_glob_gitignore_aware(executor: FusionSandboxExecutor, tmp_path):
    (tmp_path / ".gitignore").write_text("ignored.py\n")
    (tmp_path / "ignored.py").write_text("x\n")
    (tmp_path / "kept.py").write_text("y\n")
    entries = executor.glob("*.py", cwd=str(tmp_path))
    paths = [e.path for e in entries]
    assert "kept.py" in paths
    assert "ignored.py" not in paths


def test_apply_patch_simple(executor: FusionSandboxExecutor, tmp_path):
    fp = tmp_path / "app.py"
    fp.write_text("line1\nline2\nline3\n")
    diff = "--- a/app.py\n+++ b/app.py\n@@ -1,3 +1,4 @@\n line1\n line2\n+line2b\n line3\n"
    r = executor.apply_patch(diff, cwd=str(tmp_path))
    assert r.ok
    assert fp.read_text() == "line1\nline2\nline2b\nline3\n"


def test_replace_function_python(executor: FusionSandboxExecutor, tmp_path):
    fp = tmp_path / "mod.py"
    fp.write_text("def old():\n    return 1\n\ndef keep():\n    return 2\n")
    r = executor.replace_function("mod.py", "old", "def old():\n    return 99\n", cwd=str(tmp_path))
    assert r.ok
    after = fp.read_text()
    assert "return 99" in after
    assert "return 2" in after
    assert "return 1" not in after


def test_replace_function_not_found(executor: FusionSandboxExecutor, tmp_path):
    fp = tmp_path / "mod.py"
    fp.write_text("def keep():\n    return 2\n")
    r = executor.replace_function("mod.py", "ghost", "def ghost():\n    pass\n", cwd=str(tmp_path))
    assert not r.ok
    assert "未找到" in r.error


# ── Issue #6: replace_all / MultiEdit 原子批改 / NotebookEdit ──


def test_file_edit_replace_all_replaces_every_occurrence(executor: FusionSandboxExecutor, tmp_path):
    fp = tmp_path / "dup.txt"
    fp.write_text("foo\nfoo\nfoo\n")
    r = executor.file_edit("dup.txt", "foo", "bar", cwd=str(tmp_path), replace_all=True)
    assert isinstance(r, EditResult)
    assert r.ok
    assert r.matches == 3
    assert fp.read_text() == "bar\nbar\nbar\n"


def test_file_edit_replace_all_false_default_preserves_unique_check(executor: FusionSandboxExecutor, tmp_path):
    fp = tmp_path / "ambig.txt"
    fp.write_text("x\nx\n")
    r = executor.file_edit("ambig.txt", "x", "y", cwd=str(tmp_path))
    assert not r.ok
    assert r.matches == 2
    assert fp.read_text() == "x\nx\n"


def test_multi_edit_all_succeed_atomic(executor: FusionSandboxExecutor, tmp_path):
    fp = tmp_path / "app.py"
    fp.write_text("a = 1\nb = 2\nc = 3\n")
    r = executor.multi_edit(
        "app.py",
        [
            {"old_string": "a = 1", "new_string": "a = 11"},
            {"old_string": "c = 3", "new_string": "c = 33"},
        ],
        cwd=str(tmp_path),
    )
    assert isinstance(r, EditResult)
    assert r.ok
    assert r.matches == 2
    assert fp.read_text() == "a = 11\nb = 2\nc = 33\n"


def test_multi_edit_partial_failure_no_write(executor: FusionSandboxExecutor, tmp_path):
    fp = tmp_path / "app.py"
    original = "a = 1\nb = 2\n"
    fp.write_text(original)
    r = executor.multi_edit(
        "app.py",
        [
            {"old_string": "a = 1", "new_string": "a = 11"},
            {"old_string": "ghost", "new_string": "x"},  # 第 2 项未匹配 → 全回滚
        ],
        cwd=str(tmp_path),
    )
    assert not r.ok
    assert "第 2" in r.error or "未匹配" in r.error
    assert fp.read_text() == original, "部分失败: 文件未被修改 (all-or-nothing)"


def test_multi_edit_per_item_replace_all(executor: FusionSandboxExecutor, tmp_path):
    fp = tmp_path / "m.txt"
    fp.write_text("p\np\nq\n")
    r = executor.multi_edit(
        "m.txt",
        [MultiEditItem(old_string="p", new_string="P", replace_all=True)],
        cwd=str(tmp_path),
    )
    assert r.ok
    assert r.matches == 2
    assert fp.read_text() == "P\nP\nq\n"


# ── #2 write_file: 整文件创建/覆盖 + 建父目录 (Claude Code Write parity) ──


def test_write_file_creates_new_with_parent_dirs(executor: FusionSandboxExecutor, tmp_path):
    r = executor.write_file("nested/deep/new.py", "x = 1\n", cwd=str(tmp_path))
    assert isinstance(r, EditResult)
    assert r.ok
    assert r.matches == 1
    assert (tmp_path / "nested" / "deep" / "new.py").read_text() == "x = 1\n"


def test_write_file_overwrites_existing(executor: FusionSandboxExecutor, tmp_path):
    fp = tmp_path / "old.txt"
    fp.write_text("old content\n")
    r = executor.write_file("old.txt", "brand new\n", cwd=str(tmp_path))
    assert r.ok
    assert fp.read_text() == "brand new\n"


def test_write_file_rejects_oversize_content(executor: FusionSandboxExecutor, tmp_path):
    big = "A" * (64 * 1024 * 1024 + 1)
    r = executor.write_file("big.txt", big, cwd=str(tmp_path))
    assert not r.ok
    assert "超大小上限" in (r.error or "")
    assert not (tmp_path / "big.txt").exists()


def test_file_edit_create_on_empty_missing_path(executor: FusionSandboxExecutor, tmp_path):
    # #2: 路径不存在 + old_string 空 → 用 new_string 建文件
    r = executor.file_edit("new_via_edit.py", "", "created = True\n", cwd=str(tmp_path))
    assert r.ok
    assert (tmp_path / "new_via_edit.py").read_text() == "created = True\n"


def test_file_edit_existing_empty_old_string_still_rejected(executor: FusionSandboxExecutor, tmp_path):
    fp = tmp_path / "exists.txt"
    fp.write_text("data\n")
    r = executor.file_edit("exists.txt", "", "x\n", cwd=str(tmp_path))
    assert not r.ok
    assert "不能为空" in (r.error or "")
    assert fp.read_text() == "data\n", "已存在文件空 old_string 不应写入"


def test_file_edit_missing_path_nonempty_old_string_rejected(executor: FusionSandboxExecutor, tmp_path):
    r = executor.file_edit("ghost.py", "old", "new\n", cwd=str(tmp_path))
    assert not r.ok
    assert "未找到" in (r.error or "")
    assert not (tmp_path / "ghost.py").exists()


def _write_minimal_nb(path, n_cells: int = 2) -> None:
    cells = [
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [f"# cell {i}\n"],
        }
        for i in range(n_cells)
    ]
    path.write_text(
        json.dumps(
            {
                "nbformat": 4,
                "nbformat_minor": 5,
                "metadata": {},
                "cells": cells,
            },
            ensure_ascii=False,
        )
    )


def test_notebook_edit_replace_by_number(executor: FusionSandboxExecutor, tmp_path):
    fp = tmp_path / "nb.ipynb"
    _write_minimal_nb(fp, 2)
    r = executor.notebook_edit("nb.ipynb", "# replaced\n", cell_number=0, edit_mode="replace", cwd=str(tmp_path))
    assert isinstance(r, EditResult)
    assert r.ok
    nb = json.loads(fp.read_text())
    assert nb["cells"][0]["source"] == ["# replaced\n"]
    assert nb["cells"][1]["source"] == ["# cell 1\n"]
    assert len(nb["cells"]) == 2


def test_notebook_edit_insert_by_id(executor: FusionSandboxExecutor, tmp_path):
    fp = tmp_path / "nb.ipynb"
    _write_minimal_nb(fp, 1)
    r = executor.notebook_edit("nb.ipynb", "# inserted\n", cell_id=None, edit_mode="insert", cwd=str(tmp_path))
    assert r.ok
    nb = json.loads(fp.read_text())
    assert len(nb["cells"]) == 2
    assert nb["cells"][1]["source"] == ["# inserted\n"]


def test_notebook_edit_delete_by_number(executor: FusionSandboxExecutor, tmp_path):
    fp = tmp_path / "nb.ipynb"
    _write_minimal_nb(fp, 2)
    r = executor.notebook_edit("nb.ipynb", "", cell_number=0, edit_mode="delete", cwd=str(tmp_path))
    assert r.ok
    nb = json.loads(fp.read_text())
    assert len(nb["cells"]) == 1
    assert nb["cells"][0]["source"] == ["# cell 1\n"]


def test_notebook_edit_missing_id_degrades(executor: FusionSandboxExecutor, tmp_path):
    fp = tmp_path / "nb.ipynb"
    _write_minimal_nb(fp, 1)
    original = fp.read_text()
    r = executor.notebook_edit("nb.ipynb", "x", cell_number=9, edit_mode="replace", cwd=str(tmp_path))
    assert not r.ok
    assert fp.read_text() == original, "无效 cell_number → 不修改文件 (降级返回)"


def test_notebook_edit_rejects_non_ipynb(executor: FusionSandboxExecutor, tmp_path):
    fp = tmp_path / "notnb.txt"
    fp.write_text("hello\n")
    r = executor.notebook_edit("notnb.txt", "x", cell_number=0, cwd=str(tmp_path))
    assert not r.ok


def _rpc_once(sock: str, req: dict) -> dict:
    import json
    import socket

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(15.0)
        s.connect(sock)
        s.sendall((json.dumps(req, ensure_ascii=False) + "\n").encode("utf-8"))
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
    return json.loads(buf.decode("utf-8").strip())


def test_file_edit_over_uds_roundtrip(uds_server: str, tmp_path):
    fp = tmp_path / "app.py"
    fp.write_text("hello\n")
    resp = _rpc_once(
        uds_server,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "executor.file_edit",
            "params": {
                "path": "app.py",
                "old_string": "hello",
                "new_string": "world",
                "cwd": str(tmp_path),
            },
        },
    )
    assert resp["result"]["ok"] is True
    assert resp["result"]["matches"] == 1
    assert fp.read_text() == "world\n"


def test_write_file_over_uds_roundtrip(uds_server: str, tmp_path):
    resp = _rpc_once(
        uds_server,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "executor.write_file",
            "params": {
                "path": "sub/created.py",
                "content": "print('hi')\n",
                "cwd": str(tmp_path),
            },
        },
    )
    assert resp["result"]["ok"] is True
    assert resp["result"]["matches"] == 1
    assert (tmp_path / "sub" / "created.py").read_text() == "print('hi')\n"


def test_glob_over_uds_roundtrip(uds_server: str, tmp_path):
    (tmp_path / "a.py").write_text("")
    (tmp_path / "b.py").write_text("")
    resp = _rpc_once(
        uds_server,
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "executor.glob",
            "params": {"pattern": "*.py", "cwd": str(tmp_path)},
        },
    )
    paths = sorted(e["path"] for e in resp["result"])
    assert paths == ["a.py", "b.py"]


def test_grep_with_opts_over_uds_roundtrip(uds_server: str, tmp_path):
    (tmp_path / "a.py").write_text("TODO fix\n")
    (tmp_path / "b.py").write_text("TODO again\n")
    resp = _rpc_once(
        uds_server,
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "executor.grep_with_opts",
            "params": {
                "pattern": "TODO",
                "paths": ["."],
                "opts": {"output_mode": "files_with_matches"},
                "cwd": str(tmp_path),
            },
        },
    )
    assert resp["result"]["output_mode"] == "files_with_matches"
    assert sorted(resp["result"]["files"]) == ["a.py", "b.py"]


def test_multi_edit_over_uds_roundtrip(uds_server: str, tmp_path):
    fp = tmp_path / "app.py"
    fp.write_text("a = 1\nb = 2\n")
    resp = _rpc_once(
        uds_server,
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "executor.multi_edit",
            "params": {
                "path": "app.py",
                "edits": [
                    {"old_string": "a = 1", "new_string": "a = 11", "replace_all": False},
                    {"old_string": "b = 2", "new_string": "b = 22"},
                ],
                "cwd": str(tmp_path),
            },
        },
    )
    assert resp["result"]["ok"] is True
    assert resp["result"]["matches"] == 2
    assert fp.read_text() == "a = 11\nb = 22\n"


def test_notebook_edit_over_uds_roundtrip(uds_server: str, tmp_path):
    fp = tmp_path / "nb.ipynb"
    _write_minimal_nb(fp, 1)
    resp = _rpc_once(
        uds_server,
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "executor.notebook_edit",
            "params": {
                "path": "nb.ipynb",
                "new_source": "# uds replaced\n",
                "cell_id": None,
                "cell_number": 0,
                "edit_mode": "replace",
                "cwd": str(tmp_path),
            },
        },
    )
    assert resp["result"]["ok"] is True
    nb = json.loads(fp.read_text())
    assert nb["cells"][0]["source"] == ["# uds replaced\n"]


# ── 自动回滚 (FR-04 auto policy) ──


def test_auto_rollback_triggers_on_failure_with_file_damage(executor: FusionSandboxExecutor, git_repo: str):
    with open(os.path.join(git_repo, "app.py")) as f:
        assert f.read() == "print(1)\n"
    cmd = "python3 -c \"open('app.py','w').write('broken\\n'); raise ValueError(1)\""
    result = executor.run(cmd, cwd=git_repo, auto_rollback=RollbackPolicy())
    assert result.exit_code != 0
    assert result.auto_rolled_back is True
    with open(os.path.join(git_repo, "app.py")) as f:
        assert f.read() == "print(1)\n", "文件已回滚到基线"


def test_auto_rollback_skipped_when_exit_ok(executor: FusionSandboxExecutor, git_repo: str):
    result = executor.run("echo ok", cwd=git_repo, auto_rollback=RollbackPolicy())
    assert result.exit_code == 0
    assert result.auto_rolled_back is False


def test_auto_rollback_no_policy_means_no_action(executor: FusionSandboxExecutor, git_repo: str):
    cmd = "python3 -c \"open('app.py','w').write('broken\\n'); raise ValueError(1)\""
    result = executor.run(cmd, cwd=git_repo)
    assert result.exit_code != 0
    assert result.auto_rolled_back is False
    with open(os.path.join(git_repo, "app.py")) as f:
        assert f.read() == "broken\n", "无 policy 不回滚, 改动保留"


def test_auto_rollback_streaming_triggers(executor: FusionSandboxExecutor, git_repo: str):
    cmd = "python3 -c \"open('app.py','w').write('broken\\n'); raise ValueError(1)\""
    result = None
    for frame in executor.run_streaming(cmd, cwd=git_repo, auto_rollback=RollbackPolicy()):
        if isinstance(frame, ExecutionResult):
            result = frame
            break
    assert result is not None
    assert result.exit_code != 0
    assert result.auto_rolled_back is True
    with open(os.path.join(git_repo, "app.py")) as f:
        assert f.read() == "print(1)\n", "流式路径自动回滚恢复基线"


def test_auto_rollback_over_uds_roundtrip(uds_server: str, tmp_path):
    import json as _json

    d = str(tmp_path)
    subprocess.run(["git", "-C", d, "init", "-q"], check=True, capture_output=True)
    subprocess.run(["git", "-C", d, "config", "user.email", "t@t"], check=True, capture_output=True)
    subprocess.run(["git", "-C", d, "config", "user.name", "t"], check=True, capture_output=True)
    (tmp_path / "app.py").write_text("print(1)\n")
    subprocess.run(["git", "-C", d, "add", "."], check=True, capture_output=True)
    subprocess.run(["git", "-C", d, "commit", "-q", "-m", "base"], check=True, capture_output=True)
    cmd = "python3 -c \"open('app.py','w').write('broken\\n'); raise ValueError(1)\""
    resp = _rpc_once(
        uds_server,
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "executor.execute",
            "params": {
                "command": cmd,
                "cwd": d,
                "auto_rollback_policy": {"max_consecutive_failures": 3, "file_damage_check": True},
            },
        },
    )
    assert resp["result"]["exit_code"] != 0
    assert resp["result"]["auto_rolled_back"] is True
    assert (tmp_path / "app.py").read_text() == "print(1)\n"
    del _json


def test_telemetry_native_iterator(executor: FusionSandboxExecutor):
    it = executor._native.telemetry_stream(20, 3)
    frames = [f for f in it]
    assert len(frames) == 3, "max_samples=3 应产 3 帧"
    # L-TEL-01: ts_ms 墙钟 (非假计数); 单调递增, 末帧 > 首帧
    assert frames[0]["ts_ms"] > 0, "墙钟时间戳非零"
    assert frames[2]["ts_ms"] > frames[0]["ts_ms"], "末帧 ts > 首帧 (单调递增)"
    assert frames[0]["mem_mb"] > 0.0, "本进程内存非零"
    assert frames[0]["cpu_pct"] >= 0.0
    assert frames[0].get("gpu_pct") is None, "GPU 默认不注入 (serde skip)"


def test_telemetry_python_wrapper(executor: FusionSandboxExecutor):
    samples = list(executor.telemetry_stream(interval_ms=20, max_samples=4))
    assert len(samples) == 4
    assert all(isinstance(s, TelemetrySample) for s in samples)
    # L-TEL-01: ts_ms 墙钟 (非假计数); 单调递增
    assert samples[0].ts_ms > 0, "墙钟时间戳非零"
    assert samples[3].ts_ms > samples[0].ts_ms, "末帧 ts > 首帧 (单调递增)"
    assert samples[0].mem_mb > 0.0
    assert all(s.gpu_pct is None for s in samples)


def test_telemetry_over_uds(uds_server: str):
    import json as _json
    import socket as _socket

    with _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM) as s:
        s.settimeout(15.0)
        s.connect(uds_server)
        s.sendall(
            (
                _json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 11,
                        "method": "executor.telemetry_stream",
                        "params": {"interval_ms": 20, "max_samples": 3},
                    },
                    ensure_ascii=False,
                )
                + "\n"
            ).encode("utf-8")
        )
        frames = []
        buf = b""
        while len(frames) < 3:
            chunk = s.recv(8192)
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if line.strip():
                    frames.append(_json.loads(line.decode("utf-8")))
    assert len(frames) == 3, "UDS 应收 3 帧 sample"
    assert all(f["id"] == 11 for f in frames)
    assert all(f["result"]["type"] == "sample" for f in frames)
    samples = [f["result"]["sample"] for f in frames]
    # L-TEL-01: ts_ms 墙钟 (非假计数); 单调递增
    assert samples[0]["ts_ms"] > 0, "墙钟时间戳非零"
    assert samples[2]["ts_ms"] > samples[0]["ts_ms"], "末帧 ts > 首帧 (单调递增)"
    assert samples[0]["mem_mb"] > 0.0
    assert samples[0].get("gpu_pct") is None, "GPU 默认不注入 (serde skip)"
    del _json, _socket


# ── v1.6 E2E 自愈闭环 smoke (PRD §5: run→diagnose→file_edit→re-run) ──

# 故障脚本: add(1, "two") 在 return a + b 处抛 TypeError
BUG_SRC = (
    'def add(a, b):\n    return a + b\n\n\ndef main():\n    result = add(1, "two")\n    print(result)\n\n\nmain()\n'
)


def test_self_healing_closed_loop(executor: FusionSandboxExecutor, tmp_path):
    # 1. 落盘故障脚本
    bug = tmp_path / "bug.py"
    bug.write_text(BUG_SRC)

    # 2. 首次执行 — 应失败, diagnostics 切片定位到 bug.py
    first = executor.run("python3 bug.py", cwd=str(tmp_path), timeout_sec=15.0, enable_rollback_snapshot=False)
    assert first.exit_code != 0, "故障脚本应非零退出"
    assert not first.blocked_by_security
    assert first.diagnostics is not None, "exit!=0 应触发诊断切片"
    assert first.diagnostics.error_type == "TypeError", f"应识别 TypeError: {first.diagnostics.error_type}"
    assert first.diagnostics.file_path is not None, "应定位文件路径"
    assert "bug.py" in first.diagnostics.file_path, f"file_path 应含 bug.py: {first.diagnostics.file_path}"
    assert first.diagnostics.line_number is not None and first.diagnostics.line_number >= 1

    # 3. file_edit 手术式修复调用点 (add(1, "two") → add(1, 2)) — 无模型, 确定性补丁
    fix = executor.file_edit(
        "bug.py",
        '    result = add(1, "two")',
        "    result = add(1, 2)",
        cwd=str(tmp_path),
    )
    assert isinstance(fix, EditResult)
    assert fix.ok, f"file_edit 应成功: {fix.error}"
    assert fix.matches == 1

    # 4. 二次执行 — 应通过 (闭环收敛)
    second = executor.run("python3 bug.py", cwd=str(tmp_path), timeout_sec=15.0, enable_rollback_snapshot=False)
    assert second.exit_code == 0, f"修复后应 exit 0: stderr={second.stderr}"
    assert "3" in second.stdout, "修复后应输出 3"
    assert second.diagnostics is None, "exit==0 不应触发诊断"

    # 5. 过程数据清理 — 只保留 tmp_path (pytest 自动清)
    bug.unlink(missing_ok=True)


# ── T8 输入校验 (M-PY-01 / M-PY-02): 前置 fail-fast, 非延迟到 PyO3 ──


def test_run_non_str_command_raises_typeerror(executor: FusionSandboxExecutor):
    with pytest.raises(TypeError, match="command 必须为 str"):
        executor.run(123)  # type: ignore[arg-type]


def test_run_non_positive_timeout_raises_valueerror(executor: FusionSandboxExecutor):
    with pytest.raises(ValueError, match="timeout_sec 必须为正数"):
        executor.run("echo hi", timeout_sec=0)
    with pytest.raises(ValueError, match="timeout_sec 必须为正数"):
        executor.run("echo hi", timeout_sec=-1.5)


def test_run_non_str_cwd_raises_typeerror(executor: FusionSandboxExecutor):
    with pytest.raises(TypeError, match="cwd 必须为 str"):
        executor.run("echo hi", cwd=42)  # type: ignore[arg-type]


def test_run_non_dict_env_vars_raises_typeerror(executor: FusionSandboxExecutor):
    with pytest.raises(TypeError, match="env_vars 必须为 dict"):
        executor.run("echo hi", env_vars="PATH=/x")  # type: ignore[arg-type]


def test_run_env_vars_non_str_value_raises_typeerror(executor: FusionSandboxExecutor):
    with pytest.raises(TypeError, match="env_vars 键值均须 str"):
        executor.run("echo hi", env_vars={"K": 42})  # type: ignore[dict-item]


def test_gui_action_non_dict_raises_typeerror(executor: FusionSandboxExecutor):
    with pytest.raises(TypeError, match="action 必须为 dict"):
        executor.gui_action("focus_app")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="action 必须为 dict"):
        executor.gui_action(None)  # type: ignore[arg-type]


def test_gui_action_missing_kind_raises_valueerror(executor: FusionSandboxExecutor):
    with pytest.raises(ValueError, match="kind"):
        executor.gui_action({"bundle_id": "com.apple.TextEdit"})


def test_gui_action_non_str_kind_raises_typeerror(executor: FusionSandboxExecutor):
    with pytest.raises(TypeError, match="action\\['kind'\\] 必须为 str"):
        executor.gui_action({"kind": 123})  # type: ignore[dict-item]


def test_run_streaming_non_str_command_raises_typeerror(executor: FusionSandboxExecutor):
    with pytest.raises(TypeError, match="command 必须为 str"):
        list(executor.run_streaming(None))  # type: ignore[arg-type]


def test_run_streaming_non_positive_timeout_raises_valueerror(executor: FusionSandboxExecutor):
    with pytest.raises(ValueError, match="timeout_sec 必须为正数"):
        list(executor.run_streaming("echo hi", timeout_sec=0))


# ── Blocker 10 (审计 §2.9 跨租户泄漏) stdio per-sub scope ──


def test_subscribe_invalid_scope_raises_valueerror(uds_server: str):
    ex = FusionSandboxExecutor(sock_path=uds_server)
    with pytest.raises(ValueError, match="scope 须为"):
        ex.subscribe(["stdio"], scope="bogus")


def test_subscribe_own_conn_default_blocks_cross_connection(uds_server: str):
    # 连接 A 默认订阅 stdio (own_conn), 连接 B execute_stream → A 不应收 B 的 stdio。
    import json as _json
    import socket as _socket

    # 连接 A: 默认 scope 订阅
    sa = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
    sa.settimeout(8.0)
    sa.connect(uds_server)
    sa.sendall(
        (
            _json.dumps(
                {"jsonrpc": "2.0", "id": 1, "method": "executor.subscribe", "params": {"channels": ["stdio"]}},
                ensure_ascii=False,
            )
            + "\n"
        ).encode("utf-8")
    )
    buf_a = b""
    while b"\n" not in buf_a:
        buf_a += sa.recv(4096)
    resp = _json.loads(buf_a.split(b"\n", 1)[0].decode("utf-8"))
    assert resp["result"]["ok"] is True
    # 连接 B: execute_stream echo
    sb = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
    sb.settimeout(8.0)
    sb.connect(uds_server)
    sb.sendall(
        (
            _json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 7,
                    "method": "executor.execute_stream",
                    "params": {"command": "echo hi", "enable_rollback_snapshot": False},
                },
                ensure_ascii=False,
            )
            + "\n"
        ).encode("utf-8")
    )
    # B 读到 done
    buf_b = b""
    b_done = False
    deadline_b = __import__("time").time() + 5.0
    while __import__("time").time() < deadline_b:
        chunk = sb.recv(8192)
        if not chunk:
            break
        buf_b += chunk
        for line in buf_b.split(b"\n"):
            if line.strip():
                v = _json.loads(line.decode("utf-8"))
                if v.get("id") == 7 and v.get("result", {}).get("type") == "done":
                    b_done = True
        if b_done:
            break
    # A 等一小窗确认无跨连接推送
    import time as _t

    _t.sleep(0.3)
    a_got_stdio = False
    sa.settimeout(0.5)
    try:
        while True:
            chunk = sa.recv(4096)
            if not chunk:
                break
            for line in chunk.split(b"\n"):
                if line.strip():
                    v = _json.loads(line.decode("utf-8"))
                    if (
                        v.get("id") is None
                        and v.get("method") == "executor.event"
                        and v["params"]["channel"] == "stdio"
                    ):
                        a_got_stdio = True
    except (TimeoutError, OSError):
        pass
    assert b_done, "B 应收到自己 done 帧"
    assert not a_got_stdio, "默认 own_conn 应拦截跨连接 stdio (审计 §2.9)"
    sa.close()
    sb.close()


def test_subscribe_task_ids_whitelist_receives_matched(uds_server: str):
    # scope=["t1"] 订阅, execute_stream task_id="t1" → 收推送; task_id="t2" → 不收。
    import json as _json
    import socket as _socket
    import time as _t

    sa = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
    sa.settimeout(8.0)
    sa.connect(uds_server)
    sa.sendall(
        (
            _json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "executor.subscribe",
                    "params": {"channels": ["stdio"], "task_ids": ["t1"]},
                },
                ensure_ascii=False,
            )
            + "\n"
        ).encode("utf-8")
    )
    buf = b""
    while b"\n" not in buf:
        buf += sa.recv(4096)
    assert _json.loads(buf.split(b"\n", 1)[0].decode("utf-8"))["result"]["ok"] is True
    # B: task_id="t1" (匹配)
    sb = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
    sb.settimeout(8.0)
    sb.connect(uds_server)
    sb.sendall(
        (
            _json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 7,
                    "method": "executor.execute_stream",
                    "params": {"command": "echo match", "task_id": "t1", "enable_rollback_snapshot": False},
                },
                ensure_ascii=False,
            )
            + "\n"
        ).encode("utf-8")
    )
    a_got = False
    deadline = _t.time() + 5.0
    sa.settimeout(1.0)
    while _t.time() < deadline:
        try:
            chunk = sa.recv(8192)
        except (TimeoutError, OSError):
            break
        if not chunk:
            break
        for line in chunk.split(b"\n"):
            if line.strip():
                v = _json.loads(line.decode("utf-8"))
                if v.get("id") is None and v.get("method") == "executor.event" and v["params"]["channel"] == "stdio":
                    a_got = True
        if a_got:
            break
    assert a_got, "task_ids 白名单匹配应收到 stdio 推送"
    sa.close()
    sb.close()


# ── 审计 §3.11/§3.13/§3.15 Python 收尾回归 ──


def test_telemetry_stream_strict_rejects_missing_field(executor: FusionSandboxExecutor):
    # 3.11: telemetry_stream 用 model_validate (旧 frame.get("ts_ms", 0) 默认 0 吞缺失字段)。
    # 注入缺 ts_ms 的坏帧 → model_validate 应抛 ValidationError (fail-loud, 非假数据)。
    from pydantic import ValidationError

    bad_frame = {"cpu_pct": 1.0, "mem_mb": 2.0}  # 缺必填 ts_ms
    with pytest.raises(ValidationError):
        TelemetrySample.model_validate(bad_frame)
    # 额外字段也应被 _STRICT extra=forbid 拒
    with pytest.raises(ValidationError):
        TelemetrySample.model_validate({"ts_ms": 1, "cpu_pct": 1.0, "mem_mb": 2.0, "bogus": 9})


def test_subscribe_idle_timeout_configurable(uds_server: str):
    # 3.13: idle_timeout 参数可配 (旧版硬编 15s recv 超时)。None=无超时。
    # 订阅 telemetry (10Hz), idle_timeout=None, 应持续收帧 (不 15s 后误断)。
    import time as _t

    ex = FusionSandboxExecutor(sock_path=uds_server)
    sub = ex.subscribe(["telemetry"], interval_ms=20, idle_timeout=None)
    assert sub.subscription_id is not None
    # 收 3 帧 — None 超时不限, 10Hz(20ms) 下秒级回
    got = 0
    deadline = _t.time() + 5.0
    for _ in sub:
        got += 1
        if got >= 3 or _t.time() > deadline:
            break
    sub.unsubscribe()
    assert got >= 3, f"idle_timeout=None 应持续收帧, 实得 {got}"


def test_subscribe_idle_timeout_short_stops_stream(uds_server: str):
    # 3.13: 短 idle_timeout — 无推送时 recv 超时 → __next__ 抛 StopIteration (流尾)。
    # 订阅 screenshot 慢通道 (1s), idle_timeout=0.2 → 0.2s 无帧 → StopIteration。
    import time as _t

    ex = FusionSandboxExecutor(sock_path=uds_server)
    sub = ex.subscribe(["screenshot"], screenshot_interval_ms=5000, idle_timeout=0.2)
    t0 = _t.time()
    with pytest.raises(StopIteration):
        next(sub)
    elapsed = _t.time() - t0
    assert elapsed < 1.0, f"短 idle_timeout 应秒级停, 实耗 {elapsed:.2f}s"
    sub.close()


def test_serve_passes_resolved_path_not_raw_none(monkeypatch, tmp_path):
    # 3.15: serve() 解析 path (env/default) 后传 Rust, 非 None。验证路径解析优先级:
    # 显式 sock_path > env > default。仅验 Python 侧路径选择逻辑 (不真启 server)。
    sp = str(tmp_path / "explicit.sock")
    captured = {}

    class _FakeNative:
        def serve(self, path):
            captured["path"] = path
            raise KeyboardInterrupt  # 立即跳出, 不阻塞

    ex = FusionSandboxExecutor()
    ex._native = _FakeNative()
    monkeypatch.delenv("FUSION_EXECUTOR_SOCK", raising=False)
    with pytest.raises(KeyboardInterrupt):
        ex.serve(sp)
    assert captured["path"] == sp, "serve 应传解析后 path 非原始 sock_path"


def test_validate_safe_command_allowed(executor: FusionSandboxExecutor):
    # Issue #11 / #12.4: 非执行预校验 — 安全命令 allowed=True, 不执行
    v = executor.validate("echo hi")
    assert v["allowed"] is True
    assert v["blocked"] is False
    assert v["reason"] is None
    assert v["stage"] is None


def test_validate_blocked_command_returns_verdict(executor: FusionSandboxExecutor):
    # 危险命令 → blocked=True + reason + stage, 命令不执行 (无副作用)
    v = executor.validate("rm -rf /")
    assert v["allowed"] is False
    assert v["blocked"] is True
    assert isinstance(v["reason"], str) and v["reason"]
    assert v["stage"] == "regex"


def test_validate_chain_bypass_caught_at_tokenizer(executor: FusionSandboxExecutor):
    # 链装配绕过: echo hi && sudo ls → Stage-2 tokenizer 拦 sudo
    v = executor.validate("echo hi && sudo ls")
    assert v["blocked"] is True
    assert v["stage"] in ("regex", "tokenizer")


def test_validate_empty_command_raises_valueerror(executor: FusionSandboxExecutor):
    with pytest.raises(ValueError, match="command 必须非空字符串"):
        executor.validate("")
    with pytest.raises(ValueError, match="command 必须非空字符串"):
        executor.validate("   ")
    with pytest.raises(ValueError, match="command 必须非空字符串"):
        executor.validate(123)  # type: ignore[arg-type]


# Issue #10: 白名单覆盖 + 项目级扩展 + 动态执行拦截
# D3-6 (审计 0827 product): extra_whitelist 的工具须 resolve 到可信目录才放行 (fail-closed 防
#   /tmp 投毒)。测试建真实可执行工具到临时 bin 目录, 登记 trusted_bin_dirs, 校验放行。
def test_extra_whitelist_allows_project_tool(tmp_path):
    tool = tmp_path / "myproj-runner"
    tool.write_text("#!/bin/sh\necho run\n")
    tool.chmod(0o755)
    ex = FusionSandboxExecutor(extra_whitelist=["myproj-runner"], trusted_bin_dirs=[str(tmp_path)])
    v = ex.validate(f"{tool} --version")
    assert v["allowed"] is True, v


def test_extra_whitelist_rejects_shell_interpreter():
    # 解释器/内建不可经扩展自我后门
    ex = FusionSandboxExecutor(extra_whitelist=["bash", "sh", "exec", "eval"])
    for cmd in ["bash -c 'x'", "sh -c 'x'", "eval 'x'", "exec foo"]:
        v = ex.validate(cmd)
        assert v["allowed"] is False, f"危险扩展项应仍被拦: {cmd} -> {v}"


def test_blocks_eval_source_exec_dynamic():
    ex = FusionSandboxExecutor()
    for cmd, kw in [
        ("eval 'echo hi'", "eval"),
        ("source /tmp/evil.sh", "source"),
        ("exec /bin/sh", "exec"),
    ]:
        v = ex.validate(cmd)
        assert v["allowed"] is False, f"{cmd} 应被拦: {v}"
        assert kw in v["reason"], f"{cmd} reason 应提及 {kw}: {v['reason']}"


def test_blocks_interpreter_dash_c_and_pipe_to_shell():
    ex = FusionSandboxExecutor()
    for cmd in [
        "bash -c 'echo pwned'",
        "sh -c 'echo pwned'",
        "echo aGVsbG8= | base64 -d | sh",
        "echo 'rm -rf /' | sh",
        "printf 'pwn' | bash",
    ]:
        v = ex.validate(cmd)
        assert v["allowed"] is False, f"{cmd} 应被拦: {v}"


def test_allows_pipe_to_non_shell_no_false_positive():
    ex = FusionSandboxExecutor()
    for cmd in ["echo hi | grep hi", "git log --oneline | head -5", "echo bash | grep bash"]:
        v = ex.validate(cmd)
        assert v["allowed"] is True, f"{cmd} 不应误拦: {v}"


# Issue #9: 环境隔离 — 默认不泄漏宿主密钥; env_vars 注入; inherit_env opt-in 继承
_REFLECT = 'python3 -c "import os,sys;sys.stdout.write(os.environ.get(%r,%r))"'


def test_env_isolation_strips_host_secret_by_default(executor: FusionSandboxExecutor, monkeypatch):
    monkeypatch.setenv("FE_TEST_SECRET", "leak-me-please")
    r = executor.run(_REFLECT % ("FE_TEST_SECRET", "clean"), timeout_sec=5)
    assert r.exit_code == 0, f"stderr={r.stderr}"
    assert "leak-me-please" not in r.stdout, "宿主密钥不应泄漏到默认隔离的子进程"


def test_env_isolation_injects_env_vars(executor: FusionSandboxExecutor):
    r = executor.run(_REFLECT % ("FE_TASK_VAR", "missing"), timeout_sec=5, env_vars={"FE_TASK_VAR": "injected"})
    assert r.exit_code == 0
    assert "injected" in r.stdout, "env_vars 必须注入到子进程"


def test_env_isolation_baseline_present(executor: FusionSandboxExecutor):
    for key in ("PATH", "TMPDIR", "SHELL"):
        r = executor.run(_REFLECT % (key, "missing"), timeout_sec=5)
        assert r.exit_code == 0
        assert "missing" not in r.stdout, f"基线 {key} 应存在使命令可解析"


def test_env_inherit_true_restores_host_env(executor: FusionSandboxExecutor, monkeypatch):
    monkeypatch.setenv("FE_TEST_SECRET", "leak-me-please")
    r = executor.run(_REFLECT % ("FE_TEST_SECRET", "clean"), timeout_sec=5, inherit_env=True)
    assert r.exit_code == 0
    assert "leak-me-please" in r.stdout, "inherit_env=True 应继承宿主 env (opt-in 受信场景)"


# Issue #4: use_pty=False stdio 后端 — stdout/stderr 独立捕获 (PTY 合流, stderr 恒空)
def test_use_pty_false_captures_stderr_separately(executor: FusionSandboxExecutor):
    cmd = "python3 -c \"import sys; sys.stdout.write('OUT-LINE\\n'); sys.stderr.write('ERR-LINE\\n')\""
    r = executor.run(cmd, timeout_sec=5, use_pty=False)
    assert r.exit_code == 0, f"exit={r.exit_code} stdout={r.stdout!r} stderr={r.stderr!r}"
    assert "OUT-LINE" in r.stdout, f"stdout 应含 OUT: {r.stdout!r}"
    assert "ERR-LINE" not in r.stdout, f"stdout 不应被 stderr 污染: {r.stdout!r}"
    assert "ERR-LINE" in r.stderr, f"stderr 应独立捕获 ERR: {r.stderr!r}"


def test_use_pty_true_merges_stderr_into_stdout(executor: FusionSandboxExecutor):
    # PTY 后端: stdout/stderr 合流, stderr 恒空 (portable-pty 强制 stderr=PTY as_stdio)
    cmd = "python3 -c \"import sys; sys.stdout.write('OUT\\n'); sys.stderr.write('ERR\\n')\""
    r = executor.run(cmd, timeout_sec=5, use_pty=True)
    assert r.exit_code == 0
    assert r.stderr == "", "PTY 后端 stderr 恒空 (合流进 stdout)"
    assert "OUT" in r.stdout
    assert "ERR" in r.stdout, "PTY 后端 stderr 应合流进 stdout"


def test_run_streaming_rejects_use_pty_false(executor: FusionSandboxExecutor):
    # 流式无 stdio 后端, 显式拒 (fail-loud 而非静默降级 PTY)
    with pytest.raises(ValueError, match="use_pty=False"):
        next(executor.run_streaming("echo hi", timeout_sec=5, use_pty=False))


# Issue #1: 后台持久 shell (run_in_background/BashOutput/KillShell parity)
def test_shell_start_echo_and_poll(executor: FusionSandboxExecutor):
    import time

    r = executor.shell_start("echo hi-bg")
    assert isinstance(r, ShellStartResult)
    assert r.ok
    assert r.shell_id and r.shell_id.startswith("sh-")
    assert not r.blocked_by_security
    sid = r.shell_id
    time.sleep(0.8)
    out = executor.shell_output(sid)
    assert isinstance(out, ShellOutput)
    assert out.shell_id == sid
    assert "hi-bg" in out.output
    assert not out.running
    assert out.exit_code == 0


def test_shell_start_repeated_output_accumulates(executor: FusionSandboxExecutor):
    import time

    sid = executor.shell_start("python3 -c 'for i in range(5): print(i)'").shell_id
    time.sleep(1.0)
    out = executor.shell_output(sid)
    for i in range(5):
        assert str(i) in out.output, f"缺 {i}: {out.output!r}"
    assert out.exit_code == 0


def test_shell_kill_long_running(executor: FusionSandboxExecutor):
    import time

    sid = executor.shell_start("python3 -c 'import time; time.sleep(30)'").shell_id
    time.sleep(0.4)
    mid = executor.shell_output(sid)
    assert mid.running, "长任务应仍在跑"
    ok = executor.kill_shell(sid)
    assert ok
    time.sleep(0.8)
    after = executor.shell_output(sid)
    assert not after.running, "kill 后应结束"


def test_list_shells_records_all(executor: FusionSandboxExecutor):
    import time

    a = executor.shell_start("echo a1").shell_id
    b = executor.shell_start("echo b1").shell_id
    time.sleep(0.8)
    infos = executor.list_shells()
    ids = {i.shell_id for i in infos}
    assert all(isinstance(i, ShellInfo) for i in infos)
    assert a in ids and b in ids
    for i in infos:
        if i.shell_id in (a, b):
            assert i.finished
            assert i.exit_code == 0


def test_shell_output_unknown_id_errors(executor: FusionSandboxExecutor):
    with pytest.raises(Exception, match="sh-999"):
        executor.shell_output("sh-999")


def test_shell_start_blocked_by_security(executor: FusionSandboxExecutor):
    r = executor.shell_start("rm -rf /")
    assert isinstance(r, ShellStartResult)
    assert not r.ok
    assert r.blocked_by_security
    assert r.shell_id is None
    assert r.security_reason is not None


def test_shell_start_rejects_empty(executor: FusionSandboxExecutor):
    r = executor.shell_start("   ")
    assert not r.ok
    assert r.error is not None


def test_shell_start_over_uds_roundtrip(uds_server: str):
    resp = _rpc_once(
        uds_server,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "executor.shell_start",
            "params": {"command": "echo uds-bg"},
        },
    )
    assert resp["result"]["ok"] is True
    sid = resp["result"]["shell_id"]
    assert sid and sid.startswith("sh-")


def test_shell_output_over_uds_roundtrip(uds_server: str):
    import time

    start = _rpc_once(
        uds_server,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "executor.shell_start",
            "params": {"command": "echo poll-me"},
        },
    )
    sid = start["result"]["shell_id"]
    time.sleep(0.8)
    out = _rpc_once(
        uds_server,
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "executor.shell_output",
            "params": {"shell_id": sid},
        },
    )
    assert out["result"]["shell_id"] == sid
    assert "poll-me" in out["result"]["output"]
    assert out["result"]["running"] is False
    assert out["result"]["exit_code"] == 0


def test_kill_shell_over_uds_roundtrip(uds_server: str):
    import time

    start = _rpc_once(
        uds_server,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "executor.shell_start",
            "params": {"command": "python3 -c 'import time; time.sleep(30)'"},
        },
    )
    sid = start["result"]["shell_id"]
    time.sleep(0.4)
    kill = _rpc_once(
        uds_server,
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "executor.kill_shell",
            "params": {"shell_id": sid},
        },
    )
    assert kill["result"]["ok"] is True
    time.sleep(0.8)
    out = _rpc_once(
        uds_server,
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "executor.shell_output",
            "params": {"shell_id": sid},
        },
    )
    assert out["result"]["running"] is False


def test_list_shells_over_uds_roundtrip(uds_server: str):
    import time

    _rpc_once(
        uds_server,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "executor.shell_start",
            "params": {"command": "echo list-me"},
        },
    )
    time.sleep(0.8)
    lst = _rpc_once(
        uds_server,
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "executor.list_shells",
            "params": {},
        },
    )
    assert isinstance(lst["result"], list)
    assert len(lst["result"]) >= 1
    assert all("shell_id" in e and "command" in e for e in lst["result"])


# ── #104 P-2/M-4/M-6 Python 层修复 ──


def test_m4_native_import_failure_warns(monkeypatch):
    # M-4: _native 导入失败应 warn (fail-visible), 非静默吞 ABI/链接错误。
    # 模拟 native 扩展缺失: importlib 触发 ImportError → __init__ 回退 + warn。
    import importlib

    # 用独立模块名重载 __init__, 隔离对全局已加载 fusion_executor 的影响:
    # 直接 monkeypatch sys.modules 注入坏 _native, 再 reload。
    import sys
    import warnings

    import fusion_executor

    class _BrokenNative:
        def __getattr__(self, name):
            raise ImportError(f"模拟 native 加载失败: {name}")

    monkeypatch.setitem(sys.modules, "fusion_executor._native", _BrokenNative())
    # __init__ 的 try/except 用 `from ._native import version_info`, 触发 ImportError
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        importlib.reload(fusion_executor)
    monkeypatch.delitem(sys.modules, "fusion_executor._native", raising=False)
    # 还原真实 _native (后续测试依赖), reload 回真实扩展
    importlib.reload(fusion_executor)
    # 断言: warn 发出 RuntimeWarning 提及 native 加载失败
    rw = [w for w in caught if issubclass(w.category, RuntimeWarning)]
    assert any("native" in str(w.message) or "加载" in str(w.message) for w in rw), (
        f"native 导入失败应 warn, 得 {[str(w.message) for w in caught]}"
    )


def test_m6_run_streaming_unknown_frame_skipped(executor: FusionSandboxExecutor, caplog):
    # M-6: run_streaming 收未知帧 type 不抛 (向前兼容), debug 记录可追溯。
    # 用 monkeypatch 替换 _native.execute_streaming 返回未知帧序列 + 正常 done 帧。
    import logging

    class _FakeStream:
        def __init__(self):
            self._frames = [
                {"type": "chunk", "data": "ok-chunk"},
                {"type": "future_frame_kind", "payload": {"x": 1}},  # 未知 type
                {
                    "type": "done",
                    "exit_code": 0,
                    "stdout": "ok-chunk",
                    "stderr": "",
                    "blocked_by_security": False,
                    "timed_out": False,
                },
            ]
            self._i = 0

        def __iter__(self):
            return self

        def __next__(self):
            if self._i >= len(self._frames):
                raise StopIteration
            f = self._frames[self._i]
            self._i += 1
            return f

    orig_native = executor._native

    class _FakeNative:
        def execute_streaming(self, *a, **k):
            return _FakeStream()

    executor._native = _FakeNative()  # type: ignore[assignment]
    try:
        chunks: list[str] = []
        result = None
        with caplog.at_level(logging.DEBUG, logger="fusion_executor"):
            for frame in executor.run_streaming("echo hi", enable_rollback_snapshot=False):
                if isinstance(frame, ExecutionResult):
                    result = frame
                else:
                    chunks.append(frame)
    finally:
        executor._native = orig_native  # type: ignore[assignment]
    assert result is not None
    assert result.exit_code == 0
    assert chunks == ["ok-chunk"], "未知帧应跳过不抛, 仅 chunk 产出"
    # M-6 核心: debug 日志记录未知 type (可追溯)
    assert any("future_frame_kind" in rec.getMessage() for rec in caplog.records), "未知帧 type 应 debug 记录"


def test_p2_subscription_buf_cap_returns_none():
    # P-2: _buf 超 _SUB_BUF_MAX_BYTES → 丢弃缓冲返 None (当流结束), 不 OOM。
    # 构造一个 Subscription (不连真实 socket), monkeypatch recv 返无 newline 超大块。
    from fusion_executor.executor import _SUB_BUF_MAX_BYTES, Subscription

    sub = Subscription.__new__(Subscription)
    sub._buf = b""

    class _FakeSock:
        def __init__(self):
            self.calls = 0

        def recv(self, n):
            self.calls += 1
            if self.calls == 1:
                # 单块超 cap (无 newline) → 触发截断
                return b"x" * (_SUB_BUF_MAX_BYTES + 1024)
            return b""

    sub._sock = _FakeSock()
    out = sub._read_json()
    assert out is None, "超 cap 损坏流应返 None 当流结束"
    assert sub._buf == b"", "截断后 _buf 清空"


def test_p2_subscription_buf_normal_line_still_works():
    # P-2: cap 不影响正常 newline 分帧 (回归守卫)。
    from fusion_executor.executor import Subscription

    sub = Subscription.__new__(Subscription)
    sub._buf = b""

    class _FakeSock:
        def __init__(self):
            self.sent = False

        def recv(self, n):
            if not self.sent:
                self.sent = True
                return b'{"jsonrpc":"2.0","id":1,"result":{"ok":true}}\n'
            return b""

    sub._sock = _FakeSock()
    out = sub._read_json()
    assert out is not None
    assert out["id"] == 1
    assert out["result"]["ok"] is True


# D3-4 (审计 0827 product): per-task RSS watchdog — 子进程树 RSS 超 rss_limit_mb
# 被 sysinfo 轮询 kill (exit_code -124, oom_killed=true)。Darwin RLIMIT_AS/RLIMIT_DATA
# 平台无效, 改轮询缓解。inline 解释器经 D3-1 opt-in 网关放行 (fixture allow_inline_interpreter)。
def test_run_rss_watchdog_kills_memory_bomb(executor: FusionSandboxExecutor):
    bomb = "python3 -c \"x=[bytearray(b'a'*10**7) for _ in range(100)]; import time; time.sleep(5)\""
    r = executor.run(bomb, rss_limit_mb=256, timeout_sec=10.0, enable_rollback_snapshot=False)
    assert r.oom_killed, f"内存炸弹应触发 oom_killed, exit={r.exit_code}"
    assert r.exit_code == -124, f"OOM kill exit 应 -124, got {r.exit_code}"


def test_run_rss_watchdog_zero_disables(executor: FusionSandboxExecutor):
    # rss_limit_mb=0 禁用 watchdog — 较小分配正常完成 (受信 opt-out)
    r = executor.run(
        "python3 -c \"x=[bytearray(b'a'*10**6) for _ in range(10)]; print(len(x))\"",
        rss_limit_mb=0,
        timeout_sec=15.0,
        enable_rollback_snapshot=False,
    )
    assert not r.oom_killed, "rss_limit_mb=0 不应触发 oom_killed"
    assert r.exit_code == 0, f"正常完成 exit 0, got {r.exit_code}"


def test_run_rss_watchdog_normal_unaffected(executor: FusionSandboxExecutor):
    r = executor.run("echo hi", rss_limit_mb=256, enable_rollback_snapshot=False)
    assert r.exit_code == 0, f"echo 应 exit 0, got {r.exit_code}"
    assert not r.oom_killed, "echo 不应触发 oom_killed"


def test_run_streaming_rss_watchdog(executor: FusionSandboxExecutor):
    bomb = "python3 -c \"x=[bytearray(b'a'*10**7) for _ in range(100)]; import time; time.sleep(5)\""
    _chunks, result = _consume_stream(executor, bomb, rss_limit_mb=256, timeout_sec=10.0)
    assert result is not None
    assert result.oom_killed, f"流式 Done 帧 oom_killed 应 true, exit={result.exit_code}"
    assert result.exit_code == -124, f"流式 OOM exit 应 -124, got {result.exit_code}"


# ── Issue #23: fusion-guard Phase 3 集成 (guard OFF 默认 / guard_sock opt-in / 降级 fail-closed) ──
# guard 默认 OFF — FusionSandboxExecutor() 不连 guard daemon, 行为同 v0.2.5 (回归红线)。
# guard_sock 指向不存在 socket → fe-security 降级 fail-closed: 缓存规则 + 静态白名单栅栏,
# 白名单 binary (echo) 仍放行 (严于 guard 活时不放宽), 非白名单/危险命令仍拦。guard_action_id
# 仅 guard 判 Block/L3 时有值, guard OFF / 降级 allow 时 None。


def test_guard_off_default_runs_normally():
    # 默认无 guard_sock → guard OFF, echo 正常执行 (回归红线)
    ex = FusionSandboxExecutor(allow_inline_interpreter=True)
    r = ex.run("echo no-guard")
    assert r.exit_code == 0
    assert "no-guard" in r.stdout
    assert r.guard_action_id is None, "guard OFF 时 guard_action_id 须 None"


def test_guard_off_blocked_command_has_no_action_id():
    # guard OFF 下 rm -rf / 仍被静态白名单栅栏拦 (降级 fail-closed 不放宽), 但无 guard_action_id
    ex = FusionSandboxExecutor(allow_inline_interpreter=True)
    r = ex.run("rm -rf /")
    assert r.blocked_by_security
    assert r.exit_code == -1
    assert r.guard_action_id is None, "guard OFF 静态拦截不产 guard_action_id"


def test_guard_sock_nonexistent_degrades_fail_closed():
    # guard_sock 指不存在 socket → fe-security 探活失败降级 fail-closed。
    # 白名单 echo 仍执行 (严于 guard 活时不放宽); rm -rf / 仍被静态栅栏/缓存规则拦。
    ex = FusionSandboxExecutor(
        allow_inline_interpreter=True,
        guard_sock="/tmp/fe-guard-nonexistent-test.sock",
        guard_tenant="test-tenant",
    )
    r_ok = ex.run("echo degraded")
    assert r_ok.exit_code == 0, f"降级下白名单 echo 应执行, exit={r_ok.exit_code} reason={r_ok.security_reason}"
    assert "degraded" in r_ok.stdout
    assert r_ok.guard_action_id is None, "降级 allow 不产 guard_action_id"
    r_blk = ex.run("rm -rf /")
    assert r_blk.blocked_by_security
    assert r_blk.exit_code == -1


def test_guard_action_id_pydantic_roundtrip():
    # guard_action_id 字段 Pydantic 往返 + extra=forbid 不破 (4 层字段集一致)
    raw = {
        "exit_code": -1,
        "blocked_by_security": True,
        "security_reason": "guard Block L4",
        "guard_action_id": "11111111-2222-3333-4444-555555555555",
    }
    r = ExecutionResult.model_validate(raw)
    assert r.guard_action_id == "11111111-2222-3333-4444-555555555555"
    dumped = r.model_dump()
    assert dumped["guard_action_id"] == "11111111-2222-3333-4444-555555555555"


def test_guard_action_id_none_omitted_in_strict_roundtrip():
    # guard_action_id None 时 Pydantic 不破 (默认 None); extra=forbid 不拒未知字段
    r = ExecutionResult.model_validate({"exit_code": 0})
    assert r.guard_action_id is None
    assert r.model_dump()["guard_action_id"] is None


def test_guard_env_var_enables_guard():
    # FUSION_GUARD_SOCK env → __init__ 透传 guard (daemon 不存在 → 降级 fail-closed)
    env_sock = "/tmp/fe-guard-env-test.sock"
    old = os.environ.pop("FUSION_GUARD_SOCK", None)
    try:
        os.environ["FUSION_GUARD_SOCK"] = env_sock
        ex = FusionSandboxExecutor(allow_inline_interpreter=True)
        # echo 白名单 → 降级放行 (不放宽)
        r = ex.run("echo env-guard")
        assert r.exit_code == 0, f"env guard 降级下 echo 应执行, exit={r.exit_code}"
        assert "env-guard" in r.stdout
    finally:
        if old is not None:
            os.environ["FUSION_GUARD_SOCK"] = old
        else:
            os.environ.pop("FUSION_GUARD_SOCK", None)


def test_execution_result_cancelled_field_default_false(
    executor: FusionSandboxExecutor,
):
    # Issue #32: ExecutionResult.cancelled 默认 False, 正常 run 不置 true。
    r = executor.run("echo nocancel", enable_rollback_snapshot=False)
    assert r.exit_code == 0
    assert r.cancelled is False, "非 cancel 路径 cancelled 应 False"
    assert "nocancel" in r.stdout


def test_execution_result_cancelled_field_in_extra_forbid_rejects():
    # _STRICT extra=forbid: cancelled 已是合法字段, Pydantic 接受; 未知字段仍拒。
    from pydantic import ValidationError

    r = ExecutionResult(exit_code=0, cancelled=True)
    assert r.cancelled is True
    with pytest.raises(ValidationError):
        ExecutionResult(exit_code=0, bogus_field=1)  # type: ignore[call-arg]


def test_cancel_stream_unknown_id_over_uds(uds_server: str):
    # Issue #32: cancel 未知 stream_id → False (best-effort, 不抛)。
    ex = FusionSandboxExecutor(allow_inline_interpreter=True)
    ok = ex.cancel_stream(99999, sock_path=uds_server)
    assert ok is False, "未知 stream_id 应返 False"


def test_cancel_stream_kills_inflight_over_uds(uds_server: str, tmp_path):
    # Issue #32: 长跑 execute_stream + cancel_stream → Done exit_code -1 + cancelled true。
    # 用原生 UDS 客户端发 execute_stream (id=51) 并读流, 另发 cancel — 因 run_streaming 是
    # in-process 路径 (不经 serve), 此测走原生 UDS 验证 serve 侧 cancel。
    import socket

    script = tmp_path / "spin.py"
    script.write_text("while True:\n    pass\n")
    path = uds_server
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(path)
    sock.settimeout(12.0)
    req = {
        "jsonrpc": "2.0",
        "id": 51,
        "method": "executor.execute_stream",
        "params": {
            "command": f"python3 {script}",
            "enable_rollback_snapshot": False,
            "timeout_sec": 120,
        },
    }
    sock.sendall((json.dumps(req) + "\n").encode("utf-8"))
    # 等流启动
    import time

    time.sleep(0.6)
    # cancel 走 wrapper (同 socket path, 跨连接 StreamRegistry 共享)
    ex = FusionSandboxExecutor(allow_inline_interpreter=True)
    ok = ex.cancel_stream(51, sock_path=path)
    assert ok is True, "应找到 in-flight 流 id=51 并下发 cancel"
    # 读 done 帧
    buf = b""
    done = None
    deadline = time.time() + 10.0
    while time.time() < deadline:
        while b"\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
        if b"\n" not in buf:
            break
        line, buf = buf.split(b"\n", 1)
        line = line.decode("utf-8").strip()
        if not line:
            continue
        v = json.loads(line)
        if v.get("id") != 51:
            continue
        if v.get("result", {}).get("type") == "done":
            done = v["result"]["result"]
            break
    sock.close()
    assert done is not None, "Issue #32: 应收到 done 帧"
    assert done["exit_code"] == -1, "Issue #32: cancel done exit_code 应 -1"
    assert done["cancelled"] is True, "Issue #32: cancelled 应透传 true"
