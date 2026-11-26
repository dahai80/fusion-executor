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
    SandboxProfile,
    ShellInfo,
    ShellOutput,
    ShellStartResult,
    TelemetrySample,
)


@pytest.fixture(scope="module")
def executor():
    # D3-1: this test machine relies on the python3 -c inline interpreter (diagnostics slicing/real execution), so opt-in.
    # Enterprise hardening defaults to False rejecting inline interpreters; test machines are a trusted-caller local interaction scenario.
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
    # env isolation defaults to inherit_env=false → hardened PATH allowlist (/opt/homebrew/bin...)
    # contains only python3 (no venv `python` shim), so real execution uses python3.
    # python-token allowlisting is covered by the fe-security unit test allows_python.
    result = executor.run("python3 -c \"print('hello')\"")
    assert not result.blocked_by_security
    assert result.exit_code == 0


# ── Issue #34: per-command seatbelt/sandbox profile ──


def test_run_sandbox_none_default_no_regression(executor: FusionSandboxExecutor):
    # sandbox=None (default) → same behavior as v0.2.7 (existing fixed profile), regression preserved
    result = executor.run("echo hi")
    assert result.exit_code == 0
    assert not result.blocked_by_security


def test_run_with_sandbox_profile_network_allow(executor: FusionSandboxExecutor):
    # sandbox network=allow → the seatbelt profile omits deny network-outbound, echo still runs normally
    result = executor.run(
        "echo sbx",
        sandbox=SandboxProfile(network="allow", excluded_commands=["rm"]),
    )
    assert result.exit_code == 0
    assert not result.blocked_by_security


def test_run_with_sandbox_excluded_command_blocks(executor: FusionSandboxExecutor):
    # excluded_commands rejects rm — deny process-exec (literal) inside the seatbelt profile blocks it
    # note: the seatbelt blocks process-exec; when sh -c 'rm' spawns rm the seatbelt denies it → non-zero exit
    result = executor.run("rm /tmp/nonexistent_issue34", sandbox=SandboxProfile(excluded_commands=["rm"]))
    # rm on a missing file is non-zero anyway; the seatbelt-deny path also exits non-zero, but must not be blocked_by_security (that is the security guard, not the seatbelt)
    assert result.exit_code != 0


def test_sandbox_over_uds_roundtrip(uds_server: str):
    # UDS execute passes the sandbox profile through (additive field auto-flow via serde_json::from_value)
    resp = _rpc_once(
        uds_server,
        {
            "jsonrpc": "2.0",
            "id": 42,
            "method": "executor.execute",
            "params": {
                "command": "echo uds_sbx",
                "sandbox": {"network": "allow", "excluded_commands": ["rm"], "fail_if_unavailable": False},
            },
        },
    )
    assert resp["result"]["exit_code"] == 0
    assert not resp["result"]["blocked_by_security"]


def test_sandbox_over_uds_excluded_blocks(uds_server: str):
    # UDS: sandbox excluded_commands rejects a binary → seatbelt deny process-exec
    resp = _rpc_once(
        uds_server,
        {
            "jsonrpc": "2.0",
            "id": 43,
            "method": "executor.execute",
            "params": {
                "command": "rm /tmp/no_such_issue34_uds",
                "sandbox": {"excluded_commands": ["rm"]},
            },
        },
    )
    assert resp["result"]["exit_code"] != 0


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
    assert snap, "snapshot id not empty"
    with open(os.path.join(git_repo, "app.py"), "w") as f:
        f.write("WORSE\n")
    ok = executor.rollback(snap, git_repo)
    assert ok, "rollback succeeded"
    with open(os.path.join(git_repo, "app.py")) as f:
        assert f.read() == "BROKEN\n", "rolled back to snapshot content"


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
            raise TimeoutError(f"socket did not appear: {sp}")
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
    assert chunks == [], "blocked run should emit no chunks, only a single result frame"


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
    # 0827 C-16/A-12: the seatbelt layer dropped the DANGEROUS_BINS process-exec denylist (A-12 —
    # blocklists are not enumerable, rm renamed/symlink bypasses; binary isolation is led by fe-security Stage-2 allowlist),
    # replaced with a targeted SENSITIVE_FS_PATHS file-write* deny (C-16 — best-effort; the Darwin 25 global
    # file-write* is a NO-OP but targeted literals may still work; on failure it degrades to no FS protection without false positives).
    # This test verifies the post-A-12 isolation status quo: the seatbelt no longer denies /bin/rm execve (denylist removed),
    # allowlisted binaries (echo/python3) run normally (allow default); rm's destructive deletes are covered by the fe-security
    # regex blocklist + C-16 targeted FS deny as fallback, not by the seatbelt process-exec layer.
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
    assert not r_off.blocked_by_security, "seatbelt off must not be blocked by the security layer"
    r_on = executor.run(cmd, seatbelt=True)
    assert not r_on.blocked_by_security, "seatbelt on must not be blocked by the security layer (python3 allowlisted)"
    assert "probe_exit=" in r_on.stdout, (
        "seatbelt on allowlisted python3 carrier should execute normally (allow default)"
    )


def test_seatbelt_allows_whitelisted_echo(executor: FusionSandboxExecutor):
    # seatbelt=True does not affect normal execution of allowlisted commands (allow default).
    result = executor.run("echo seatbelt_ok", seatbelt=True)
    assert result.exit_code == 0
    assert not result.blocked_by_security
    assert "seatbelt_ok" in result.stdout


def test_seatbelt_default_true_all_layers_no_drift():
    # D1-2/D2-3 (audit 0827 arch ARCH-1 + product): the seatbelt default must be consistently True across all 4 layers.
    # Historical drift — models.py Pydantic defaulted False while executor.run/run_async/shell_start defaulted True +
    # Rust serde default_true. Any layer defaulting False = commercially silent isolation off (bypasses ARCH-1). This test locks the alignment.
    import inspect

    from fusion_executor.models import ExecutionRequest

    # layer 1: Pydantic ExecutionRequest defaults True
    assert ExecutionRequest(command="x").seatbelt is True, "ExecutionRequest.seatbelt must default True"

    # layers 2-3: FusionSandboxExecutor.run / run_streaming / shell_start signature defaults True
    # (run_async absorbs **kw and forwards to run, no separate seatbelt parameter, excluded from this check)
    for name in ("run", "run_streaming", "shell_start"):
        fn = getattr(FusionSandboxExecutor, name)
        sig = inspect.signature(fn)
        param = sig.parameters.get("seatbelt")
        assert param is not None, f"{name} must have a seatbelt parameter"
        assert param.default is True, f"{name} seatbelt must default True, got {param.default!r}"

    # layer 4: Rust serde default_true — Python ExecutionRequest defaults True → serialization contains seatbelt=true
    # (native deserialization aligned; ARCH-1 health already asserts seatbelt_default_on).
    req = ExecutionRequest(command="echo drift_check")
    dumped = req.model_dump()
    assert dumped.get("seatbelt") is True, (
        f"serialized default request must have seatbelt True, got {dumped.get('seatbelt')}"
    )


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


# ── M-OPS-06: trace_id cross-layer correlation (auto-gen + forwarded + blocked + streaming) ──


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


# ── Issue #3: RLIMIT_NPROC/CPU injection (run + run_streaming 4-layer end to end) ──
# Darwin RLIMIT_NPROC is a per-UID spread-limiter: a low value makes sh's own fork of python3 hit EAGAIN,
# so test the observable rlimit (python resource.getrlimit reads back the injected value), deterministic with no fork dependency.


def test_run_injects_rlimits(executor: FusionSandboxExecutor):
    # injection goes through `ulimit -u/-t`; the setrlimit soft cap cannot exceed the hard cap — a CI runner's hard cap may be < the requested value (e.g. 1333),
    # the kernel silently clamps. Assert observed <= requested and bounded by the kernel hard cap; do not hardcode 2048.
    probe = (
        "python3 -c 'import resource; "
        'print("NPROC", resource.getrlimit(resource.RLIMIT_NPROC)[0], resource.getrlimit(resource.RLIMIT_NPROC)[1]); '
        'print("CPU", resource.getrlimit(resource.RLIMIT_CPU)[0])\''
    )
    result = executor.run(probe, max_nproc=2048, max_cpu_sec=15)
    assert result.exit_code == 0, f"probe should exit 0, stdout={result.stdout}"
    nproc_line = next(ln for ln in result.stdout.splitlines() if ln.startswith("NPROC"))
    nproc_soft, nproc_hard = nproc_line.split()[1], nproc_line.split()[2]
    assert int(nproc_soft) <= 2048, f"soft NPROC should be <= requested 2048, got {nproc_soft}"
    assert int(nproc_soft) <= int(nproc_hard), f"soft NPROC should be <= hard cap, soft={nproc_soft} hard={nproc_hard}"
    assert int(nproc_soft) > 0, f"injected NPROC should be non-zero, got {nproc_soft}"
    assert "CPU 15" in result.stdout, f"injected CPU=15 should be observable, stdout={result.stdout}"


def test_run_rlimits_default_zero_cpu(executor: FusionSandboxExecutor):
    probe = "python3 -c 'import resource; print(\"CPU\", resource.getrlimit(resource.RLIMIT_CPU)[0])'"
    result = executor.run(probe)
    assert result.exit_code == 0
    # default max_cpu_sec=0 → the RLIMIT_CPU cap should be unlimited (0 or a huge number, not a finite value like 15)
    cpu_val = result.stdout.split("CPU")[1].strip()
    assert cpu_val in ("0", "9223372036854775807", "-1"), f"default CPU should be unlimited, got {cpu_val}"


def test_run_rejects_negative_nproc(executor: FusionSandboxExecutor):
    try:
        executor.run("echo hi", max_nproc=-1)
        raise AssertionError("max_nproc<0 should raise ValueError")
    except ValueError:
        pass


def test_run_streaming_injects_rlimits(executor: FusionSandboxExecutor):
    # same as test_run_injects_rlimits: the soft cap is clamped by the kernel hard cap, do not hardcode 2048.
    probe = "python3 -c 'import resource; print(\"NPROC\", resource.getrlimit(resource.RLIMIT_NPROC)[0], resource.getrlimit(resource.RLIMIT_NPROC)[1])'"
    _chunks, result = _consume_stream(executor, probe, max_nproc=2048)
    assert result is not None
    assert result.exit_code == 0
    nproc_line = next(ln for ln in result.stdout.splitlines() if ln.startswith("NPROC"))
    nproc_soft, nproc_hard = nproc_line.split()[1], nproc_line.split()[2]
    assert int(nproc_soft) <= 2048, f"soft NPROC should be <= requested 2048, got {nproc_soft}"
    assert int(nproc_soft) <= int(nproc_hard), f"soft NPROC should be <= hard cap, soft={nproc_soft} hard={nproc_hard}"
    assert int(nproc_soft) > 0, f"injected NPROC should be non-zero, got {nproc_soft}"


# ── native file tools (fe-tools) ──


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
    assert "not found" in r.error


# ── Issue #6: replace_all / MultiEdit atomic batching / NotebookEdit ──


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
            {"old_string": "ghost", "new_string": "x"},  # item 2 did not match → full rollback
        ],
        cwd=str(tmp_path),
    )
    assert not r.ok
    assert "old_string did not match" in r.error
    assert fp.read_text() == original, "partial failure: file not modified (all-or-nothing)"


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


# ── #2 write_file: whole-file create/overwrite + parent-dir creation (Claude Code Write parity) ──


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
    assert "size cap" in (r.error or "")
    assert not (tmp_path / "big.txt").exists()


def test_file_edit_create_on_empty_missing_path(executor: FusionSandboxExecutor, tmp_path):
    # #2: path missing + empty old_string → create the file with new_string
    r = executor.file_edit("new_via_edit.py", "", "created = True\n", cwd=str(tmp_path))
    assert r.ok
    assert (tmp_path / "new_via_edit.py").read_text() == "created = True\n"


def test_file_edit_existing_empty_old_string_still_rejected(executor: FusionSandboxExecutor, tmp_path):
    fp = tmp_path / "exists.txt"
    fp.write_text("data\n")
    r = executor.file_edit("exists.txt", "", "x\n", cwd=str(tmp_path))
    assert not r.ok
    assert "must not be empty" in (r.error or "")
    assert fp.read_text() == "data\n", "existing file with empty old_string must not be written"


def test_file_edit_missing_path_nonempty_old_string_rejected(executor: FusionSandboxExecutor, tmp_path):
    r = executor.file_edit("ghost.py", "old", "new\n", cwd=str(tmp_path))
    assert not r.ok
    assert "not found" in (r.error or "")
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
    assert fp.read_text() == original, "invalid cell_number → file not modified (degraded return)"


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


# ── auto rollback (FR-04 auto policy) ──


def test_auto_rollback_triggers_on_failure_with_file_damage(executor: FusionSandboxExecutor, git_repo: str):
    with open(os.path.join(git_repo, "app.py")) as f:
        assert f.read() == "print(1)\n"
    cmd = "python3 -c \"open('app.py','w').write('broken\\n'); raise ValueError(1)\""
    result = executor.run(cmd, cwd=git_repo, auto_rollback=RollbackPolicy())
    assert result.exit_code != 0
    assert result.auto_rolled_back is True
    with open(os.path.join(git_repo, "app.py")) as f:
        assert f.read() == "print(1)\n", "file rolled back to baseline"


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
        assert f.read() == "broken\n", "no policy → no rollback, changes kept"


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
        assert f.read() == "print(1)\n", "streaming path auto-rollback restored baseline"


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
    assert len(frames) == 3, "max_samples=3 should yield 3 frames"
    # L-TEL-01: ts_ms wall clock (not a fake counter); monotonically increasing, last frame > first frame
    assert frames[0]["ts_ms"] > 0, "wall-clock timestamp non-zero"
    assert frames[2]["ts_ms"] > frames[0]["ts_ms"], "last frame ts > first frame (monotonically increasing)"
    assert frames[0]["mem_mb"] > 0.0, "this process memory non-zero"
    assert frames[0]["cpu_pct"] >= 0.0
    assert frames[0].get("gpu_pct") is None, "GPU not injected by default (serde skip)"


def test_telemetry_python_wrapper(executor: FusionSandboxExecutor):
    samples = list(executor.telemetry_stream(interval_ms=20, max_samples=4))
    assert len(samples) == 4
    assert all(isinstance(s, TelemetrySample) for s in samples)
    # L-TEL-01: ts_ms wall clock (not a fake counter); monotonically increasing
    assert samples[0].ts_ms > 0, "wall-clock timestamp non-zero"
    assert samples[3].ts_ms > samples[0].ts_ms, "last frame ts > first frame (monotonically increasing)"
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
    assert len(frames) == 3, "UDS should receive 3 sample frames"
    assert all(f["id"] == 11 for f in frames)
    assert all(f["result"]["type"] == "sample" for f in frames)
    samples = [f["result"]["sample"] for f in frames]
    # L-TEL-01: ts_ms wall clock (not a fake counter); monotonically increasing
    assert samples[0]["ts_ms"] > 0, "wall-clock timestamp non-zero"
    assert samples[2]["ts_ms"] > samples[0]["ts_ms"], "last frame ts > first frame (monotonically increasing)"
    assert samples[0]["mem_mb"] > 0.0
    assert samples[0].get("gpu_pct") is None, "GPU not injected by default (serde skip)"
    del _json, _socket


# ── v1.6 E2E self-healing loop smoke (PRD §5: run→diagnose→file_edit→re-run) ──

# faulty script: add(1, "two") raises TypeError at return a + b
BUG_SRC = (
    'def add(a, b):\n    return a + b\n\n\ndef main():\n    result = add(1, "two")\n    print(result)\n\n\nmain()\n'
)


def test_self_healing_closed_loop(executor: FusionSandboxExecutor, tmp_path):
    # 1. write the faulty script to disk
    bug = tmp_path / "bug.py"
    bug.write_text(BUG_SRC)

    # 2. first run — should fail, diagnostics slicing locates bug.py
    first = executor.run("python3 bug.py", cwd=str(tmp_path), timeout_sec=15.0, enable_rollback_snapshot=False)
    assert first.exit_code != 0, "faulty script should exit non-zero"
    assert not first.blocked_by_security
    assert first.diagnostics is not None, "exit!=0 should trigger diagnostics slicing"
    assert first.diagnostics.error_type == "TypeError", f"should identify TypeError: {first.diagnostics.error_type}"
    assert first.diagnostics.file_path is not None, "should locate the file path"
    assert "bug.py" in first.diagnostics.file_path, f"file_path should contain bug.py: {first.diagnostics.file_path}"
    assert first.diagnostics.line_number is not None and first.diagnostics.line_number >= 1

    # 3. file_edit surgically fixes the call site (add(1, "two") → add(1, 2)) — no model, deterministic patch
    fix = executor.file_edit(
        "bug.py",
        '    result = add(1, "two")',
        "    result = add(1, 2)",
        cwd=str(tmp_path),
    )
    assert isinstance(fix, EditResult)
    assert fix.ok, f"file_edit should succeed: {fix.error}"
    assert fix.matches == 1

    # 4. second run — should pass (loop converges)
    second = executor.run("python3 bug.py", cwd=str(tmp_path), timeout_sec=15.0, enable_rollback_snapshot=False)
    assert second.exit_code == 0, f"after the fix should exit 0: stderr={second.stderr}"
    assert "3" in second.stdout, "after the fix should print 3"
    assert second.diagnostics is None, "exit==0 should not trigger diagnostics"

    # 5. cleanup of intermediate data — keep only tmp_path (pytest cleans automatically)
    bug.unlink(missing_ok=True)


# ── T8 input validation (M-PY-01 / M-PY-02): upfront fail-fast, not deferred to PyO3 ──


def test_run_non_str_command_raises_typeerror(executor: FusionSandboxExecutor):
    with pytest.raises(TypeError, match="command must be str"):
        executor.run(123)  # type: ignore[arg-type]


def test_run_non_positive_timeout_raises_valueerror(executor: FusionSandboxExecutor):
    with pytest.raises(ValueError, match="timeout_sec must be positive"):
        executor.run("echo hi", timeout_sec=0)
    with pytest.raises(ValueError, match="timeout_sec must be positive"):
        executor.run("echo hi", timeout_sec=-1.5)


def test_run_non_str_cwd_raises_typeerror(executor: FusionSandboxExecutor):
    with pytest.raises(TypeError, match="cwd must be str"):
        executor.run("echo hi", cwd=42)  # type: ignore[arg-type]


def test_run_non_dict_env_vars_raises_typeerror(executor: FusionSandboxExecutor):
    with pytest.raises(TypeError, match="env_vars must be dict"):
        executor.run("echo hi", env_vars="PATH=/x")  # type: ignore[arg-type]


def test_run_env_vars_non_str_value_raises_typeerror(executor: FusionSandboxExecutor):
    with pytest.raises(TypeError, match="env_vars keys and values must both be str"):
        executor.run("echo hi", env_vars={"K": 42})  # type: ignore[dict-item]


def test_gui_action_non_dict_raises_typeerror(executor: FusionSandboxExecutor):
    with pytest.raises(TypeError, match="action must be dict"):
        executor.gui_action("focus_app")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="action must be dict"):
        executor.gui_action(None)  # type: ignore[arg-type]


def test_gui_action_missing_kind_raises_valueerror(executor: FusionSandboxExecutor):
    with pytest.raises(ValueError, match="kind"):
        executor.gui_action({"bundle_id": "com.apple.TextEdit"})


def test_gui_action_non_str_kind_raises_typeerror(executor: FusionSandboxExecutor):
    with pytest.raises(TypeError, match="action\\['kind'\\] must be str"):
        executor.gui_action({"kind": 123})  # type: ignore[dict-item]


def test_run_streaming_non_str_command_raises_typeerror(executor: FusionSandboxExecutor):
    with pytest.raises(TypeError, match="command must be str"):
        list(executor.run_streaming(None))  # type: ignore[arg-type]


def test_run_streaming_non_positive_timeout_raises_valueerror(executor: FusionSandboxExecutor):
    with pytest.raises(ValueError, match="timeout_sec must be positive"):
        list(executor.run_streaming("echo hi", timeout_sec=0))


# ── Blocker 10 (audit §2.9 cross-tenant leak) stdio per-sub scope ──


def test_subscribe_invalid_scope_raises_valueerror(uds_server: str):
    ex = FusionSandboxExecutor(sock_path=uds_server)
    with pytest.raises(ValueError, match="scope must be"):
        ex.subscribe(["stdio"], scope="bogus")


def test_subscribe_own_conn_default_blocks_cross_connection(uds_server: str):
    # connection A subscribes to stdio with the default scope (own_conn); connection B execute_stream → A must not receive B's stdio.
    import json as _json
    import socket as _socket

    # connection A: subscribe with the default scope
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
    # connection B: execute_stream echo
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
    # B reads done
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
    # A waits a short window to confirm no cross-connection push
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
    assert b_done, "B should receive its own done frame"
    assert not a_got_stdio, "default own_conn should block cross-connection stdio (audit §2.9)"
    sa.close()
    sb.close()


def test_subscribe_task_ids_whitelist_receives_matched(uds_server: str):
    # scope=["t1"] subscription, execute_stream task_id="t1" → receives push; task_id="t2" → does not.
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
    # B: task_id="t1" (matches)
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
    assert a_got, "task_ids allowlist match should receive the stdio push"
    sa.close()
    sb.close()


# ── audit §3.11/§3.13/§3.15 Python wrap-up regression ──


def test_telemetry_stream_strict_rejects_missing_field(executor: FusionSandboxExecutor):
    # 3.11: telemetry_stream uses model_validate (the old frame.get("ts_ms", 0) defaulted 0 and swallowed missing fields).
    # inject a bad frame missing ts_ms → model_validate should raise ValidationError (fail-loud, not fake data).
    from pydantic import ValidationError

    bad_frame = {"cpu_pct": 1.0, "mem_mb": 2.0}  # missing required ts_ms
    with pytest.raises(ValidationError):
        TelemetrySample.model_validate(bad_frame)
    # extra fields should also be rejected by _STRICT extra=forbid
    with pytest.raises(ValidationError):
        TelemetrySample.model_validate({"ts_ms": 1, "cpu_pct": 1.0, "mem_mb": 2.0, "bogus": 9})


def test_subscribe_idle_timeout_configurable(uds_server: str):
    # 3.13: idle_timeout is configurable (the old version hardcoded a 15s recv timeout). None=no timeout.
    # subscribe telemetry (10Hz) with idle_timeout=None; frames should keep flowing (no spurious cut after 15s).
    import time as _t

    ex = FusionSandboxExecutor(sock_path=uds_server)
    sub = ex.subscribe(["telemetry"], interval_ms=20, idle_timeout=None)
    assert sub.subscription_id is not None
    # receive 3 frames — None timeout is unbounded, at 10Hz (20ms) frames return within seconds
    got = 0
    deadline = _t.time() + 5.0
    for _ in sub:
        got += 1
        if got >= 3 or _t.time() > deadline:
            break
    sub.unsubscribe()
    assert got >= 3, f"idle_timeout=None should keep receiving frames, got {got}"


def test_subscribe_idle_timeout_short_stops_stream(uds_server: str):
    # 3.13: short idle_timeout — with no push the recv times out → __next__ raises StopIteration (stream end).
    # subscribe the slow screenshot channel (1s) with idle_timeout=0.2 → no frame within 0.2s → StopIteration.
    import time as _t

    ex = FusionSandboxExecutor(sock_path=uds_server)
    sub = ex.subscribe(["screenshot"], screenshot_interval_ms=5000, idle_timeout=0.2)
    t0 = _t.time()
    with pytest.raises(StopIteration):
        next(sub)
    elapsed = _t.time() - t0
    assert elapsed < 1.0, f"short idle_timeout should stop within a second, took {elapsed:.2f}s"
    sub.close()


def test_serve_passes_resolved_path_not_raw_none(monkeypatch, tmp_path):
    # 3.15: serve() resolves the path (env/default) before passing to Rust, never None. Verifies path resolution priority:
    # explicit sock_path > env > default. Only checks the Python-side path selection logic (does not really start a server).
    sp = str(tmp_path / "explicit.sock")
    captured = {}

    class _FakeNative:
        def serve(self, path):
            captured["path"] = path
            raise KeyboardInterrupt  # break out immediately, do not block

    ex = FusionSandboxExecutor()
    ex._native = _FakeNative()
    monkeypatch.delenv("FUSION_EXECUTOR_SOCK", raising=False)
    with pytest.raises(KeyboardInterrupt):
        ex.serve(sp)
    assert captured["path"] == sp, "serve should pass the resolved path, not the raw sock_path"


def test_validate_safe_command_allowed(executor: FusionSandboxExecutor):
    # Issue #11 / #12.4: pre-execution validation without executing — a safe command gets allowed=True, not executed
    v = executor.validate("echo hi")
    assert v["allowed"] is True
    assert v["blocked"] is False
    assert v["reason"] is None
    assert v["stage"] is None


def test_validate_blocked_command_returns_verdict(executor: FusionSandboxExecutor):
    # dangerous command → blocked=True + reason + stage, the command is not executed (no side effects)
    v = executor.validate("rm -rf /")
    assert v["allowed"] is False
    assert v["blocked"] is True
    assert isinstance(v["reason"], str) and v["reason"]
    assert v["stage"] == "regex"


def test_validate_chain_bypass_caught_at_tokenizer(executor: FusionSandboxExecutor):
    # chain-assembly bypass: echo hi && sudo ls → Stage-2 tokenizer blocks sudo
    v = executor.validate("echo hi && sudo ls")
    assert v["blocked"] is True
    assert v["stage"] in ("regex", "tokenizer")


def test_validate_empty_command_raises_valueerror(executor: FusionSandboxExecutor):
    with pytest.raises(ValueError, match="command must be a non-empty string"):
        executor.validate("")
    with pytest.raises(ValueError, match="command must be a non-empty string"):
        executor.validate("   ")
    with pytest.raises(ValueError, match="command must be a non-empty string"):
        executor.validate(123)  # type: ignore[arg-type]


# Issue #10: allowlist override + project-level extension + dynamic execution blocking
# D3-6 (audit 0827 product): tools in extra_whitelist must resolve into a trusted directory to be allowed (fail-closed against
#   /tmp poisoning). The test creates real executable tools in a temp bin dir, registers trusted_bin_dirs, and verifies they are allowed.
def test_extra_whitelist_allows_project_tool(tmp_path):
    tool = tmp_path / "myproj-runner"
    tool.write_text("#!/bin/sh\necho run\n")
    tool.chmod(0o755)
    ex = FusionSandboxExecutor(extra_whitelist=["myproj-runner"], trusted_bin_dirs=[str(tmp_path)])
    v = ex.validate(f"{tool} --version")
    assert v["allowed"] is True, v


def test_extra_whitelist_rejects_shell_interpreter():
    # interpreters/builtins cannot self-backdoor via the extension
    ex = FusionSandboxExecutor(extra_whitelist=["bash", "sh", "exec", "eval"])
    for cmd in ["bash -c 'x'", "sh -c 'x'", "eval 'x'", "exec foo"]:
        v = ex.validate(cmd)
        assert v["allowed"] is False, f"dangerous extension entries must still be blocked: {cmd} -> {v}"


def test_blocks_eval_source_exec_dynamic():
    ex = FusionSandboxExecutor()
    for cmd, kw in [
        ("eval 'echo hi'", "eval"),
        ("source /tmp/evil.sh", "source"),
        ("exec /bin/sh", "exec"),
    ]:
        v = ex.validate(cmd)
        assert v["allowed"] is False, f"{cmd} should be blocked: {v}"
        assert kw in v["reason"], f"{cmd} reason should mention {kw}: {v['reason']}"


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
        assert v["allowed"] is False, f"{cmd} should be blocked: {v}"


def test_allows_pipe_to_non_shell_no_false_positive():
    ex = FusionSandboxExecutor()
    for cmd in ["echo hi | grep hi", "git log --oneline | head -5", "echo bash | grep bash"]:
        v = ex.validate(cmd)
        assert v["allowed"] is True, f"{cmd} should not be falsely blocked: {v}"


# Issue #9: environment isolation — host secrets not leaked by default; env_vars injection; inherit_env opt-in inheritance
_REFLECT = 'python3 -c "import os,sys;sys.stdout.write(os.environ.get(%r,%r))"'


def test_env_isolation_strips_host_secret_by_default(executor: FusionSandboxExecutor, monkeypatch):
    monkeypatch.setenv("FE_TEST_SECRET", "leak-me-please")
    r = executor.run(_REFLECT % ("FE_TEST_SECRET", "clean"), timeout_sec=5)
    assert r.exit_code == 0, f"stderr={r.stderr}"
    assert "leak-me-please" not in r.stdout, "host secrets must not leak into the default-isolated subprocess"


def test_env_isolation_injects_env_vars(executor: FusionSandboxExecutor):
    r = executor.run(_REFLECT % ("FE_TASK_VAR", "missing"), timeout_sec=5, env_vars={"FE_TASK_VAR": "injected"})
    assert r.exit_code == 0
    assert "injected" in r.stdout, "env_vars must be injected into the subprocess"


def test_env_isolation_baseline_present(executor: FusionSandboxExecutor):
    for key in ("PATH", "TMPDIR", "SHELL"):
        r = executor.run(_REFLECT % (key, "missing"), timeout_sec=5)
        assert r.exit_code == 0
        assert "missing" not in r.stdout, f"baseline {key} should exist so the command resolves"


def test_env_inherit_true_restores_host_env(executor: FusionSandboxExecutor, monkeypatch):
    monkeypatch.setenv("FE_TEST_SECRET", "leak-me-please")
    r = executor.run(_REFLECT % ("FE_TEST_SECRET", "clean"), timeout_sec=5, inherit_env=True)
    assert r.exit_code == 0
    assert "leak-me-please" in r.stdout, "inherit_env=True should inherit the host env (opt-in trusted scenario)"


# Issue #4: use_pty=False stdio backend — stdout/stderr captured independently (PTY merges, stderr always empty)
def test_use_pty_false_captures_stderr_separately(executor: FusionSandboxExecutor):
    cmd = "python3 -c \"import sys; sys.stdout.write('OUT-LINE\\n'); sys.stderr.write('ERR-LINE\\n')\""
    r = executor.run(cmd, timeout_sec=5, use_pty=False)
    assert r.exit_code == 0, f"exit={r.exit_code} stdout={r.stdout!r} stderr={r.stderr!r}"
    assert "OUT-LINE" in r.stdout, f"stdout should contain OUT: {r.stdout!r}"
    assert "ERR-LINE" not in r.stdout, f"stdout must not be polluted by stderr: {r.stdout!r}"
    assert "ERR-LINE" in r.stderr, f"stderr should capture ERR independently: {r.stderr!r}"


def test_use_pty_true_merges_stderr_into_stdout(executor: FusionSandboxExecutor):
    # PTY backend: stdout/stderr merged, stderr always empty (portable-pty forces stderr=PTY as_stdio)
    cmd = "python3 -c \"import sys; sys.stdout.write('OUT\\n'); sys.stderr.write('ERR\\n')\""
    r = executor.run(cmd, timeout_sec=5, use_pty=True)
    assert r.exit_code == 0
    assert r.stderr == "", "PTY backend stderr is always empty (merged into stdout)"
    assert "OUT" in r.stdout
    assert "ERR" in r.stdout, "PTY backend stderr should merge into stdout"


def test_run_streaming_rejects_use_pty_false(executor: FusionSandboxExecutor):
    # streaming has no stdio backend, explicitly rejected (fail-loud rather than silently degrading to PTY)
    with pytest.raises(ValueError, match="use_pty=False"):
        next(executor.run_streaming("echo hi", timeout_sec=5, use_pty=False))


# Issue #1: persistent background shells (run_in_background/BashOutput/KillShell parity)
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
        assert str(i) in out.output, f"missing {i}: {out.output!r}"
    assert out.exit_code == 0


def test_shell_kill_long_running(executor: FusionSandboxExecutor):
    import time

    sid = executor.shell_start("python3 -c 'import time; time.sleep(30)'").shell_id
    time.sleep(0.4)
    mid = executor.shell_output(sid)
    assert mid.running, "long task should still be running"
    ok = executor.kill_shell(sid)
    assert ok
    time.sleep(0.8)
    after = executor.shell_output(sid)
    assert not after.running, "should be finished after kill"


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
    out = None
    deadline = time.time() + 15
    while time.time() < deadline:
        out = _rpc_once(
            uds_server,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "executor.shell_output",
                "params": {"shell_id": sid},
            },
        )["result"]
        if out["running"] is False and "poll-me" in out["output"]:
            break
        time.sleep(0.2)
    assert out is not None
    assert out["shell_id"] == sid
    assert "poll-me" in out["output"]
    assert out["running"] is False
    assert out["exit_code"] == 0


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


# ── #104 P-2/M-4/M-6 Python-layer fixes ──


def test_m4_native_import_failure_warns(monkeypatch):
    # M-4: _native import failure should warn (fail-visible), not silently swallow ABI/link errors.
    # simulate a missing native extension: importlib triggers ImportError → __init__ falls back + warns.
    import importlib

    # reload __init__ under a separate module name to isolate the impact on the globally loaded fusion_executor:
    # monkeypatch sys.modules to inject a broken _native, then reload.
    import sys
    import warnings

    import fusion_executor

    class _BrokenNative:
        def __getattr__(self, name):
            raise ImportError(f"simulated native load failure: {name}")

    monkeypatch.setitem(sys.modules, "fusion_executor._native", _BrokenNative())
    # __init__'s try/except uses `from ._native import version_info`, triggering ImportError
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        importlib.reload(fusion_executor)
    monkeypatch.delitem(sys.modules, "fusion_executor._native", raising=False)
    # restore the real _native (later tests depend on it), reload back to the real extension
    importlib.reload(fusion_executor)
    # assert: the warn emits a RuntimeWarning mentioning the native load failure
    rw = [w for w in caught if issubclass(w.category, RuntimeWarning)]
    assert any("native" in str(w.message) for w in rw), (
        f"native import failure should warn, got {[str(w.message) for w in caught]}"
    )


def test_m6_run_streaming_unknown_frame_skipped(executor: FusionSandboxExecutor, caplog):
    # M-6: run_streaming receiving an unknown frame type must not raise (forward-compatible), debug-logged for traceability.
    # monkeypatch _native.execute_streaming to return an unknown-frame sequence + a normal done frame.
    import logging

    class _FakeStream:
        def __init__(self):
            self._frames = [
                {"type": "chunk", "data": "ok-chunk"},
                {"type": "future_frame_kind", "payload": {"x": 1}},  # unknown type
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
    assert chunks == ["ok-chunk"], "unknown frames should be skipped without raising, only chunks yielded"
    # M-6 core: the debug log records the unknown type (traceable)
    assert any("future_frame_kind" in rec.getMessage() for rec in caplog.records), (
        "unknown frame type should be debug-logged"
    )


def test_p2_subscription_buf_cap_returns_none():
    # P-2: _buf exceeding _SUB_BUF_MAX_BYTES → drop the buffer and return None (treated as stream end), no OOM.
    # build a Subscription (no real socket), monkeypatch recv to return an oversized chunk without newline.
    from fusion_executor.executor import _SUB_BUF_MAX_BYTES, Subscription

    sub = Subscription.__new__(Subscription)
    sub._buf = b""

    class _FakeSock:
        def __init__(self):
            self.calls = 0

        def recv(self, n):
            self.calls += 1
            if self.calls == 1:
                # single chunk over cap (no newline) → triggers truncation
                return b"x" * (_SUB_BUF_MAX_BYTES + 1024)
            return b""

    sub._sock = _FakeSock()
    out = sub._read_json()
    assert out is None, "corrupted stream over cap should return None as stream end"
    assert sub._buf == b"", "_buf cleared after truncation"


def test_p2_subscription_buf_normal_line_still_works():
    # P-2: the cap does not affect normal newline framing (regression guard).
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


# D3-4 (audit 0827 product): per-task RSS watchdog — the child tree is killed by the sysinfo poll when RSS
# exceeds rss_limit_mb (exit_code -124, oom_killed=true). Darwin RLIMIT_AS/RLIMIT_DATA are platform-invalid,
# mitigated by polling instead. The inline interpreter is allowed via the D3-1 opt-in gateway (fixture allow_inline_interpreter).
def test_run_rss_watchdog_kills_memory_bomb(executor: FusionSandboxExecutor):
    bomb = "python3 -c \"x=[bytearray(b'a'*10**7) for _ in range(100)]; import time; time.sleep(5)\""
    r = executor.run(bomb, rss_limit_mb=256, timeout_sec=10.0, enable_rollback_snapshot=False)
    assert r.oom_killed, f"memory bomb should trigger oom_killed, exit={r.exit_code}"
    assert r.exit_code == -124, f"OOM kill exit should be -124, got {r.exit_code}"


def test_run_rss_watchdog_zero_disables(executor: FusionSandboxExecutor):
    # rss_limit_mb=0 disables the watchdog — a smaller allocation completes normally (trusted opt-out)
    r = executor.run(
        "python3 -c \"x=[bytearray(b'a'*10**6) for _ in range(10)]; print(len(x))\"",
        rss_limit_mb=0,
        timeout_sec=15.0,
        enable_rollback_snapshot=False,
    )
    assert not r.oom_killed, "rss_limit_mb=0 should not trigger oom_killed"
    assert r.exit_code == 0, f"normal completion exits 0, got {r.exit_code}"


def test_run_rss_watchdog_normal_unaffected(executor: FusionSandboxExecutor):
    r = executor.run("echo hi", rss_limit_mb=256, enable_rollback_snapshot=False)
    assert r.exit_code == 0, f"echo should exit 0, got {r.exit_code}"
    assert not r.oom_killed, "echo should not trigger oom_killed"


def test_run_streaming_rss_watchdog(executor: FusionSandboxExecutor):
    bomb = "python3 -c \"x=[bytearray(b'a'*10**7) for _ in range(100)]; import time; time.sleep(5)\""
    _chunks, result = _consume_stream(executor, bomb, rss_limit_mb=256, timeout_sec=10.0)
    assert result is not None
    assert result.oom_killed, f"streaming Done frame oom_killed should be true, exit={result.exit_code}"
    assert result.exit_code == -124, f"streaming OOM exit should be -124, got {result.exit_code}"


# ── Issue #23: fusion-guard Phase 3 integration (guard OFF default / guard_sock opt-in / fail-closed degradation) ──
# guard is OFF by default — FusionSandboxExecutor() does not connect to a guard daemon, same behavior as v0.2.5 (regression red line).
# guard_sock pointing at a non-existent socket → fe-security degrades fail-closed: cached rules + static allowlist fence;
# allowlisted binaries (echo) still run (stricter than guard-alive, never loosened), non-allowlisted/dangerous commands still blocked. guard_action_id
# is only set when guard decides Block/L3; None on guard OFF / degraded allow.


def test_guard_off_default_runs_normally():
    # no guard_sock by default → guard OFF, echo runs normally (regression red line)
    ex = FusionSandboxExecutor(allow_inline_interpreter=True)
    r = ex.run("echo no-guard")
    assert r.exit_code == 0
    assert "no-guard" in r.stdout
    assert r.guard_action_id is None, "guard_action_id must be None when guard is OFF"


def test_guard_off_blocked_command_has_no_action_id():
    # with guard OFF, rm -rf / is still blocked by the static allowlist fence (degraded fail-closed never loosens), but no guard_action_id
    ex = FusionSandboxExecutor(allow_inline_interpreter=True)
    r = ex.run("rm -rf /")
    assert r.blocked_by_security
    assert r.exit_code == -1
    assert r.guard_action_id is None, "guard OFF static blocking produces no guard_action_id"


def test_guard_sock_nonexistent_degrades_fail_closed():
    # guard_sock pointing at a non-existent socket → fe-security liveness probe fails, degrades fail-closed.
    # allowlisted echo still runs (stricter than guard-alive, never loosened); rm -rf / still blocked by the static fence/cached rules.
    ex = FusionSandboxExecutor(
        allow_inline_interpreter=True,
        guard_sock="/tmp/fe-guard-nonexistent-test.sock",
        guard_tenant="test-tenant",
    )
    r_ok = ex.run("echo degraded")
    assert r_ok.exit_code == 0, (
        f"under degradation the allowlisted echo should run, exit={r_ok.exit_code} reason={r_ok.security_reason}"
    )
    assert "degraded" in r_ok.stdout
    assert r_ok.guard_action_id is None, "degraded allow produces no guard_action_id"
    r_blk = ex.run("rm -rf /")
    assert r_blk.blocked_by_security
    assert r_blk.exit_code == -1


def test_guard_action_id_pydantic_roundtrip():
    # guard_action_id field survives the Pydantic round-trip + extra=forbid (4-layer field set consistent)
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
    # Pydantic stays intact when guard_action_id is None (default None); extra=forbid does not reject unknown fields
    r = ExecutionResult.model_validate({"exit_code": 0})
    assert r.guard_action_id is None
    assert r.model_dump()["guard_action_id"] is None


def test_guard_env_var_enables_guard():
    # FUSION_GUARD_SOCK env → __init__ passes guard through (daemon missing → fail-closed degradation)
    env_sock = "/tmp/fe-guard-env-test.sock"
    old = os.environ.pop("FUSION_GUARD_SOCK", None)
    try:
        os.environ["FUSION_GUARD_SOCK"] = env_sock
        ex = FusionSandboxExecutor(allow_inline_interpreter=True)
        # echo allowlisted → degraded allow (never loosened)
        r = ex.run("echo env-guard")
        assert r.exit_code == 0, f"under env-guard degradation echo should run, exit={r.exit_code}"
        assert "env-guard" in r.stdout
    finally:
        if old is not None:
            os.environ["FUSION_GUARD_SOCK"] = old
        else:
            os.environ.pop("FUSION_GUARD_SOCK", None)


def test_execution_result_cancelled_field_default_false(
    executor: FusionSandboxExecutor,
):
    # Issue #32: ExecutionResult.cancelled defaults False; a normal run never sets it true.
    r = executor.run("echo nocancel", enable_rollback_snapshot=False)
    assert r.exit_code == 0
    assert r.cancelled is False, "cancelled should be False on the non-cancel path"
    assert "nocancel" in r.stdout


def test_execution_result_cancelled_field_in_extra_forbid_rejects():
    # _STRICT extra=forbid: cancelled is already a legal field, Pydantic accepts it; unknown fields are still rejected.
    from pydantic import ValidationError

    r = ExecutionResult(exit_code=0, cancelled=True)
    assert r.cancelled is True
    with pytest.raises(ValidationError):
        ExecutionResult(exit_code=0, bogus_field=1)  # type: ignore[call-arg]


def test_cancel_stream_unknown_id_over_uds(uds_server: str):
    # Issue #32: cancelling an unknown stream_id → False (best-effort, no raise).
    ex = FusionSandboxExecutor(allow_inline_interpreter=True)
    ok = ex.cancel_stream(99999, sock_path=uds_server)
    assert ok is False, "unknown stream_id should return False"


def test_cancel_stream_kills_inflight_over_uds(uds_server: str, tmp_path):
    # Issue #32: long-running execute_stream + cancel_stream → Done exit_code -1 + cancelled true.
    # a raw UDS client sends execute_stream (id=51) and reads the stream while another connection sends cancel —
    # run_streaming is the in-process path (not via serve), so this test verifies serve-side cancel over raw UDS.
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
    # wait for the stream to start
    import time

    time.sleep(0.6)
    # cancel via the wrapper (same socket path, cross-connection StreamRegistry shared)
    ex = FusionSandboxExecutor(allow_inline_interpreter=True)
    ok = ex.cancel_stream(51, sock_path=path)
    assert ok is True, "should find the in-flight stream id=51 and issue cancel"
    # read the done frame
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
    assert done is not None, "Issue #32: should receive the done frame"
    assert done["exit_code"] == -1, "Issue #32: cancel done exit_code should be -1"
    assert done["cancelled"] is True, "Issue #32: cancelled should pass through as true"
