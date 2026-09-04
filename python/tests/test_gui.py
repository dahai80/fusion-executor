from __future__ import annotations

import base64
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from contextlib import suppress

import pytest

from fusion_executor import FusionSandboxExecutor, GuiResult, Subscription


def _ax_trusted() -> bool:
    # 经 IPC health 探测 ax_trusted, 或直接调 native
    try:
        ex = FusionSandboxExecutor()
        r = ex.gui_action({"kind": "screenshot"})
        return r.ok and r.screenshot_png_b64 is not None
    except Exception:
        return False


def _ax_access_trusted() -> bool:
    # 探测 TCC Accessibility (非 Screen Recording) — Rust !ax_trusted() 降级闸门用此权限。
    # hover 仅带坐标, 不走 AX 树遍历: trusted→ok=True, untrusted→ok=False+accessibility-permission-required。
    # 与 _ax_trusted() (screenshot=Screen Recording) 分离 — 两 TCC 权限独立。
    # RUN-12: 关闭焦点 app 白名单 (disable_bundle_allowlist=True) — 否则默认白名单先拦 hover,
    #         误判 trusted 机为 untrusted, 降级测试在 trusted 机误跑。探测须纯净测 AX 权限。
    try:
        ex = FusionSandboxExecutor(disable_bundle_allowlist=True)
        r = ex.gui_action({"kind": "hover", "ax_position": [0.0, 0.0]})
        return r.ok
    except Exception:
        return False


def _sock_path() -> str:
    fd, p = tempfile.mkstemp(suffix=".sock", prefix="fe-gui-py-")
    os.close(fd)
    os.unlink(p)
    return p


def _wait_sock(path: str, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.exists(path):
            return
        time.sleep(0.05)
    raise TimeoutError(f"socket 未出现: {path}")


def _rpc(path: str, req: dict) -> dict:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(15.0)
        s.connect(path)
        s.sendall((json.dumps(req, ensure_ascii=False) + "\n").encode("utf-8"))
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
    return json.loads(buf.decode("utf-8").strip())


@pytest.fixture
def server():
    sock = _sock_path()
    env = dict(os.environ, FUSION_EXECUTOR_SOCK=sock)
    proc = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "from fusion_executor import FusionSandboxExecutor; FusionSandboxExecutor().serve()",
        ],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        _wait_sock(sock)
        yield sock
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        if os.path.exists(sock):
            os.unlink(sock)


def test_gui_result_model_roundtrip():
    r = GuiResult(
        ok=True,
        node_tree="{}",
        screenshot_png_b64="abc",
        screenshot_width=1920,
        screenshot_height=1080,
        error=None,
    )
    d = r.model_dump()
    assert d["ok"] is True
    assert d["node_tree"] == "{}"
    assert d["screenshot_png_b64"] == "abc"
    assert d["screenshot_width"] == 1920
    assert d["screenshot_height"] == 1080
    assert d["error"] is None
    back = GuiResult.model_validate(d)
    assert back == r


def test_gui_action_returns_gui_result_type():
    ex = FusionSandboxExecutor()
    # 未知键名 → 无论授权与否都降级 (trusted-independent): ok=False + error
    r = ex.gui_action({"kind": "key_press", "key": "totally-fake-key"})
    assert isinstance(r, GuiResult)
    assert r.ok is False
    assert r.error is not None
    assert "unknown-key" in r.error


def test_gui_action_bad_kind_degrades():
    ex = FusionSandboxExecutor()
    r = ex.gui_action({"kind": "no_such_kind"})
    assert isinstance(r, GuiResult)
    assert r.ok is False
    assert r.error is not None


def test_gui_action_unknown_modifier_degrades():
    ex = FusionSandboxExecutor()
    # 已知键 + 未知修饰键 → ok=False + unknown-modifier (trusted-independent)
    r = ex.gui_action({"kind": "key_press", "key": "Tab", "modifiers": ["hyper"]})
    assert isinstance(r, GuiResult)
    assert r.ok is False
    assert r.error is not None
    assert "unknown-modifier" in r.error


def test_gui_action_screenshot_when_trusted():
    if not _ax_trusted():
        pytest.skip("AX/Screen Recording 未授权 — 跳过真实截图测试 (CI 路径)")
    ex = FusionSandboxExecutor()
    r = ex.gui_action({"kind": "screenshot"})
    assert r.ok is True
    assert r.screenshot_png_b64 is not None
    raw = base64.b64decode(r.screenshot_png_b64)
    assert raw[:8] == b"\x89PNG\r\n\x1a\n", "截图非 PNG"
    assert r.screenshot_width is not None and r.screenshot_width > 0
    assert r.screenshot_height is not None and r.screenshot_height > 0


def test_gui_action_keypress_when_trusted():
    if not _ax_trusted():
        pytest.skip("AX 未授权 — 跳过真实按键合成测试 (CI 路径)")
    # RUN-12: 关闭默认白名单 — 测试机聚焦 app (pytest 进程的终端) 不一定在默认安全集内,
    #         白名单会先拦 key_press 合成。显式 disable 走真实 CGEvent 路径验 ok=True。
    ex = FusionSandboxExecutor(disable_bundle_allowlist=True)
    # 已知键名 → CGEvent 合成 keydown+keyup, post HID; 应 ok=True
    r = ex.gui_action({"kind": "key_press", "key": "Tab"})
    assert isinstance(r, GuiResult)
    assert r.ok is True, f"KeyPress Tab 应成功: {r.error}"
    assert r.error is None


def test_gui_action_keypress_chord_when_trusted():
    if not _ax_trusted():
        pytest.skip("AX 未授权 — 跳过真实修饰键和弦测试 (CI 路径)")
    # RUN-12: 同 keypress_when_trusted — 关闭默认白名单走真实 CGEvent 和弦路径。
    ex = FusionSandboxExecutor(disable_bundle_allowlist=True)
    # 修饰键和弦 (Cmd+Tab) — 已知键 + 已知修饰键 → ok=True
    r = ex.gui_action({"kind": "key_press", "key": "Tab", "modifiers": ["command"]})
    assert isinstance(r, GuiResult)
    assert r.ok is True, f"KeyPress Cmd+Tab 应成功: {r.error}"
    assert r.error is None


def test_gui_action_over_uds(server: str):
    resp = _rpc(
        server,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "executor.gui_action",
            "params": {"action": {"kind": "key_press", "key": "totally-fake-key"}},
        },
    )
    assert resp["jsonrpc"] == "2.0"
    assert resp["id"] == 1
    r = resp["result"]
    # 未知键名 → ok=False + unknown-key (trusted-independent, CI 路径)
    assert r["ok"] is False
    assert r["error"] is not None
    assert "unknown-key" in r["error"]


def test_gui_action_bad_kind_over_uds(server: str):
    resp = _rpc(
        server,
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "executor.gui_action",
            "params": {"action": {"kind": "no_such_kind"}},
        },
    )
    # 反序列化失败 → JSON-RPC error (-32600 invalid req)
    assert "error" in resp
    assert resp["error"]["code"] == -32600


def test_gui_action_wait_ok_without_trust():
    # Wait 纯延时, trusted-independent — 无 TCC 依赖, CI 可跑。0s 立即返回 ok=True。
    ex = FusionSandboxExecutor()
    r = ex.gui_action({"kind": "wait", "seconds": 0.0})
    assert isinstance(r, GuiResult)
    assert r.ok is True, f"Wait 0s 应 ok=True (trusted-independent): {r.error}"
    assert r.error is None


def test_gui_action_wait_negative_clamps():
    # 负值 Wait 裁 0 (不睡眠), ok=True
    ex = FusionSandboxExecutor()
    r = ex.gui_action({"kind": "wait", "seconds": -5.0})
    assert r.ok is True, f"负值 Wait 应裁 0 后 ok=True: {r.error}"


def test_gui_action_wait_over_uds(server: str):
    # Wait 经 UDS 往返, trusted-independent — 0s 应 ok=True
    resp = _rpc(
        server,
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "executor.gui_action",
            "params": {"action": {"kind": "wait", "seconds": 0.0}},
        },
    )
    assert resp["jsonrpc"] == "2.0"
    assert resp["id"] == 3
    assert resp["result"]["ok"] is True
    assert resp["result"]["error"] is None


def test_gui_action_scroll_when_trusted():
    if not _ax_trusted():
        pytest.skip("AX 未授权 — 跳过真实滚轮合成测试 (CI 路径)")
    # RUN-12: 关闭默认白名单走真实 CGEvent scrollWheel 路径。
    ex = FusionSandboxExecutor(disable_bundle_allowlist=True)
    r = ex.gui_action({"kind": "scroll", "dx": 0, "dy": -3})
    assert isinstance(r, GuiResult)
    assert r.ok is True, f"Scroll 应成功: {r.error}"
    assert r.error is None


def test_gui_action_drag_when_trusted():
    if not _ax_trusted():
        pytest.skip("AX 未授权 — 跳过真实拖拽合成测试 (CI 路径)")
    # RUN-12: 关闭默认白名单走真实 CGEvent mouseMove/down/up 拖拽路径。
    ex = FusionSandboxExecutor(disable_bundle_allowlist=True)
    r = ex.gui_action({"kind": "drag", "from": [10.0, 10.0], "to": [50.0, 50.0]})
    assert isinstance(r, GuiResult)
    assert r.ok is True, f"Drag 应成功: {r.error}"
    assert r.error is None


# ── v1.5 新动作 (double_click/right_click/hover/window_*) ──


# CI 路径 (untrusted): 9 个新变体均经 !ax_trusted() 闸门降级 — 证明 4 层 auto-flow
NEW_VARIANTS_CI = [
    {"kind": "double_click", "ax_position": [5.0, 5.0]},
    {"kind": "right_click", "ax_position": [5.0, 5.0]},
    {"kind": "hover", "ax_position": [5.0, 5.0]},
    {"kind": "window_close"},
    {"kind": "window_minimize"},
    {"kind": "window_zoom"},
    {"kind": "window_resize", "width": 800.0, "height": 600.0},
    {"kind": "triple_click", "ax_position": [5.0, 5.0]},
    {"kind": "hold_key", "key": "Return", "duration_ms": 20},
]


def test_gui_action_new_variants_degrade_without_trust():
    # trusted 机走真实 AX/CGEvent (非降级路径) — 仅 CI (untrusted) 跑降级断言
    # 闸门 = TCC Accessibility (Rust !ax_trusted()), 用 _ax_access_trusted() 探测 (非 Screen Recording)
    if _ax_access_trusted():
        pytest.skip("AX Accessibility 已授权 — 降级路径仅 CI (untrusted) 跑")
    ex = FusionSandboxExecutor()
    for action in NEW_VARIANTS_CI:
        r = ex.gui_action(action)
        assert isinstance(r, GuiResult), f"{action['kind']} 应返回 GuiResult"
        assert r.ok is False, f"{action['kind']} 未授权应 ok=False"
        assert r.error is not None and "accessibility-permission-required" in r.error, (
            f"{action['kind']} 降级错误应含 accessibility-permission-required: {r.error}"
        )


def test_gui_action_pointer_variants_when_trusted():
    # pointer 变体 (double_click/right_click/hover) 带坐标 → CGEvent 合成, 无需 AX 树遍历 → ok=True
    # window_* 变体需真实 GUI 会话 (AX 窗口树), 沙箱内 fail — 不在此断言
    if not _ax_access_trusted():
        pytest.skip("AX Accessibility 未授权 — 跳过真实 pointer 合成测试 (CI 路径)")
    # RUN-12: 关闭默认白名单 — 聚焦 app (pytest 终端) 不在默认安全集, 白名单会先拦 hover/pointer。
    ex = FusionSandboxExecutor(disable_bundle_allowlist=True)
    for action in [
        {"kind": "hover", "ax_position": [10.0, 20.0]},
        {"kind": "double_click", "ax_position": [5.0, 5.0]},
        {"kind": "right_click", "ax_position": [5.0, 5.0]},
        {"kind": "triple_click", "ax_position": [5.0, 5.0]},
    ]:
        r = ex.gui_action(action)
        assert isinstance(r, GuiResult), f"{action['kind']} 应返回 GuiResult"
        assert r.ok is True, f"{action['kind']} 带坐标应 ok=True: {r.error}"
        assert r.error is None


def test_gui_action_holdkey_when_trusted():
    # hold_key 单键 CGEvent 合成 (keydown→sleep→keyup), 无需 AX 树 → ok=True
    if not _ax_access_trusted():
        pytest.skip("AX Accessibility 未授权 — 跳过真实 key 合成测试 (CI 路径)")
    # RUN-12: 关闭默认白名单走真实 CGEvent hold_key 路径 (同 keypress/pointer)。
    ex = FusionSandboxExecutor(disable_bundle_allowlist=True)
    r = ex.gui_action({"kind": "hold_key", "key": "return", "duration_ms": 20})
    assert isinstance(r, GuiResult)
    assert r.ok is True, f"HoldKey 应成功: {r.error}"
    assert r.error is None


# ── v1.5 #14 双向 server-push (subscribe/unsubscribe) ──


def test_subscribe_telemetry_yields_event_frames(server: str):
    ex = FusionSandboxExecutor(sock_path=server)
    sub = ex.subscribe(["telemetry"], interval_ms=20)
    assert sub.subscription_id is not None
    assert sub.subscription_id.startswith("sub-")
    frames = []
    deadline = time.time() + 5.0
    for params in sub:
        assert params["channel"] == "telemetry"
        assert params["subscription_id"] == sub.subscription_id
        assert "data" in params
        frames.append(params)
        if len(frames) >= 3 or time.time() > deadline:
            break
    assert len(frames) >= 3, f"应收到 >=3 telemetry 推送帧, got={len(frames)}"
    sub.unsubscribe()


def test_subscribe_stdio_broadcasts_across_connections(server: str):
    # 连接 A 订阅 stdio (scope=all 跨连接收), 连接 B 经 UDS execute_stream → A 收到 stdio 推送
    # Blocker 10: 默认 own_conn 已隔离跨连接; 显式 all 才全广播。
    import threading

    ex_a = FusionSandboxExecutor(sock_path=server)
    sub = ex_a.subscribe(["stdio"], scope="all")
    assert sub.subscription_id is not None
    a_frames: list[dict] = []
    stop = threading.Event()

    def reader():
        while not stop.is_set():
            try:
                params = next(sub)
            except StopIteration:
                break
            except OSError:
                break
            if params["channel"] == "stdio" and params["subscription_id"] == sub.subscription_id:
                a_frames.append(params)
                break

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    # 连接 B: execute_stream echo via raw UDS
    b = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    b.settimeout(15.0)
    b.connect(server)
    req = {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "executor.execute_stream",
        "params": {"command": "echo hi", "enable_rollback_snapshot": False},
    }
    b.sendall((json.dumps(req) + "\n").encode("utf-8"))
    buf = b""
    b_done = False
    deadline = time.time() + 5.0
    while time.time() < deadline:
        try:
            chunk = b.recv(4096)
        except TimeoutError:
            chunk = b""
        if chunk:
            buf += chunk
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            v = json.loads(line.decode("utf-8").strip())
            if v.get("id") == 7 and v.get("result", {}).get("type") == "done":
                b_done = True
        if b_done:
            break
    b.close()
    stop.set()
    t.join(timeout=2.0)
    sub.unsubscribe()
    assert b_done, "B 应收到自己 done 帧"
    assert a_frames, "A 应收到 stdio 跨连接推送"


def test_subscribe_unknown_channel_raises(server: str):
    ex = FusionSandboxExecutor(sock_path=server)
    with pytest.raises(ValueError, match="未知通道"):
        ex.subscribe(["bogus"])


# ── v1.6 覆盖率补缺 (Subscription 错误/边界路径) ──


def test_subscribe_passes_screenshot_interval(server: str):
    # 覆盖 _open 行 329: screenshot_interval_ms 非空 → 写入 params
    ex = FusionSandboxExecutor(sock_path=server)
    sub = ex.subscribe(["screenshot"], interval_ms=None, screenshot_interval_ms=200)
    assert sub.subscription_id is not None
    sub.unsubscribe()


def test_subscription_close_without_open():
    # 覆盖 close() 行 395-397: open 后显式 close 关 socket
    sub = Subscription("/tmp/fe-cov-close.sock", ["telemetry"], None, None)
    assert sub._sock is None
    sub.close()  # 未 open — 仍安全
    assert sub._sock is None


def test_subscription_unsubscribe_without_open_returns_false():
    # 覆盖 unsubscribe() 行 373: sock/sub_id 均空 → 提前返回 False
    sub = Subscription("/tmp/fe-cov-nosub.sock", ["telemetry"], None, None)
    assert sub.unsubscribe() is False
    assert sub._sock is None


def test_subscription_subscribe_error_raises():
    # 覆盖 _open 行 334-335: 服务端返 error → RuntimeError
    sock_path = _sock_path()
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(sock_path)
    listener.listen(1)
    listener.settimeout(5.0)

    def fake_server():
        conn, _ = listener.accept()
        conn.recv(4096)
        conn.sendall(
            (json.dumps({"jsonrpc": "2.0", "id": 1, "error": {"code": -32600, "message": "bad"}}) + "\n").encode()
        )
        conn.close()

    import threading

    t = threading.Thread(target=fake_server, daemon=True)
    t.start()
    try:
        sub = Subscription(sock_path, ["telemetry"], None, None)
        with pytest.raises(RuntimeError, match="subscribe 失败"):
            sub._open()
    finally:
        listener.close()
        if os.path.exists(sock_path):
            os.unlink(sock_path)


def test_subscription_next_raises_connectionerror_on_unexpected_disconnect():
    # IMPL-3: 伪 server 发合法 subscribe 响应后立即关连接 (无 unsubscribe) = server 崩溃场景。
    # __next__ 内 recv 返 b"" → _eof_seen=True + 非 _closed_by_server → ConnectionError (非 StopIteration)。
    # 调用方可 catch ConnectionError 重连/告警, 不当干净流尾吞掉。
    sock_path = _sock_path()
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(sock_path)
    listener.listen(1)
    listener.settimeout(5.0)

    def fake_server():
        conn, _ = listener.accept()
        conn.recv(4096)
        conn.sendall(
            (
                json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"ok": True, "subscription_id": "sub-eof"}}) + "\n"
            ).encode()
        )
        conn.close()

    import threading

    t = threading.Thread(target=fake_server, daemon=True)
    t.start()
    try:
        sub = Subscription(sock_path, ["telemetry"], None, None)
        sub._open()
        assert sub.subscription_id == "sub-eof"
        with pytest.raises(ConnectionError, match="server disconnected"):
            next(sub)
        # sock 仍开 (服务端关了对端, 本地未关) → close() 覆盖
        assert sub._sock is not None
        sub.close()
        assert sub._sock is None
    finally:
        listener.close()
        if os.path.exists(sock_path):
            os.unlink(sock_path)


def test_subscription_graceful_close_raises_stopiteration():
    # IMPL-3: 主动 unsubscribe/close (_closed_by_server=True) → __next__ 得 None 抛 StopIteration (干净流尾)。
    # 用真实 server: subscribe 后本端调 close (标记主动关), 再 next → StopIteration (非 ConnectionError)。
    sock_path = _sock_path()
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(sock_path)
    listener.listen(1)
    listener.settimeout(5.0)

    def fake_server():
        conn, _ = listener.accept()
        conn.recv(4096)
        conn.sendall(
            (
                json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"ok": True, "subscription_id": "sub-grace"}}) + "\n"
            ).encode()
        )
        # 保持连接开, 等本端 close
        with suppress(OSError):
            conn.recv(4096)
        conn.close()

    import threading

    t = threading.Thread(target=fake_server, daemon=True)
    t.start()
    try:
        sub = Subscription(sock_path, ["telemetry"], None, None)
        sub._open()
        assert sub.subscription_id == "sub-grace"
        sub.close()  # 主动关 → _closed_by_server=True
        assert sub._closed_by_server is True
        with pytest.raises(StopIteration):
            next(sub)
    finally:
        listener.close()
        if os.path.exists(sock_path):
            os.unlink(sock_path)


# ── T8 M-PY-03 空 channels + C-PYO3-03 上下文管理器 ──


def test_subscribe_empty_channels_raises_valueerror():
    ex = FusionSandboxExecutor()
    with pytest.raises(ValueError, match="channels 不能为空"):
        ex.subscribe([])


def test_subscribe_none_channels_raises_valueerror():
    ex = FusionSandboxExecutor()
    with pytest.raises((ValueError, TypeError)):
        ex.subscribe(None)  # type: ignore[arg-type]


def test_subscription_context_manager_closes_socket(server: str):
    # C-PYO3-03: `with executor.subscribe(...) as sub:` — __enter__ 返 self,
    # __exit__ 调 unsubscribe (关 sock) + close 幂等
    ex = FusionSandboxExecutor(sock_path=server)
    with ex.subscribe(["telemetry"], interval_ms=50) as sub:
        assert sub.subscription_id is not None
        assert sub._sock is not None
    # __exit__ 后 sock 应关
    assert sub._sock is None


def test_subscription_del_closes_without_raise(server: str):
    # C-PYO3-03: __del__ 尽力 close, 不抛异常
    ex = FusionSandboxExecutor(sock_path=server)
    sub = ex.subscribe(["telemetry"], interval_ms=50)
    assert sub._sock is not None
    sub.__del__()  # 显式触发, 不应抛
    assert sub._sock is None


def test_subscription_close_idempotent():
    # close() 多次调用安全 (M-PY-04 + C-PYO3-03)
    sub = Subscription("/tmp/fe-cov-del.sock", ["telemetry"], None, None)
    sub.close()
    sub.close()  # 二次不抛
    assert sub._sock is None


# ── #38/#39/#40 (v0.2.10) scale_factor + mask_sensitive + gui_action_batch ──


def test_gui_result_scale_factor_default_and_roundtrip():
    # #38: GuiResult.scale_factor 默认 1.0, 序列化往返保持
    r = GuiResult(ok=True, scale_factor=2.0)
    assert r.scale_factor == 2.0
    d = r.model_dump()
    assert d["scale_factor"] == 2.0
    back = GuiResult.model_validate(d)
    assert back.scale_factor == 2.0
    # 默认
    assert GuiResult().scale_factor == 1.0


def test_gui_action_screenshot_mask_sensitive_default_false():
    # #40: screenshot 默认 mask_sensitive=false (不遮蔽), 走 TCC-skip 守卫 (CI 路径)
    ex = FusionSandboxExecutor()
    # 无 TCC → 降级 skip mask, 仍返回 GuiResult (不崩)
    r = ex.gui_action({"kind": "screenshot"})
    assert isinstance(r, GuiResult)


def test_gui_action_screenshot_mask_sensitive_true_when_trusted():
    # #40: trusted 机 mask_sensitive=true → 遮蔽 secure field, ok=True + 有 PNG
    if not _ax_trusted():
        pytest.skip("AX/Screen Recording 未授权 — 跳过 mask_sensitive 真实截图测试 (CI 路径)")
    ex = FusionSandboxExecutor()
    r = ex.gui_action({"kind": "screenshot", "mask_sensitive": True})
    assert r.ok is True
    assert r.screenshot_png_b64 is not None
    raw = base64.b64decode(r.screenshot_png_b64)
    assert raw[:8] == b"\x89PNG\r\n\x1a\n"
    assert r.scale_factor >= 1.0


def test_gui_action_batch_empty_returns_empty():
    # #39: 空批 → 空列表 (不调 native)
    ex = FusionSandboxExecutor()
    results = ex.gui_action_batch([])
    assert results == []


def test_gui_action_batch_sequential_collects_per_step():
    # #39: 多动作顺序执行, 每步返 GuiResult; Wait ok=True, 未知键 ok=False 降级
    ex = FusionSandboxExecutor()
    results = ex.gui_action_batch(
        [
            {"kind": "wait", "seconds": 0.0},
            {"kind": "key_press", "key": "totally-fake-key"},
            {"kind": "wait", "seconds": 0.0},
        ]
    )
    assert len(results) == 3
    assert all(isinstance(r, GuiResult) for r in results)
    assert results[0].ok is True
    assert results[1].ok is False
    assert "unknown-key" in results[1].error
    assert results[2].ok is True


def test_gui_action_batch_non_list_raises():
    ex = FusionSandboxExecutor()
    with pytest.raises(TypeError, match="actions 必须为 list"):
        ex.gui_action_batch({"kind": "wait"})  # type: ignore[arg-type]


def test_gui_action_batch_item_missing_kind_raises():
    ex = FusionSandboxExecutor()
    with pytest.raises(ValueError, match="缺 'kind'"):
        ex.gui_action_batch([{"seconds": 0.0}])


def test_gui_action_batch_over_uds(server: str):
    # #39: UDS roundtrip — wait ok + 未知键降级
    resp = _rpc(
        server,
        {
            "jsonrpc": "2.0",
            "id": 42,
            "method": "executor.gui_action_batch",
            "params": {
                "actions": [
                    {"kind": "wait", "seconds": 0.0},
                    {"kind": "key_press", "key": "totally-fake-key"},
                ]
            },
        },
    )
    assert resp["jsonrpc"] == "2.0"
    assert resp["id"] == 42
    results = resp["result"]
    assert isinstance(results, list)
    assert len(results) == 2
    assert results[0]["ok"] is True
    assert results[1]["ok"] is False
    assert "unknown-key" in results[1]["error"]
