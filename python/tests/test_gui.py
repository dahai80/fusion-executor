from __future__ import annotations

import base64
import json
import os
import socket
import subprocess
import sys
import tempfile
import time

import pytest

from fusion_executor import FusionSandboxExecutor, GuiResult


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
    try:
        ex = FusionSandboxExecutor()
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
    ex = FusionSandboxExecutor()
    # 已知键名 → CGEvent 合成 keydown+keyup, post HID; 应 ok=True
    r = ex.gui_action({"kind": "key_press", "key": "Tab"})
    assert isinstance(r, GuiResult)
    assert r.ok is True, f"KeyPress Tab 应成功: {r.error}"
    assert r.error is None


def test_gui_action_keypress_chord_when_trusted():
    if not _ax_trusted():
        pytest.skip("AX 未授权 — 跳过真实修饰键和弦测试 (CI 路径)")
    ex = FusionSandboxExecutor()
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
    ex = FusionSandboxExecutor()
    r = ex.gui_action({"kind": "scroll", "dx": 0, "dy": -3})
    assert isinstance(r, GuiResult)
    assert r.ok is True, f"Scroll 应成功: {r.error}"
    assert r.error is None


def test_gui_action_drag_when_trusted():
    if not _ax_trusted():
        pytest.skip("AX 未授权 — 跳过真实拖拽合成测试 (CI 路径)")
    ex = FusionSandboxExecutor()
    r = ex.gui_action({"kind": "drag", "from": [10.0, 10.0], "to": [50.0, 50.0]})
    assert isinstance(r, GuiResult)
    assert r.ok is True, f"Drag 应成功: {r.error}"
    assert r.error is None


# ── v1.5 新动作 (double_click/right_click/hover/window_*) ──


# CI 路径 (untrusted): 7 个新变体均经 !ax_trusted() 闸门降级 — 证明 4 层 auto-flow
NEW_VARIANTS_CI = [
    {"kind": "double_click", "ax_position": [5.0, 5.0]},
    {"kind": "right_click", "ax_position": [5.0, 5.0]},
    {"kind": "hover", "ax_position": [5.0, 5.0]},
    {"kind": "window_close"},
    {"kind": "window_minimize"},
    {"kind": "window_zoom"},
    {"kind": "window_resize", "width": 800.0, "height": 600.0},
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
    ex = FusionSandboxExecutor()
    for action in [
        {"kind": "hover", "ax_position": [10.0, 20.0]},
        {"kind": "double_click", "ax_position": [5.0, 5.0]},
        {"kind": "right_click", "ax_position": [5.0, 5.0]},
    ]:
        r = ex.gui_action(action)
        assert isinstance(r, GuiResult), f"{action['kind']} 应返回 GuiResult"
        assert r.ok is True, f"{action['kind']} 带坐标应 ok=True: {r.error}"
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
    # 连接 A 订阅 stdio (后台线程读), 连接 B 经 UDS execute_stream → A 收到 stdio 推送
    import threading

    ex_a = FusionSandboxExecutor(sock_path=server)
    sub = ex_a.subscribe(["stdio"])
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
