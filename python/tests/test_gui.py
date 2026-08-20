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
