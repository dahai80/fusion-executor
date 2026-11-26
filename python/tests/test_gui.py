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
    # probe ax_trusted via IPC health, or call native directly
    try:
        ex = FusionSandboxExecutor()
        r = ex.gui_action({"kind": "screenshot"})
        return r.ok and r.screenshot_png_b64 is not None
    except Exception:
        return False


def _ax_access_trusted() -> bool:
    # probe TCC Accessibility (not Screen Recording) — the Rust !ax_trusted() degradation gate uses this permission.
    # hover only carries coords, no AX tree walk: trusted→ok=True, untrusted→ok=False+accessibility-permission-required.
    # separate from _ax_trusted() (screenshot=Screen Recording) — the two TCC permissions are independent.
    # RUN-12: disable the focused-app allowlist (disable_bundle_allowlist=True) — otherwise the default allowlist intercepts hover first,
    #         misjudging a trusted machine as untrusted and wrongly running degradation tests on a trusted machine. The probe must purely test AX permission.
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
    raise TimeoutError(f"socket did not appear: {path}")


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
    # unknown key name → degraded regardless of authorization (trusted-independent): ok=False + error
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
    # known key + unknown modifier → ok=False + unknown-modifier (trusted-independent)
    r = ex.gui_action({"kind": "key_press", "key": "Tab", "modifiers": ["hyper"]})
    assert isinstance(r, GuiResult)
    assert r.ok is False
    assert r.error is not None
    assert "unknown-modifier" in r.error


def test_gui_action_screenshot_when_trusted():
    if not _ax_trusted():
        pytest.skip("AX/Screen Recording not authorized — skipping real screenshot tests (CI path)")
    ex = FusionSandboxExecutor()
    r = ex.gui_action({"kind": "screenshot"})
    assert r.ok is True
    assert r.screenshot_png_b64 is not None
    raw = base64.b64decode(r.screenshot_png_b64)
    assert raw[:8] == b"\x89PNG\r\n\x1a\n", "screenshot is not a PNG"
    assert r.screenshot_width is not None and r.screenshot_width > 0
    assert r.screenshot_height is not None and r.screenshot_height > 0


def test_gui_action_keypress_when_trusted():
    if not _ax_trusted():
        pytest.skip("AX not authorized — skipping real key synthesis tests (CI path)")
    # RUN-12: disable the default allowlist — the focused app on the test machine (the terminal running pytest) may not be in the default safe set,
    #         and the allowlist would intercept key_press synthesis first. Explicit disable exercises the real CGEvent path to verify ok=True.
    ex = FusionSandboxExecutor(disable_bundle_allowlist=True)
    # known key name → CGEvent synthesizes keydown+keyup, posted to HID; should be ok=True
    r = ex.gui_action({"kind": "key_press", "key": "Tab"})
    assert isinstance(r, GuiResult)
    assert r.ok is True, f"KeyPress Tab should succeed: {r.error}"
    assert r.error is None


def test_gui_action_keypress_chord_when_trusted():
    if not _ax_trusted():
        pytest.skip("AX not authorized — skipping real modifier chord tests (CI path)")
    # RUN-12: same as keypress_when_trusted — disable the default allowlist to exercise the real CGEvent chord path.
    ex = FusionSandboxExecutor(disable_bundle_allowlist=True)
    # modifier chord (Cmd+Tab) — known key + known modifier → ok=True
    r = ex.gui_action({"kind": "key_press", "key": "Tab", "modifiers": ["command"]})
    assert isinstance(r, GuiResult)
    assert r.ok is True, f"KeyPress Cmd+Tab should succeed: {r.error}"
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
    # unknown key name → ok=False + unknown-key (trusted-independent, CI path)
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
    # deserialization failure → JSON-RPC error (-32600 invalid req)
    assert "error" in resp
    assert resp["error"]["code"] == -32600


def test_gui_action_wait_ok_without_trust():
    # Wait is pure delay, trusted-independent — no TCC dependency, runs in CI. 0s returns ok=True immediately.
    ex = FusionSandboxExecutor()
    r = ex.gui_action({"kind": "wait", "seconds": 0.0})
    assert isinstance(r, GuiResult)
    assert r.ok is True, f"Wait 0s should be ok=True (trusted-independent): {r.error}"
    assert r.error is None


def test_gui_action_wait_negative_clamps():
    # negative Wait clamps to 0 (no sleep), ok=True
    ex = FusionSandboxExecutor()
    r = ex.gui_action({"kind": "wait", "seconds": -5.0})
    assert r.ok is True, f"negative Wait should clamp to 0 then be ok=True: {r.error}"


def test_gui_action_wait_over_uds(server: str):
    # Wait over the UDS round-trip, trusted-independent — 0s should be ok=True
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
        pytest.skip("AX not authorized — skipping real scroll-wheel synthesis tests (CI path)")
    # RUN-12: disable the default allowlist to exercise the real CGEvent scrollWheel path.
    ex = FusionSandboxExecutor(disable_bundle_allowlist=True)
    r = ex.gui_action({"kind": "scroll", "dx": 0, "dy": -3})
    assert isinstance(r, GuiResult)
    assert r.ok is True, f"Scroll should succeed: {r.error}"
    assert r.error is None


def test_gui_action_drag_when_trusted():
    if not _ax_trusted():
        pytest.skip("AX not authorized — skipping real drag synthesis tests (CI path)")
    # RUN-12: disable the default allowlist to exercise the real CGEvent mouseMove/down/up drag path.
    ex = FusionSandboxExecutor(disable_bundle_allowlist=True)
    r = ex.gui_action({"kind": "drag", "from": [10.0, 10.0], "to": [50.0, 50.0]})
    assert isinstance(r, GuiResult)
    assert r.ok is True, f"Drag should succeed: {r.error}"
    assert r.error is None


# ── v1.5 new actions (double_click/right_click/hover/window_*) ──


# CI path (untrusted): all 9 new variants degrade through the !ax_trusted() gate — proving the 4-layer auto-flow
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
    {"kind": "move_path", "points": [[0.0, 0.0], [10.0, 10.0]]},
]


def test_gui_action_new_variants_degrade_without_trust():
    # trusted machines take the real AX/CGEvent path (not degradation) — only CI (untrusted) runs the degradation assertions
    # gate = TCC Accessibility (Rust !ax_trusted()), probed with _ax_access_trusted() (not Screen Recording)
    if _ax_access_trusted():
        pytest.skip("AX Accessibility authorized — the degradation path only runs on CI (untrusted)")
    ex = FusionSandboxExecutor()
    for action in NEW_VARIANTS_CI:
        r = ex.gui_action(action)
        assert isinstance(r, GuiResult), f"{action['kind']} should return a GuiResult"
        assert r.ok is False, f"{action['kind']} should be ok=False when unauthorized"
        assert r.error is not None and "accessibility-permission-required" in r.error, (
            f"{action['kind']} degradation error should contain accessibility-permission-required: {r.error}"
        )


def test_gui_action_pointer_variants_when_trusted():
    # pointer variants (double_click/right_click/hover) carry coords → CGEvent synthesis, no AX tree walk → ok=True
    # window_* variants need a real GUI session (AX window tree) and fail in a sandbox — not asserted here
    if not _ax_access_trusted():
        pytest.skip("AX Accessibility not authorized — skipping real pointer synthesis tests (CI path)")
    # RUN-12: disable the default allowlist — the focused app (the pytest terminal) is not in the default safe set, the allowlist would intercept hover/pointer first.
    ex = FusionSandboxExecutor(disable_bundle_allowlist=True)
    for action in [
        {"kind": "hover", "ax_position": [10.0, 20.0]},
        {"kind": "double_click", "ax_position": [5.0, 5.0]},
        {"kind": "right_click", "ax_position": [5.0, 5.0]},
        {"kind": "triple_click", "ax_position": [5.0, 5.0]},
    ]:
        r = ex.gui_action(action)
        assert isinstance(r, GuiResult), f"{action['kind']} should return a GuiResult"
        assert r.ok is True, f"{action['kind']} with coords should be ok=True: {r.error}"
        assert r.error is None


def test_gui_action_holdkey_when_trusted():
    # hold_key single-key CGEvent synthesis (keydown→sleep→keyup), no AX tree needed → ok=True
    if not _ax_access_trusted():
        pytest.skip("AX Accessibility not authorized — skipping real key synthesis tests (CI path)")
    # RUN-12: disable the default allowlist to exercise the real CGEvent hold_key path (same as keypress/pointer).
    ex = FusionSandboxExecutor(disable_bundle_allowlist=True)
    r = ex.gui_action({"kind": "hold_key", "key": "return", "duration_ms": 20})
    assert isinstance(r, GuiResult)
    assert r.ok is True, f"HoldKey should succeed: {r.error}"
    assert r.error is None


# ── v0.2.11 #43/#44 (display_info + move_path) ──


def test_gui_action_display_info_trusted_independent():
    # #43: DisplayInfo uses the CGDisplay API (trusted-independent) — no TCC authorization needed, ok=True on any machine.
    # Returns a displays JSON (active display list id/scale/bounds/primary) + scale_factor (main display).
    ex = FusionSandboxExecutor()
    r = ex.gui_action({"kind": "display_info"})
    assert isinstance(r, GuiResult)
    assert r.ok is True, f"DisplayInfo trusted-independent should be ok=True: {r.error}"
    assert r.error is None
    assert r.displays is not None, "displays should not be None"
    entries = json.loads(r.displays)
    assert isinstance(entries, list), f"displays should be a list: {entries}"
    # headless/SSH environments have no active display — ok=True + empty list is correct behavior, skip the remaining assertions
    if len(entries) == 0:
        pytest.skip("no active display (headless/SSH environment) — skipping display field assertions (CI path)")
    main = entries[0]
    assert {"id", "scale", "bounds", "primary"} <= set(main.keys()), f"missing fields: {main}"
    assert main["scale"] >= 1.0, f"scale should be >= 1.0: {main['scale']}"
    assert r.scale_factor >= 1.0, f"main-display scale_factor should be >= 1.0: {r.scale_factor}"


def test_gui_action_move_path_pointer_when_trusted():
    # #44: MovePath completes an N-point path in a single UDS round-trip — on trusted machines CGEvent MouseMoved synthesis is ok=True.
    if not _ax_access_trusted():
        pytest.skip("AX Accessibility not authorized — skipping real move_path synthesis tests (CI path)")
    ex = FusionSandboxExecutor(disable_bundle_allowlist=True)
    r = ex.gui_action({"kind": "move_path", "points": [[0.0, 0.0], [10.0, 10.0], [20.0, 5.0]]})
    assert isinstance(r, GuiResult)
    assert r.ok is True, f"MovePath with coords should be ok=True: {r.error}"
    assert r.error is None


def test_gui_action_move_path_too_few_points_rejects():
    # #44: MovePath with <2 points → ok=False (trusted-independent rejection, no TCC needed).
    ex = FusionSandboxExecutor()
    r = ex.gui_action({"kind": "move_path", "points": [[5.0, 5.0]]})
    assert isinstance(r, GuiResult)
    assert r.ok is False, "single-point move_path should be ok=False"
    assert r.error is not None


# ── v1.5 #14 bidirectional server-push (subscribe/unsubscribe) ──


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
    assert len(frames) >= 3, f"should receive >=3 telemetry push frames, got={len(frames)}"
    sub.unsubscribe()


def test_subscribe_stdio_broadcasts_across_connections(server: str):
    # connection A subscribes to stdio (scope=all receives across connections); connection B runs UDS execute_stream → A receives the stdio push
    # Blocker 10: the default own_conn already isolates across connections; only explicit all broadcasts fully.
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
    # connection B: execute_stream echo via raw UDS
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
    assert b_done, "B should receive its own done frame"
    assert a_frames, "A should receive the cross-connection stdio push"


def test_subscribe_unknown_channel_raises(server: str):
    ex = FusionSandboxExecutor(sock_path=server)
    with pytest.raises(ValueError, match="unknown channels"):
        ex.subscribe(["bogus"])


# ── v1.6 coverage gaps (Subscription error/boundary paths) ──


def test_subscribe_passes_screenshot_interval(server: str):
    # covers _open line 329: non-empty screenshot_interval_ms → written into params
    ex = FusionSandboxExecutor(sock_path=server)
    sub = ex.subscribe(["screenshot"], interval_ms=None, screenshot_interval_ms=200)
    assert sub.subscription_id is not None
    sub.unsubscribe()


def test_subscription_close_without_open():
    # covers close() lines 395-397: explicit close after open closes the socket
    sub = Subscription("/tmp/fe-cov-close.sock", ["telemetry"], None, None)
    assert sub._sock is None
    sub.close()  # never opened — still safe
    assert sub._sock is None


def test_subscription_unsubscribe_without_open_returns_false():
    # covers unsubscribe() line 373: both sock/sub_id empty → early return False
    sub = Subscription("/tmp/fe-cov-nosub.sock", ["telemetry"], None, None)
    assert sub.unsubscribe() is False
    assert sub._sock is None


def test_subscription_subscribe_error_raises():
    # covers _open lines 334-335: server returns error → RuntimeError
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
        with pytest.raises(RuntimeError, match="subscribe failed"):
            sub._open()
    finally:
        listener.close()
        if os.path.exists(sock_path):
            os.unlink(sock_path)


def test_subscription_next_raises_connectionerror_on_unexpected_disconnect():
    # IMPL-3: fake server sends a valid subscribe response then immediately closes the connection (no unsubscribe) = server-crash scenario.
    # inside __next__ recv returns b"" → _eof_seen=True + not _closed_by_server → ConnectionError (not StopIteration).
    # the caller can catch ConnectionError to reconnect/alert, instead of swallowing it as a clean stream end.
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
        # sock still open (the server closed its peer side, local side not closed) → covered by close()
        assert sub._sock is not None
        sub.close()
        assert sub._sock is None
    finally:
        listener.close()
        if os.path.exists(sock_path):
            os.unlink(sock_path)


def test_subscription_graceful_close_raises_stopiteration():
    # IMPL-3: active unsubscribe/close (_closed_by_server=True) → __next__ gets None and raises StopIteration (clean stream end).
    # using a real server: after subscribe the local side calls close (marks an active close), then next → StopIteration (not ConnectionError).
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
        # keep the connection open, waiting for the local close
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
        sub.close()  # active close → _closed_by_server=True
        assert sub._closed_by_server is True
        with pytest.raises(StopIteration):
            next(sub)
    finally:
        listener.close()
        if os.path.exists(sock_path):
            os.unlink(sock_path)


# ── T8 M-PY-03 empty channels + C-PYO3-03 context manager ──


def test_subscribe_empty_channels_raises_valueerror():
    ex = FusionSandboxExecutor()
    with pytest.raises(ValueError, match="channels must not be empty"):
        ex.subscribe([])


def test_subscribe_none_channels_raises_valueerror():
    ex = FusionSandboxExecutor()
    with pytest.raises((ValueError, TypeError)):
        ex.subscribe(None)  # type: ignore[arg-type]


def test_subscription_context_manager_closes_socket(server: str):
    # C-PYO3-03: `with executor.subscribe(...) as sub:` — __enter__ returns self,
    # __exit__ calls unsubscribe (closing the sock) + close is idempotent
    ex = FusionSandboxExecutor(sock_path=server)
    with ex.subscribe(["telemetry"], interval_ms=50) as sub:
        assert sub.subscription_id is not None
        assert sub._sock is not None
    # after __exit__ the sock should be closed
    assert sub._sock is None


def test_subscription_del_closes_without_raise(server: str):
    # C-PYO3-03: __del__ best-effort close, never raises
    ex = FusionSandboxExecutor(sock_path=server)
    sub = ex.subscribe(["telemetry"], interval_ms=50)
    assert sub._sock is not None
    sub.__del__()  # triggered explicitly, must not raise
    assert sub._sock is None


def test_subscription_close_idempotent():
    # close() is safe to call multiple times (M-PY-04 + C-PYO3-03)
    sub = Subscription("/tmp/fe-cov-del.sock", ["telemetry"], None, None)
    sub.close()
    sub.close()  # second call does not raise
    assert sub._sock is None


# ── #38/#39/#40 (v0.2.10) scale_factor + mask_sensitive + gui_action_batch ──


def test_gui_result_scale_factor_default_and_roundtrip():
    # #38: GuiResult.scale_factor defaults to 1.0, serialization round-trip preserved
    r = GuiResult(ok=True, scale_factor=2.0)
    assert r.scale_factor == 2.0
    d = r.model_dump()
    assert d["scale_factor"] == 2.0
    back = GuiResult.model_validate(d)
    assert back.scale_factor == 2.0
    # defaults
    assert GuiResult().scale_factor == 1.0


def test_gui_action_screenshot_mask_sensitive_default_false():
    # #40: screenshot defaults mask_sensitive=false (no masking), goes through the TCC-skip guard (CI path)
    ex = FusionSandboxExecutor()
    # no TCC → degrade by skipping the mask, still returns a GuiResult (no crash)
    r = ex.gui_action({"kind": "screenshot"})
    assert isinstance(r, GuiResult)


def test_gui_action_screenshot_mask_sensitive_true_when_trusted():
    # #40: on trusted machines mask_sensitive=true → masks secure fields, ok=True + PNG present
    if not _ax_trusted():
        pytest.skip("AX/Screen Recording not authorized — skipping mask_sensitive real screenshot tests (CI path)")
    ex = FusionSandboxExecutor()
    r = ex.gui_action({"kind": "screenshot", "mask_sensitive": True})
    assert r.ok is True
    assert r.screenshot_png_b64 is not None
    raw = base64.b64decode(r.screenshot_png_b64)
    assert raw[:8] == b"\x89PNG\r\n\x1a\n"
    assert r.scale_factor >= 1.0


def test_gui_action_batch_empty_returns_empty():
    # #39: empty batch → empty list (native not called)
    ex = FusionSandboxExecutor()
    results = ex.gui_action_batch([])
    assert results == []


def test_gui_action_batch_sequential_collects_per_step():
    # #39: multiple actions execute in order, each step returns a GuiResult; Wait ok=True, unknown key ok=False degraded
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
    with pytest.raises(TypeError, match="actions must be list"):
        ex.gui_action_batch({"kind": "wait"})  # type: ignore[arg-type]


def test_gui_action_batch_item_missing_kind_raises():
    ex = FusionSandboxExecutor()
    with pytest.raises(ValueError, match="missing the 'kind'"):
        ex.gui_action_batch([{"seconds": 0.0}])


def test_gui_action_batch_over_uds(server: str):
    # #39: UDS roundtrip — wait ok + unknown key degraded
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
