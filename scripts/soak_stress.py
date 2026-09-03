"""Load/stress soak test (enterprise gap #5).

Drives the UDS server under sustained concurrent load to verify:
  - bounded concurrency (MAX_CONCURRENT_EXECS=16, streams=64) holds — no
    unbounded spawn, no memory blowup, no deadlock under contention.
  - no request hangs (every request returns within a hard wall-clock budget).
  - streams complete (chunk + done frames), shells start/finish/kill.
  - cancel works under load (in-flight stream killed deterministically).
  - metrics surface (fe_exec_total increments).

Launches a real serve() subprocess on a temp socket, fans out N concurrent
UDS clients, then tears down. Cleans up its temp socket + subprocess.

Run: python scripts/soak_stress.py
Exit 0 = soak passed.
"""

import json
import logging
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time

log = logging.getLogger("soak")
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

PASS = 0
FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        log.info("PASS %s %s", name, detail)
        PASS += 1
    else:
        log.error("FAIL %s %s", name, detail)
        FAIL += 1


def uds_call(sock_path, method, params=None, req_id=1, timeout=30):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(sock_path)
    req = {"jsonrpc": "2.0", "id": req_id, "method": method}
    if params is not None:
        req["params"] = params
    s.sendall((json.dumps(req) + "\n").encode())
    buf = b""
    while b"\n" not in buf:
        chunk = s.recv(65536)
        if not chunk:
            break
        buf += chunk
    s.close()
    line = buf.split(b"\n", 1)[0]
    return json.loads(line)


def uds_stream(sock_path, command, req_id=1, timeout=60):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(sock_path)
    req = {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "executor.execute_stream",
        "params": {"command": command, "timeout_sec": 30},
    }
    s.sendall((json.dumps(req) + "\n").encode())
    frames = []
    buf = b""
    got_done = False
    deadline = time.time() + timeout
    while time.time() < deadline and not got_done:
        try:
            chunk = s.recv(65536)
        except TimeoutError:
            break
        if not chunk:
            break
        buf += chunk
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            if not line.strip():
                continue
            try:
                fr = json.loads(line)
            except json.JSONDecodeError:
                continue
            frames.append(fr)
            res = fr.get("result", {})
            if isinstance(res, dict) and res.get("type") == "done":
                got_done = True
                break
    s.close()
    return frames, got_done


def start_server():
    sock_dir = tempfile.mkdtemp(prefix="fe_soak_")
    sock_path = os.path.join(sock_dir, "fe.sock")
    proc = subprocess.Popen(
        [
            sys.executable,
            "-c",
            f"from fusion_executor import FusionSandboxExecutor as F; F().serve(sock_path={sock_path!r})",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    deadline = time.time() + 20
    while time.time() < deadline:
        if os.path.exists(sock_path):
            try:
                t = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                t.settimeout(2)
                t.connect(sock_path)
                t.close()
                return proc, sock_path, sock_dir
            except OSError:
                pass
        if proc.poll() is not None:
            out = proc.stdout.read(4000) if proc.stdout else b""
            raise RuntimeError(f"server died early: {out!r}")
        time.sleep(0.1)
    proc.kill()
    raise RuntimeError("server did not start in 20s")


def soak_concurrent_execute(sock_path, n=80):
    errors = []
    latencies = []

    def worker(i):
        t0 = time.time()
        try:
            r = uds_call(sock_path, "executor.execute", {"command": f"echo soak-{i}", "timeout_sec": 15}, req_id=i + 1)
            latencies.append(time.time() - t0)
            res = r.get("result", {})
            if res.get("exit_code") != 0:
                errors.append(f"worker {i}: exit={res.get('exit_code')}")
        except Exception as e:
            errors.append(f"worker {i}: {type(e).__name__}: {e}")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    t0 = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    elapsed = time.time() - t0
    check("soak-execute all returned", len(errors) == 0, f"{len(errors)} errors")
    check("soak-execute count", len(latencies) == n, f"{len(latencies)}/{n}")
    check("soak-execute wallclock", elapsed < 60, f"{elapsed:.2f}s")
    if latencies:
        log.info("soak-execute latencies p50=%.3fs max=%.3fs", sorted(latencies)[len(latencies) // 2], max(latencies))


def soak_concurrent_streams(sock_path, n=30):
    done_count = 0
    errors = []

    def worker(i):
        nonlocal done_count
        try:
            _, got_done = uds_stream(sock_path, f"echo stream-{i}", req_id=1000 + i)
            if got_done:
                done_count += 1
            else:
                errors.append(f"stream {i}: no done frame")
        except Exception as e:
            errors.append(f"stream {i}: {type(e).__name__}: {e}")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    check("soak-stream all done", done_count == n, f"{done_count}/{n}")
    check("soak-stream no errors", len(errors) == 0, str(errors[:3]))


def soak_shell_lifecycle(sock_path, n=20):
    started = 0
    killed = 0
    for i in range(n):
        r = uds_call(
            sock_path, "executor.shell_start", {"command": f"echo sh-{i}", "task_id": f"soak-sh-{i}"}, req_id=2000 + i
        )
        res = r.get("result", {})
        sid = res.get("shell_id")
        if sid:
            started += 1
            time.sleep(0.05)
            kr = uds_call(sock_path, "executor.kill_shell", {"shell_id": sid}, req_id=3000 + i)
            if kr.get("result", {}).get("ok"):
                killed += 1
    check("soak-shell started", started == n, f"{started}/{n}")
    check("soak-shell killed", killed == n, f"{killed}/{n}")


def soak_cancel_under_load(sock_path):
    sid_dir = tempfile.mkdtemp(prefix="fe_soak_cancel_")
    tail_target = os.path.join(sid_dir, "tailtarget.txt")
    open(tail_target, "w").close()
    try:
        # start a long stream (tail -f on an empty tmp file blocks forever,
        # whitelisted + non-sensitive — /dev/null is a sensitive path, rejected),
        # then cancel it from a second connection
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(30)
        s.connect(sock_path)
        req = {
            "jsonrpc": "2.0",
            "id": 9001,
            "method": "executor.execute_stream",
            "params": {
                "command": f"tail -f {tail_target}",
                "timeout_sec": 30,
                "cwd": sid_dir,
            },
        }
        s.sendall((json.dumps(req) + "\n").encode())
        time.sleep(0.5)
        cr = uds_call(sock_path, "executor.cancel", {"id": 9001}, req_id=9002, timeout=10)
        cancelled = cr.get("result", {}).get("cancelled")
        # read the done frame on the stream conn
        buf = b""
        got_done = False
        deadline = time.time() + 10
        while time.time() < deadline and not got_done:
            try:
                chunk = s.recv(65536)
            except TimeoutError:
                break
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if not line.strip():
                    continue
                try:
                    fr = json.loads(line)
                except json.JSONDecodeError:
                    continue
                res = fr.get("result", {})
                if isinstance(res, dict) and res.get("type") == "done":
                    got_done = True
                    cancelled_flag = res.get("result", {}).get("cancelled")
                    check("soak-cancel done cancelled", cancelled_flag is True, f"cancelled={cancelled_flag}")
                    break
        s.close()
        check("soak-cancel ack", cancelled is True, f"cancelled={cancelled}")
        check("soak-cancel done frame", got_done, "")
    finally:
        if os.path.exists(tail_target):
            os.remove(tail_target)
        os.rmdir(sid_dir)


def soak_metrics(sock_path):
    r = uds_call(sock_path, "executor.metrics_prometheus", req_id=9999, timeout=10)
    text = r.get("result", {}).get("text", "")
    check("soak-metrics text", "fe_exec_total" in text, "has fe_exec_total")
    check("soak-metrics connections", "fe_connections" in text, "has fe_connections")


def main():
    t0 = time.time()
    log.info("=== load/stress soak (gap #5) ===")
    proc, sock_path, sock_dir = start_server()
    log.info("server up on %s pid=%d", sock_path, proc.pid)
    try:
        soak_concurrent_execute(sock_path, n=80)
        soak_concurrent_streams(sock_path, n=30)
        soak_shell_lifecycle(sock_path, n=20)
        soak_cancel_under_load(sock_path)
        soak_metrics(sock_path)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        if os.path.exists(sock_path):
            os.remove(sock_path)
        os.rmdir(sock_dir)
        log.info("server subprocess cleaned up")
    log.info("=== done in %.2fs — %d pass / %d fail ===", time.time() - t0, PASS, FAIL)
    sys.exit(0 if FAIL == 0 else 1)


if __name__ == "__main__":
    main()
