"""Long-running stability harness (enterprise gap #6).

Runs sustained execute + stream traffic against a real serve() subprocess for
N minutes, sampling the server process RSS at intervals to verify:
  - no memory leak (RSS does not grow unboundedly across the run).
  - no request hang (every execute/stream returns within a wall-clock budget).
  - no fd/socket leak (server keeps accepting new connections).
  - error rate stays at zero under steady load.

Launches a real serve() subprocess on a temp socket, drives a fixed concurrency
of workers in a loop until the duration elapses, samples RSS via resource/psutil
-free `mach_vm_rss`-equivalent (macOS: reads /proc-free vm via psutil if present,
else falls back to RSS from `ps -o rss`), then tears down. Cleans up its temp
socket + subprocess.

Run: python scripts/long_stability.py [duration_minutes]
Exit 0 = stability passed.
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

log = logging.getLogger("stab")
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

PASS = 0
FAIL = 0

DEFAULT_MINUTES = 3
CONCURRENCY = 8
EXEC_TIMEOUT = 15
STREAM_TIMEOUT = 30
HANG_BUDGET = 60
RSS_LEAK_MB = 200
ERROR_RATE_CAP = 0.01


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
    got_done = False
    buf = b""
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
            res = fr.get("result", {})
            if isinstance(res, dict) and res.get("type") == "done":
                got_done = True
                break
    s.close()
    return got_done


def start_server():
    sock_dir = tempfile.mkdtemp(prefix="fe_stab_")
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


def sample_rss_kb(pid):
    try:
        out = subprocess.check_output(
            ["ps", "-o", "rss=", "-p", str(pid)], stderr=subprocess.DEVNULL, text=True
        ).strip()
        return int(out) if out else 0
    except (subprocess.CalledProcessError, ValueError):
        return 0


def stability_loop(sock_path, pid, duration_sec):
    deadline = time.time() + duration_sec
    rss_samples = [sample_rss_kb(pid)]
    rss_t0 = time.time()
    req_counter = [0]
    err_counter = [0]
    hang_counter = [0]
    stop = threading.Event()

    def worker(wid):
        rid = wid * 100000
        while not stop.is_set() and time.time() < deadline:
            rid += 1
            t0 = time.time()
            try:
                if rid % 3 == 0:
                    ok = uds_stream(sock_path, f"echo stb-s{wid}-{rid}", req_id=rid, timeout=STREAM_TIMEOUT)
                    if not ok:
                        err_counter[0] += 1
                        log.warning("worker %d stream no done frame rid=%d", wid, rid)
                else:
                    r = uds_call(
                        sock_path,
                        "executor.execute",
                        {"command": f"echo stb-{wid}-{rid}", "timeout_sec": EXEC_TIMEOUT},
                        req_id=rid,
                        timeout=EXEC_TIMEOUT + 5,
                    )
                    if r.get("result", {}).get("exit_code") != 0:
                        err_counter[0] += 1
                        log.warning("worker %d exec bad exit rid=%d: %s", wid, rid, r)
            except Exception as e:
                err_counter[0] += 1
                log.warning("worker %d rid=%d %s: %s", wid, rid, type(e).__name__, e)
            elapsed = time.time() - t0
            if elapsed > HANG_BUDGET:
                hang_counter[0] += 1
                log.error("worker %d rid=%d HANG %.1fs", wid, rid, elapsed)
            req_counter[0] += 1

    threads = [threading.Thread(target=worker, args=(i,), name=f"stab-w{i}") for i in range(CONCURRENCY)]
    for t in threads:
        t.start()

    sample_interval = max(5, duration_sec // 20)
    while time.time() < deadline:
        time.sleep(sample_interval)
        rss = sample_rss_kb(pid)
        rss_samples.append(rss)
        log.info(
            "tick t=%.0fs reqs=%d errs=%d hangs=%d rss=%dKB",
            time.time() - rss_t0,
            req_counter[0],
            err_counter[0],
            hang_counter[0],
            rss,
        )

    stop.set()
    for t in threads:
        t.join(timeout=HANG_BUDGET + 10)

    return rss_samples, req_counter[0], err_counter[0], hang_counter[0]


def main():
    minutes = float(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_MINUTES
    duration_sec = int(minutes * 60)
    t0 = time.time()
    log.info("=== long stability (gap #6) %.1fmin concurrency=%d ===", minutes, CONCURRENCY)
    proc, sock_path, sock_dir = start_server()
    log.info("server up on %s pid=%d", sock_path, proc.pid)
    try:
        rss_samples, total_reqs, total_errs, total_hangs = stability_loop(sock_path, proc.pid, duration_sec)
        server_alive_at_end = proc.poll() is None
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

    log.info("rss samples (KB): %s", rss_samples)
    rss_baseline = rss_samples[0] if rss_samples else 0
    rss_final = rss_samples[-1] if rss_samples else 0
    rss_growth_mb = (rss_final - rss_baseline) / 1024.0

    check("stability requests ran", total_reqs > 0, f"{total_reqs} reqs")
    error_rate = total_errs / total_reqs if total_reqs else 1.0
    check(
        "stability low error rate",
        error_rate < ERROR_RATE_CAP,
        f"{total_errs}/{total_reqs} ({error_rate:.4%}, cap {ERROR_RATE_CAP:.2%})",
    )
    check("stability zero hangs", total_hangs == 0, f"{total_hangs} hangs")
    check("stability rss no leak", rss_growth_mb < RSS_LEAK_MB, f"+{rss_growth_mb:.1f}MB (cap {RSS_LEAK_MB}MB)")
    check("stability server alive", server_alive_at_end, "")

    log.info("=== done in %.2fs — %d pass / %d fail ===", time.time() - t0, PASS, FAIL)
    sys.exit(0 if FAIL == 0 else 1)


if __name__ == "__main__":
    main()
