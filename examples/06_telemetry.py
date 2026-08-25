"""Example 06 — Live telemetry sampling.

telemetry_stream() yields TelemetrySample at 10Hz (interval_ms=100) by
default: CPU%, resident memory (MB), and a wall-clock ts_ms. GPU fields are
optional (caller-injected — the executor runs no model and holds no GPU
handle). Set max_samples to bound the stream.

    python examples/06_telemetry.py
"""

import logging

from fusion_executor import FusionSandboxExecutor

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")


def main() -> None:
    ex = FusionSandboxExecutor()

    print("--- telemetry samples (10Hz, 8 samples) ---")
    count = 0
    for sample in ex.telemetry_stream(interval_ms=100, max_samples=8):
        count += 1
        gpu = f" gpu={sample.gpu_pct}%" if sample.gpu_pct is not None else ""
        print(f"  #{count:2d} ts_ms={sample.ts_ms} cpu={sample.cpu_pct:5.1f}% mem={sample.mem_mb:6.1f}MB{gpu}")

    if count != 8:
        raise SystemExit(f"expected 8 samples, got {count}")
    print("done.")


if __name__ == "__main__":
    main()
