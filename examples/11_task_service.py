"""Example 11 — shared async batch-task service (Issue #57).

TaskManager gives any business app (~/fusion/business/*) a persistent
task_id-polling workflow without building its own SQLite queue + worker:

  submit shell job  -> task_id, poll status(), read result()
  retry with backoff -> RetryPolicy(max_retries=2, backoff_initial_sec=1.0)
  live progress      -> task stdout line "TASK_PROGRESS: 0.42"
  result export      -> export(task_id) / export_report()

Shell tasks run through the executor's background-shell path, so the
security guard, seatbelt and kill-tree semantics all apply.
"""
from __future__ import annotations

import asyncio
import logging
import tempfile
from pathlib import Path

from fusion_executor import RetryPolicy, TaskManager, TaskState


async def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    data_dir = Path(tempfile.mkdtemp(prefix="fe-task-demo-"))
    tm = TaskManager(data_dir, max_workers=2, poll_interval_sec=0.1)
    await tm.start()
    try:
        # 1) plain shell batch job with progress protocol
        t1 = tm.submit_shell(
            "echo 'TASK_PROGRESS: 0.5' && echo batch-item-1 && echo done",
            name="bulk-generate",
            timeout_sec=60,
        )

        # 2) failing job that retries with backoff, then gives up
        t2 = tm.submit_shell(
            "cat /nonexistent-fe-demo-path",
            name="flaky-job",
            retry=RetryPolicy(max_retries=1, backoff_initial_sec=0.5),
        )

        # 3) in-process async job (LLM batch calls, etc.)
        async def assess_batch(report_progress):
            report_progress(0.25)
            await asyncio.sleep(0.1)
            report_progress(0.75)
            return {"assessed": 3, "avg_score": 87.5}

        t3 = tm.submit_async(assess_batch, name="bulk-assess")

        for label, tid in [("bulk-generate", t1), ("flaky-job", t2), ("bulk-assess", t3)]:
            while tm.status(tid).state in (TaskState.QUEUED, TaskState.RUNNING):
                await asyncio.sleep(0.1)
            st = tm.status(tid)
            print(f"{label}: state={st.state} attempts={st.attempts} progress={st.progress}")
            if st.state == TaskState.DONE:
                print(f"  result: {tm.result(tid)}")
            else:
                print(f"  failure: {st.failure_reason}")

        report = tm.export_report()
        print(f"report exported: {report}")
    finally:
        await tm.stop()
        tm.close()


if __name__ == "__main__":
    asyncio.run(main())
