"""Example 05 — Native file tools + surgical patch engine.

Native replacements for Claude SDK FileEdit/Glob/Grep, plus a surgical patch
engine (Unified Diff apply + function-level replace). Full-rewrite is
forbidden — only targeted edits land.

  file_edit(path, old, new)        unique-match exact replace (atomic, flock)
  glob(pattern)                    recursive wildcard, skips .venv/target/etc
  grep(pattern, paths)             regex search, recursive, 2000-hit cap
  apply_patch(diff)                Unified Diff (diffy), multi-file, no full-rewrite
  replace_function(path, fn, body) tree-sitter AST function replace (py/js/ts/rs)

    python examples/05_file_tools.py
"""

import logging
import tempfile
from pathlib import Path

from fusion_executor import FusionSandboxExecutor

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")


def main() -> None:
    ex = FusionSandboxExecutor()

    with tempfile.TemporaryDirectory(prefix="fe-tools-demo-") as td:
        root = Path(td)
        (root / "a.py").write_text("def foo():\n    return 1\n")
        (root / "b.py").write_text("VALUE = 2\nNAME = 'demo'\n")
        (root / "sub").mkdir()
        (root / "sub" / "c.py").write_text("def bar():\n    return 3\n")

        # file_edit — unique-match exact replace.
        r = ex.file_edit("a.py", "return 1", "return 42", cwd=str(root))
        print(f"file_edit: ok={r.ok} matches={r.matches} -> {r.error or '(a.py updated)'}")

        # glob — wildcard match (paths relative to cwd).
        entries = ex.glob("**/*.py", cwd=str(root))
        print(f"glob **/*.py: {[e.path for e in entries]}")

        # grep — regex over a list of paths/dirs.
        hits = ex.grep(r"def \w+", ["."], cwd=str(root))
        for h in hits:
            print(f"  grep hit: {h.path}:{h.line_number} {h.content}")

        # apply_patch — single-file Unified Diff (keep a context line so it is a
        # surgical patch, not a full rewrite; deleting all original lines is rejected).
        diff = "--- a/b.py\n+++ b/b.py\n@@ -1,2 +1,2 @@\n-VALUE = 2\n+VALUE = 99\n NAME = 'demo'\n"
        r = ex.apply_patch(diff, cwd=str(root))
        print(f"apply_patch: ok={r.ok} matches={r.matches} -> {r.error or '(b.py updated)'}")

        # replace_function — AST-level function body replace (python grammar).
        new_body = "def bar():\n    return 300\n"
        r = ex.replace_function("sub/c.py", "bar", new_body, cwd=str(root))
        print(f"replace_function: ok={r.ok} matches={r.matches} -> {r.error or '(sub/c.py bar updated)'}")

        # Verify final file states.
        print(f"a.py      = {(root / 'a.py').read_text().strip()!r}")
        print(f"b.py      = {(root / 'b.py').read_text().strip()!r}")
        print(f"sub/c.py  = {(root / 'sub' / 'c.py').read_text().strip()!r}")


if __name__ == "__main__":
    main()
