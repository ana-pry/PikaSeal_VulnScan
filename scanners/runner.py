"""Thin subprocess wrapper.

Every external tool call goes through run_tool(). It NEVER raises on tool
failure -- a hung host, a missing binary, or a non-zero exit all come back as a
ToolResult with ok=False and a reason. This is what stops one bad target from
crashing the whole run (Day 3 requirement).
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass


@dataclass
class ToolResult:
    ok: bool
    returncode: int | None
    stdout: str
    stderr: str
    reason: str = ""   # human-readable failure reason when ok is False


def run_tool(
    cmd: list[str],
    timeout: float,
    stdin: str | None = None,
) -> ToolResult:
    """Run `cmd`, capturing stdout/stderr as text.

    Returns a ToolResult. Failure modes handled:
      - binary not installed      -> ok=False, reason="not installed"
      - timed out                 -> ok=False, reason="timeout"  (still returns
                                     whatever partial stdout was captured)
      - non-zero exit             -> ok=False, reason="exit N"    (stdout/stderr
                                     preserved -- some tools exit non-zero but
                                     still emit useful output)
      - anything else             -> ok=False, reason=str(exc)
    """
    try:
        proc = subprocess.run(
            cmd,
            input=stdin,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return ToolResult(False, None, "", "", reason=f"not installed: {cmd[0]}")
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout or ""
        err = exc.stderr or ""
        if isinstance(out, bytes):
            out = out.decode(errors="replace")
        if isinstance(err, bytes):
            err = err.decode(errors="replace")
        return ToolResult(False, None, out, err, reason=f"timeout after {timeout}s")
    except Exception as exc:  # pragma: no cover - defensive
        return ToolResult(False, None, "", "", reason=str(exc))

    ok = proc.returncode == 0
    reason = "" if ok else f"exit {proc.returncode}"
    return ToolResult(ok, proc.returncode, proc.stdout, proc.stderr, reason=reason)
