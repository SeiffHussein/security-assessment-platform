"""
modules/tool_utils.py - the ONE safe way to run external tools (shared helper).

Owner: Foundation (shared). Do not change without telling the team.

Why this file exists: every scanner module must run command-line tools the same
safe way (argument lists, no shell, timeouts, clear errors). Putting that logic
in one place keeps the scanner modules short and consistent.

Error contract used across the project:
    ValueError    -> bad user input (e.g. invalid target)
    RuntimeError  -> tool missing, failed, timed out, unsupported OS
                     (NotImplementedError is a RuntimeError subclass, so the
                     dashboard also catches "not implemented yet")
"""

from __future__ import annotations

import shutil
import subprocess

import config


def tool_available(name: str) -> bool:
    """Return True if the command-line tool `name` is on the PATH."""
    return shutil.which(name) is not None


def run_tool(args: list[str], timeout: int | None = None) -> subprocess.CompletedProcess:
    """Run an external tool safely and return the completed process.

    Args:
        args: argument list, e.g. ["nmap", "-sT", "-oX", "-", "10.0.0.5"].
              NEVER build a single command string and NEVER use shell=True.
        timeout: seconds before the tool is killed. Defaults to the value in
                 config.TOOL_TIMEOUTS for args[0], else config.DEFAULT_TIMEOUT.

    Returns:
        subprocess.CompletedProcess with .returncode, .stdout, .stderr (text).
        A non-zero return code is NOT raised automatically - many tools use
        non-zero codes for "findings found". The caller decides.

    Raises:
        ValueError: if args is empty or not a list of strings.
        RuntimeError: if the tool is not installed or exceeds the timeout.
    """
    if not args or not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        raise ValueError("run_tool() needs a non-empty list of strings.")
    tool = args[0]
    if not tool_available(tool):
        raise RuntimeError(f"'{tool}' is not installed or not on PATH. See README > External tools.")
    if timeout is None:
        timeout = config.TOOL_TIMEOUTS.get(tool, config.DEFAULT_TIMEOUT)
    try:
        return subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"'{tool}' timed out after {timeout} s.") from exc
    except OSError as exc:
        raise RuntimeError(f"Could not run '{tool}': {exc}") from exc
