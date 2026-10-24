"""
modules/host_auditor.py - Lynis host security audit.

OWNER: Member 3 (Host Audit & Remediation)
Data format: schemas.py (every result is a finding dict)
Shared helpers: modules/tool_utils.py (run_tool, tool_available)

IMPORTANT: Lynis audits the machine it RUNS ON (this laptop), not a remote
host. It supports Linux and macOS; it does not run natively on Windows (use WSL).
The audit only READS the system - this module must never change settings.

Done by Foundation:   sample mode, OS check.
TODO for Member 3:    real Lynis run + _parse_lynis_report().
"""

from __future__ import annotations

import platform
import socket

import config  # noqa: F401  (paths/timeouts used by Member 3)
from modules.tool_utils import run_tool, tool_available  # noqa: F401
from schemas import new_finding, sample_source

SUPPORTED_SYSTEMS = ("Linux", "Darwin")  # Darwin = macOS


def audit_host(sample_mode: bool = False) -> list[dict]:
    """Audit the local machine with Lynis (or return sample findings).

    Args:
        sample_mode: True -> clearly labelled mock findings, Lynis is not run.

    Returns:
        list of finding dicts (schemas.py format). target = this machine's
        hostname, source = "lynis". Lynis warnings -> "Medium",
        suggestions -> "Low" (use schemas.normalize_severity("warning") etc.).

    Raises:
        RuntimeError: unsupported OS, Lynis missing, failed or timed out
                      (NotImplementedError until Member 3 finishes real mode).
    """
    hostname = socket.gethostname() or "localhost"

    if sample_mode:
        return _sample_results(hostname)

    if platform.system() not in SUPPORTED_SYSTEMS:
        raise RuntimeError(
            f"Lynis is not supported on {platform.system()}. Use Linux, macOS or WSL, or sample mode."
        )

    # ------------------------------------------------------------------ TODO (Member 3)
    # 1. If not tool_available("lynis"): raise RuntimeError("Lynis is not installed ...")
    # 2. Write the report to a file we control (no root needed for the file):
    #        report = config.REPORTS_DIR / "lynis-report.dat"
    #        args = ["lynis", "audit", "system", "--quick", "--no-colors",
    #                "--report-file", str(report)]
    #    Running without sudo works but skips some tests - document that in the
    #    dashboard message. Never pass options that fix or change settings.
    # 3. res = run_tool(args)   # timeout from config.TOOL_TIMEOUTS["lynis"]
    #    Non-zero return code with no report file -> RuntimeError(res.stderr[:300])
    # 4. return _parse_lynis_report(report.read_text(errors="replace"), hostname)
    # -------------------------------------------------------------------------------
    raise NotImplementedError("Real Lynis auditing is not implemented yet (Member 3). Use sample mode.")


def _parse_lynis_report(report_text: str, hostname: str) -> list[dict]:
    """Convert a Lynis report file (key=value lines) into finding dicts.

    TODO (Member 3):
        Lines look like:
            warning[]=SSH-7408|Root login allowed|-|-|
            suggestion[]=AUTH-9262|Install a PAM module for password strength|-|-|
        Split on "=" once, then on "|": test_id, text, details...
        warning[]    -> severity "Medium"
        suggestion[] -> severity "Low"
        title = text, evidence = f"Lynis test {test_id}", description = short explanation.
        Also read "hardening_index=NN" and add one Info finding with the score.
        Ignore all other lines. Empty text -> return [].

    Args:
        report_text: full content of the Lynis report file.
        hostname: name of the audited machine (finding target).

    Returns:
        list of finding dicts (schemas.py format).
    """
    raise NotImplementedError("_parse_lynis_report is not implemented yet (Member 3).")


def _sample_results(hostname: str) -> list[dict]:
    """Mock Lynis findings. Clearly labelled as sample data."""
    src = sample_source("lynis")
    note = "SAMPLE DATA - not from a real audit. "
    return [
        new_finding(hostname, src, "SSH root login is allowed", severity="Medium",
                    description=note + "PermitRootLogin is enabled in the SSH server configuration.",
                    evidence="Lynis test SSH-7408"),
        new_finding(hostname, src, "No password strength checking module installed", severity="Low",
                    description=note + "Users can set weak passwords.",
                    evidence="Lynis test AUTH-9262"),
        new_finding(hostname, src, "Host firewall is not active", severity="Medium",
                    description=note + "No active packet filter was detected.",
                    evidence="Lynis test FIRE-4590"),
        new_finding(hostname, src, "Hardening index: 62/100", severity="Info",
                    description=note + "Overall Lynis hardening score.",
                    evidence="hardening_index=62"),
    ]
