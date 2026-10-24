"""
modules/reporting.py - CSV and HTML report export.

OWNER: Member 5 (Dashboard & Reporting)
Data format: schemas.py (columns = schemas.FINDING_FIELDS)

Done by Foundation:   working baseline CSV and HTML export (escaped, handles
                      empty results, creates folders).
TODO for Member 5:    improve the HTML report (summary chart/table, sorting,
                      styling, sample-data banner wording). PDF is optional -
                      the simplest route is "print to PDF" from the browser.

Security: every value from a finding is untrusted (it can contain text from a
scanned web server). Always pass it through html.escape() before putting it in
HTML. Never build HTML with unescaped finding text.
"""

from __future__ import annotations

import html
from collections import Counter
from datetime import datetime
from pathlib import Path

import pandas as pd

import config
from schemas import FINDING_FIELDS, SEVERITIES, is_sample, sort_by_severity


def _prepare_path(output_path: str) -> Path:
    path = Path(output_path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise RuntimeError(f"Cannot create folder {path.parent}: {exc}") from exc
    return path


def generate_csv_report(findings: list[dict], output_path: str) -> str:
    """Write findings to a CSV file.

    Args:
        findings: list of finding dicts (schemas.py format). May be empty -
                  an empty list writes a header-only CSV.
        output_path: file path, e.g. "reports/assessment.csv". Folders are created.

    Returns:
        The output path as a string.

    Raises:
        RuntimeError: the file cannot be written.
    """
    path = _prepare_path(output_path)
    rows = [{k: f.get(k, "") for k in FINDING_FIELDS} for f in sort_by_severity(findings or [])]
    try:
        pd.DataFrame(rows, columns=list(FINDING_FIELDS)).to_csv(path, index=False)
    except OSError as exc:
        raise RuntimeError(f"Cannot write CSV report to {path}: {exc}") from exc
    return str(path)


def generate_html_report(findings: list[dict], output_path: str) -> str:
    """Write findings to a self-contained HTML report (all values escaped).

    Args:
        findings: list of finding dicts (schemas.py format). May be empty.
        output_path: file path, e.g. "reports/assessment.html". Folders are created.

    Returns:
        The output path as a string.

    Raises:
        RuntimeError: the file cannot be written.
    """
    path = _prepare_path(output_path)
    findings = sort_by_severity(findings or [])
    esc = lambda value: html.escape(str(value), quote=True)  # noqa: E731

    counts = Counter(f.get("severity", "Info") for f in findings)
    summary = "".join(f"<td class='sev-{s.lower()}'>{s}: {counts.get(s, 0)}</td>" for s in SEVERITIES)
    banner = ("<p class='sample'>Contains SAMPLE DATA - some results did not come from a real scan.</p>"
              if any(is_sample(f) for f in findings) else "")

    if findings:
        header = "".join(f"<th>{esc(k)}</th>" for k in FINDING_FIELDS)
        body = "".join(
            "<tr>" + "".join(
                f"<td class='sev-{esc(f.get(k, '')).lower()}'>{esc(f.get(k, ''))}</td>" if k == "severity"
                else f"<td>{esc(f.get(k, ''))}</td>"
                for k in FINDING_FIELDS
            ) + "</tr>"
            for f in findings
        )
        table = f"<table><thead><tr>{header}</tr></thead><tbody>{body}</tbody></table>"
    else:
        table = "<p>No findings were recorded for this assessment.</p>"

    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>{esc(config.APP_NAME)} report</title>
<style>
 body {{ font-family: Arial, sans-serif; margin: 24px; color: #222; }}
 table {{ border-collapse: collapse; width: 100%; font-size: 13px; }}
 th, td {{ border: 1px solid #ccc; padding: 6px; text-align: left; vertical-align: top; }}
 th {{ background: #f0f0f0; }}
 .sample {{ background: #fff3cd; padding: 8px; border: 1px solid #e0c060; }}
 .sev-critical {{ background: #f8d7da; }} .sev-high {{ background: #fde2c8; }}
 .sev-medium {{ background: #fff3cd; }} .sev-low {{ background: #e2f0d9; }}
 .sev-info {{ background: #e7eef8; }}
</style></head><body>
<h1>{esc(config.APP_NAME)} - Assessment Report</h1>
<p>Generated {esc(datetime.now().strftime('%Y-%m-%d %H:%M'))} - {len(findings)} finding(s)</p>
{banner}
<table><tr>{summary}</tr></table>
<h2>Findings</h2>
{table}
<p><small>ML priority is a demonstration trained on synthetic data and does not
measure real-world accuracy. Recommendations must be reviewed before applying.</small></p>
</body></html>
"""
    try:
        path.write_text(document, encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"Cannot write HTML report to {path}: {exc}") from exc
    return str(path)
