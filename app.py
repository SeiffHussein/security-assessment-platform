"""
app.py - Streamlit dashboard. Run with:  streamlit run app.py

OWNER: Member 5 (Dashboard & Reporting)

The dashboard only CALLS the module functions; it never re-implements scanning,
ML, remediation or reporting logic. Nothing runs on startup - a scan starts only
when the user presses the button. Fixes are never applied.

run_assessment() holds the pipeline and is importable without Streamlit running
(used by tests). The UI lives in main().
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pandas as pd

import config
from modules import host_auditor, ml_classifier, remediation, reporting, target_scanner, vulnerability_scanner
from schemas import FINDING_FIELDS, SEVERITIES, is_sample, sort_by_severity

SCAN_OPTIONS = {
    "discovery": "Network discovery (Nmap)",
    "vulnerability": "Vulnerability & web checks (Nuclei / Nikto)",
    "host_audit": "Host audit of THIS machine (Lynis)",
}


def run_assessment(target: str, checks: list[str], sample_mode: bool) -> tuple[list[dict], list[str]]:
    """Run the selected checks, then ML prioritisation and recommendations.

    Args:
        target: IP / hostname / small CIDR (ignored by the host audit).
        checks: subset of SCAN_OPTIONS keys.
        sample_mode: pass-through to every scanner.

    Returns:
        (findings, messages): findings in schemas.py format, sorted by severity;
        messages = human-readable warnings/errors (one module failing does not
        stop the others).
    """
    findings: list[dict] = []
    messages: list[str] = []

    steps = {
        "discovery": ("Network discovery", lambda: target_scanner.scan_target(target, sample_mode)),
        "vulnerability": ("Vulnerability scan", lambda: vulnerability_scanner.scan_vulnerabilities(target, sample_mode)),
        "host_audit": ("Host audit", lambda: host_auditor.audit_host(sample_mode)),
    }
    for key in checks:
        label, func = steps[key]
        try:
            findings.extend(func())
        except (ValueError, RuntimeError) as exc:   # NotImplementedError is a RuntimeError
            messages.append(f"{label}: {exc}")

    try:
        findings = ml_classifier.classify_findings(findings)
    except RuntimeError as exc:
        messages.append(f"ML prioritisation unavailable: {exc}")

    findings = remediation.add_recommendations(findings)
    return sort_by_severity(findings), messages


def main() -> None:
    import streamlit as st

    st.set_page_config(page_title=config.APP_NAME, layout="wide")
    st.title(config.APP_NAME)
    st.caption("University prototype - scan only systems you own or have written permission to test.")

    # ---------------------------------------------------------------- sidebar controls
    with st.sidebar:
        st.header("Assessment")
        target = st.text_input("Target (IP, hostname or small CIDR)", value="192.168.1.10")
        sample_mode = st.toggle("Sample mode (no real scans)", value=config.SAMPLE_MODE_DEFAULT)
        checks = [key for key, label in SCAN_OPTIONS.items()
                  if st.checkbox(label, value=True, key=f"chk_{key}")]
        authorised = True
        if not sample_mode:
            st.warning("Real mode runs external tools against the target.")
            authorised = st.checkbox("I confirm I am authorised to scan this target.")
        start = st.button("Start assessment", type="primary")

    if sample_mode:
        st.info("SAMPLE MODE - results below are mock data, not from a real scan.")

    # ---------------------------------------------------------------- run
    if start:
        if not checks:
            st.error("Select at least one check.")
        elif not target_scanner.validate_target(target):
            st.error("Invalid target. Use an IP address, a hostname, or a CIDR range no larger than /24.")
        elif not authorised:
            st.error("Please confirm you are authorised to scan this target.")
        else:
            with st.spinner("Running assessment..."):
                findings, messages = run_assessment(target.strip(), checks, sample_mode)
            st.session_state["findings"] = findings
            st.session_state["messages"] = messages

    findings: list[dict] = st.session_state.get("findings", [])
    for msg in st.session_state.get("messages", []):
        st.warning(msg)

    if not findings:
        st.write("Configure the assessment in the sidebar and press **Start assessment**.")
        return

    if any(is_sample(f) for f in findings):
        st.warning("These results include SAMPLE DATA.")

    # ---------------------------------------------------------------- summary
    df = pd.DataFrame(findings, columns=list(FINDING_FIELDS))
    cols = st.columns(len(SEVERITIES))
    for col, sev in zip(cols, SEVERITIES):
        col.metric(sev, int((df["severity"] == sev).sum()))

    # ---------------------------------------------------------------- hosts
    st.subheader("Discovered hosts")
    hosts = df[df["source"].str.startswith("nmap")]
    if hosts.empty:
        st.write("No network discovery results.")
    else:
        st.dataframe(hosts.groupby("target").agg(open_ports=("evidence", "count"),
                                                  services=("evidence", "; ".join)).reset_index(),
                     hide_index=True)

    # ---------------------------------------------------------------- findings
    st.subheader("Findings")
    chosen = st.multiselect("Severity filter", SEVERITIES, default=list(SEVERITIES))
    view = df[df["severity"].isin(chosen)]
    st.dataframe(view[["severity", "ml_priority", "target", "source", "title", "evidence"]],
                 hide_index=True)
    if (df["ml_priority"] == "").all():
        st.caption("ML priority is empty until modules/ml_classifier.py is implemented.")

    st.subheader("Remediation recommendations")
    st.caption("Recommendations only - this application never applies fixes automatically.")
    for row in view.to_dict("records"):
        with st.expander(f"[{row['severity']}] {row['title']} - {row['target']}"):
            st.write(row["description"] or "_No description._")
            st.code(row["evidence"] or "-", language=None)
            st.markdown(f"**Recommendation:** {row['recommendation']}")

    # ---------------------------------------------------------------- export
    st.subheader("Export report")
    if st.button("Generate CSV and HTML reports"):
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        try:
            st.session_state["reports"] = [
                reporting.generate_csv_report(findings, str(config.REPORTS_DIR / f"assessment_{stamp}.csv")),
                reporting.generate_html_report(findings, str(config.REPORTS_DIR / f"assessment_{stamp}.html")),
            ]
        except RuntimeError as exc:
            st.error(f"Report export failed: {exc}")
    for path in st.session_state.get("reports", []):
        mime = "text/csv" if path.endswith(".csv") else "text/html"
        with open(path, "rb") as fh:
            name = Path(path).name
            st.download_button(f"Download {name}", fh.read(), file_name=name, mime=mime, key=path)


if __name__ == "__main__":
    main()
