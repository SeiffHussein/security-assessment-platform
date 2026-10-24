"""
modules/remediation.py - remediation recommendations (and a disabled auto-fix).

OWNER: Member 3 (Host Audit & Remediation)
Data format: schemas.py

DESIGN DECISION (Foundation): the project is RECOMMENDATIONS ONLY.
apply_fix() is a documented, disabled placeholder. Reasons:
    * findings come from untrusted scanner output - turning them into commands
      is a command-injection risk;
    * we must never modify remote systems;
    * safe local fixes need admin rights and differ per OS, which is out of
      scope for a student prototype.
config.ALLOW_AUTO_REMEDIATION is False and apply_fix() never runs anything,
even with confirmed=True. Do not change this without team + instructor approval.

Done by Foundation:   keyword rule table, recommend_fix(), disabled apply_fix().
TODO for Member 3:    expand/improve RECOMMENDATION_RULES so every sample and
                      real finding gets a specific, plain-language fix.
"""

from __future__ import annotations

import config

# (keywords to look for in title/description/evidence, recommendation).
# First match wins, so put specific rules before general ones. All lowercase.
# TODO (Member 3): add rules for the findings your teammates' tools produce.
RECOMMENDATION_RULES: list[tuple[tuple[str, ...], str]] = [
    (("cve-2021-41773", "path traversal"),
     "Upgrade Apache HTTP Server to 2.4.51 or later and make sure directories outside the "
     "web root are protected with 'Require all denied'."),
    (("telnet",),
     "Disable the Telnet service and use SSH instead; Telnet sends passwords in clear text."),
    (("root login",),
     "Set 'PermitRootLogin no' in /etc/ssh/sshd_config, then restart the SSH service."),
    (("firewall",),
     "Enable the host firewall (ufw/firewalld on Linux, the Application Firewall on macOS) "
     "and allow only the services you need."),
    (("password strength", "pam"),
     "Install and configure a password-quality module (e.g. pam_pwquality) and set a minimum length."),
    (("directory indexing", "directory listing"),
     "Disable directory listing on the web server (e.g. 'Options -Indexes' in Apache)."),
    (("banner", "version disclosure", "reveals version"),
     "Hide server version details (Apache: 'ServerTokens Prod' and 'ServerSignature Off')."),
    (("content-security-policy", "csp"),
     "Add a Content-Security-Policy header that only allows trusted sources."),
    (("self-signed", "certificate"),
     "Replace the certificate with one from a trusted certificate authority (e.g. Let's Encrypt)."),
    (("open port",),
     "Confirm this service is needed. If not, stop it or block the port in the firewall; "
     "if it is, keep it patched and restrict who can reach it."),
    (("hardening index",),
     "Work through the Lynis warnings first, then the suggestions, and re-run the audit."),
]

GENERIC_RECOMMENDATIONS: dict[str, str] = {
    "Critical": "Fix immediately: apply the vendor patch or take the service offline until patched.",
    "High": "Fix as soon as possible: apply the latest security update and restrict access.",
    "Medium": "Plan a fix soon: review the configuration and apply the vendor's hardening guidance.",
    "Low": "Fix when convenient: review the setting and harden it if it is not needed.",
    "Info": "No action required; review to confirm this is expected.",
}


def recommend_fix(finding: dict) -> str:
    """Return a plain-language remediation recommendation for one finding.

    Args:
        finding: dict in the schemas.py format (missing keys are tolerated).

    Returns:
        Non-empty recommendation string. Matches RECOMMENDATION_RULES on the
        title/description/evidence text; falls back to a severity-based advice.
        Never executes anything and never raises.
    """
    if not isinstance(finding, dict):
        return GENERIC_RECOMMENDATIONS["Info"]
    text = " ".join(str(finding.get(k, "")) for k in ("title", "description", "evidence")).lower()
    for keywords, advice in RECOMMENDATION_RULES:
        if any(k in text for k in keywords):
            return advice
    return GENERIC_RECOMMENDATIONS.get(str(finding.get("severity", "Info")), GENERIC_RECOMMENDATIONS["Info"])


def add_recommendations(findings: list[dict]) -> list[dict]:
    """Return copies of `findings` with "recommendation" filled in where it is empty."""
    return [{**f, "recommendation": f.get("recommendation") or recommend_fix(f)} for f in findings]


def apply_fix(finding: dict, confirmed: bool = False) -> dict:
    """Disabled remediation placeholder - NEVER changes any system.

    Args:
        finding: finding dict (schemas.py format).
        confirmed: explicit administrator confirmation. Even when True, nothing
                   is executed while config.ALLOW_AUTO_REMEDIATION is False.

    Returns:
        dict: {"finding_id": str, "applied": False, "message": str,
               "recommendation": str}
    """
    finding_id = str(finding.get("id", "")) if isinstance(finding, dict) else ""
    recommendation = recommend_fix(finding if isinstance(finding, dict) else {})
    if not config.ALLOW_AUTO_REMEDIATION:
        message = "Automatic remediation is disabled in this prototype. Apply the recommendation manually."
    elif not confirmed:
        message = "Administrator confirmation is required before any remediation."
    else:
        # Intentionally not implemented: see the module docstring.
        message = "No safe automatic fix is defined for this finding. Apply the recommendation manually."
    return {"finding_id": finding_id, "applied": False, "message": message,
            "recommendation": recommendation}
