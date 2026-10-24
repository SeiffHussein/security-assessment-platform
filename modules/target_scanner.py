"""
modules/target_scanner.py - target validation and Nmap network discovery.

OWNER: Member 1 (Network Discovery)
Data format: schemas.py (every result is a finding dict, see schemas.FINDING_FIELDS)
Shared helpers: modules/tool_utils.py (run_tool, tool_available)

Done by Foundation:   validate_target() (complete, tested), sample mode.
TODO for Member 1:    real Nmap mode in scan_target() + _parse_nmap_xml().

Output contract of scan_target(): one finding per OPEN PORT, e.g.
    {
      "id": "3f2a91c0", "target": "192.168.1.10", "source": "nmap",
      "title": "Open port 22/tcp (ssh)", "severity": "Info",
      "description": "Port 22/tcp is open and running ssh.",
      "evidence": "22/tcp open ssh OpenSSH 8.9p1",
      "ml_priority": "", "recommendation": ""
    }
Hosts that are up but have no open ports get one "Host is up" Info finding,
so the dashboard can still list them.
"""

from __future__ import annotations

import ipaddress
import re

import config
from modules.tool_utils import run_tool, tool_available  # noqa: F401  (used by Member 1)
from schemas import new_finding, sample_source

# RFC 1123 hostname label: letters, digits, hyphens; not starting/ending with "-".
_HOST_LABEL = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")


def validate_target(target: str) -> bool:
    """Check that `target` is a safe, acceptable scan target.

    Accepted:
        * IPv4 / IPv6 address          e.g. "192.168.1.10", "::1"
        * small network in CIDR form   e.g. "192.168.1.0/24" (no larger than
          /config.MIN_IPV4_PREFIX for IPv4, /config.MIN_IPV6_PREFIX for IPv6)
        * hostname                     e.g. "localhost", "scanme.nmap.org"

    Rejected: empty input, spaces, anything starting with "-" (could be read as
    a tool option), shell characters, URLs ("http://..."), ports, over-long
    names, and ranges larger than the configured limit.

    Args:
        target: user-supplied text.

    Returns:
        True if acceptable, False otherwise. Never raises.

    NOTE: validation is about FORMAT only. Authorisation (written permission to
    scan) is confirmed by the user in the dashboard before any real scan.
    """
    if not isinstance(target, str):
        return False
    target = target.strip()
    if not target or len(target) > 253 or target.startswith("-"):
        return False

    # IP address or CIDR network
    try:
        if "/" in target:
            net = ipaddress.ip_network(target, strict=False)
            limit = config.MIN_IPV4_PREFIX if net.version == 4 else config.MIN_IPV6_PREFIX
            return net.prefixlen >= limit
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass

    # Hostname (only letters, digits, hyphens and dots allowed)
    labels = target.rstrip(".").split(".")
    if all(_HOST_LABEL.match(label) for label in labels):
        # Reject things like "999.1.1.1" that look numeric but are not valid IPs.
        return not all(label.isdigit() for label in labels)
    return False


def scan_target(target: str, sample_mode: bool = False) -> list[dict]:
    """Discover hosts and open ports with Nmap (or return sample results).

    Args:
        target: IP, small CIDR range or hostname (validated with validate_target).
        sample_mode: True -> return clearly labelled mock findings
                     (source "nmap (sample)"); no tool is executed.

    Returns:
        list of finding dicts (schemas.py format), one per open port.
        Empty list if the scan completed and nothing was found.

    Raises:
        ValueError: target fails validate_target().
        RuntimeError: Nmap missing, failed or timed out
                      (NotImplementedError until Member 1 finishes real mode).
    """
    if not validate_target(target):
        raise ValueError(f"Invalid target: {target!r}")
    target = target.strip()

    if sample_mode:
        return _sample_results(target)

    # ------------------------------------------------------------------ TODO (Member 1)
    # 1. If not tool_available("nmap"): raise RuntimeError("Nmap is not installed ...").
    # 2. Build an ARGUMENT LIST (never a string, never shell=True), e.g.:
    #        args = ["nmap", "-sT", "-sV", "-T3",
    #                "--top-ports", str(config.NMAP_TOP_PORTS),
    #                "-oX", "-", target]
    #    -sT (TCP connect) works without root/admin on macOS, Linux and Windows.
    #    Do NOT add intrusive options (no --script vuln, no -A, no -sU floods).
    # 3. result = run_tool(args)   # timeout comes from config.TOOL_TIMEOUTS["nmap"]
    # 4. If result.returncode != 0: raise RuntimeError(f"Nmap failed: {result.stderr[:300]}")
    # 5. return _parse_nmap_xml(result.stdout)
    # 6. Optional: raise severity for risky services (telnet 23, ftp 21,
    #    rdp 3389, smb 445 exposed...) - keep the rule list short and documented.
    # Test with: pytest tests/test_interfaces.py -k target   and a mocked run_tool.
    # -------------------------------------------------------------------------------
    raise NotImplementedError("Real Nmap scanning is not implemented yet (Member 1). Use sample mode.")


def _parse_nmap_xml(xml_text: str) -> list[dict]:
    """Convert Nmap XML output (-oX -) into finding dicts.

    TODO (Member 1): use xml.etree.ElementTree (standard library, no new dependency).
        For each <host> with <status state="up">:
            address = host/address[@addr]
            for each <port> whose <state state="open">:
                portid, protocol, service name/product/version
                -> new_finding(address, "nmap", f"Open port {portid}/{protocol} ({service})",
                               severity="Info",
                               description=f"Port {portid}/{protocol} is open and running {service}.",
                               evidence=f"{portid}/{protocol} open {service} {product} {version}".strip())
            no open ports -> one "Host is up" Info finding.
        Malformed/empty XML -> raise RuntimeError("Could not parse Nmap output").

    Args:
        xml_text: Nmap's XML output as a string.

    Returns:
        list of finding dicts (schemas.py format).
    """
    raise NotImplementedError("_parse_nmap_xml is not implemented yet (Member 1).")


def _sample_results(target: str) -> list[dict]:
    """Mock discovery results. Clearly labelled as sample data - never real."""
    src = sample_source("nmap")
    note = "SAMPLE DATA - not from a real scan. "
    host = target.split("/")[0] if "/" in target else target
    return [
        new_finding(host, src, "Open port 22/tcp (ssh)", severity="Info",
                    description=note + "Port 22/tcp is open and running ssh.",
                    evidence="22/tcp open ssh OpenSSH 8.9p1"),
        new_finding(host, src, "Open port 80/tcp (http)", severity="Info",
                    description=note + "Port 80/tcp is open and running http.",
                    evidence="80/tcp open http Apache httpd 2.4.49"),
        new_finding(host, src, "Open port 23/tcp (telnet)", severity="Medium",
                    description=note + "Telnet sends credentials in clear text.",
                    evidence="23/tcp open telnet BusyBox telnetd"),
    ]
