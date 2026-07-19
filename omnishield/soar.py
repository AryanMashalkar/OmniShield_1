"""SOAR response actions (Windows Firewall isolation) + human-in-the-loop policy.

Safe-autonomy design: the AI *recommends* containment, but a state-changing
action (blocking an IP) requires (a) a valid API key and (b) — when
``OMNISHIELD_SOAR_REQUIRE_CONFIRMATION`` is enabled — an explicit analyst
confirmation token. The AI never blocks unilaterally; a human authorises.
"""

import ipaddress
import subprocess

from .config import settings
from .db import log_incident

RULE_SPECS = [
    ("Outbound", "TCP"),
    ("Inbound", "TCP"),
    ("Outbound", "UDP"),
    ("Inbound", "UDP"),
    ("Outbound", "ICMPv4"),
    ("Inbound", "ICMPv4"),
]


def validate_ip(target_ip: str) -> None:
    ipaddress.ip_address(target_ip)  # raises ValueError on bad input


def confirmation_required() -> bool:
    return settings.soar_require_confirmation


def block_ip(target_ip: str) -> dict:
    """Inject Windows Defender Firewall block rules for an IP (all proto/dir)."""
    rule_base = f"OmniShield_Block_{target_ip}"

    # Clear any stale rules first.
    subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            f"Get-NetFirewallRule -DisplayName '{rule_base}*' "
            "-ErrorAction SilentlyContinue | Remove-NetFirewallRule",
        ],
        capture_output=True,
        text=True,
    )

    errors: list[str] = []
    for direction, protocol in RULE_SPECS:
        display_name = f"{rule_base}_{protocol}_{direction}"
        ps_cmd = (
            f"New-NetFirewallRule -DisplayName '{display_name}' "
            f"-Direction {direction} -RemoteAddress {target_ip} "
            f"-Protocol {protocol} -Action Block -Profile Any -Enabled True"
        )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            errors.append(f"{display_name}: {result.stderr.strip()}")

    if errors:
        log_incident(target_ip, "BLOCK", "partial_failure", "; ".join(errors))
        return {
            "status": "partial_failure",
            "message": f"Some rules failed to apply for {target_ip}. "
            "Ensure the backend is running as Administrator.",
            "errors": errors,
        }

    log_incident(target_ip, "BLOCK", "success", "TCP/UDP/ICMP blocked, both directions")
    return {
        "status": "success",
        "message": f"Full isolation applied for {target_ip} "
        "(TCP/UDP/ICMP blocked, both directions)",
    }


def unblock_ip(target_ip: str) -> dict:
    rule_base = f"OmniShield_Block_{target_ip}"
    result = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            f"Get-NetFirewallRule -DisplayName '{rule_base}*' "
            "-ErrorAction SilentlyContinue | Remove-NetFirewallRule",
        ],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        log_incident(target_ip, "UNBLOCK", "error", result.stderr.strip())
        return {"status": "error", "message": result.stderr.strip()}

    log_incident(target_ip, "UNBLOCK", "success", "All rules removed")
    return {"status": "success", "message": f"All rules removed for {target_ip}"}
