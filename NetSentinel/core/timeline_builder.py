"""Build a master event timeline from all analysis sources."""
from datetime import datetime


CATEGORIES = {"credential", "file", "dns", "alert", "session", "email", "chat", "tls"}


def _ts_str(ts):
    if ts is None:
        return "unknown"
    try:
        return datetime.utcfromtimestamp(float(ts)).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return str(ts)


class TimelineBuilder:
    """Aggregate and sort events from all analysis modules."""

    def __init__(self):
        self._events = []

    def add_event(self, ts, category: str, severity: str, src_ip: str,
                  dst_ip: str, description: str) -> None:
        self._events.append({
            "timestamp": ts,
            "timestamp_str": _ts_str(ts),
            "category": category if category in CATEGORIES else "other",
            "severity": severity,
            "src_ip": src_ip or "",
            "dst_ip": dst_ip or "",
            "description": description,
        })

    @property
    def events(self):
        return sorted(self._events, key=lambda e: (e["timestamp"] or 0))

    def build_attack_narrative(self, alerts: list) -> str:
        """Generate a plain-English summary of the attack sequence."""
        if not alerts:
            return "No alerts detected. Traffic appears normal."

        sorted_alerts = sorted(alerts, key=lambda a: (a.get("timestamp") or 0))
        critical = [a for a in sorted_alerts if a["severity"] == "CRITICAL"]
        high = [a for a in sorted_alerts if a["severity"] == "HIGH"]
        medium = [a for a in sorted_alerts if a["severity"] == "MEDIUM"]

        lines = []
        lines.append(f"=== Attack Narrative ===")
        lines.append(f"Total alerts: {len(alerts)} "
                     f"(CRITICAL: {len(critical)}, HIGH: {len(high)}, MEDIUM: {len(medium)})")
        lines.append("")

        if sorted_alerts:
            first = sorted_alerts[0]
            last = sorted_alerts[-1]
            lines.append(f"Timeline: {first.get('timestamp_str', 'unknown')} → "
                         f"{last.get('timestamp_str', 'unknown')}")
            lines.append("")

        if critical:
            lines.append("CRITICAL findings:")
            for a in critical[:5]:
                lines.append(f"  [{a.get('timestamp_str', '')}] {a['rule_name']}: {a['description']}")
            lines.append("")

        if high:
            lines.append("High severity findings:")
            for a in high[:5]:
                lines.append(f"  [{a.get('timestamp_str', '')}] {a['rule_name']}: {a['description']}")
            lines.append("")

        # Attack pattern summary
        rule_names = [a["rule_name"] for a in sorted_alerts]
        unique_rules = list(dict.fromkeys(rule_names))
        if len(unique_rules) >= 3:
            lines.append("Attack pattern: Multi-stage attack detected.")
            lines.append(f"Stages: {' → '.join(unique_rules[:5])}")
        elif "Port Scan" in unique_rules and "SSH Brute Force" in unique_rules:
            lines.append("Attack pattern: Reconnaissance followed by brute-force login attempt.")
        elif "Cleartext Credentials Detected" in unique_rules:
            lines.append("Attack pattern: Credential exposure over insecure protocols.")
        elif "Data Exfiltration" in unique_rules:
            lines.append("Attack pattern: Potential data exfiltration detected.")

        return "\n".join(lines)
