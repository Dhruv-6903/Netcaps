"""Alert engine with 20 built-in detection rules."""
import math
import socket
from collections import defaultdict
from datetime import datetime


DOH_RESOLVERS = {"1.1.1.1", "8.8.8.8", "9.9.9.9", "94.140.14.14"}
INTERNAL_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
                     "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
                     "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.")


def _is_internal(ip: str) -> bool:
    return any(ip.startswith(p) for p in INTERNAL_PREFIXES)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def _ts_str(ts):
    if ts is None:
        return ""
    try:
        return datetime.utcfromtimestamp(float(ts)).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return str(ts)


class AlertEngine:
    """Generate alerts from analysis data."""

    def __init__(self):
        self._alerts = []

    def _add(self, ts, severity, rule_name, description, related_ips, ref_type="", ref_id=""):
        self._alerts.append({
            "timestamp": ts,
            "timestamp_str": _ts_str(ts),
            "severity": severity,
            "rule_name": rule_name,
            "description": description,
            "related_ips": list(related_ips),
            "ref_type": ref_type,
            "ref_id": ref_id,
        })

    def check_all(self, hosts: dict, sessions: list, dns_events: list,
                  credentials: list, files: list, packets_window: list) -> None:
        self._alerts.clear()
        self._rule_cleartext_creds(credentials)
        self._rule_dns_entropy(dns_events)
        self._rule_dns_tunneling(dns_events)
        self._rule_port_scan(sessions)
        self._rule_vertical_scan(sessions)
        self._rule_large_file(files)
        self._rule_nonstandard_http(sessions)
        self._rule_icmp_flood(packets_window)
        self._rule_syn_flood(sessions)
        self._rule_udp_flood(sessions)
        self._rule_ftp_brute(sessions)
        self._rule_ssh_brute(sessions)
        self._rule_malicious_hash(files)
        self._rule_dns_beaconing(dns_events)
        self._rule_fast_flux(dns_events)
        self._rule_doh_bypass(sessions)
        self._rule_multi_method()
        self._rule_data_exfil(sessions)
        self._rule_ldap_creds(credentials)
        self._rule_smb_lateral(sessions)

    # Rule 1
    def _rule_cleartext_creds(self, credentials):
        for cred in credentials:
            self._add(cred.get("timestamp"), "HIGH", "Cleartext Credentials Detected",
                      f"Cleartext {cred['protocol']} credentials from {cred['src_ip']}",
                      [cred["src_ip"], cred["dst_ip"]], "credential", "")

    # Rule 2
    def _rule_dns_entropy(self, dns_events):
        for ev in dns_events:
            fqdn = ev.get("fqdn", "")
            labels = fqdn.split(".")
            if labels:
                sub = labels[0] if len(labels) > 2 else fqdn
                if _shannon_entropy(sub) > 3.5:
                    self._add(ev["timestamp"], "MEDIUM", "Suspicious DNS Entropy",
                              f"High entropy subdomain '{sub}' (possible DGA)",
                              [ev["src_ip"]], "dns", fqdn)

    # Rule 3
    def _rule_dns_tunneling(self, dns_events):
        for ev in dns_events:
            fqdn = ev.get("fqdn", "")
            labels = fqdn.split(".")
            if any(len(l) > 50 for l in labels):
                self._add(ev["timestamp"], "MEDIUM", "DNS Subdomain Tunneling",
                          f"DNS label >50 chars in '{fqdn}'",
                          [ev["src_ip"]], "dns", fqdn)

    # Rule 4
    def _rule_port_scan(self, sessions):
        src_ports = defaultdict(lambda: defaultdict(set))  # src -> dst -> {ports}
        src_times = defaultdict(lambda: defaultdict(list))
        for s in sessions:
            src = s["src_ip"]
            dst = s["dst_ip"]
            ts = s["start_time"]
            port = s["dst_port"]
            src_times[src][dst].append(ts)
            src_ports[src][dst].add(port)

        for src, dsts in src_ports.items():
            for dst, ports in dsts.items():
                times = sorted(src_times[src][dst])
                if not times:
                    continue
                # Check 5s window
                for i, t in enumerate(times):
                    window_ports = set()
                    for j, t2 in enumerate(times):
                        if t <= t2 <= t + 5:
                            pass
                    # Simplified: if >20 distinct ports total in 5s window
                    window = [t2 for t2 in times if t <= t2 <= t + 5]
                    if len(window) >= 20:
                        wports = set()
                        for s2 in sessions:
                            if s2["src_ip"] == src and s2["dst_ip"] == dst and t <= s2["start_time"] <= t + 5:
                                wports.add(s2["dst_port"])
                        if len(wports) > 20:
                            self._add(t, "HIGH", "Port Scan",
                                      f"{src} hit {len(wports)} ports on {dst} in 5s",
                                      [src, dst])
                            break

    # Rule 5
    def _rule_vertical_scan(self, sessions):
        src_port_dst = defaultdict(lambda: defaultdict(list))  # src -> port -> [dst_ips, ts]
        for s in sessions:
            src_port_dst[s["src_ip"]][s["dst_port"]].append((s["dst_ip"], s["start_time"]))

        for src, ports in src_port_dst.items():
            for port, targets in ports.items():
                times = [t for _, t in targets]
                if not times:
                    continue
                for t in times:
                    window = [(ip, t2) for ip, t2 in targets if t <= t2 <= t + 10]
                    distinct_ips = {ip for ip, _ in window}
                    if len(distinct_ips) > 10:
                        self._add(t, "HIGH", "Vertical Port Scan",
                                  f"{src} scanned port {port} on {len(distinct_ips)} hosts in 10s",
                                  [src])
                        break

    # Rule 6
    def _rule_large_file(self, files):
        for f in files:
            if f.get("protocol") == "HTTP" and f.get("size", 0) > 50 * 1024 * 1024:
                self._add(f.get("timestamp"), "MEDIUM", "Large File Transfer",
                          f"File '{f['filename']}' ({f['size']//1024//1024}MB) via HTTP",
                          [f.get("src_ip", ""), f.get("dst_ip", "")], "file", f["md5"])

    # Rule 7
    def _rule_nonstandard_http(self, sessions):
        HTTP_PORTS = {80, 443, 8080}
        for s in sessions:
            if s.get("app_label") == "HTTP" and s["dst_port"] not in HTTP_PORTS:
                self._add(s["start_time"], "LOW", "Non-Standard HTTP Port",
                          f"HTTP traffic on port {s['dst_port']}",
                          [s["src_ip"], s["dst_ip"]])

    # Rule 8
    def _rule_icmp_flood(self, packets_window):
        # packets_window: list of (ts, src_ip, proto_name)
        icmp_count = defaultdict(list)
        for item in packets_window:
            if len(item) >= 3 and item[2] == "ICMP":
                icmp_count[item[1]].append(item[0])
        for src, times in icmp_count.items():
            for t in times:
                window = [t2 for t2 in times if t <= t2 <= t + 10]
                if len(window) > 100:
                    self._add(t, "MEDIUM", "ICMP Flood",
                              f"{src} sent {len(window)} ICMP echo-req in 10s",
                              [src])
                    break

    # Rule 9
    def _rule_syn_flood(self, sessions):
        syn_only = defaultdict(list)
        for s in sessions:
            flags = s.get("tcp_flags", set())
            if "SYN" in flags and "ACK" not in flags:
                syn_only[s["src_ip"]].append(s["start_time"])
        for src, times in syn_only.items():
            for t in times:
                window = [t2 for t2 in times if t <= t2 <= t + 10]
                if len(window) > 200:
                    self._add(t, "HIGH", "SYN Flood",
                              f"{src} sent {len(window)} SYN packets in 10s",
                              [src])
                    break

    # Rule 10
    def _rule_udp_flood(self, sessions):
        udp_traffic = defaultdict(lambda: defaultdict(list))
        for s in sessions:
            if s["protocol"] == "UDP":
                udp_traffic[s["src_ip"]][s["dst_ip"]].append(s["start_time"])
        for src, dsts in udp_traffic.items():
            for dst, times in dsts.items():
                for t in times:
                    window = [t2 for t2 in times if t <= t2 <= t + 5]
                    if len(window) > 500:
                        self._add(t, "HIGH", "UDP Flood",
                                  f"{src} sent {len(window)} UDP to {dst} in 5s",
                                  [src, dst])
                        break

    # Rule 11
    def _rule_ftp_brute(self, sessions):
        # Simplified: look for many sessions to port 21
        ftp_sess = defaultdict(list)
        for s in sessions:
            if s["dst_port"] == 21:
                ftp_sess[s["src_ip"]].append(s["start_time"])
        for src, times in ftp_sess.items():
            if len(times) > 5:
                self._add(times[0], "HIGH", "FTP Brute Force",
                          f"{src} made {len(times)} FTP connections",
                          [src])

    # Rule 12
    def _rule_ssh_brute(self, sessions):
        ssh_sess = defaultdict(list)
        for s in sessions:
            if s["dst_port"] == 22:
                ssh_sess[s["src_ip"]].append(s["start_time"])
        for src, times in sorted(ssh_sess.items()):
            for t in times:
                window = [t2 for t2 in times if t <= t2 <= t + 30]
                if len(window) > 5:
                    self._add(t, "HIGH", "SSH Brute Force",
                              f"{src} made {len(window)} SSH connections in 30s",
                              [src])
                    break

    # Rule 13
    def _rule_malicious_hash(self, files):
        for f in files:
            if f.get("vt_status") == "malicious":
                self._add(f.get("timestamp"), "CRITICAL", "Known Malicious Hash",
                          f"File '{f['filename']}' flagged by VT: {f['md5']}",
                          [f.get("src_ip", ""), f.get("dst_ip", "")], "file", f["md5"])

    # Rule 14
    def _rule_dns_beaconing(self, dns_events):
        domain_queries = defaultdict(list)
        for ev in dns_events:
            if not ev.get("is_response"):
                domain_queries[ev["fqdn"]].append((ev["timestamp"], ev["src_ip"]))
        for domain, items in domain_queries.items():
            times = [t for t, _ in items]
            for t in times:
                window = [t2 for t2 in times if t <= t2 <= t + 60]
                if len(window) > 50:
                    src_ips = list({ip for _, ip in items})
                    self._add(t, "MEDIUM", "DNS Beaconing",
                              f"Domain '{domain}' queried {len(window)}x in 60s",
                              src_ips, "dns", domain)
                    break

    # Rule 15
    def _rule_fast_flux(self, dns_events):
        for ev in dns_events:
            if ev.get("ttl") is not None and ev["ttl"] < 60 and ev.get("is_response"):
                self._add(ev["timestamp"], "LOW", "Fast-Flux DNS",
                          f"TTL={ev['ttl']}s for '{ev['fqdn']}'",
                          [ev["src_ip"]], "dns", ev["fqdn"])

    # Rule 16
    def _rule_doh_bypass(self, sessions):
        for s in sessions:
            if s["dst_port"] == 443 and s["dst_ip"] in DOH_RESOLVERS:
                self._add(s["start_time"], "LOW", "DoH Bypass",
                          f"HTTPS to DoH resolver {s['dst_ip']}",
                          [s["src_ip"], s["dst_ip"]])

    # Rule 17 (runs after all other rules)
    def _rule_multi_method(self):
        high_crit = defaultdict(list)
        for alert in self._alerts:
            if alert["severity"] in ("HIGH", "CRITICAL"):
                for ip in alert["related_ips"]:
                    if ip:
                        high_crit[ip].append(alert)
        for ip, ip_alerts in high_crit.items():
            if len(ip_alerts) >= 2:
                rule_names = list({a["rule_name"] for a in ip_alerts})
                self._add(ip_alerts[0]["timestamp"], "CRITICAL", "Multi-Method Attack",
                          f"{ip} triggered {len(ip_alerts)} HIGH/CRITICAL alerts: {', '.join(rule_names[:3])}",
                          [ip])

    # Rule 18
    def _rule_data_exfil(self, sessions):
        threshold = 100 * 1024 * 1024
        for s in sessions:
            src = s["src_ip"]
            dst = s["dst_ip"]
            if _is_internal(src) and not _is_internal(dst):
                if s.get("bytes_src_to_dst", 0) > threshold:
                    self._add(s["start_time"], "HIGH", "Data Exfiltration",
                              f"{src}→{dst}: {s['bytes_src_to_dst']//1024//1024}MB outbound",
                              [src, dst])

    # Rule 19
    def _rule_ldap_creds(self, credentials):
        for cred in credentials:
            if cred["protocol"] == "LDAP Bind":
                self._add(cred["timestamp"], "HIGH", "LDAP Cleartext Credentials",
                          f"LDAP bind from {cred['src_ip']} user={cred['username']}",
                          [cred["src_ip"], cred["dst_ip"]])

    # Rule 20
    def _rule_smb_lateral(self, sessions):
        smb_src = defaultdict(lambda: defaultdict(list))
        for s in sessions:
            if s["dst_port"] in (445, 139):
                src = s["src_ip"]
                dst = s["dst_ip"]
                if _is_internal(src) and _is_internal(dst):
                    smb_src[src][dst].append(s["start_time"])

        for src, dsts in smb_src.items():
            if not dsts:
                continue
            all_times = [t for times in dsts.values() for t in times]
            for t in sorted(all_times):
                window_dsts = set()
                for dst, times in dsts.items():
                    if any(t <= t2 <= t + 60 for t2 in times):
                        window_dsts.add(dst)
                if len(window_dsts) > 5:
                    self._add(t, "HIGH", "SMB Lateral Movement",
                              f"{src} contacted {len(window_dsts)} internal hosts via SMB in 60s",
                              [src])
                    break

    @property
    def alerts(self):
        return self._alerts
