"""Export analysis data to CSV, JSON, HTML, and ZIP formats."""
import csv
import io
import json
import os
import zipfile
from datetime import datetime


def _ts(ts):
    if ts is None:
        return ""
    try:
        return datetime.utcfromtimestamp(float(ts)).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return str(ts)


def _set_to_list(obj):
    if isinstance(obj, set):
        return sorted(obj)
    return obj


def _sanitize(val):
    if isinstance(val, set):
        return ",".join(sorted(str(v) for v in val))
    if isinstance(val, (list, tuple)):
        return ",".join(str(v) for v in val)
    if isinstance(val, bool):
        return str(val)
    if val is None:
        return ""
    return str(val)


class ExportEngine:
    """Export analysis data to various formats."""

    def export_csv(self, data_dict: dict, output_dir: str) -> None:
        os.makedirs(output_dir, exist_ok=True)

        hosts = data_dict.get("hosts", {})
        if hosts:
            path = os.path.join(output_dir, "Hosts.csv")
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["IP", "MAC", "Hostnames", "OS", "Vendor", "Country",
                             "First Seen", "Last Seen", "Bytes Sent", "Bytes Recv"])
                for ip, h in hosts.items():
                    w.writerow([ip, h.get("mac", ""), _sanitize(h.get("hostnames", set())),
                                 h.get("os_guess", ""), h.get("vendor", ""),
                                 h.get("country", ""), _ts(h.get("first_seen")),
                                 _ts(h.get("last_seen")), h.get("bytes_sent", 0),
                                 h.get("bytes_recv", 0)])

        sessions = data_dict.get("sessions", [])
        if sessions:
            path = os.path.join(output_dir, "Sessions.csv")
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["ID", "Protocol", "App", "Src IP", "Src Port",
                             "Dst IP", "Dst Port", "Start", "Duration",
                             "Bytes Fwd", "Bytes Bwd", "State"])
                for s in sessions:
                    w.writerow([s.get("session_id", ""), s.get("protocol", ""),
                                 s.get("app_label", ""), s.get("src_ip", ""),
                                 s.get("src_port", ""), s.get("dst_ip", ""),
                                 s.get("dst_port", ""), _ts(s.get("start_time")),
                                 f"{s.get('duration', 0):.2f}",
                                 s.get("bytes_src_to_dst", 0), s.get("bytes_dst_to_src", 0),
                                 s.get("state", "")])

        credentials = data_dict.get("credentials", [])
        if credentials:
            path = os.path.join(output_dir, "Credentials.csv")
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["Protocol", "Username", "Password", "Src IP",
                             "Dst IP", "Timestamp"])
                for c in credentials:
                    w.writerow([c.get("protocol", ""), c.get("username", ""),
                                 "***MASKED***", c.get("src_ip", ""),
                                 c.get("dst_ip", ""), _ts(c.get("timestamp"))])

        files = data_dict.get("files", [])
        if files:
            path = os.path.join(output_dir, "Files.csv")
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["Filename", "Protocol", "Src IP", "Dst IP",
                             "MIME", "Size", "MD5", "SHA256", "VT Status"])
                for fi in files:
                    w.writerow([fi.get("filename", ""), fi.get("protocol", ""),
                                 fi.get("src_ip", ""), fi.get("dst_ip", ""),
                                 fi.get("mime_type", ""), fi.get("size", 0),
                                 fi.get("md5", ""), fi.get("sha256", ""),
                                 fi.get("vt_status", "")])

        dns_events = data_dict.get("dns_events", [])
        if dns_events:
            path = os.path.join(output_dir, "DNS.csv")
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["FQDN", "Type", "Response IPs", "Src IP", "Dst IP",
                             "Timestamp", "TTL", "Tags"])
                for ev in dns_events:
                    w.writerow([ev.get("fqdn", ""), ev.get("query_type", ""),
                                 ",".join(ev.get("response_ips", [])),
                                 ev.get("src_ip", ""), ev.get("dst_ip", ""),
                                 _ts(ev.get("timestamp")), ev.get("ttl", ""),
                                 ",".join(ev.get("tags", []))])

        alerts = data_dict.get("alerts", [])
        if alerts:
            path = os.path.join(output_dir, "Alerts.csv")
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["Timestamp", "Severity", "Rule", "Description", "IPs"])
                for a in alerts:
                    w.writerow([_ts(a.get("timestamp")), a.get("severity", ""),
                                 a.get("rule_name", ""), a.get("description", ""),
                                 ",".join(a.get("related_ips", []))])

    def export_json(self, data_dict: dict, output_path: str) -> None:
        def default_serializer(obj):
            if isinstance(obj, set):
                return sorted(obj)
            if isinstance(obj, bytes):
                return obj.hex()
            if isinstance(obj, bytearray):
                return bytes(obj).hex()
            return str(obj)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data_dict, f, indent=2, default=default_serializer)

    def export_html(self, data_dict: dict, output_path: str) -> None:
        hosts = data_dict.get("hosts", {})
        sessions = data_dict.get("sessions", [])
        credentials = data_dict.get("credentials", [])
        files = data_dict.get("files", [])
        dns_events = data_dict.get("dns_events", [])
        alerts = data_dict.get("alerts", [])

        sev_colors = {
            "CRITICAL": "#d63031", "HIGH": "#e17055", "MEDIUM": "#fdcb6e",
            "LOW": "#74b9ff", "INFO": "#636e72",
        }

        def html_table(headers, rows, row_color_fn=None):
            buf = ['<table><thead><tr>']
            for h in headers:
                buf.append(f'<th>{h}</th>')
            buf.append('</tr></thead><tbody>')
            for row in rows:
                color = row_color_fn(row) if row_color_fn else ""
                style = f' style="background:{color}"' if color else ""
                buf.append(f'<tr{style}>')
                for cell in row:
                    buf.append(f'<td>{cell}</td>')
                buf.append('</tr>')
            buf.append('</tbody></table>')
            return "".join(buf)

        css = """
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { background: #1a1a2e; color: #eaeaea; font-family: 'Segoe UI', monospace; }
        h1 { color: #e94560; padding: 20px; border-bottom: 2px solid #0f3460; }
        h2 { color: #0f3460; background: #16213e; padding: 10px 20px; margin: 20px 0 10px; }
        .summary { display: flex; gap: 20px; padding: 20px; flex-wrap: wrap; }
        .card { background: #16213e; border: 1px solid #2a2a4a; border-radius: 8px; padding: 15px; min-width: 150px; }
        .card .val { font-size: 2em; color: #e94560; font-weight: bold; }
        .card .label { color: #a0a0b0; font-size: 0.8em; }
        table { width: 100%; border-collapse: collapse; margin: 0 20px; width: calc(100% - 40px); }
        th { background: #0f3460; color: #eaeaea; padding: 8px 12px; text-align: left; }
        td { padding: 6px 12px; border-bottom: 1px solid #2a2a4a; font-size: 0.85em; word-break: break-all; }
        tr:hover td { background: #1f2a4a; }
        .section { margin-bottom: 30px; }
        """

        alert_rows = []
        for a in alerts[:100]:
            color = sev_colors.get(a.get("severity", ""), "")
            ts = _ts(a.get("timestamp"))
            alert_rows.append([ts, a.get("severity", ""), a.get("rule_name", ""),
                                a.get("description", ""), ",".join(a.get("related_ips", []))])

        def alert_color(row):
            return sev_colors.get(row[1], "")

        host_rows = [[ip, h.get("mac", ""), _sanitize(h.get("hostnames", set())),
                      h.get("os_guess", ""), h.get("vendor", ""), h.get("country", ""),
                      h.get("bytes_sent", 0), h.get("bytes_recv", 0)]
                     for ip, h in list(hosts.items())[:100]]

        cred_rows = [[c.get("protocol", ""), c.get("username", ""), "***MASKED***",
                      c.get("src_ip", ""), c.get("dst_ip", ""), _ts(c.get("timestamp"))]
                     for c in credentials[:100]]

        file_rows = [[f.get("filename", ""), f.get("protocol", ""), f.get("size", 0),
                      f.get("md5", ""), f.get("vt_status", "")]
                     for f in files[:100]]

        dns_rows = [[ev.get("fqdn", ""), ev.get("query_type", ""),
                     ",".join(ev.get("response_ips", [])), ev.get("src_ip", ""),
                     _ts(ev.get("timestamp")), ",".join(ev.get("tags", []))]
                    for ev in dns_events[:200]]

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>NetSentinel Report - {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</title>
<style>{css}</style>
</head>
<body>
<h1>🛡 NetSentinel Forensic Report</h1>
<p style="padding:10px 20px;color:#a0a0b0">Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>

<div class="summary">
  <div class="card"><div class="val">{len(hosts)}</div><div class="label">Hosts</div></div>
  <div class="card"><div class="val">{len(sessions)}</div><div class="label">Sessions</div></div>
  <div class="card"><div class="val">{len(alerts)}</div><div class="label">Alerts</div></div>
  <div class="card"><div class="val">{len(credentials)}</div><div class="label">Credentials</div></div>
  <div class="card"><div class="val">{len(files)}</div><div class="label">Files</div></div>
  <div class="card"><div class="val">{len(dns_events)}</div><div class="label">DNS Events</div></div>
</div>

<div class="section">
<h2>Alert Timeline</h2>
{html_table(["Timestamp","Severity","Rule","Description","IPs"], alert_rows, alert_color)}
</div>

<div class="section">
<h2>Host Inventory</h2>
{html_table(["IP","MAC","Hostnames","OS","Vendor","Country","Bytes Sent","Bytes Recv"], host_rows)}
</div>

<div class="section">
<h2>Credentials (Masked)</h2>
{html_table(["Protocol","Username","Password","Src IP","Dst IP","Timestamp"], cred_rows)}
</div>

<div class="section">
<h2>Extracted Files</h2>
{html_table(["Filename","Protocol","Size","MD5","VT Status"], file_rows)}
</div>

<div class="section">
<h2>DNS Events</h2>
{html_table(["FQDN","Type","Responses","Src IP","Timestamp","Tags"], dns_rows)}
</div>
</body>
</html>"""

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

    def export_files_zip(self, files_list: list, output_path: str) -> None:
        with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
            # Write manifest
            manifest_buf = io.StringIO()
            w = csv.writer(manifest_buf)
            w.writerow(["Filename", "MD5", "SHA256", "MIME", "Size", "Protocol"])
            for fi in files_list:
                path = fi.get("path", "")
                fname = fi.get("filename", os.path.basename(path))
                w.writerow([fname, fi.get("md5", ""), fi.get("sha256", ""),
                             fi.get("mime_type", ""), fi.get("size", 0),
                             fi.get("protocol", "")])
                if path and os.path.exists(path):
                    zf.write(path, arcname=fname)
            zf.writestr("manifest.csv", manifest_buf.getvalue())

    def export_timeline_csv(self, timeline_events: list, output_path: str) -> None:
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Timestamp", "Category", "Severity", "Src IP", "Dst IP", "Description"])
            for ev in sorted(timeline_events, key=lambda e: (e.get("timestamp") or 0)):
                w.writerow([_ts(ev.get("timestamp")), ev.get("category", ""),
                             ev.get("severity", ""), ev.get("src_ip", ""),
                             ev.get("dst_ip", ""), ev.get("description", "")])
