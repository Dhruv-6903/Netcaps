"""Threat intelligence: VirusTotal and AbuseIPDB integration."""
import asyncio
import hashlib
import ipaddress
import os
import socket
import time
from collections import deque


class ThreatIntel:
    """Manage VT and AbuseIPDB threat lookups with rate limiting."""

    def __init__(self):
        self._hash_queue = deque()
        self._ip_queue = deque()
        self._hash_results = {}   # hash -> result dict
        self._ip_results = {}     # ip -> result dict
        self._hash_blocklist = set()
        self._ip_blocklist = []   # list of network objects

    def queue_file_hash(self, file_dict: dict) -> None:
        h = file_dict.get("sha256") or file_dict.get("md5") or ""
        if h and h not in self._hash_results:
            self._hash_queue.append(file_dict)

    def queue_ip(self, ip: str) -> None:
        if ip and ip not in self._ip_results:
            self._ip_queue.append(ip)

    def process_queue_vt(self, api_key: str) -> None:
        """Process VT hash queue with rate limiting (4/min)."""
        if not api_key:
            return
        try:
            asyncio.run(self._process_vt_async(api_key))
        except Exception:
            pass

    async def _process_vt_async(self, api_key: str) -> None:
        try:
            import httpx
        except ImportError:
            return

        headers = {"x-apikey": api_key}
        delay = 15.0  # 4 per minute

        async with httpx.AsyncClient(timeout=30) as client:
            while self._hash_queue:
                file_dict = self._hash_queue.popleft()
                h = file_dict.get("sha256") or file_dict.get("md5") or ""
                if not h:
                    continue
                try:
                    url = f"https://www.virustotal.com/api/v3/files/{h}"
                    resp = await client.get(url, headers=headers)
                    if resp.status_code == 200:
                        data = resp.json()
                        attrs = data.get("data", {}).get("attributes", {})
                        stats = attrs.get("last_analysis_stats", {})
                        positives = stats.get("malicious", 0)
                        total = sum(stats.values())
                        result = {
                            "hash": h,
                            "result": "malicious" if positives > 0 else "clean",
                            "score": positives,
                            "positives": positives,
                            "total": total,
                            "permalink": f"https://www.virustotal.com/gui/file/{h}",
                        }
                    elif resp.status_code == 404:
                        result = {"hash": h, "result": "not_found", "score": 0, "positives": 0, "total": 0, "permalink": ""}
                    else:
                        result = {"hash": h, "result": "error", "score": 0, "positives": 0, "total": 0, "permalink": ""}
                    self._hash_results[h] = result
                    file_dict["vt_status"] = result["result"]
                except Exception:
                    pass
                await asyncio.sleep(delay)

    def process_queue_abuseipdb(self, api_key: str) -> None:
        """Process AbuseIPDB IP queue."""
        if not api_key:
            return
        try:
            asyncio.run(self._process_abuseipdb_async(api_key))
        except Exception:
            pass

    async def _process_abuseipdb_async(self, api_key: str) -> None:
        try:
            import httpx
        except ImportError:
            return

        headers = {"Key": api_key, "Accept": "application/json"}

        async with httpx.AsyncClient(timeout=30) as client:
            while self._ip_queue:
                ip = self._ip_queue.popleft()
                try:
                    url = "https://api.abuseipdb.com/api/v2/check"
                    params = {"ipAddress": ip, "maxAgeInDays": 90}
                    resp = await client.get(url, headers=headers, params=params)
                    if resp.status_code == 200:
                        data = resp.json().get("data", {})
                        score = data.get("abuseConfidenceScore", 0)
                        result = {
                            "ip": ip,
                            "result": "malicious" if score > 50 else "clean",
                            "score": score,
                            "positives": score,
                            "total": 100,
                            "permalink": f"https://www.abuseipdb.com/check/{ip}",
                        }
                        self._ip_results[ip] = result
                except Exception:
                    pass
                await asyncio.sleep(1)

    def load_hash_blocklist(self, path: str) -> None:
        """Load hash blocklist from file (one hash per line)."""
        self._hash_blocklist.clear()
        if not path or not os.path.exists(path):
            return
        try:
            with open(path, "r") as f:
                for line in f:
                    h = line.strip().lower()
                    if h:
                        self._hash_blocklist.add(h)
        except Exception:
            pass

    def check_hash_blocklist(self, hash_val: str) -> bool:
        return hash_val.lower() in self._hash_blocklist

    def load_ip_blocklist(self, path: str) -> None:
        """Load IP/CIDR blocklist from file."""
        self._ip_blocklist.clear()
        if not path or not os.path.exists(path):
            return
        try:
            with open(path, "r") as f:
                for line in f:
                    entry = line.strip()
                    if not entry or entry.startswith("#"):
                        continue
                    try:
                        net = ipaddress.ip_network(entry, strict=False)
                        self._ip_blocklist.append(net)
                    except ValueError:
                        try:
                            net = ipaddress.ip_address(entry)
                            self._ip_blocklist.append(ipaddress.ip_network(str(net)))
                        except ValueError:
                            pass
        except Exception:
            pass

    def check_ip_blocklist(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in self._ip_blocklist)
        except ValueError:
            return False

    @property
    def hash_results(self):
        return self._hash_results

    @property
    def ip_results(self):
        return self._ip_results
