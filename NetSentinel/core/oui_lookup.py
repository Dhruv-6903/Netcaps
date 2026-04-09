"""OUI vendor lookup from manuf file."""
import os


class OuiLookup:
    """Lookup MAC vendor from manuf file."""

    def __init__(self, manuf_path: str = "assets/manuf"):
        self._table = {}
        self._load(manuf_path)

    def _load(self, path: str) -> None:
        if not os.path.exists(path):
            # Try manuf library fallback
            try:
                import manuf as _manuf_lib
                self._manuf_lib = _manuf_lib.MacParser()
            except Exception:
                self._manuf_lib = None
            return

        self._manuf_lib = None
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split("\t")
                    if len(parts) < 2:
                        parts = line.split()
                    if len(parts) < 2:
                        continue
                    prefix = parts[0].upper().replace("-", ":").strip()
                    vendor = parts[-1].strip()
                    if len(prefix) == 8:  # AA:BB:CC
                        self._table[prefix] = vendor
        except Exception:
            pass

    def lookup(self, mac: str) -> str:
        if not mac:
            return "Unknown"
        # Try manuf library if available
        if not self._table and hasattr(self, "_manuf_lib") and self._manuf_lib:
            try:
                result = self._manuf_lib.get_manuf(mac)
                return result if result else "Unknown"
            except Exception:
                return "Unknown"

        prefix = mac.upper()[:8]
        return self._table.get(prefix, "Unknown")
