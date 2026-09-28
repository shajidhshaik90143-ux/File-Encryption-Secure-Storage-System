from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path

class AuditLogger:
    def __init__(self, path="logs/audit.jsonl"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def event(self, action, status, target="", details=None):
        record = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "status": status,
            "target": str(target),
            "details": details or {},
        }
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    def read_recent(self, limit=100):
        if not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8").splitlines()
        out = []
        for line in lines[-limit:]:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return list(reversed(out))
