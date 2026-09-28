"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, float] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        req_key = request_id or user_id
        self._open[req_key] = datetime.now(timezone.utc).timestamp()
        self.logs.append({
            "event_type": "input",
            "request_id": req_key,
            "user_id": user_id,
            "text": text,
            "timestamp": utc_now_iso(),
        })

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        req_key = request_id or user_id
        start_time = self._open.pop(req_key, None)
        end_time = datetime.now(timezone.utc).timestamp()
        latency = end_time - start_time if start_time else 0.0

        self.logs.append({
            "event_type": "output",
            "request_id": req_key,
            "user_id": user_id,
            "text": text,
            "blocked": blocked,
            "layer": layer,
            "latency_ms": round(latency * 1000, 2),
            "timestamp": utc_now_iso(),
        })

    def export_json(self, filepath: str | None = None):
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(self.logs, f, indent=2)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
