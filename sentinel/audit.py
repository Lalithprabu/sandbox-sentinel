"""Tamper-evident, append-only audit log.

Every entry stores the SHA-256 of the previous entry, forming a hash chain.
Editing, deleting or reordering any line breaks the chain and `verify()`
reports the first broken sequence number. Publish `head_hash` somewhere the
agent cannot write (a ticket, a chat message, a remote store) to also detect
truncation of the tail.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS_HASH = "0" * 64


def _digest(entry: dict[str, Any]) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass
class VerifyResult:
    ok: bool
    entries: int
    broken_at: int | None = None
    reason: str = ""


class AuditLog:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)
        self._lock = threading.Lock()

    def entries(self) -> list[dict[str, Any]]:
        out = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                out.append(json.loads(line))
        return out

    @property
    def head_hash(self) -> str:
        entries = self.entries()
        return entries[-1]["hash"] if entries else GENESIS_HASH

    def append(self, record: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            entries = self.entries()
            entry = {
                "seq": len(entries),
                "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                "prev_hash": entries[-1]["hash"] if entries else GENESIS_HASH,
                "record": record,
            }
            entry["hash"] = _digest(entry)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
            return entry

    def verify(self, expected_head: str | None = None) -> VerifyResult:
        try:
            entries = self.entries()
        except json.JSONDecodeError as exc:
            return VerifyResult(False, 0, None, f"unparseable line: {exc}")

        prev = GENESIS_HASH
        for i, entry in enumerate(entries):
            if entry.get("seq") != i:
                return VerifyResult(False, len(entries), i, f"sequence gap: expected {i}, found {entry.get('seq')}")
            if entry.get("prev_hash") != prev:
                return VerifyResult(False, len(entries), i, "prev_hash mismatch (entry removed or reordered)")
            if _digest(entry) != entry.get("hash"):
                return VerifyResult(False, len(entries), i, "content hash mismatch (entry edited)")
            prev = entry["hash"]

        if expected_head is not None and prev != expected_head:
            return VerifyResult(False, len(entries), len(entries), "head hash differs from published anchor (tail truncated)")
        return VerifyResult(True, len(entries))

    def clear(self) -> None:
        """Reset the log. For demos/tests only - a real deployment would never expose this to agents."""
        with self._lock:
            self.path.write_text("", encoding="utf-8")
