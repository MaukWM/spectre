"""Per-project findings store — persists agent discoveries across tasks.

Persisted at ``<project_root>/findings.json``. Atomic write per mutation
(temp + rename) so a crash mid-mutation can't half-clobber the file.
No locking — one agent run at a time, single writer.

Shape::

    {
      "version": 1,
      "findings": [
        {
          "id": "f001",
          "kind": "address",
          "address": "8030fa4c",
          "label": "player_x_pos",
          "detail": "Big-endian f32. Updates every frame.",
          "source_task": "",
          "created_at": 1715000000.0,
          "updated_at": 1715000000.0
        }
      ]
    }
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

FINDINGS_VERSION = 1


@dataclass
class Finding:
    """A single discovery about the game."""

    id: str
    kind: str  # "address" | "function" | "note"
    address: str  # lowercase hex, no 0x prefix; "" for notes
    label: str
    detail: str
    source_task: str = ""
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)


@dataclass
class FindingsStore:
    """In-memory view of ``findings.json``, persisted on each mutation."""

    path: Path
    findings: list[Finding] = field(default_factory=list)

    @classmethod
    def load(cls, project_dir: Path) -> FindingsStore:
        path = project_dir / "findings.json"
        if not path.exists():
            return cls(path=path)
        raw = json.loads(path.read_text() or "{}")
        findings = [
            Finding(**{k: v for k, v in f.items() if k in Finding.__dataclass_fields__})
            for f in raw.get("findings", [])
        ]
        return cls(path=path, findings=findings)

    def _flush(self) -> None:
        payload = json.dumps(
            {
                "version": FINDINGS_VERSION,
                "findings": [asdict(f) for f in self.findings],
            },
            indent=2,
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = tempfile.NamedTemporaryFile(
            "w",
            dir=str(self.path.parent),
            delete=False,
            prefix=".findings-",
            suffix=".tmp",
        )
        try:
            tmp.write(payload)
            tmp.flush()
            os.fsync(tmp.fileno())
        finally:
            tmp.close()
        os.replace(tmp.name, self.path)

    def _next_id(self) -> str:
        if not self.findings:
            return "f001"
        max_num = max(int(f.id[1:]) for f in self.findings if f.id.startswith("f"))
        return f"f{max_num + 1:03d}"

    def add(
        self,
        kind: str,
        label: str,
        detail: str,
        address: str = "",
        source_task: str = "",
    ) -> Finding:
        """Add or update a finding. Upserts by address for address/function kinds."""
        addr = address.lower().removeprefix("0x")
        now = time.time()

        # Upsert by address for address/function kinds
        if kind in ("address", "function") and addr:
            for f in self.findings:
                if f.kind == kind and f.address == addr:
                    f.label = label
                    f.detail = detail
                    f.source_task = source_task
                    f.updated_at = now
                    self._flush()
                    return f

        finding = Finding(
            id=self._next_id(),
            kind=kind,
            address=addr,
            label=label,
            detail=detail,
            source_task=source_task,
            created_at=now,
            updated_at=now,
        )
        self.findings.append(finding)
        self._flush()
        return finding

    def list_all(self) -> list[Finding]:
        """Return findings sorted: address/function first (by address), then notes."""
        addressed = sorted(
            (f for f in self.findings if f.address),
            key=lambda f: f.address,
        )
        notes = [f for f in self.findings if not f.address]
        return addressed + notes

    def get_by_address(self, addr_hex: str) -> Finding | None:
        addr = addr_hex.lower().removeprefix("0x")
        for f in self.findings:
            if f.address == addr:
                return f
        return None

    def remove(self, finding_id: str) -> bool:
        """Remove a finding by ID. Returns True if found and removed."""
        for i, f in enumerate(self.findings):
            if f.id == finding_id:
                self.findings.pop(i)
                self._flush()
                return True
        return False

    def format_table(self, exclude_kinds: set[str] | None = None) -> str:
        """Format findings as a human-readable table for the agent.

        Args:
            exclude_kinds: Kinds to skip (e.g. {"function"} to omit
                function findings that are already visible via Ghidra renames).
        """
        findings = self.list_all()
        if exclude_kinds:
            findings = [f for f in findings if f.kind not in exclude_kinds]
        if not findings:
            return "No findings saved yet."
        lines = [f"{'ID':<6} {'Kind':<10} {'Address':<12} {'Label':<24} Detail"]
        lines.append("-" * 80)
        for f in findings:
            addr = f"0x{f.address}" if f.address else ""
            detail = f.detail[:40] + "..." if len(f.detail) > 40 else f.detail
            lines.append(f"{f.id:<6} {f.kind:<10} {addr:<12} {f.label:<24} {detail}")
        return "\n".join(lines)
