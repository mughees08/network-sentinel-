"""Small data models used by Network Sentinel."""
from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class Alert:
    severity: str
    rule_id: str
    title: str
    evidence: str
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
