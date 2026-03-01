from dataclasses import dataclass


@dataclass(frozen=True)
class PolicyResult:
    allowed: bool
    reason: str
    decision_tier: str
    matched_rule: str | None
