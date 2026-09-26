"""Core policy engine: turns a proposed agent action into an allow/review/block verdict."""

from __future__ import annotations

import functools
import inspect
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from .audit import AuditLog
from .llm import OllamaReviewer
from .rules import ACTION_KINDS, FILE_DELETE, FILE_WRITE, HTTP, RULES, SEVERITY_WEIGHT, Rule

ALLOW, REVIEW, BLOCK = "allow", "review", "block"


@dataclass
class Action:
    kind: str
    target: str
    payload: str = ""
    agent_id: str = "agent"

    def __post_init__(self) -> None:
        if self.kind not in ACTION_KINDS:
            raise ValueError(f"unknown action kind {self.kind!r}; expected one of {ACTION_KINDS}")


@dataclass
class Finding:
    rule_id: str
    category: str
    severity: str
    description: str
    evidence: str


@dataclass
class Verdict:
    decision: str
    score: int
    findings: list[Finding] = field(default_factory=list)
    llm_risk: int | None = None
    llm_reason: str = ""
    audit_seq: int | None = None

    @property
    def allowed(self) -> bool:
        return self.decision == ALLOW

    def summary(self) -> str:
        if not self.findings and self.llm_risk is None:
            return f"{self.decision.upper()} (score {self.score}) - no risks detected"
        ids = ", ".join(f.rule_id for f in self.findings) or "LLM_REVIEW"
        return f"{self.decision.upper()} (score {self.score}) - {ids}"


@dataclass
class Policy:
    workspace: str = "."
    allowed_domains: tuple[str, ...] = ()
    review_threshold: int = 25
    block_threshold: int = 70
    llm_escalation_threshold: int = 70


class ActionBlocked(PermissionError):
    def __init__(self, verdict: Verdict) -> None:
        super().__init__(verdict.summary())
        self.verdict = verdict


class ReviewRequired(PermissionError):
    def __init__(self, verdict: Verdict) -> None:
        super().__init__(verdict.summary())
        self.verdict = verdict


class Sentinel:
    def __init__(
        self,
        policy: Policy | None = None,
        audit_log: AuditLog | str | Path | None = None,
        reviewer: OllamaReviewer | None = None,
        rules: tuple[Rule, ...] = RULES,
    ) -> None:
        self.policy = policy or Policy()
        if isinstance(audit_log, (str, Path)):
            audit_log = AuditLog(audit_log)
        self.audit = audit_log
        self.reviewer = reviewer
        self.rules = rules

    # -- evaluation -------------------------------------------------------------------

    def evaluate(self, action: Action) -> Verdict:
        findings = self._rule_findings(action) + self._policy_findings(action)
        score = min(100, sum(SEVERITY_WEIGHT[f.severity] for f in findings))
        has_critical = any(f.severity == "critical" for f in findings)

        if has_critical or score >= self.policy.block_threshold:
            decision = BLOCK
        elif score >= self.policy.review_threshold:
            decision = REVIEW
        else:
            decision = ALLOW

        verdict = Verdict(decision=decision, score=score, findings=findings)

        # The local LLM only gets a say on actions the rules would let through.
        if self.reviewer is not None and decision == ALLOW:
            opinion = self.reviewer.review(action.kind, action.target, action.payload)
            if opinion is not None:
                verdict.llm_risk, verdict.llm_reason = opinion.risk, opinion.reason
                if opinion.risk >= self.policy.llm_escalation_threshold:
                    verdict.decision = REVIEW

        if self.audit is not None:
            entry = self.audit.append({"action": asdict(action), "verdict": _verdict_record(verdict)})
            verdict.audit_seq = entry["seq"]
        return verdict

    def check(self, kind: str, target: str, payload: str = "", agent_id: str = "agent") -> Verdict:
        return self.evaluate(Action(kind=kind, target=target, payload=payload, agent_id=agent_id))

    def _rule_findings(self, action: Action) -> list[Finding]:
        text = f"{action.target}\n{action.payload}" if action.payload else action.target
        out = []
        for rule in self.rules:
            if action.kind not in rule.kinds:
                continue
            # Path-anchored file rules must look at the normalised target only.
            anchored = rule.pattern.startswith("^") or rule.pattern.endswith("$")
            haystack = _norm_path(action.target) if anchored and action.kind in (FILE_WRITE, FILE_DELETE) else text
            match = rule.search(haystack)
            if match:
                out.append(Finding(rule.id, rule.category, rule.severity, rule.description, _snippet(haystack, match)))
        return out

    def _policy_findings(self, action: Action) -> list[Finding]:
        out = []
        if action.kind in (FILE_WRITE, FILE_DELETE) and not _inside(action.target, self.policy.workspace):
            out.append(Finding(
                "OUTSIDE_WORKSPACE", "sandbox_escape", "high",
                "File operation outside the agent's workspace.", action.target[:120],
            ))
        if action.kind == HTTP and self.policy.allowed_domains:
            host = (urlparse(action.target if "://" in action.target else f"https://{action.target}").hostname or "").lower()
            if not any(host == d or host.endswith("." + d) for d in self.policy.allowed_domains):
                out.append(Finding(
                    "UNLISTED_DOMAIN", "exfiltration", "medium",
                    "Host is not on the network allowlist.", host or action.target[:120],
                ))
        return out

    # -- integration ------------------------------------------------------------------

    def guard(self, kind: str, target_arg: str | int = 0, payload_arg: str | int | None = None,
              allow_review: bool = False) -> Callable:
        """Decorate an agent tool so every call is vetted before it runs.

        >>> @sentinel.guard("shell")
        ... def run_shell(cmd: str) -> str: ...
        """

        def decorator(fn: Callable) -> Callable:
            sig = inspect.signature(fn)

            def pick(bound: inspect.BoundArguments, ref: str | int | None) -> str:
                if ref is None:
                    return ""
                if isinstance(ref, int):
                    return str(list(bound.arguments.values())[ref])
                return str(bound.arguments.get(ref, ""))

            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()
                verdict = self.check(kind, pick(bound, target_arg), pick(bound, payload_arg))
                if verdict.decision == BLOCK:
                    raise ActionBlocked(verdict)
                if verdict.decision == REVIEW and not allow_review:
                    raise ReviewRequired(verdict)
                return fn(*args, **kwargs)

            wrapper.sentinel = self  # type: ignore[attr-defined]
            return wrapper

        return decorator


def _verdict_record(v: Verdict) -> dict[str, Any]:
    return {
        "decision": v.decision,
        "score": v.score,
        "rules": [f.rule_id for f in v.findings],
        "llm_risk": v.llm_risk,
    }


def _snippet(text: str, match: Any, pad: int = 30) -> str:
    start, end = max(0, match.start() - pad), min(len(text), match.end() + pad)
    s = text[start:end].replace("\n", " ")
    return ("..." if start else "") + s + ("..." if end < len(text) else "")


def _norm_path(p: str) -> str:
    return p.strip().strip("\"'").replace("\\\\", "\\")


def _inside(target: str, workspace: str) -> bool:
    target = _norm_path(target)
    ws = os.path.abspath(workspace)
    # A POSIX-absolute path on Windows (e.g. /etc/passwd) is never inside the workspace.
    if os.name == "nt" and target.startswith("/"):
        return False
    full = os.path.abspath(os.path.join(ws, os.path.expanduser(target)))
    try:
        return os.path.commonpath([ws, full]) == ws
    except ValueError:  # different drives on Windows
        return False
