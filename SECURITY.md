# Security Policy

Sandbox Sentinel is a defensive security tool. We take its own security seriously.

## What Sentinel is (and is not)

- ✅ **A defence-in-depth layer**: it screens an AI agent's tool calls and keeps a tamper-evident audit log.
- ❌ **Not a sandbox**: it decides whether a call *should* run; it cannot contain a call that runs anyway. Always run agents in real isolation too (containers, seccomp, restricted users, no default network egress).
- The regex rules can be evaded by a determined, obfuscating adversary. Treat a bypass of the rules as a known limitation, not a vulnerability — but a **reliable, general** bypass technique is very welcome as a report so we can add coverage.

## Reporting a vulnerability

Please **do not** open a public issue for a security problem.

- Use GitHub's **[Report a vulnerability](https://github.com/Lalithprabu/sandbox-sentinel/security/advisories/new)** (Security → Advisories) to report privately, **or**
- Contact **[LalithPrabu on GitHub](https://github.com/Lalithprabu)**.

Please include: a description, reproduction steps, the version (`python -m sentinel --version`), and the impact. We aim to acknowledge reports within a few days.

## Scope examples

In scope:
- A way to make Sentinel return **ALLOW** for an action that clearly should block (a rule bypass that generalises).
- Audit-log tampering that `verify()` fails to detect.
- Secret leakage: a case where `sentinel.redact` sends an unredacted secret to a cloud provider.

Out of scope:
- The tool not containing an action it already decided to allow (it is not a sandbox).
- False positives on legitimate commands (tune thresholds / allowlists instead).

## Safe by default

- The rules engine runs fully offline. No telemetry, no network calls at rest.
- The optional AI reviewer is **off by default**. Local Ollama sends nothing off your machine. Cloud providers receive **redacted** text only, and can only escalate to REVIEW — never block on their own.

Created by LalithPrabu.
