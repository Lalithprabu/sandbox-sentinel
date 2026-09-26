# Changelog

All notable changes to Sandbox Sentinel. Created by LalithPrabu.

## [0.2.0] — 2026-09-26

### Added
- **Plain-English prompt input.** Describe what an agent wants to do; an offline parser extracts the commands, files and URLs and checks each. Optional AI interprets vaguer wording. The AI can *add* actions but never remove what the parser found, and AI concerns escalate to REVIEW only. New `python -m sentinel prompt "..."` and `check_prompt()`.
- **Free, pluggable AI providers.** Local Ollama (default, private) plus free cloud tiers — GitHub Models, Groq, Gemini, OpenRouter — selectable in the sidebar and via `--provider`. All $0.
- **Secret redaction** (`sentinel.redact`) before any cloud request; local Ollama sends nothing off-machine.
- **Plain-English "why" + safer alternative** for every verdict (`sentinel.explain`), offline, with an optional AI note.
- **Example prompt gallery** (14 prompts) in the demo and as tests.
- New rule: `WORLD_WRITABLE` (recursive `chmod 777`).

### Changed
- Test suite grew from 58 to 104 (95% coverage).

## [0.1.0] — 2026-09-26

### Added
- Core rules engine: 20 detection rules across 13 threat categories.
- Workspace confinement + HTTP domain allowlist policy.
- Tamper-evident, hash-chained audit log with edit/deletion/truncation detection.
- `@sentinel.guard` decorator, Python API, CLI, and JSON-stdin input modes.
- Optional local-Ollama second opinion (escalate-only).
- Streamlit demo: live checker, incident replay, flight recorder, test report, how-to walkthrough video.

[0.2.0]: https://github.com/Lalithprabu/sandbox-sentinel/releases/tag/v0.2.0
[0.1.0]: https://github.com/Lalithprabu/sandbox-sentinel/releases/tag/v0.1.0
