"""Plain-English explanations and safer alternatives for a verdict. Created by LalithPrabu.

Works offline from built-in guidance; an optional (free) AI model can write a
tailored explanation instead.
"""

from __future__ import annotations

from dataclasses import dataclass

from .engine import ALLOW, Action, Verdict
from .llm import parse_json_loose
from .redact import redact

SAFER: dict[str, str] = {
    "REMOTE_EXEC": "Download the script to a file first, read it, verify its checksum or signature, then run it deliberately.",
    "DESTRUCTIVE": "Delete only the specific project folder you mean (for example `./build`), never `/`, `~` or `*`.",
    "RECURSIVE_DELETE": "Double-check the path is inside the project, or move the folder to a trash location first.",
    "LOG_TAMPER": "Agents should never delete logs or history. Let a human-managed retention policy (e.g. logrotate) handle cleanup.",
    "LOG_FILE_TAMPER": "Leave audit and log files alone. Retention should be handled by humans, outside the agent.",
    "REVERSE_SHELL": "There is no safe variant: an