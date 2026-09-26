"""Detection rules for agent actions.

Each rule is a case-insensitive regex applied to the text of an action
(target + payload) for the action kinds it lists. Rules are deliberately
transparent so operators can audit and extend them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

SHELL = "shell"
FILE_WRITE = "file_write"
FILE_DELETE = "file_delete"
HTTP = "http"
CONTENT = "content"

ACTION_KINDS = (SHELL, FILE_WRITE, FILE_DELETE, HTTP, CONTENT)

SEVERITY_WEIGHT = {"low": 10, "medium": 25, "high": 50, "critical": 100}


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    severity: str
    pattern: str
    kinds: frozenset[str]
    description: str
    _regex: re.Pattern = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_regex", re.compile(self.pattern, re.IGNORECASE | re.DOTALL))

    def search(self, text: str) -> re.Match | None:
        return self._regex.search(text)


def _k(*kinds: str) -> frozenset[str]:
    return frozenset(kinds)


RULES: tuple[Rule, ...] = (
    # --- Sandbox escape & privilege -------------------------------------------------
    Rule(
        "SANDBOX_ESCAPE", "sandbox_escape", "critical",
        r"\bnsenter\b|\bchroot\b|--privileged|/var/run/docker\.sock|\bunshare\s+-|mount\s+(-t\s+\S+\s+)?/proc|/proc/1/root|release_agent",
        _k(SHELL, FILE_WRITE),
        "Attempts to break out of a container or sandbox boundary.",
    ),
    Rule(
        "PRIV_ESC", "privilege_escalation", "high",
        r"\bsudo\b|\bsu\s+-|\bchmod\s+(u?\+s|[0-7]?4[0-7]{3})\b|\bsetuid\b|\brunas\s+/user",
        _k(SHELL),
        "Requests elevated privileges.",
    ),
    # --- Destruction ---------------------------------------------------------------
    Rule(
        "DESTRUCTIVE", "destructive", "critical",
        r"\brm\s+-[a-z]*r[a-z]*\s+(/|~|\*|\$HOME)(\s|$)|\bmkfs(\.\w+)?\b|\bdd\s+if=\S+\s+of=/dev/|:\(\)\s*\{\s*:\|:&\s*\};:|\bformat\s+[a-z]:",
        _k(SHELL),
        "Mass deletion, disk wipe or fork bomb.",
    ),
    Rule(
        "RECURSIVE_DELETE", "destructive", "medium",
        r"\brm\s+-[a-z]*r|Remove-Item\b.*-Recurse|\brmdir\s+/s",
        _k(SHELL),
        "Recursive delete; needs a human glance.",
    ),
    # --- Covering tracks (the Hugging Face incident pattern) ------------------------
    Rule(
        "LOG_TAMPER", "log_tampering", "critical",
        r"(\brm\b|\bshred\b|\btruncate\b|\bdel\b|Remove-Item|>\s*)[^\n;|&]*(\.log\b|/var/log|audit|\.bash_history|\.zsh_history)"
        r"|\bhistory\s+-c\b|unset\s+HISTFILE|HISTFILE=/dev/null|\bwevtutil\s+cl\b|Clear-EventLog|\bauditctl\s+-D\b|journalctl\s+--vacuum",
        _k(SHELL),
        "Deletes or rewrites logs/history - an agent covering its tracks.",
    ),
    Rule(
        "LOG_FILE_TAMPER", "log_tampering", "critical",
        r"(\.log|/var/log/|audit[^/\\]*\.(jsonl|log|db)|\.bash_history|\.zsh_history)$",
        _k(FILE_WRITE, FILE_DELETE),
        "Direct modification or deletion of a log / audit file.",
    ),
    # --- Remote code & shells -------------------------------------------------------
    Rule(
        "REMOTE_EXEC", "remote_code_execution", "critical",
        r"\b(curl|wget|iwr|Invoke-WebRequest)\b[^|\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b|\biex\s*\(|Invoke-Expression|base64\s+(-d|--decode)[^|\n]*\|\s*(ba)?sh|python[23]?\s+-c\s+[\"'].*(exec|eval)\(",
        _k(SHELL),
        "Downloads and executes code in one step.",
    ),
    Rule(
        "REVERSE_SHELL", "reverse_shell", "critical",
        r"/dev/tcp/|\bnc\b[^\n]*\s-e\s|\bncat\b[^\n]*--exec|\bsocat\b[^\n]*exec|bash\s+-i\s*>&",
        _k(SHELL),
        "Opens an interactive shell to a remote host.",
    ),
    # --- Secrets --------------------------------------------------------------------
    Rule(
        "CREDENTIAL_ACCESS", "credential_access", "high",
        r"\.ssh/id_\w+|\.aws/credentials|/etc/shadow|\.netrc\b|\.git-credentials|\.docker/config\.json|(^|[\s/\\])\.env(\s|$)|\bkeychain\b|\bprintenv\b",
        _k(SHELL, FILE_WRITE, FILE_DELETE, HTTP),
        "Reads or touches credential stores.",
    ),
    Rule(
        "SECRET_IN_PAYLOAD", "secret_exfiltration", "critical",
        r"\bAKIA[0-9A-Z]{16}\b|\bsk-(ant-|proj-)?[A-Za-z0-9_\-]{20,}|\bghp_[A-Za-z0-9]{36}\b|\bxox[bpa]-[A-Za-z0-9\-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----",
        _k(SHELL, HTTP),
        "A live-looking secret is about to leave the sandbox.",
    ),
    Rule(
        "EXFIL_ENDPOINT", "exfiltration", "high",
        r"pastebin\.com|webhook\.site|requestbin|ngrok(-free)?\.(io|app)|transfer\.sh|file\.io|interact\.sh|burpcollaborator|discord(app)?\.com/api/webhooks",
        _k(SHELL, HTTP, CONTENT),
        "Known drop-box / tunnel endpoint commonly used to exfiltrate data.",
    ),
    # --- Persistence & recon --------------------------------------------------------
    Rule(
        "PERSISTENCE", "persistence", "high",
        r"\bcrontab\b|systemctl\s+enable|\bschtasks\b|\.bashrc\b|\.bash_profile\b|\.profile\b|authorized_keys|CurrentVersion\\Run|launchctl\s+load",
        _k(SHELL, FILE_WRITE),
        "Installs something that survives restarts.",
    ),
    Rule(
        "SYSTEM_PATH_WRITE", "system_modification", "critical",
        r"^(/etc/|/usr/(s?bin|lib)/|/boot/|/bin/|/sbin/|[a-z]:\\windows\\|[a-z]:\\program files)",
        _k(FILE_WRITE, FILE_DELETE),
        "Writes into operating-system directories.",
    ),
    Rule(
        "NETWORK_ATTACK_TOOL", "offensive_tooling", "critical",
        r"\bnmap\b|\bmasscan\b|\bhydra\b|\bsqlmap\b|\bmetasploit\b|\bmsfconsole\b|\bgobuster\b|\bnikto\b",
        _k(SHELL),
        "Offensive scanning / exploitation tool.",
    ),
    Rule(
        "PATH_TRAVERSAL", "sandbox_escape", "medium",
        r"(\.\.[/\\]){2,}",
        _k(FILE_WRITE, FILE_DELETE, HTTP),
        "Climbs out of the working directory.",
    ),
    Rule(
        "RAW_IP_TARGET", "exfiltration", "medium",
        r"https?://\d{1,3}(\.\d{1,3}){3}",
        _k(SHELL, HTTP),
        "Talks to a bare IP address instead of a named host.",
    ),
    # --- Prompt injection in fetched content ---------------------------------------
    Rule(
        "PROMPT_INJECTION", "prompt_injection", "high",
        r"ignore\s+(all\s+)?(the\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules)"
        r"|disregard\s+(all\s+)?(your|the|previous)\s+[\w\s]{0,20}(instructions|rules|guidelines)"
        r"|you\s+are\s+now\s+(a|an|in)\b|new\s+instructions\s*:|reveal\s+(your\s+)?(system\s+prompt|instructions)"
        r"|do\s+not\s+(tell|inform|alert)\s+the\s+user|override\s+(your\s+)?safety",
        _k(CONTENT, HTTP),
        "Text trying to take over the agent's instructions.",
    ),
    Rule(
        "TOOL_COERCION", "prompt_injection", "medium",
        r"(run|execute|paste)\s+(the\s+following|this)\s+(command|code|script)|as\s+an\s+ai\s+(agent|assistant)\s*,?\s+you\s+(must|should)",
        _k(CONTENT),
        "Content instructing the agent to run code.",
    ),
    Rule(
        "HIDDEN_TEXT", "prompt_injection", "medium",
        "[​‌‍⁠﻿‮]|<!--[^>]*(instruction|assistant|agent|ignore)[^>]*-->|color\\s*:\\s*(white|#fff(fff)?)\\b[^>]*>",
        _k(CONTENT),
        "Invisible characters or hidden markup - a classic injection carrier.",
    ),
    Rule(
        "AGENT_BACKCHANNEL", "covert_coordination", "medium",
        r"(message\s+board|side\s+channel|backchannel)\s+for\s+agents|coordinate\s+with\s+(the\s+)?other\s+agents|share\s+(the\s+)?(solution|answers?)\s+with\s+(other\s+)?agents",
        _k(CONTENT, HTTP, SHELL),
        "Agents setting up unsanctioned coordination channels.",
    ),
)
