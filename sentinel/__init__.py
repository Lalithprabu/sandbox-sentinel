"""Sandbox Sentinel - a zero-cost firewall and tamper-evident flight recorder for AI agents.

Created by LalithPrabu.
"""

from .advice import Advice, explain
from .audit import AuditLog, VerifyResult
from .engine import (
    ALLOW,
    BLOCK,
    REVIEW,
    Action,
    ActionBlocked,
    Finding,
    Policy,
    ReviewRequired,
    Sentinel,
    Verdict,
)
from .llm import (
    CLOUD_PRESETS,
    LLMOpinion,
    LLMReviewer,
    OllamaProvider,
    OllamaReviewer,
    OpenAICompatProvider,
    make_provider,
)
from .nl import Interpretation, PromptInterpreter, PromptResult, check_prompt, offline_actions
from .redact import redact

__all__ = [
    "ALLOW", "BLOCK", "REVIEW", "Action", "ActionBlocked", "Advice", "AuditLog", "CLOUD_PRESETS", "Finding",
    "Interpretation", "LLMOpinion", "LLMReviewer", "OllamaProvider", "OllamaReviewer", "OpenAICompatProvider",
    "Policy", "PromptInterpreter", "PromptResult", "ReviewRequired", "Sentinel", "Verdict", "VerifyResult",
    "check_prompt", "explain", "make_provider", "offline_actions", "redact",
]
__version__ = "0.2.0"
__author__ = "LalithPrabu"
