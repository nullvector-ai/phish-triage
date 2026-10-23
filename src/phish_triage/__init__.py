"""phish-triage: explainable phishing email triage with an optional LLM layer."""
from .parse import ParsedEmail, parse_email
from .indicators import Indicator, analyse
from .report import triage

__all__ = ["ParsedEmail", "parse_email", "Indicator", "analyse", "triage"]
__version__ = "0.1.0"
