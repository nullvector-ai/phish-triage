"""Glue: parse -> indicators -> score -> (LLM or mock) summary."""
from __future__ import annotations

from . import llm
from .indicators import analyse, score
from .parse import parse_email


def triage(raw: bytes | str, use_llm: bool = True) -> dict:
    mail = parse_email(raw)
    inds = analyse(mail)
    total, verdict = score(inds)
    analyst = None
    if use_llm and llm.configured():
        try:
            analyst = llm.ask_llm(mail, inds)
        except Exception as exc:  # network/parse problems must never break triage
            analyst = llm.mock_summary(inds, verdict)
            analyst["source"] = f"mock (LLM error: {type(exc).__name__})"
    if analyst is None:
        analyst = llm.mock_summary(inds, verdict)
    return {
        "subject": mail.subject,
        "from": mail.from_addr,
        "rule_score": round(total, 2),
        "rule_verdict": verdict,
        "indicators": [i.__dict__ for i in inds],
        "analyst": analyst,
    }


def format_text(r: dict) -> str:
    lines = [f"Subject : {r['subject']}", f"From    : {r['from']}",
             f"Verdict : {r['rule_verdict'].upper()}  (rule score {r['rule_score']})", "Indicators:"]
    lines += [f"  [{i['weight']:>3}] {i['name']}: {i['detail']}" for i in r["indicators"]] or ["  (none)"]
    a = r["analyst"]
    lines += [f"Analyst ({a['source']}):", f"  {a['summary']}", f"  -> {a['recommended_action']}"]
    return "\n".join(lines)
