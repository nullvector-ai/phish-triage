import io
import json

from phish_triage import llm
from phish_triage.cli import main
from phish_triage.report import triage


def test_mock_mode_without_env(sample, monkeypatch):
    monkeypatch.delenv("PHISH_LLM_BASE_URL", raising=False)
    r = triage(sample("paypal_spoof.eml"))
    assert r["rule_verdict"] == "phishing"
    assert r["analyst"]["source"].startswith("mock")


def test_llm_path_with_fake_server(sample, monkeypatch):
    monkeypatch.setenv("PHISH_LLM_BASE_URL", "http://fake.local/v1")
    monkeypatch.setenv("PHISH_LLM_MODEL", "test-model")
    captured = {}

    class FakeResp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=0):
        captured["url"] = req.full_url
        captured["body"] = json.loads(req.data)
        content = json.dumps({"verdict": "phishing", "confidence": 0.9, "summary": "s", "recommended_action": "a"})
        return FakeResp(json.dumps({"choices": [{"message": {"content": content}}]}).encode())

    monkeypatch.setattr(llm.urllib.request, "urlopen", fake_urlopen)
    r = triage(sample("paypal_spoof.eml"))
    assert captured["url"] == "http://fake.local/v1/chat/completions"
    assert "untrusted" in captured["body"]["messages"][0]["content"]
    assert r["analyst"]["source"] == "llm:test-model"


def test_llm_failure_falls_back(sample, monkeypatch):
    monkeypatch.setenv("PHISH_LLM_BASE_URL", "http://127.0.0.1:9/v1")
    monkeypatch.setenv("PHISH_LLM_MODEL", "x")

    def boom(*a, **k):
        raise OSError("down")

    monkeypatch.setattr(llm.urllib.request, "urlopen", boom)
    r = triage(sample("colleague_benign.eml"))
    assert "LLM error" in r["analyst"]["source"]


def test_cli_exit_code(tmp_path, capsys, monkeypatch, sample):
    monkeypatch.delenv("PHISH_LLM_BASE_URL", raising=False)
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent / "samples"
    assert main([str(root / "paypal_spoof.eml")]) == 2
    assert main([str(root / "colleague_benign.eml"), "--json"]) == 0
