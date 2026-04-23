import logging
from pathlib import Path

from agents.triage_agent import TriageAgent
from schemas import TriageInput, Vulnerability


def _make_vulnerability() -> Vulnerability:
    return Vulnerability(
        id="custom_obscure_rule",
        title="Custom Obscure Rule",
        severity="medium",
        host="127.0.0.1",
        description="A synthetic finding used to test LLM fallback behavior.",
        recommendation="Return a classification decision.",
    )


def test_malformed_primary_model_logs_and_fallback_model_succeeds(monkeypatch, caplog):
    transcript_dir = Path("pipeline_work/test_transcripts/test_triage_agent_fallback")
    transcript_dir.mkdir(parents=True, exist_ok=True)

    agent = TriageAgent(
        mode="smart",
        lenient=True,
        max_complexity="high",
        transcript_dir=str(transcript_dir),
        model_override="bad-model",
        fallback_models=["good-model"],
        api_key="test-key",
        base_url="https://example.invalid/api",
    )
    calls = []

    def fake_classify(prompt: str):
        model_name = agent._client.model
        calls.append(model_name)
        if model_name == "bad-model":
            return "this is not valid json", {"content": "this is not valid json"}, {}, 0.01
        return (
            (
                '{"finding_id":"custom_obscure_rule","rule_id":"Custom Obscure Rule",'
                '"category":"safe_to_remediate","confidence":0.93,'
                '"rationale":"Fallback model returned valid structured output.",'
                '"risk_factors":[],"safe_next_steps":["Proceed with normal remediation flow."],'
                '"requires_reboot":false,"touches_authn_authz":false,'
                '"touches_networking":false,"touches_filesystems":false,'
                '"estimated_complexity":"low"}'
            ),
            {"content": "valid json"},
            {},
            0.01,
        )

    monkeypatch.setattr(agent._client, "classify", fake_classify)

    with caplog.at_level(logging.WARNING):
        result = agent.process(TriageInput(vulnerability=_make_vulnerability()))

    assert calls == ["bad-model", "good-model"]
    assert result.should_remediate is True
    assert result.requires_human_review is False
    assert "Validation/JSON error with bad-model" in caplog.text
