"""Offline tests for the variance-reduction request knobs (seed / provider).

No network: `requests.post` is patched to capture the JSON payload that
`_post_chat` assembles, so we can assert what would be sent to OpenRouter.
"""

import src.llm as llm
from src.llm import _provider, _seed, complete


class _FakeResponse:
    def raise_for_status(self):
        pass

    def json(self):
        return {"choices": [{"message": {"content": "ok"}}], "usage": {}}


def _capture_post(monkeypatch):
    """Patch requests.post to record the outgoing JSON payload; return a box."""
    box = {}

    def fake_post(url, headers=None, json=None, timeout=None):
        box["url"] = url
        box["payload"] = json
        return _FakeResponse()

    monkeypatch.setattr(llm.requests, "post", fake_post)
    return box


# --- seed helper -------------------------------------------------------------

def test_seed_defaults_on(monkeypatch):
    monkeypatch.delenv("LLM_SEED", raising=False)
    assert _seed() == 0


def test_seed_honors_int(monkeypatch):
    monkeypatch.setenv("LLM_SEED", "42")
    assert _seed() == 42


def test_backend_identity_tracks_variance_settings(monkeypatch):
    monkeypatch.delenv("TRIAGE_LLM_URL", raising=False)
    monkeypatch.setenv("LLM_SEED", "42")
    monkeypatch.setenv("OPENROUTER_PROVIDER", "Anthropic")
    identity = llm.backend_identity()
    assert "provider=Anthropic" in identity
    assert "seed=42" in identity
    monkeypatch.setenv("LLM_SEED", "43")
    assert llm.backend_identity() != identity


def test_seed_disabled_values(monkeypatch):
    for val in ("off", "none", "", "  ", "false"):
        monkeypatch.setenv("LLM_SEED", val)
        assert _seed() is None, val


def test_seed_unparseable_omitted(monkeypatch):
    monkeypatch.setenv("LLM_SEED", "banana")
    assert _seed() is None


# --- provider helper ---------------------------------------------------------

def test_provider_off_by_default(monkeypatch):
    monkeypatch.delenv("OPENROUTER_PROVIDER", raising=False)
    assert _provider() is None


def test_provider_returns_trimmed_name(monkeypatch):
    monkeypatch.setenv("OPENROUTER_PROVIDER", "  Anthropic  ")
    assert _provider() == "Anthropic"


# --- payload assembly --------------------------------------------------------

def test_payload_includes_seed_by_default(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
    monkeypatch.delenv("LLM_SEED", raising=False)
    monkeypatch.delenv("OPENROUTER_PROVIDER", raising=False)
    box = _capture_post(monkeypatch)

    complete("sys", "user")

    assert box["payload"]["seed"] == 0
    assert box["payload"]["temperature"] == 0.0
    assert "provider" not in box["payload"]  # off by default


def test_payload_seed_configurable(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
    monkeypatch.setenv("LLM_SEED", "7")
    box = _capture_post(monkeypatch)

    complete("sys", "user")
    assert box["payload"]["seed"] == 7


def test_payload_seed_omitted_when_off(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
    monkeypatch.setenv("LLM_SEED", "off")
    box = _capture_post(monkeypatch)

    complete("sys", "user")
    assert "seed" not in box["payload"]


def test_payload_provider_pinning(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
    monkeypatch.setenv("OPENROUTER_PROVIDER", "Anthropic")
    box = _capture_post(monkeypatch)

    complete("sys", "user")
    assert box["payload"]["provider"] == {
        "order": ["Anthropic"],
        "allow_fallbacks": False,
    }
