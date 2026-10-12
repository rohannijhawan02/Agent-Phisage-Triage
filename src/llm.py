"""Thin OpenRouter chat-completion client built on `requests`.

Also provides lightweight cost/latency telemetry: `complete_with_usage`
returns per-call token usage and latency alongside the text, and
`record_usage` accumulates that into the shared TriageState (per-agent
breakdown plus running totals). Cost is estimated from configurable
per-1K-token prices in the environment (COST_PER_1K_INPUT / COST_PER_1K_OUTPUT).
"""

import os
import time

import requests
from dotenv import load_dotenv

load_dotenv()

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_MODEL = "anthropic/claude-sonnet-4.6"

# All pipeline LLM calls use greedy (temperature 0) sampling for reproducible
# scoring. NOTE: hosted LLM APIs are not guaranteed bit-for-bit deterministic
# even at temperature 0, so small run-to-run variation can remain.
DEFAULT_TEMPERATURE = 0.0


def _seed():
    """Fixed sampling seed for the request; on by default.

    Env LLM_SEED: unset -> 0 (a seed is sent by default); a valid integer ->
    that seed; "", "off", "none", or unparseable -> None (omit the seed).

    A fixed seed REDUCES run-to-run variance on providers that honour it; it is
    not a determinism guarantee — hosted APIs may still vary.
    """
    raw = os.environ.get("LLM_SEED", "0").strip()
    if raw.lower() in ("", "off", "none"):
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _provider():
    """Optional single-provider pin (OPENROUTER_PROVIDER); off by default.

    Returns the trimmed provider name, or None to use OpenRouter's default
    routing. Pinning one provider removes cross-backend load-balancing as a
    source of variance, but still does not guarantee determinism.
    """
    return os.environ.get("OPENROUTER_PROVIDER", "").strip() or None


def backend_identity():
    """Identity of request settings that can change model outputs."""
    endpoint = os.environ.get("TRIAGE_LLM_URL") or OPENROUTER_URL
    provider = _provider() if endpoint == OPENROUTER_URL else None
    seed = _seed() if endpoint == OPENROUTER_URL else None
    return f"{endpoint}|provider={provider or 'none'}|seed={seed if seed is not None else 'off'}|temperature={DEFAULT_TEMPERATURE}"


def _post_chat(system_prompt, user_content, model, temperature, timeout):
    """POST a chat completion to OpenRouter and return the parsed JSON dict."""
    api_key = os.environ.get("TRIAGE_LLM_API_KEY") or os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        raise RuntimeError("TRIAGE_LLM_API_KEY or OPENROUTER_API_KEY is not set")

    payload = {
        "model": model,
        "temperature": temperature,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ],
    }

    # Variance-reduction knobs (neither guarantees determinism on hosted APIs).
    endpoint = os.environ.get("TRIAGE_LLM_URL") or OPENROUTER_URL
    seed = _seed() if endpoint == OPENROUTER_URL else None
    if seed is not None:
        payload["seed"] = seed
    provider = _provider() if endpoint == OPENROUTER_URL else None
    if provider:
        payload["provider"] = {"order": [provider], "allow_fallbacks": False}

    response = requests.post(
        endpoint,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json=payload,
        timeout=timeout,
    )
    response.raise_for_status()
    return response.json()


def _price(name):
    """Read a per-1K-token price from the environment; default 0.0 if unset/bad."""
    try:
        return float(os.environ.get(name, "0") or "0")
    except ValueError:
        return 0.0


def _cost(prompt_tokens, completion_tokens):
    """Estimate USD cost from token counts and the configured per-1K prices."""
    return (prompt_tokens / 1000.0) * _price("COST_PER_1K_INPUT") + (
        completion_tokens / 1000.0
    ) * _price("COST_PER_1K_OUTPUT")


def complete_with_usage(
    system_prompt,
    user_content,
    model=DEFAULT_MODEL,
    *,
    temperature=DEFAULT_TEMPERATURE,
    timeout=60,
):
    """Send a completion and return (text, usage).

    `usage` is a dict with prompt_tokens, completion_tokens, total_tokens,
    latency_sec (wall-clock of the API call), and cost_usd (estimated).
    """
    start = time.perf_counter()
    data = _post_chat(system_prompt, user_content, model, temperature, timeout)
    latency = time.perf_counter() - start

    text = data["choices"][0]["message"]["content"]

    usage = data.get("usage") or {}
    prompt_tokens = int(usage.get("prompt_tokens", 0) or 0)
    completion_tokens = int(usage.get("completion_tokens", 0) or 0)
    total_tokens = int(
        usage.get("total_tokens", prompt_tokens + completion_tokens)
        or (prompt_tokens + completion_tokens)
    )

    telemetry = {
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": total_tokens,
        "latency_sec": round(latency, 3),
        "cost_usd": round(_cost(prompt_tokens, completion_tokens), 6),
        "resolved_model": data.get("model") or model,
    }
    return text, telemetry


def complete(
    system_prompt,
    user_content,
    model=DEFAULT_MODEL,
    *,
    temperature=DEFAULT_TEMPERATURE,
    timeout=60,
):
    """Backward-compatible wrapper: return only the completion text.

    Reads the API key from the OPENROUTER_API_KEY environment variable.
    """
    text, _usage = complete_with_usage(
        system_prompt, user_content, model, temperature=temperature, timeout=timeout
    )
    return text


def _empty_telemetry():
    return {
        "per_agent": {},
        "total_prompt_tokens": 0,
        "total_completion_tokens": 0,
        "total_tokens": 0,
        "total_cost_usd": 0.0,
        "total_llm_latency_sec": 0.0,
    }


def record_usage(state, agent_name, usage):
    """Accumulate one call's `usage` into state['telemetry'] under agent_name.

    Totals are recomputed from the per-agent map each call, so this is
    idempotent and robust to node re-execution. Also mirrors total_tokens and
    total_cost_usd at the top level of the state for easy downstream access.

    NOTE: accumulation relies on the triage graph being SEQUENTIAL — each node
    reads the prior node's committed telemetry and merges its own. The
    `telemetry` state channel has no merge reducer (last-write-wins), so if the
    LLM nodes were ever fanned out in parallel they would clobber each other;
    a parallel topology would need an Annotated reducer on the channel.
    """
    telemetry = state.get("telemetry") or _empty_telemetry()

    per_agent = dict(telemetry.get("per_agent", {}))
    prompt_tokens = int(usage.get("prompt_tokens", 0) or 0)
    completion_tokens = int(usage.get("completion_tokens", 0) or 0)
    per_agent[agent_name] = {
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        # Fall back to prompt+completion when total is absent, matching
        # complete_with_usage's own derivation.
        "total_tokens": int(usage.get("total_tokens", 0) or 0)
        or (prompt_tokens + completion_tokens),
        "latency_sec": float(usage.get("latency_sec", 0.0) or 0.0),
        "cost_usd": float(usage.get("cost_usd", 0.0) or 0.0),
    }

    telemetry["per_agent"] = per_agent
    telemetry["total_prompt_tokens"] = sum(a["prompt_tokens"] for a in per_agent.values())
    telemetry["total_completion_tokens"] = sum(
        a["completion_tokens"] for a in per_agent.values()
    )
    telemetry["total_tokens"] = sum(a["total_tokens"] for a in per_agent.values())
    telemetry["total_cost_usd"] = round(sum(a["cost_usd"] for a in per_agent.values()), 6)
    telemetry["total_llm_latency_sec"] = round(
        sum(a["latency_sec"] for a in per_agent.values()), 3
    )

    state["telemetry"] = telemetry
    state["total_tokens"] = telemetry["total_tokens"]
    state["total_cost_usd"] = telemetry["total_cost_usd"]
    return state
