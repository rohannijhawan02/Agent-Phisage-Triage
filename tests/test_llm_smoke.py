"""Live smoke test for the OpenRouter client.

Gated behind RUN_LIVE_AI=1 so it is skipped unless live AI testing is
explicitly enabled (it makes a real network call and costs tokens).
"""

import os

import pytest

from src.llm import complete


@pytest.mark.skipif(
    os.environ.get("RUN_LIVE_AI") != "1",
    reason="set RUN_LIVE_AI=1 to run live AI tests",
)
def test_complete_smoke():
    reply = complete(
        system_prompt="You are a terse assistant. Reply with a single word.",
        user_content="Say 'pong' and nothing else.",
    )
    assert isinstance(reply, str)
    assert reply.strip() != ""
