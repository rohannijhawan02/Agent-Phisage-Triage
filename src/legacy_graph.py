"""Copied upstream graph retained only as an evaluation baseline."""

from typing import TypedDict

from langgraph.graph import END, StateGraph

from src.agents.content import content_agent
from src.agents.headers import header_agent, parse_email
from src.agents.verdict import verdict_agent


class LegacyState(TypedDict, total=False):
    raw_email: str
    parsed_headers: dict
    header_analysis: dict
    content_analysis: dict
    risk_floor: int
    risk_score: float
    verdict: str
    explanation: str
    telemetry: dict
    total_tokens: int
    total_cost_usd: float


def build_graph():
    graph = StateGraph(LegacyState)
    graph.add_node("parse_email", parse_email)
    graph.add_node("header_agent", header_agent)
    graph.add_node("content_agent", content_agent)
    graph.add_node("verdict_agent", verdict_agent)
    graph.set_entry_point("parse_email")
    graph.add_edge("parse_email", "header_agent")
    graph.add_edge("header_agent", "content_agent")
    graph.add_edge("content_agent", "verdict_agent")
    graph.add_edge("verdict_agent", END)
    return graph.compile()


def run(raw_email: str) -> LegacyState:
    return build_graph().invoke({"raw_email": raw_email})
