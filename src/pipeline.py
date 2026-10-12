"""Analyst entry point for the production LangGraph investigation."""

from __future__ import annotations

from pathlib import Path

from src.graph import run


def analyze(path: str | Path, *, artifact: dict | None = None, model: str | None = None,
            auth_attestations: dict | None = None, protected_domains: set[str] | None = None,
            intel_file: str | Path | None = None,
            memory_file: str | Path | None = None,
            as_of: str | None = None) -> dict:
    return run(path, artifact=artifact, model=model, auth_attestations=auth_attestations,
               protected_domains=protected_domains, intel_file=intel_file,
               memory_file=memory_file, as_of=as_of)
