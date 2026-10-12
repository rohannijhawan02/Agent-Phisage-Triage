# Upstream provenance

This workspace began with files from [CBowman706/agentic-phishing-triage](https://github.com/CBowman706/agentic-phishing-triage), commit `d70bfc012501fa8331b45f895a5fa2f1fa563dbe`, at the user's request. The original sequential graph is preserved as `src/legacy_graph.py`; `src/agents/`, `src/batch.py`, the original samples, and the original regression tests remain for comparison. `src/llm.py` extends the upstream chat client with provider configuration and telemetry. `src/graph.py`, `triage.py`, `run.py`, and `run_batch.py` now implement or call the new production workflow. New MIME parsing, specialist agents, debate, calibration, and reports were added independently.

The upstream repository did not include a license file when copied. This provenance note does not claim a license or change ownership of upstream code.
