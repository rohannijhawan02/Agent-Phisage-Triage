"""Verdict node: synthesize header + content analysis into a final call.

Structural anti-injection note: the model's score and label are never trusted
unconditionally. A deterministic, model-independent risk floor (computed in
Python from parsed headers) is enforced over the model output, so a prompt
injection that coerces the model into "risk_score 0 / benign" still cannot
suppress a spoofed, auth-failing email below that floor.
"""

import json
import logging
import re

from src.agents.headers import deterministic_risk_floor
from src.llm import complete_with_usage, record_usage

logger = logging.getLogger(__name__)

VALID_VERDICTS = {"benign", "spam", "suspicious", "malicious"}

# Ordered weakest -> strongest so we can compare label severity. "spam" sits
# above "benign" but below "suspicious": it is unwanted, not dangerous.
VERDICT_ORDER = ["benign", "spam", "suspicious", "malicious"]

# A deterministic floor at or above this forces the label up to at least
# "suspicious" — i.e. off any below-suspicious label ("benign" or "spam").
FLOOR_OVERRIDE_THRESHOLD = 70


def _below_suspicious(verdict):
    """True if `verdict` ranks below "suspicious" (i.e. "benign" or "spam").

    Unknown labels rank lowest, so the floor still protects if one slips through.
    """
    try:
        rank = VERDICT_ORDER.index(verdict)
    except ValueError:
        return True
    return rank < VERDICT_ORDER.index("suspicious")

VERDICT_SYSTEM_PROMPT = """You are a senior email security analyst making a \
final triage decision. You will be given two upstream analyses: one of the \
message headers and one of the message body.

Weigh them together and return your decision as STRICT JSON — and nothing \
else. No markdown, no code fences, no commentary outside the JSON object.

The object must have exactly these three fields:
- "risk_score": an integer from 0 to 100 (0 = clearly safe, 100 = clearly \
malicious). Score the danger actually present, independently of the label.
- "verdict": exactly one of "benign", "spam", "suspicious", or "malicious".
- "explanation": 2-3 sentences a non-technical person could follow, \
explaining the decision in plain language.

Choose the verdict using these boundaries:

- "benign": legitimate mail the recipient would want or expect — real \
correspondence, transactional notices, or a newsletter they knowingly \
subscribed to. Nothing deceptive.

- "spam": unwanted bulk, promotional, or junk mail. This includes aggressive \
or sketchy marketing, unsolicited cold outreach, and manipulative \
pump-and-dump or stock-hype newsletters. The defining test: the message is \
unwanted, and may be low-quality or manipulative, but it is NOT trying to \
steal credentials, extract a payment, or impersonate a person or brand in \
order to defraud. It is a nuisance, not an attack. Still give it an honest \
risk_score for whatever danger is genuinely present — typically low.

- "suspicious": shows some phishing or fraud indicators — authentication \
problems, sender/domain mismatch, pressure tactics, or an unexpected link or \
request — but the evidence is incomplete or ambiguous.

- "malicious": clear phishing or fraud — credential harvesting, payment, \
wire, or gift-card fraud, or impersonation of a person or brand, especially \
alongside failed authentication or a spoofed sender.

Boundary rule: the moment a message attempts credential theft, payment \
fraud, or impersonation, it is NOT spam — classify it "suspicious" or \
"malicious" according to the strength of the evidence. Being unwanted is \
never on its own enough to raise a message above "spam"; deception is what \
makes something an attack. Conversely, do not label a message "spam" merely \
because it is bulk or automated — legitimate mail the recipient signed up \
for is "benign".

Example of the exact shape (values illustrative only):
{"risk_score": 82, "verdict": "malicious", "explanation": "..."}"""


def verdict_agent(state):
    """Synthesize the final verdict; never crash the pipeline on bad output."""
    user_content = (
        "HEADER ANALYSIS:\n"
        f"{state.get('header_analysis', '(none)')}\n\n"
        "CONTENT ANALYSIS:\n"
        f"{state.get('content_analysis', '(none)')}"
    )

    raw, usage = complete_with_usage(
        system_prompt=VERDICT_SYSTEM_PROMPT,
        user_content=user_content,
    )
    record_usage(state, "verdict_agent", usage)

    risk_score, verdict, explanation = _parse_verdict(raw)

    # Enforce the deterministic, model-independent floor over the model's call.
    floor, reasons = deterministic_risk_floor(state.get("parsed_headers", {}))
    risk_score, verdict, explanation = _apply_floor(
        risk_score, verdict, explanation, floor, reasons
    )

    # Persist the floor as a first-class output (used by the batch runner and
    # visible in run.py) so it never has to be recomputed downstream.
    state["risk_floor"] = floor
    state["risk_score"] = risk_score
    state["verdict"] = verdict
    state["explanation"] = explanation
    return state


def _apply_floor(risk_score, verdict, explanation, floor, reasons):
    """Reconcile the model's verdict with the deterministic header floor.

    The floor can only ever *raise* risk, never lower it. When the floor is
    high enough to contradict a benign call, we override the label to at least
    "suspicious" and flag the conflict in the explanation so an analyst can see
    that deterministic signals disagreed with the model.
    """
    # A parse-failure sentinel still gets the protective floor if one exists.
    if verdict == "error":
        if floor <= 0:
            return risk_score, verdict, explanation
        forced = "malicious" if floor >= 85 else "suspicious"
        note = (
            "[CONFLICT] The model output could not be used, but deterministic "
            f"header signals indicate risk (floor {floor}: {'; '.join(reasons)})."
        )
        return floor, forced, note

    if floor <= risk_score and not (
        floor >= FLOOR_OVERRIDE_THRESHOLD and _below_suspicious(verdict)
    ):
        # Model already met or exceeded the floor in both score and label.
        return risk_score, verdict, explanation

    new_score = max(risk_score, floor)
    new_verdict = verdict
    explanation_out = explanation

    # A fired floor forces the label to at least "suspicious". This catches
    # "spam" as well as "benign": header signals that hard cannot be reconciled
    # with "merely unwanted", so spam is only ever reachable when the floor is
    # quiet.
    if floor >= FLOOR_OVERRIDE_THRESHOLD and _below_suspicious(verdict):
        new_verdict = "suspicious"
        explanation_out = (
            "[CONFLICT] Deterministic header checks disagree with the model: "
            f"the model judged this '{verdict}', but {('; '.join(reasons))} "
            f"(risk floor {floor}). Overriding to '{new_verdict}'. "
            f"Original model explanation: {explanation}"
        )
    elif new_score != risk_score:
        explanation_out = (
            f"[Risk raised to {new_score} by deterministic header signals: "
            f"{('; '.join(reasons))}.] {explanation}"
        )

    return new_score, new_verdict, explanation_out


def _parse_verdict(raw):
    """Parse the model's JSON into (risk_score, verdict, explanation).

    Returns a sentinel (-1, "error", ...) rather than raising if the output
    is not valid, well-formed JSON in the expected shape.
    """
    data = _load_json(raw)
    if data is None:
        logger.error("verdict_agent: could not parse model output as JSON: %r", raw)
        return -1, "error", "Could not parse the model's verdict output."

    try:
        risk_score = int(data["risk_score"])
        verdict = str(data["verdict"]).strip().lower()
        explanation = str(data["explanation"])
    except (KeyError, TypeError, ValueError):
        logger.error("verdict_agent: model JSON missing/invalid fields: %r", raw)
        return -1, "error", "The model's verdict output was missing required fields."

    if not 0 <= risk_score <= 100:
        logger.error("verdict_agent: risk_score out of range: %r", risk_score)
        return -1, "error", f"The model returned an out-of-range risk_score: {risk_score}."

    if verdict not in VALID_VERDICTS:
        logger.error("verdict_agent: unexpected verdict label %r in %r", verdict, raw)
        return -1, "error", f"The model returned an unrecognized verdict: {verdict!r}."

    return risk_score, verdict, explanation


def _load_json(raw):
    """Best-effort JSON load; tolerates a ```json code fence around the object.

    Returns the parsed object, or None if nothing parseable was found. This is
    parsing robustness only — it never relaxes the downstream schema checks.
    """
    if not isinstance(raw, str):
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    # Strip a fenced block (```json ... ``` or ``` ... ```) and retry on the
    # first {...} object we can find.
    match = re.search(r"\{.*\}", raw, re.DOTALL)
    if not match:
        return None
    try:
        return json.loads(match.group(0))
    except json.JSONDecodeError:
        return None
