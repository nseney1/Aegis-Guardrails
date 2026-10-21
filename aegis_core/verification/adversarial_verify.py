"""Adversarial pair enzyme — builds prompts and parses structured output.

Provides the information-partitioned interface between the Spec Agent
(sees plan + signatures only) and the Code Agent (sees implementation +
test results only). Neither agent sees the other's input.
"""
from __future__ import annotations

import ast
import json
import textwrap
from typing import Optional

from . import (
    RiskCategory,
    Severity,
    Prediction,
    Claim,
    PREDICTION_SCHEMA,
    CLAIM_SCHEMA,
)


# ── Helpers ────────────────────────────────────────────────────────────────


def _risk_category_listing() -> str:
    """Return a formatted listing of all RiskCategory enum values."""
    return "\n".join(f"  - {c.value}" for c in RiskCategory)


# ── Public API ─────────────────────────────────────────────────────────────


def extract_signatures(filepath: str) -> list[str]:
    """Extract function signatures WITH docstrings but WITHOUT bodies.

    Uses the ``ast`` module to parse *filepath*, pulling out each
    ``def name(args):`` line together with any docstring.  Implementation
    constants, operators, and variable assignments are never included.
    """
    with open(filepath, "r") as fh:
        source = fh.read()

    tree = ast.parse(source)
    signatures: list[str] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue

        # Reconstruct the signature line from the AST args
        args = []
        defaults_offset = len(node.args.args) - len(node.args.defaults)
        for i, arg in enumerate(node.args.args):
            default_idx = i - defaults_offset
            if default_idx >= 0:
                default_node = node.args.defaults[default_idx]
                try:
                    default_val = ast.literal_eval(default_node)
                    args.append(f"{arg.arg}={default_val!r}")
                except (ValueError, SyntaxError):
                    try:
                        args.append(f"{arg.arg}={ast.unparse(default_node)}")
                    except Exception:
                        args.append(f"{arg.arg}=...")
            else:
                args.append(arg.arg)

        sig_line = f"def {node.name}({', '.join(args)}):"

        # Extract docstring if present
        docstring = ast.get_docstring(node)
        if docstring:
            sig_line += f'\n    """{docstring}"""'

        signatures.append(sig_line)

    return signatures


def build_spec_prompt(
    plan: str,
    signatures: list[str],
    test_names: list[str],
) -> str:
    """Build the prompt for the Spec Agent.

    The prompt contains the plan, function signatures, and test names, but
    NEVER implementation code.  It also embeds the full prediction schema
    and the complete ``RiskCategory`` taxonomy so the agent knows the
    allowed output format.
    """
    schema_json = json.dumps(PREDICTION_SCHEMA, indent=2)
    return textwrap.dedent(f"""\
        You are the Spec Agent in an adversarial verification pair.

        ## Plan
        {plan}

        ## Function Signatures
        {chr(10).join(signatures)}

        ## Test Names
        {chr(10).join('- ' + t for t in test_names)}

        ## Required Output Schema
        Return a JSON array matching this schema. Each object MUST have these keys:
        category, severity, risk, mechanism, affected_function

        ```json
        {schema_json}
        ```

        ## Risk Category Taxonomy (you MUST use these values for "category")
        {_risk_category_listing()}
    """)


def build_code_prompt(
    implementation: str,
    test_results: str,
    layer1_output: dict,
    spec_predictions: Optional[list[dict | Prediction]] = None,
) -> str:
    """Build the prompt for the Code Agent.

    The prompt contains the implementation source, test results, layer-1 tool
    output, and optionally the Spec Agent's predicted risk charges (the
    prosecution charges to defend against), but NEVER the task plan text.
    It embeds the full claim schema and the complete ``RiskCategory``
    taxonomy.
    """
    schema_json = json.dumps(CLAIM_SCHEMA, indent=2)
    layer1_json = json.dumps(layer1_output, indent=2)

    charges_section = ""
    if spec_predictions:
        charge_lines = []
        for p in spec_predictions:
            if isinstance(p, dict):
                cat = p.get("category", "")
                sev = p.get("severity", "")
                risk = p.get("risk", "")
                func = p.get("affected_function", "")
            else:
                cat = getattr(p.category, "value", str(p.category))
                sev = getattr(p.severity, "value", str(p.severity))
                risk = getattr(p, "risk", "")
                func = getattr(p, "affected_function", "")
            charge_lines.append(f"- [category: {cat}, severity: {sev}] {risk} (Affected: {func})")
        charges_formatted = "\n".join(charge_lines)
        charges_section = textwrap.dedent(f"""\

            ## Predicted Risk Charges
            The specification review has predicted the following potential risks:
            {charges_formatted}

            ### Defense Mandate
            Your task is to defend the implementation against these predicted risks or concede if unaddressed.
            For each predicted risk category, provide concrete claims with exact evidence_file, evidence_line, and tests_covering.
        """)

    return textwrap.dedent(f"""\
        You are the Code Agent in an adversarial verification pair.

        ## Implementation
        {implementation}

        ## Test Results
        {test_results}

        ## Layer 1 Tool Output
        {layer1_json}
        {charges_section}
        ## Required Output Schema
        Return a JSON array matching this schema. Each object MUST have these keys:
        category, claim, evidence_file, evidence_line

        ```json
        {schema_json}
        ```

        ## Risk Category Taxonomy (you MUST use these values for "category")
        {_risk_category_listing()}
    """)


def parse_predictions(raw: list[dict]) -> tuple[list[Prediction], int]:
    """Parse a list of dicts into ``Prediction`` objects and count the dropped entries.

    Maps string ``category`` to ``RiskCategory`` and string ``severity``
    to ``Severity``.  An entry with an unknown category or severity, or that is
    not an object, is skipped and counted.
    """
    predictions: list[Prediction] = []
    dropped = 0
    for entry in raw:
        try:
            category = RiskCategory(entry["category"])
            severity = Severity(entry["severity"])
        except (ValueError, KeyError, TypeError):
            dropped += 1
            continue

        predictions.append(
            Prediction(
                category=category,
                severity=severity,
                risk=entry.get("risk", ""),
                mechanism=entry.get("mechanism", ""),
                affected_function=entry.get("affected_function", ""),
            )
        )
    return predictions, dropped


def parse_claims(raw: list[dict]) -> tuple[list[Claim], int]:
    """Parse a list of dicts into ``Claim`` objects and count the dropped entries.

    Maps string ``category`` to ``RiskCategory``.  An entry with an unknown
    category, or that is not an object, is skipped and counted.
    """
    claims: list[Claim] = []
    dropped = 0
    for entry in raw:
        try:
            category = RiskCategory(entry["category"])
        except (ValueError, KeyError, TypeError):
            dropped += 1
            continue

        claims.append(
            Claim(
                category=category,
                claim=entry.get("claim", ""),
                evidence_file=entry.get("evidence_file", ""),
                evidence_line=entry.get("evidence_line", 0),
                tests_covering=entry.get("tests_covering", []),
            )
        )
    return claims, dropped
