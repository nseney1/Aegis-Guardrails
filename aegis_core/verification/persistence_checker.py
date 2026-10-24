from __future__ import annotations

"""Persistence Completeness Checker — Layer 1 Verification Tool.

Answers: "Does every in-memory dict mutation have a serialization path?"

Uses AST analysis to find dict bracket assignments and regex to find
serialization handlers. Pure deterministic — no LLM judgment.
"""

import ast
import re
import os

from . import ToolEvidence


def find_dict_mutations(source: str, dict_name: str) -> dict[str, list[int]]:
    """Find all keys assigned to a dict via bracket notation.

    Catches patterns like:
        fitness['key'] = value
        meta['fitness'] = ...

    Returns {key: [line_numbers]}
    """
    mutations: dict[str, list[int]] = {}
    tree = ast.parse(source)

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if (isinstance(target, ast.Subscript) and
                    isinstance(target.value, ast.Name) and
                    target.value.id == dict_name and
                    isinstance(target.slice, ast.Constant) and
                    isinstance(target.slice.value, str)):
                    key = target.slice.value
                    mutations.setdefault(key, []).append(node.lineno)

    return mutations


def find_serialized_keys(source: str) -> dict[str, list[int]]:
    """Find all keys handled in serialization blocks.

    Looks for patterns like:
        stripped.startswith('key_name:')
        line.startswith('key_name:')

    Returns {key: [line_numbers]}
    """
    serialized: dict[str, list[int]] = {}
    pattern = re.compile(r"startswith\(['\"](\w+):['\"]")

    for i, line in enumerate(source.split('\n'), 1):
        for match in pattern.finditer(line):
            key = match.group(1)
            serialized.setdefault(key, []).append(i)

    return serialized


def check(
    filepath: str,
    dict_name: str,
    exclude: set[str] | None = None,
) -> ToolEvidence:
    """Run persistence completeness check.

    Args:
        filepath: Path to the Python file to analyze
        dict_name: Name of the dict variable to track mutations for
        exclude: Keys that are intentionally in-memory-only

    Returns:
        ToolEvidence with verdict=True if all mutated keys are serialized
    """
    exclude = exclude or set()

    with open(filepath, 'r', encoding='utf-8') as f:
        source = f.read()

    mutated = find_dict_mutations(source, dict_name)
    serialized = find_serialized_keys(source)

    mutated_set = set(mutated.keys()) - exclude
    serialized_set = set(serialized.keys())

    gaps = mutated_set - serialized_set

    if gaps:
        gap_details = []
        gap_lines = []
        for key in sorted(gaps):
            lines = mutated[key]
            gap_lines.extend(lines)
            gap_details.append(f"{key} (assigned at L{','.join(map(str, lines))})")

        return ToolEvidence(
            tool="persistence_checker",
            target=f"{os.path.basename(filepath)}:{dict_name}",
            verdict=False,
            detail=f"PERSISTENCE GAP: {'; '.join(gap_details)} — mutated but never serialized",
            lines=gap_lines,
        )

    return ToolEvidence(
        tool="persistence_checker",
        target=f"{os.path.basename(filepath)}:{dict_name}",
        verdict=True,
        detail=f"All {len(mutated_set)} mutated keys have serialization paths",
    )
