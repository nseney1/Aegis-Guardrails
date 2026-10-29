"""The day-0 card (v4.2 #1): ``aegis check --card [--json]``, also printed at the end of ``aegis init``.

What a repository looks like to Aegis before anything is set up: its languages, the AST
drivers that can read them, the rules by type and how many are active, the share of its
files that pass Layer 1 and the five files with the most findings.

It reads and changes nothing: no state directory, no event, and ``baseline.json`` is
neither read nor written, so a card never changes what a later ``aegis check`` decides.
Above ``SAMPLE_LIMIT`` files it runs Layer 1 on an even, deterministic sample of the
files and says so. The languages and the rules are counted on the whole listing.

An *active* rule is one that is served (loaded cleanly, not expired) and whose
``target_paths`` match at least one listed file; a forbid_ast gate without
``target_paths`` targets every file. When none is, the card says so: ``aegis check``
then enforces nothing rule-based.

Findings are counted the way the ratchet baseline counts them (aegis_core.baseline): one
per matched line, so a file with three ``eval`` calls has three.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from aegis_core import primitives
from aegis_core import baseline
from aegis_core.taxonomy import RULE_TYPES

__all__ = ["SAMPLE_LIMIT", "SOURCE", "TOP_FILES", "Card", "build", "sample"]

SOURCE = "aegis check --card"
SAMPLE_LIMIT = 2000
TOP_FILES = 5
NO_ACTIVE_RULE = "No active rule targets any file: aegis check enforces no rule until one names files."
NEXT_RULE = "Next: add a rule for your own code with aegis rule create (aegis rule create --help)"


def sample(files: Sequence[str], limit: int = SAMPLE_LIMIT) -> List[str]:
    """``files`` when there are at most ``limit``; otherwise ``limit`` of them spread evenly
    over the (sorted) listing, the first always among them. Deterministic."""
    total = len(files)
    if total <= limit:
        return list(files)
    return [files[i * total // limit] for i in range(limit)]


def _languages(files: Sequence[str]) -> List[Dict[str, Any]]:
    from aegis_core.ast.detect import LANGUAGE_DEFINITIONS

    by_ext = {ext: lang for lang, config in LANGUAGE_DEFINITIONS.items() for ext in config["extensions"]}
    counts: Dict[str, int] = {}
    seen: Dict[str, set] = {}
    for path in files:
        ext = os.path.splitext(path)[1].lower()
        lang = by_ext.get(ext)
        if lang is not None:
            counts[lang] = counts.get(lang, 0) + 1
            seen.setdefault(lang, set()).add(ext)
    rows = [{"language": lang, "files": n, "extensions": sorted(seen[lang])} for lang, n in counts.items()]
    return sorted(rows, key=lambda row: (-row["files"], row["language"]))


def _drivers(root: str, languages: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    from aegis_core.ast.runner import ASTDriverRunner

    registry = ASTDriverRunner().registry
    rows: List[Dict[str, Any]] = []
    for row in languages:
        name = row["language"]
        if name == "python":
            rows.append({"language": name, "driver": "built-in (in-process)", "status": "ready", "reason": None})
            continue
        try:
            plan = registry.plan_driver(row["extensions"][0], workspace_root=root)
        except Exception as exc:  # a driver configuration that cannot even be read
            rows.append({"language": name, "driver": None, "status": "unavailable",
                         "reason": f"{type(exc).__name__}: {exc}"})
            continue
        if plan is None:
            rows.append({"language": name, "driver": None, "status": "not enabled",
                         "reason": "aegis init enables the packaged driver (ast.packaged_drivers in .aegis/config.json)"})
        elif plan.unavailable:
            rows.append({"language": name, "driver": plan.label, "status": "unavailable", "reason": plan.unavailable})
        else:
            rows.append({"language": name, "driver": plan.label, "status": "ready", "reason": None})
    return rows


def _rules(root: str, files: Sequence[str]) -> Dict[str, Any]:
    from aegis_core.rules import load_rules

    try:
        ruleset = load_rules(root)
    except Exception as exc:  # RuleInventoryError: an unsafe or unreadable rules tree
        return {"total": 0, "by_type": {}, "served": 0, "errors": 0, "active": [], "error": str(exc)}
    by_type: Dict[str, int] = {}
    for rule in ruleset.rules:
        if rule.type is not None:
            by_type[rule.type] = by_type.get(rule.type, 0) + 1
    ordered = {name: by_type[name] for name in RULE_TYPES if name in by_type}
    active = sorted({rule.id for rule in ruleset.served if rule.matching_files(files)})
    return {"total": len(ruleset.rules), "by_type": ordered, "served": len(ruleset.served),
            "errors": len(ruleset.errors), "active": active, "error": None}


def _layer1(root: str, targets: Sequence[str]) -> Dict[str, Any]:
    try:
        pairs, sources = baseline.run_fast(root, targets)
    except Exception as exc:
        return {"checked": len(targets), "passed": 0, "failed": 0, "pass_rate": None, "findings": 0,
                "checks_that_could_not_run": [f"Layer 1 could not run: {type(exc).__name__}: {exc}"], "top": []}
    collected = baseline.collect(pairs, sources)
    per_file: Dict[str, int] = {}
    for finding in collected.findings:
        per_file[finding.path] = per_file.get(finding.path, 0) + 1
    failing = {path for path, evidence in pairs if path is not None and not evidence.verdict}
    for (path, evidence), found in zip(pairs, collected.by_evidence):
        if path is not None and not evidence.verdict and found is None:
            per_file[path] = per_file.get(path, 0) + 1  # a check that failed without a line is one finding
    loose = [f"{e.tool}: {e.detail}" for path, e in pairs if path is None and not e.verdict]
    checked = len(targets)
    top = sorted(per_file.items(), key=lambda item: (-item[1], item[0]))[:TOP_FILES]
    return {
        "checked": checked,
        "passed": checked - len(failing),
        "failed": len(failing),
        "pass_rate": round((checked - len(failing)) / checked, 4) if checked else None,
        "findings": sum(per_file.values()),
        "checks_that_could_not_run": loose,
        "top": [{"path": path, "findings": count} for path, count in top],
    }


@dataclass(frozen=True)
class Card:
    """The card of one workspace: ``as_dict()`` is the ``--json`` document, which the CLI renders for
    the terminal (aegis_cli.formatters.text)."""

    workspace: str
    listing: str
    files: int
    files_analyzed: int
    sample_limit: int
    languages: Tuple[Dict[str, Any], ...]
    drivers: Tuple[Dict[str, Any], ...]
    rules: Dict[str, Any]
    layer1: Dict[str, Any]
    checked_at: Optional[float] = None

    @property
    def sampled(self) -> bool:
        return self.files_analyzed < self.files

    @property
    def notes(self) -> List[str]:
        notes: List[str] = []
        if not self.rules["active"]:
            notes.append(NO_ACTIVE_RULE)
        if self.rules.get("error"):
            notes.append(f"The rules could not be read ({self.rules['error']}), so no rule is counted.")
        elif self.rules["errors"]:
            notes.append(f"{self.rules['errors']} rule file(s) cannot be served (aegis status lists them).")
        if self.listing == "walk":
            notes.append("Not a git work tree: the files were found by walking the directory, "
                         "leaving out build and vendor directories.")
        if self.sampled:
            notes.append(f"Sampled {self.files_analyzed} of {self.files} files (every file in an even spread of the "
                         "sorted listing) for Layer 1; the languages and the rules cover all of them.")
        if self.layer1["checks_that_could_not_run"]:
            notes.append(f"{len(self.layer1['checks_that_could_not_run'])} check(s) could not run, so the pass rate "
                         "does not count them (aegis check shows why).")
        return notes

    def as_dict(self) -> Dict[str, Any]:
        layer1 = dict(self.layer1)
        top = layer1.pop("top")
        document = primitives.envelope(SOURCE, {
            "workspace": self.workspace,
            "listing": self.listing,
            "files": self.files,
            "files_analyzed": self.files_analyzed,
            "sampled": self.sampled,
            "sample_limit": self.sample_limit,
        }, now=self.checked_at)
        document.update(
            languages=[dict(row) for row in self.languages],
            drivers=[dict(row) for row in self.drivers],
            rules=dict(self.rules),
            layer1=layer1,
            top_files=top,
            notes=self.notes,
        )
        return document


def build(root: Any, now: Optional[float] = None, sample_limit: int = SAMPLE_LIMIT) -> Card:
    """The card of the workspace at ``root``. Read-only; see the module docstring."""
    base = os.path.abspath(os.fspath(root))
    files, listing = baseline.list_files(base)
    picked = sample(files, sample_limit)
    languages = _languages(files)
    return Card(
        workspace=base,
        listing=listing,
        files=len(files),
        files_analyzed=len(picked),
        sample_limit=sample_limit,
        languages=tuple(languages),
        drivers=tuple(_drivers(base, languages)),
        rules=_rules(base, files),
        layer1=_layer1(base, baseline.checkable(base, picked)),
        checked_at=now,
    )
