"""Rule packaging, starter presets, and CI workflow templates for workspace scaffolding.

Pure L1 domain helpers extracted from ``aegis_cli.init`` so rule discovery, frontmatter
type projection, and CI workflow inspection live in ``aegis_core``.
"""
from __future__ import annotations

import importlib.resources
from pathlib import Path
import re
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from aegis_core._version import __version__
from aegis_core.storage import atomic_write_bytes
from aegis_core.taxonomy import RULE_TYPES, RuleType
from aegis_core.workspace.layout import RULES_RELDIR

__all__ = [
    "ACTIVE_LABEL",
    "ACTIVE_STARTERS",
    "ACTIVE_TYPE_DIR",
    "CI_WORKFLOW_LABEL",
    "CI_WORKFLOW_PATH",
    "DEFAULT_RULE_PRESET",
    "NO_ACTIVE_PRESETS",
    "RULE_PRESETS",
    "SEED_TYPE",
    "SEED_TYPE_DIR",
    "_CI_WORKFLOW",
    "_declare_type",
    "_runs_aegis_check",
    "_shipped_rules",
    "_workflow_files",
    "ci_workflow",
    "install_rules",
    "packaged_active_rules",
    "packaged_dir",
    "packaged_rules",
    "preset_rules",
]

DEFAULT_RULE_PRESET = "standard"
_STANDARD = ("providence", "destructive-ops", "testing", "cost-optimization", "git-workflow")
RULE_PRESETS: Dict[str, Optional[Tuple[str, ...]]] = {
    "minimal": ("providence", "destructive-ops"),
    "standard": _STANDARD,
    "full": None,  # every shipped guidance rule
    "none-active": _STANDARD,  # the standard personas, and no active starter
}
# Shipped rules seeded as they are, active, into their own type directory of a new
# workspace: the personas apply to no file until someone sets their target_paths, so
# without one `aegis check` enforced nothing on day one (v4.1 field report). They are in
# no persona preset; ``--rules none-active`` leaves them out.
ACTIVE_STARTERS: Dict[str, str] = {
    "no-eval": (
        "bans builtin eval() and exec() in **/*.py (method calls like df.eval() and model.eval() "
        "are allowed); aegis check and the pre-commit hook enforce it"
    ),
}
NO_ACTIVE_PRESETS = ("none-active",)
ACTIVE_TYPE_DIR = RULE_TYPES[RuleType.INVARIANT].directory
ACTIVE_LABEL = f"{RULES_RELDIR}/{ACTIVE_TYPE_DIR}"
# The shipped rules are process guidance (what to do, not where), so they are seeded as
# persona rules whose frontmatter says so: ``type: persona`` (the repository's own lint,
# `aegis check`, requires a declared type) and ``target_paths: []`` (they apply to no file
# until the repository names the files each one governs; `aegis status` lists them).
SEED_TYPE = RuleType.PERSONA
SEED_TYPE_DIR = RULE_TYPES[SEED_TYPE].directory
_NOT_RULES = {"META.md", "README.md"}


def packaged_dir(name: str, base: Optional[Path] = None) -> Path:
    """The directory of Aegis's shipped ``rules`` or ``skills``.

    A wheel carries them in ``aegis_core/_data/<name>`` (pyproject.toml maps the
    repository's ``<name>/`` there); a source checkout has them at its root, next to its
    pyproject.toml. ``base`` is the aegis_core package directory. Nothing is imported by
    name: a top-level ``rules`` package may be another distribution's, or a repository's
    own directory first on sys.path. A missing directory is returned as is, for the
    caller to report.
    """
    base = Path(str(importlib.resources.files("aegis_core"))) if base is None else Path(base)
    installed = base / "_data" / name
    if installed.is_dir():
        return installed
    checkout = base.parent
    if (checkout / "pyproject.toml").is_file() and (checkout / name).is_dir():
        return checkout / name
    return installed


def _shipped_rules(locator: Optional[Callable[..., Path]] = None) -> Dict[str, Path]:
    base = (locator or packaged_dir)("rules")
    found: Dict[str, Path] = {}
    for directory in (base, base / ".oracles"):
        if directory.is_dir():
            for path in sorted(directory.glob("*.md")):
                if path.is_file() and path.name not in _NOT_RULES:
                    found.setdefault(path.stem, path)
    return found


def packaged_rules(locator: Optional[Callable[..., Path]] = None) -> Dict[str, Path]:
    """Every shipped guidance rule (``rules/*.md``, ``rules/.oracles/*.md``, through
    ``packaged_dir``) by id: what the persona presets seed. The active starters are not
    among them (see packaged_active_rules)."""
    return {k: v for k, v in _shipped_rules(locator=locator).items() if k not in ACTIVE_STARTERS}


def packaged_active_rules(locator: Optional[Callable[..., Path]] = None) -> Dict[str, Path]:
    """The shipped active starters (ACTIVE_STARTERS) by id; ValueError when one is missing."""
    shipped = _shipped_rules(locator=locator)
    missing = [n for n in ACTIVE_STARTERS if n not in shipped]
    if missing:
        raise ValueError(f"packaged rule(s) {', '.join(missing)} not found; reinstall aegis-guardrails")
    return {n: shipped[n] for n in ACTIVE_STARTERS}


def preset_rules(preset: str, locator: Optional[Callable[..., Path]] = None) -> List[Path]:
    """The packaged rule files of ``preset``; ValueError for an unknown preset or a missing rule."""
    if preset not in RULE_PRESETS:
        raise ValueError(f"unknown rule preset {preset!r}; presets: {', '.join(RULE_PRESETS)}")
    shipped = packaged_rules(locator=locator)
    names = RULE_PRESETS[preset]
    if names is None:
        return [shipped[n] for n in sorted(shipped)]
    missing = [n for n in names if n not in shipped]
    if missing:
        raise ValueError(f"packaged rule(s) {', '.join(missing)} not found; reinstall aegis-guardrails")
    return [shipped[n] for n in names]


_TOP_LEVEL_KEY = re.compile(r"^([A-Za-z_][\w-]*)[ \t]*:")


def _declare_type(source: Path, rule_type: str) -> bytes:
    """The bytes of ``source`` with its frontmatter declaring ``type: <rule_type>`` and, when
    it names no files, ``target_paths: []``; the rest of the file is kept as it is."""
    text = source.read_bytes().decode("utf-8")
    eol = "\r\n" if "\r\n" in text else "\n"
    lines = text.splitlines(True)
    close = next((i for i, line in enumerate(lines[1:], 1) if line.rstrip("\r\n") == "---"), None)
    if not lines or lines[0].rstrip("\r\n") != "---" or close is None:
        raise ValueError(f"packaged rule {source.name} has no frontmatter; reinstall aegis-guardrails")
    keys: Dict[str, int] = {}
    for index in range(1, close):
        match = _TOP_LEVEL_KEY.match(lines[index])
        if match:
            keys.setdefault(match.group(1), index)
    added = [] if "target_paths" in keys else [f"target_paths: []{eol}"]
    if "type" in keys:
        lines[keys["type"]] = f"type: {rule_type}{eol}"
        at = keys["type"] + 1
    else:
        added.insert(0, f"type: {rule_type}{eol}")
        at = keys.get("id", 0) + 1
    lines[at:at] = added
    return "".join(lines).encode("utf-8")


def install_rules(
    rules_dir: Path,
    preset: str = DEFAULT_RULE_PRESET,
    dry_run: bool = False,
    force: bool = False,
    skip: Sequence[str] = (),
    rule_type: Optional[str] = None,
    _preset_fn: Optional[Callable[[str], List[Path]]] = None,
) -> List[str]:
    """Copy the preset's packaged rules into ``rules_dir`` (flat); return the ids now there.

    An existing file is kept unless ``force``; a symlinked destination is never written
    through; ids in ``skip`` are left out. With ``rule_type`` each copy's frontmatter
    declares that type (and ``target_paths: []`` when it names none); without it the
    packaged bytes are copied as they are.
    """
    rules_dir = Path(rules_dir)
    present: List[str] = []
    sources = (_preset_fn or preset_rules)(preset)
    for source in sources:
        name = source.stem
        if name in skip:
            continue
        dest = rules_dir / source.name
        if dest.is_symlink():
            continue
        if dest.exists() and not force:
            present.append(name)
            continue
        data = _declare_type(source, rule_type) if rule_type else source.read_bytes()
        if not dry_run:
            atomic_write_bytes(dest, data)
        present.append(name)
    return present


# ── The CI floor ─────────────────────────────────────────────────────────────

CI_WORKFLOW_LABEL = ".github/workflows/aegis.yml"
CI_WORKFLOW_PATH = CI_WORKFLOW_LABEL
_RUNS_AEGIS_CHECK = re.compile(r"\baegis\s+check\b")
_WORKFLOW_READ_LIMIT = 1 << 20

_CI_WORKFLOW = """\
# aegis check on every pull request. CI is the floor: git commit --no-verify skips the
# local pre-commit hook, so the same check runs here.
name: Aegis

on:
  pull_request:
  push:
    branches: [main, master]

permissions:
  contents: read

jobs:
  aegis-check:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: read  # aegis check --ci reads a pull request's reviews (tier A approval)
    steps:
      - uses: actions/checkout@v7
        with:
          fetch-depth: 0  # aegis check diffs the pull request against its base branch
          persist-credentials: false
      - uses: actions/setup-python@v7
        with:
          python-version: "3.12"
      - run: pip install aegis-guardrails=={version}
      - run: aegis check
      - run: aegis check --ci
        env:
          GH_TOKEN: ${{{{ github.token }}}}
"""


def ci_workflow() -> str:
    """The GitHub Actions workflow init prints, and writes with ``--ci``: ``aegis check`` on
    every pull request, with the aegis version that wrote it (a newer release may check more)."""
    return _CI_WORKFLOW.format(version=__version__)


def _workflow_files(root: Path) -> List[Path]:
    """The GitHub Actions workflow files (``.github/workflows/*.yml|yaml``; GitHub reads no
    subdirectory there)."""
    directory = root / ".github" / "workflows"
    try:
        entries = sorted(directory.iterdir()) if directory.is_dir() else []
    except OSError:
        return []
    return [e for e in entries if e.suffix in (".yml", ".yaml") and e.is_file()]


def _runs_aegis_check(path: Path) -> bool:
    try:
        with open(path, "rb") as handle:
            text = handle.read(_WORKFLOW_READ_LIMIT).decode("utf-8", "replace")
    except OSError:
        return False
    return bool(_RUNS_AEGIS_CHECK.search(text))
