"""Rule packaging, starter presets, and CI workflow templates for workspace scaffolding.

Pure L1 domain helpers extracted from ``aegis_cli.init`` so rule discovery, frontmatter
type projection, and CI workflow inspection live in ``aegis_core``.
"""
from __future__ import annotations

import importlib.resources
from pathlib import Path
import re
import shlex
from typing import Dict, List, Optional, Sequence, Tuple

from aegis_core._version import __version__
from aegis_core.storage import atomic_write_bytes
from aegis_core.taxonomy import RULE_TYPES, RuleType
from aegis_core.workspace.layout import RULES_RELDIR

__all__ = [
    "ACTIVE_LABEL",
    "ACTIVE_STARTERS",
    "ACTIVE_TYPE_DIR",
    "CI_WORKFLOW_LABEL",
    "DEFAULT_RULE_PRESET",
    "NO_ACTIVE_PRESETS",
    "RULE_PRESETS",
    "SEED_TYPE",
    "SEED_TYPE_DIR",
    "ci_workflow",
    "declare_type",
    "install_rules",
    "packaged_active_rules",
    "packaged_dir",
    "packaged_rules",
    "preset_rules",
    "runs_aegis_check",
    "workflow_files",
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


def _shipped_rules() -> Dict[str, Path]:
    base = packaged_dir("rules")
    found: Dict[str, Path] = {}
    for directory in (base, base / ".oracles"):
        if directory.is_dir():
            for path in sorted(directory.glob("*.md")):
                if path.is_file() and path.name not in _NOT_RULES:
                    found.setdefault(path.stem, path)
    return found


def packaged_rules() -> Dict[str, Path]:
    """Every shipped guidance rule (``rules/*.md``, ``rules/.oracles/*.md``, through
    ``packaged_dir``) by id: what the persona presets seed. The active starters are not
    among them (see packaged_active_rules)."""
    return {k: v for k, v in _shipped_rules().items() if k not in ACTIVE_STARTERS}


def packaged_active_rules() -> Dict[str, Path]:
    """The shipped active starters (ACTIVE_STARTERS) by id; ValueError when one is missing."""
    shipped = _shipped_rules()
    missing = [n for n in ACTIVE_STARTERS if n not in shipped]
    if missing:
        raise ValueError(f"packaged rule(s) {', '.join(missing)} not found; reinstall aegis-guardrails")
    return {n: shipped[n] for n in ACTIVE_STARTERS}


def preset_rules(preset: str) -> List[Path]:
    """The packaged rule files of ``preset``; ValueError for an unknown preset or a missing rule."""
    if preset not in RULE_PRESETS:
        raise ValueError(f"unknown rule preset {preset!r}; presets: {', '.join(RULE_PRESETS)}")
    shipped = packaged_rules()
    names = RULE_PRESETS[preset]
    if names is None:
        return [shipped[n] for n in sorted(shipped)]
    missing = [n for n in names if n not in shipped]
    if missing:
        raise ValueError(f"packaged rule(s) {', '.join(missing)} not found; reinstall aegis-guardrails")
    return [shipped[n] for n in names]


_TOP_LEVEL_KEY = re.compile(r"^([A-Za-z_][\w-]*)[ \t]*:")


def declare_type(source: Path, rule_type: str) -> bytes:
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


def install_rules(rules_dir: Path, preset: str = DEFAULT_RULE_PRESET, dry_run: bool = False, force: bool = False,
                  skip: Sequence[str] = (), rule_type: Optional[str] = None) -> List[str]:
    """Copy the preset's packaged rules into ``rules_dir`` (flat); return the ids now there.

    An existing file is kept unless ``force``; a symlinked destination is never written
    through; ids in ``skip`` are left out. With ``rule_type`` each copy's frontmatter
    declares that type (and ``target_paths: []`` when it names none); without it the
    packaged bytes are copied as they are.
    """
    rules_dir = Path(rules_dir)
    present: List[str] = []
    sources = preset_rules(preset)
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
        data = declare_type(source, rule_type) if rule_type else source.read_bytes()
        if not dry_run:
            atomic_write_bytes(dest, data)
        present.append(name)
    return present


# ── The CI floor ─────────────────────────────────────────────────────────────

CI_WORKFLOW_LABEL = ".github/workflows/aegis.yml"
_RUNS_AEGIS_CHECK = re.compile(
    r"(?:aegis|python3?(?:[ \t]+-I)?[ \t]+-m[ \t]+aegis_cli(?:\.cli)?)[ \t]+check(?=[ \t]|$)"
)
# Keep quoted/escaped chunks inside words and recognize comments only at a word start.
# The alternatives have disjoint first characters; no shell expansion is evaluated.
_WORKFLOW_SHELL_TOKENS = re.compile(
    r"""((?!#)(?:[^\s;&|<>\\'"]|\\.|'[^']*'|"(?:[^"\\]|\\.)*")+|[;&|<>]+|\#.*)"""
)
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
{go_setup}      - run: pip install aegis-guardrails=={version}
      - run: aegis check
      - run: aegis check --ci
        env:
          GH_TOKEN: ${{{{ github.token }}}}
  # Code scanning annotations, in a job of their own: the write permission never reaches the job that
  # runs the pull request's tests with a token. Code scanning needs GitHub Advanced Security on a
  # private repository: remove the private condition there to opt in.
  aegis-sarif:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v7
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: actions/setup-python@v7
        with:
          python-version: "3.12"
{go_setup}      - run: pip install aegis-guardrails=={version}
      # Exit 1 means findings: the aegis-check job gates on them, so this step never fails the run.
      - run: aegis check --format sarif > aegis.sarif
        continue-on-error: true
      - uses: github/codeql-action/upload-sarif@v4
        if: ${{{{ always() && hashFiles('aegis.sarif') != '' && !github.event.repository.private && (github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository) }}}}
        with:
          sarif_file: aegis.sarif
          category: aegis
"""


def ci_workflow(*, go_enabled: bool = False) -> str:
    """The GitHub Actions workflow init prints, and writes with ``--ci``: ``aegis check`` on
    every pull request, with the aegis version that wrote it (a newer release may check more)."""
    go_setup = ("      - uses: actions/setup-go@v7\n"
                "        with:\n"
                "          go-version: \"1.21.x\"\n"
                "          cache: false\n") if go_enabled else ""
    return _CI_WORKFLOW.format(version=__version__, go_setup=go_setup)


def workflow_files(root: Path) -> List[Path]:
    """The GitHub Actions workflow files (``.github/workflows/*.yml|yaml``; GitHub reads no
    subdirectory there)."""
    directory = root / ".github" / "workflows"
    try:
        entries = sorted(directory.iterdir()) if directory.is_dir() else []
    except OSError:
        return []
    return [e for e in entries if e.suffix in (".yml", ".yaml") and e.is_file()]


def runs_aegis_check(path: Path) -> bool:
    try:
        with open(path, "rb") as handle:
            text = handle.read(_WORKFLOW_READ_LIMIT).decode("utf-8", "replace")
    except OSError:
        return False
    # This is a setup hint, not the required-check verifier: a command after && or ;
    # still runs a check. Token boundaries keep comments and quoted echo text out.
    for line in text.splitlines():
        body = line.strip()
        run = re.match(r"(?:-[ \t]+)?run:[ \t]*(.*)$", body)
        if run:
            body = run.group(1)
            if len(body) > 1 and body[0] in "\"'" and body[-1] == body[0]:
                body = body[1:-1]  # YAML quotes around the whole run scalar
        pieces = _WORKFLOW_SHELL_TOKENS.split(body)
        if any(gap.strip() for gap in pieces[::2]):  # unmatched quotes or a trailing escape
            continue
        words = [word for word in pieces[1::2] if not word.startswith("#")]
        starts = [0] + [i + 1 for i, word in enumerate(words)
                        if word in ("&&", "||", ";", "|", "&")]
        for start in starts:
            while start < len(words) and re.match(r"[A-Za-z_][A-Za-z0-9_]*=", words[start]):
                start += 1
            if _RUNS_AEGIS_CHECK.match(shlex.join(words[start:start + 5])):
                return True
    return False
