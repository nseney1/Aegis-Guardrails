"""The one place that spells Aegis paths (build-sheet D12).

Repository plane, committed except ``state/``::

    .aegis/
      config.json        repo configuration (aegis_core.config)
      .gitignore         "state/"
      rules/<type>/      rule files
      state/             machine-local, gitignored
        .gitignore       "*": the directory ignores itself even where .aegis/.gitignore
                         lacks "state/" (a v3 workspace not yet migrated)
        ledger.jsonl     the outcome ledger (aegis_core.telemetry_engine.ledger)
        activity.jsonl   MCP scan and edit events (aegis_core.scan_compliance); fitness never reads it
        derived.json     derived views rebuilt by `aegis sync`
        lock             the one workspace lock (aegis_core.storage.locked)

User plane: ``~/.aegis/{rules/, workspaces.json, config.json, backups/}``.

Every other module asks this one for a path instead of joining ``".aegis"`` itself
(a ratchet test enforces it). The v3 names below are kept only for ``aegis migrate``.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
from typing import Optional

AEGIS_DIRNAME = ".aegis"
LEGACY_SOMA_DIRNAME = ".soma"
# The rules directory as a repo-relative POSIX path (what inventories and manifests record).
RULES_RELDIR = f"{AEGIS_DIRNAME}/rules"

# The whole of .aegis/.gitignore that `aegis init` writes: everything machine-local
# lives under state/, so one entry covers it.
GITIGNORE_ENTRIES: tuple[str, ...] = ("state/",)

# ── v3 layout, read only by `aegis migrate` and the upgrade checks ───────────
# Ledger copies, newest-wins order: evidence/ was the live ledger, telemetry/ held
# compaction snapshots of it (a row can be in both).
LEGACY_LEDGER_FILES: tuple[str, ...] = ("evidence/signals.jsonl", "telemetry/signals.jsonl")
# v3.3 `aegis system compact` moved expired rows of each copy into monthly gzip files
# beside it (archive/signals-YYYY-MM.jsonl.gz) and summed them in checkpoint_rollup.json.
LEGACY_LEDGER_ARCHIVE = "archive"
LEGACY_LEDGER_ARCHIVE_GLOB = "*.jsonl.gz"
LEGACY_LEDGER_ROLLUP = "checkpoint_rollup.json"
# Runtime state v4 no longer reads. `aegis migrate --apply` backs these up and removes
# them; entries are relative to .aegis/ (a trailing "/" marks a directory).
LEGACY_STATE_ENTRIES: tuple[str, ...] = (
    "evidence/",          # signals ledger, outcomes, rollups, lifecycle log, arbitration receipts, lock files
    "telemetry/",
    "metrics/",
    "governance/",        # safety-gate event log
    "locks/",
    "keys/",              # HMAC keys for receipts and the v3 manifest
    "rules/manifest.json",  # the v3 signed rule manifest; v4 indexes rules in state/derived.json (D3)
    "manifest.json",      # an older v3 rule manifest location
    "quarantine/",
    "swarm/",
    "handoffs/",
    "drivers/",           # reference copies of the packaged AST drivers; never executed
    "receipt_key",
    "receipts.jsonl",
    "human_insights.jsonl",
    "insight_cursor",
    "jobs_state.json",
    "epoch_generation",
    "migration.lock",
)
# v3 config files that `aegis migrate` converts into config.json (relative to .aegis/,
# except aegis.conf, which lived at the repository root).
LEGACY_REPO_CONF = "aegis.conf"
LEGACY_REPO_CONFS: tuple[str, ...] = (LEGACY_REPO_CONF, "soma.conf")
LEGACY_CONFIG_ENTRIES: tuple[str, ...] = ("slots.yaml", "config.yaml")
# A v3 setting file with no v4 equivalent, at the repository root; migrate reports it.
LEGACY_STEERING_CONF = "steering.conf"
# Where the v1/v2 layout kept rules, relative to its .soma/ directory: cells/<type>/
# (v1, v2.2+) and rules/<type>/ (v2.0, v2.1). Both move to .aegis/rules/<type>/.
LEGACY_RULE_DIRS: tuple[str, ...] = ("cells", "rules")
# The v1/v2 ledger, relative to .soma/.
LEGACY_PREDECESSOR_LEDGER = "evidence/signals.jsonl"
# What only an unmigrated v3 workspace holds, relative to .aegis/: status, scan and sync
# refuse while one exists, check warns (discovery.unmigrated_state).
LEGACY_UPGRADE_MARKERS: tuple[str, ...] = (
    *LEGACY_LEDGER_FILES,
    f"evidence/{LEGACY_LEDGER_ARCHIVE}",
    f"telemetry/{LEGACY_LEDGER_ARCHIVE}",
    *LEGACY_CONFIG_ENTRIES,
    "keys",
    "receipts.jsonl",
    "rules/manifest.json",
)


@dataclass(frozen=True)
class WorkspaceLayout:
    """Paths of one workspace's repository plane."""

    root: Path

    def __post_init__(self) -> None:
        if not isinstance(self.root, Path):
            object.__setattr__(self, "root", Path(os.fspath(self.root)).resolve())

    @property
    def aegis_dir(self) -> Path:
        return self.root / AEGIS_DIRNAME

    @property
    def config_file(self) -> Path:
        return self.aegis_dir / "config.json"

    @property
    def rules_dir(self) -> Path:
        return self.aegis_dir / "rules"

    @property
    def state_dir(self) -> Path:
        return self.aegis_dir / "state"

    @property
    def state_gitignore(self) -> Path:
        return self.state_dir / ".gitignore"

    @property
    def ledger_file(self) -> Path:
        return self.state_dir / "ledger.jsonl"

    @property
    def activity_file(self) -> Path:
        return self.state_dir / "activity.jsonl"

    @property
    def derived_file(self) -> Path:
        return self.state_dir / "derived.json"

    @property
    def lock_file(self) -> Path:
        return self.state_dir / "lock"

    @property
    def lifecycle_log(self) -> Path:
        # Audit trail of `aegis rule prune --execute` moves; machine-local like the ledger.
        return self.state_dir / "lifecycle.jsonl"

    @property
    def predictions_log(self) -> Path:
        # Layer 2 prediction rows (T6, log-only); one writer: aegis check --full. No model text.
        return self.state_dir / "arbiter_predictions.jsonl"

    @property
    def gate_log(self) -> Path:
        # Safety-gate decisions (`aegis hook safety-gate`); machine-local.
        return self.state_dir / "gate_events.jsonl"

    def migrate_backup_dir(self, stamp: str) -> Path:
        return self.state_dir / f"migrate-backup-{stamp}"

    # ── v3 / legacy names (aegis migrate only) ──
    def legacy(self, relative: str) -> Path:
        """A v3 path under .aegis/ named by one of the LEGACY_* entries."""
        return self.aegis_dir / relative.rstrip("/")

    @property
    def legacy_soma_dir(self) -> Path:
        return self.root / LEGACY_SOMA_DIRNAME

    @property
    def legacy_rule_dirs(self) -> tuple[Path, ...]:
        """The v1/v2 rule directories (``.soma/cells``, ``.soma/rules``)."""
        base = self.legacy_soma_dir
        return tuple(base / name for name in LEGACY_RULE_DIRS)

    @property
    def legacy_predecessor_ledger(self) -> Path:
        return self.legacy_soma_dir / LEGACY_PREDECESSOR_LEDGER


@dataclass(frozen=True)
class UserLayout:
    """Paths of the user plane, ``~/.aegis``."""

    home: Path

    @classmethod
    def current(cls) -> Optional["UserLayout"]:
        """The user plane of the running user, or None when no home directory resolves."""
        try:
            return cls(Path.home())
        except (RuntimeError, KeyError, OSError):  # 3.10+: RuntimeError; 3.9: KeyError from pwd
            return None

    @property
    def aegis_dir(self) -> Path:
        return self.home / AEGIS_DIRNAME

    @property
    def rules_dir(self) -> Path:
        return self.aegis_dir / "rules"

    @property
    def workspaces_file(self) -> Path:
        return self.aegis_dir / "workspaces.json"

    @property
    def config_file(self) -> Path:
        return self.aegis_dir / "config.json"

    @property
    def backups_dir(self) -> Path:
        return self.aegis_dir / "backups"

    @property
    def legacy_slots_file(self) -> Path:
        """v3's user slot bindings; v4 reads ``config.json`` instead (aegis migrate reports it)."""
        return self.aegis_dir / "slots.yaml"


def is_aegis_workspace(directory: Path | str) -> bool:
    """True if ``directory`` holds an ``.aegis/`` directory."""
    return (Path(directory) / AEGIS_DIRNAME).is_dir()


def has_rules_dir(directory: Path | str) -> bool:
    """True if ``directory`` holds ``.aegis/rules/``."""
    return (Path(directory) / AEGIS_DIRNAME / "rules").is_dir()


def module_ancestors(rel_path: str) -> list[str]:
    """``rel_path``'s directory (or ``rel_path`` itself if already a directory) and each
    directory above it, nearest first, ending with the workspace root (``''``)."""
    import posixpath

    clean = str(rel_path or "").replace("\\", "/").strip("/")
    if posixpath.splitext(clean)[1].lower() in (".py", ".pyi", ".rs", ".js", ".ts", ".go"):
        directory = posixpath.dirname(clean)
    else:
        directory = clean
    found: list[str] = []
    while directory and directory != ".":
        found.append(directory)
        directory = posixpath.dirname(directory)
    found.append("")
    return found


def resolve_module_file(
    module: str | list[str] | tuple[str, ...],
    known_files: set[str] | frozenset[str],
    *,
    importer: str = "",
    language: str = "python",
) -> Optional[str]:
    """Resolve a module name or segment sequence against ``known_files`` upward from ``importer``."""
    import posixpath

    if isinstance(module, str):
        if language == "rust":
            segments = [p for p in module.split("::") if p and p not in ("crate", "self", "super")]
        else:
            segments = [p for p in module.replace("/", ".").split(".") if p]
    else:
        segments = [str(p) for p in module if p]
    if not segments:
        return None
    files = known_files if isinstance(known_files, (set, frozenset)) else set(known_files)
    tail = "/".join(segments)
    for directory in module_ancestors(importer):
        base = posixpath.join(directory, tail) if directory else tail
        options = (f"{base}.py", f"{base}/__init__.py") if language == "python" else (f"{base}.rs", f"{base}/mod.rs")
        for option in options:
            if option in files:
                return option
    return None


__all__ = [
    "AEGIS_DIRNAME",
    "GITIGNORE_ENTRIES",
    "LEGACY_CONFIG_ENTRIES",
    "LEGACY_LEDGER_ARCHIVE",
    "LEGACY_LEDGER_ARCHIVE_GLOB",
    "LEGACY_LEDGER_FILES",
    "LEGACY_LEDGER_ROLLUP",
    "LEGACY_PREDECESSOR_LEDGER",
    "LEGACY_REPO_CONF",
    "LEGACY_REPO_CONFS",
    "LEGACY_RULE_DIRS",
    "LEGACY_SOMA_DIRNAME",
    "LEGACY_STATE_ENTRIES",
    "LEGACY_STEERING_CONF",
    "LEGACY_UPGRADE_MARKERS",
    "RULES_RELDIR",
    "UserLayout",
    "WorkspaceLayout",
    "has_rules_dir",
    "is_aegis_workspace",
    "module_ancestors",
    "resolve_module_file",
]
