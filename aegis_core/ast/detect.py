"""Language detection and zero-touch AST driver provisioning for polyglot codebases."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Set, Tuple

from aegis_core.pathlookup import which
from aegis_core.workspace.layout import AEGIS_DIRNAME, LEGACY_SOMA_DIRNAME, WorkspaceLayout

__all__ = [
    "detect_project_languages",
    "resolve_recommended_drivers",
    "provision_ast_driver_slots",
    "packaged_driver_for_extension",
    "names_packaged_driver",
    "LANGUAGE_DEFINITIONS",
    "iter_project_files",
]

_SKIP_DIRS = {
    "__pycache__", ".git", "node_modules", ".pytest_cache",
    ".mypy_cache", ".ruff_cache", "target", "dist", "build",
    AEGIS_DIRNAME, LEGACY_SOMA_DIRNAME, ".tox", ".venv", "venv",
}

# A packaged driver's selector names a v3 staging path; nothing there is ever run (the
# runner always uses the template inside aegis), it only identifies the driver.
_SELECTOR_DIR = f"{AEGIS_DIRNAME}/drivers"
_LEGACY_SELECTOR_DIR = f"{LEGACY_SOMA_DIRNAME}/drivers"

LANGUAGE_DEFINITIONS: Dict[str, Dict[str, Any]] = {
    "rust": {
        "manifests": ["Cargo.toml", "Cargo.lock"],
        "extensions": [".rs"],
        "toolchains": ["cargo", "rustc"],
        "driver_slot": "ast_driver_rs",
        "default_command": f"{{python}} {_SELECTOR_DIR}/rust_ast.py",
        "driver_filename": "rust_ast.py",
    },
    "typescript": {
        "manifests": ["tsconfig.json"],
        "extensions": [".ts", ".tsx", ".mts", ".cts"],
        "toolchains": ["node"],
        "driver_slot": "ast_driver_ts",
        "default_command": f"node {_SELECTOR_DIR}/ts_ast.js",
        "driver_filename": "ts_ast.js",
    },
    "javascript": {
        "manifests": ["package.json"],
        "extensions": [".js", ".jsx", ".mjs", ".cjs"],
        "toolchains": ["node"],
        "driver_slot": "ast_driver_js",
        "default_command": f"node {_SELECTOR_DIR}/ts_ast.js",
        "driver_filename": "ts_ast.js",
    },
    "go": {
        "manifests": ["go.mod", "go.sum"],
        "extensions": [".go"],
        "toolchains": ["go"],
        "driver_slot": "ast_driver_go",
        "default_command": f"go run {_SELECTOR_DIR}/go_ast.go",
        "driver_filename": "go_ast.go",
    },
    "python": {
        "manifests": ["pyproject.toml", "setup.py", "setup.cfg", "requirements.txt", "Pipfile", "poetry.lock"],
        "extensions": [".py"],
        "toolchains": ["python3", "python"],
        "driver_slot": None,  # Handled in-process
        "default_command": None,
        "driver_filename": None,
    },
}


def packaged_driver_for_extension(extension: str) -> Optional[Dict[str, Any]]:
    """Return the language definition whose packaged AST driver handles ``extension``, or None.

    Its ``default_command`` is the repo slot value that opts in to that driver; the
    command itself is never executed (see ``aegis_core.ast.runner``).
    """
    ext = "." + extension.strip().lower().lstrip(".")
    for config in LANGUAGE_DEFINITIONS.values():
        if ext in config["extensions"] and config.get("driver_filename") and config.get("default_command"):
            return config
    return None


def names_packaged_driver(value: str, config: Mapping[str, Any]) -> bool:
    """True for a selector `aegis init` provisioned, including legacy forms like 'python3 .soma/drivers/rust_ast.py'."""
    parts = value.split()
    canonical = str(config["default_command"]).split()
    if len(parts) != len(canonical):
        return False
    if parts[-1] not in (f"{_SELECTOR_DIR}/{config['driver_filename']}", f"{_LEGACY_SELECTOR_DIR}/{config['driver_filename']}"):
        return False
    if canonical[0] == "{python}" and parts[0] in ("python3", "python"):
        return True
    return parts[:-1] == canonical[:-1]


def iter_project_files(project_root: Path | str):
    """Regular project files, without build directories or filesystem links."""
    for dirpath, dirnames, filenames in os.walk(Path(project_root).resolve(), followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not Path(dirpath, d).is_symlink()]
        for name in filenames:
            path = Path(dirpath, name)
            if not path.is_symlink() and path.is_file():
                yield path


def detect_project_languages(project_root: Path | str) -> Dict[str, Dict[str, Any]]:
    """Detect all active programming languages in a project using manifests and source scan."""
    root = Path(project_root).resolve()
    detected: Dict[str, Dict[str, Any]] = {}

    def installed(toolchains: List[str]) -> List[str]:
        # Only what aegis would run: a toolchain the repository itself provides is not one.
        return [t for t in toolchains if which(t, outside=root)]

    # Quick manifest check
    manifest_found: Set[str] = set()
    for lang, config in LANGUAGE_DEFINITIONS.items():
        found_manifests = [m for m in config["manifests"] if (root / m).is_file()]
        if found_manifests:
            detected[lang] = {
                "manifests": found_manifests,
                "extensions": set(),
                "file_count": 0,
                "toolchains": installed(config["toolchains"]),
            }
            manifest_found.add(lang)

    # Scan extensions under root (skipping build/vendor dirs)
    ext_to_lang: Dict[str, str] = {}
    for lang, config in LANGUAGE_DEFINITIONS.items():
        for ext in config["extensions"]:
            ext_to_lang[ext] = lang

    for path in iter_project_files(root):
        ext = path.suffix.lower()
        if ext in ext_to_lang:
            lang = ext_to_lang[ext]
            if lang not in detected:
                detected[lang] = {
                    "manifests": [],
                    "extensions": set(),
                    "file_count": 0,
                    "toolchains": installed(LANGUAGE_DEFINITIONS[lang]["toolchains"]),
                }
            detected[lang]["extensions"].add(ext)
            detected[lang]["file_count"] += 1

    # Normalize sets to sorted lists for JSON serialization
    for lang_data in detected.values():
        lang_data["extensions"] = sorted(lang_data["extensions"])

    return detected


def resolve_recommended_drivers(languages: Dict[str, Any]) -> Dict[str, str]:
    """Map detected languages to the packaged-driver slots (``ast_driver_<ext>``) that cover them."""
    recommended: Dict[str, str] = {}
    for lang in languages:
        config = LANGUAGE_DEFINITIONS.get(lang)
        if not config or not config.get("driver_slot") or not config.get("default_command"):
            continue
        for extension in config["extensions"]:
            recommended[f"ast_driver_{extension.lstrip('.')}"] = config["default_command"]
    return recommended


def provision_ast_driver_slots(
    workspace_root: Path | str,
    languages: Optional[Dict[str, Any]] = None,
    dry_run: bool = False,
) -> Tuple[Dict[str, str], List[str]]:
    """Opt the repo in to the packaged AST drivers for its languages (``ast.packaged_drivers``).

    Only drivers that ship inside aegis can be enabled this way; their commands are never
    read from the repository (H5, D10). Extensions already listed are kept.

    Raises:
        PathTraversalError: ``.aegis`` or ``.aegis/config.json`` is a symlink. Nothing is written.

    Returns:
        (the ``ast_driver_<ext>`` slots the repo opts in to, the files written). An
        existing config.json that cannot be read is left untouched and nothing is written.
    """
    from aegis_core.config import ConfigError, RepoConfig, update_repo_config

    root = Path(workspace_root).resolve()
    if languages is None:
        languages = detect_project_languages(root)
    recommended = resolve_recommended_drivers(languages)
    wanted = [slot[len("ast_driver_"):] for slot in recommended]
    try:
        current = list(RepoConfig.load(root).packaged_drivers)
    except ConfigError:
        return dict(recommended), []
    merged = current + [ext for ext in wanted if ext not in current]
    config_path = WorkspaceLayout(root).config_file
    written: List[str] = []
    if not dry_run and merged and (merged != current or not config_path.is_file()):

        def _enable(data: Dict[str, Any]) -> None:
            # Merge into the file as it is under the lock, not as it was read above:
            # another writer may have listed drivers since.
            listed = list(RepoConfig.parse(data).packaged_drivers)
            ast = data.get("ast") if isinstance(data.get("ast"), dict) else {}
            ast["packaged_drivers"] = listed + [ext for ext in wanted if ext not in listed]
            data["ast"] = ast

        merged = list(RepoConfig.parse(update_repo_config(root, _enable)).packaged_drivers)
        written = [str(config_path)]
    slots = {
        f"ast_driver_{ext}": packaged["default_command"]
        for ext, packaged in ((ext, packaged_driver_for_extension(ext)) for ext in merged)
        if packaged is not None
    }
    return slots, written
