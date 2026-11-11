"""Ratchets for the L0 storage layer (ADR 0005 AD-3, build-sheet D12).

1. In aegis_core/aegis_cli/aegis_mcp/aegis_sdk, literal write-mode ``open``/
   ``fdopen``, ``write_text``, ``write_bytes`` and ``shutil.copy*`` calls outside
   storage require a named non-state writer exemption. Direct ``os.open``,
   ``os.replace``, ``os.rename``, ``os.link``, single-target bound path rename/
   replace calls, and declared forwarding-opener calls require exact reviewed
   counts. Declared openers resolve direct imports, straight-line re-exports,
   constructors and declared methods; their direct call arguments are counted.
   Constructor class identity comparisons remain permitted; other opener loads
   fail. OS imports cannot alias operations; bare module
   loads allow only attribute bases and literal hasattr/getattr probes (getattr
   cannot retrieve a detected operation). Operation loads allow only direct
   calls, reviewed callbacks, direct comparisons and registered capability probes.
   Nonconstant flags passed to os.open or a declared flag-taking opener discover
   forwarding definitions. Every discovered definition must be declared.
2. aegis_core/workspace/layout.py is the only module that spells an ``.aegis`` path.
   User-facing sentences may mention one; a string literal that *is* a path may not.

RF-82b owns the runtime write census for other operation families (shutil.move,
os.renames, os.symlink, Path.symlink_to/hardlink_to, io.open), inherited forwarding
methods, re-exports under module-level control flow or wildcard imports, unbound
Path.replace/rename(src, dst), bound path-method aliases, and ** destination
expansion. Other indirect destination-writer wrappers and alternate module
access (for example posix.open or os.path.os) also belong to RF-82b. This static
ratchet does not claim to see every filesystem write.
"""
from __future__ import annotations

import ast
from collections import defaultdict
from pathlib import Path
import re
import sys

import pytest

from tests.contract.test_process_ratchets import ScopedNames, import_bindings

ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists())
PACKAGES = ("aegis_core", "aegis_cli", "aegis_mcp", "aegis_sdk")

# (file, enclosing function) -> what it writes. Adding an entry is a reviewed decision.
NON_AEGIS_WRITERS = {
    ("aegis_cli/verify.py", "_append_step_summary"): "$GITHUB_STEP_SUMMARY, appended once per run as every job step does (outside the workspace)",
    ("aegis_cli/hooks/commitmsg.py", "install"): "the git prepare-commit-msg hook (.git/hooks)",
    ("aegis_core/baseline.py", "Sources._ast"): "a staged non-Python blob copied into a temporary directory for the AST driver",
    ("aegis_core/ast/gobuild.py", "_build"): "the compiled executable in a confined private user-cache build directory; writable handle only for fsync before atomic publication",
    ("aegis_core/message_codec_store.py", "Store.write"): "content-addressed message records in a caller-bound directory; stdlib-only MC-1 leaf",
    ("aegis_core/verification/runner.py", "snapshot_index"): "staged blobs in a temporary directory (aegis check --hook)",
    ("aegis_core/testexec.py", "run_tests"): "the test run's output in a temporary directory (aegis check --record)",
    ("aegis_core/unittest_runner.py", "_JUnitRunner.run"): "a unittest JUnit report in the caller's temporary directory",
    ("aegis_core/treeid.py", "bind"): "a copy of the git index in a private temporary directory (tree identity)",
    ("aegis_core/benchmark.py", "materialize"): "the fixture corpus in a temporary directory (aegis benchmark)",
    ("aegis_core/release_verify.py", "verify_release"): "the attestation subject in a temporary directory (aegis doctor --release)",
}
_WRITE_MODE = re.compile(r"[wax+]")
_COPIES = {"copy", "copy2", "copyfile", "copytree"}
_OS_OPERATIONS = {"os.open", "os.replace", "os.rename", "os.link"}
_DESCRIPTOR_OPERATIONS = _OS_OPERATIONS | {"path.rename", "path.replace"}

# These atomicio wrappers expose its descriptor opener transitively. Other
# forwarding functions are discovered from nonconstant flags below.
_ATOMIC_WRAPPERS = {
    "aegis_core.atomicio.open_regular", "aegis_core.atomicio.create_private_file",
    "aegis_core.atomicio.atomic_write_bytes", "aegis_core.atomicio.atomic_write_text",
    "aegis_core.atomicio.atomic_write_and_unlink",
}
# Opener -> flags position in a function/bound-method call; None means no flags
# parameter. Fixed-flag readers may remain declared so their calls stay reviewed.
FORWARDING_OPENERS = dict.fromkeys(_ATOMIC_WRAPPERS, None) | {
    "aegis_cli.language_capabilities._package": None,
    "aegis_core.atomicio._open_regular": 1,
    "aegis_core.atomicio.open_regular": 1,
    "aegis_core.config._read_json": None,
    "aegis_core.credit_memo._snapshot": None,
    "aegis_core.credit_memo.filesystem_now": None,
    "aegis_core.insights.keys._ensure_private_dir": None,
    "aegis_core.insights.keys.create_link_key": None,
    "aegis_core.insights.keys.read_link_key": None,
    "aegis_core.language_runtime.read_runtime_report": None,
    "aegis_core.manager_config.public_file": None,
    "aegis_core.manager_store.ManagerStore._anchor": None,
    "aegis_core.manager_store.ManagerStore._audit": 0,
    "aegis_core.manager_store._sync_directory": None,
    "aegis_core.message_codec_store.Store.__init__": None,
    "aegis_core.message_codec_store.Store._open": 1,
    "aegis_core.migrate._input": None,
    "aegis_core.model_select._decision_directory": None,
    "aegis_core.model_select._open_log": None,
    "aegis_core.model_select._open_regular": None,
    "aegis_core.model_select._publish": None,
    "aegis_core.rule_inventory._read_stable_file": None,
    "aegis_core.storage._chmod_exact": None,
    "aegis_core.storage._file_lock_at": None,
    "aegis_core.storage.message_store": None,
    "aegis_core.storage.read_json_dict": None,
    "aegis_core.storage.read_jsonl": None,
    "aegis_core.storage.read_tail_bytes": None,
    "aegis_core.team.load_team": None,
    "aegis_core.testexec._inspect_junit": None,
    "aegis_core.verification.runner._identical_work_file": None,
    "aegis_core.verification.scanners._SarifLineCache.fill": None,
    "aegis_core.verification.scanners._sarif_open_artifact": None,
    "aegis_core.workspace.confinement.read_confined_bytes": None,
}
_PARTIAL_OPENERS = {
    "aegis_core.migrate._input": "aegis_core.workspace.confinement.read_confined_bytes",
}
CAPABILITY_REFERENCES = {
    ("aegis_core/model_select.py", "<module>", "os.open"): "probe directory-descriptor support before any decision-log I/O",
    ("aegis_core/model_select.py", "<module>", "os.rename"): "probe anchored rename support before decision-log publication",
}
_CAPABILITY_PROBE = ast.dump(ast.parse(
    "all(fn in os.supports_dir_fd for fn in (os.open, os.stat, os.rename, os.unlink))",
    mode="eval",
).body)
CALLBACK_EXCEPTIONS = {
    ("aegis_core/model_select.py", "_decision_directory", "os.open", "_path_call"): (
        3, "O_RDONLY|O_DIRECTORY|O_NOFOLLOW directory walk through the reviewed path-error boundary",
    ),
    ("aegis_core/model_select.py", "_open_log", "os.open", "_path_call"): (
        1, "reviewed decision-log reader opens O_RDONLY|O_NOFOLLOW|O_NONBLOCK through the path-error boundary",
    ),
    ("aegis_core/model_select.py", "_publish", "os.open", "_path_call"): (
        1, "reviewed writer exclusively creates the temporary decision log within its bound directory",
    ),
    ("aegis_core/model_select.py", "_publish", "os.rename", "_path_call"): (
        1, "reviewed writer publishes the temporary decision log within the same bound directory",
    ),
}

# (file, scope, operation) -> (exact call sites, reason). No scope-wide bypass:
# another call in an already reviewed function still requires explicit review.
REVIEWED_DESCRIPTOR_OPERATIONS = {
    ("aegis_cli/hooks/registrar.py", "install_insight_hook", "aegis_core.insights.keys.create_link_key"): (1, "initialize the user link key through storage and verify an existing key"),
    ("aegis_cli/init.py", "_config_hosts", "aegis_core.workspace.confinement.read_confined_bytes"): (2, "read-only bounded existing config or migration source bytes"),
    ("aegis_cli/init.py", "_link_key_step", "aegis_core.insights.keys.create_link_key"): (1, "initialize the user link key through storage and verify an existing key"),
    ("aegis_cli/language_capabilities.py", "runner_suggestion", "aegis_cli.language_capabilities._package"): (1, "read package metadata for the suggested language runner"),
    ("aegis_cli/msg.py", "_open_store", "aegis_core.message_codec_store.Store.__init__"): (1, "bind the explicit caller-selected message store through its public re-export"),
    ("aegis_cli/msg.py", "_open_store", "aegis_core.storage.message_store"): (1, "use the required storage boundary for a workspace-bound message store"),
    ("aegis_cli/verify.py", "_run_calibration", "aegis_core.storage.read_jsonl"): (1, "read calibration predictions through the storage boundary"),
    ("aegis_core/atomicio.py", "atomic_write_and_unlink", "aegis_core.atomicio.atomic_write_text"): (1, "atomic L0 publication delegated to by atomic_write_and_unlink"),
    ("aegis_core/atomicio.py", "atomic_write_text", "aegis_core.atomicio.atomic_write_bytes"): (1, "atomic L0 publication for the delegate or git tree export targets"),
    ("aegis_core/atomicio.py", "create_private_file", "aegis_core.atomicio._open_regular"): (1, "shared L0 regular-file descriptor delegate; caller supplies the reviewed read or private-create flags"),
    ("aegis_core/atomicio.py", "open_regular", "aegis_core.atomicio._open_regular"): (1, "shared L0 regular-file descriptor delegate; caller supplies the reviewed read or private-create flags"),
    ("aegis_core/config.py", "RepoConfig.load", "aegis_core.config._read_json"): (1, "read-only bounded repository or user config inspection"),
    ("aegis_core/config.py", "UserConfig.load", "aegis_core.config._read_json"): (1, "read-only bounded repository or user config inspection"),
    ("aegis_core/config.py", "read_user_config", "aegis_core.config._read_json"): (1, "read-only bounded repository or user config inspection"),
    ("aegis_core/config.py", "update_repo_config", "aegis_core.config._read_json"): (1, "read-only bounded repository or user config inspection"),
    ("aegis_core/checkrun.py", "record", "aegis_core.storage.read_jsonl"): (1, "read earlier check records through the storage boundary"),
    ("aegis_core/credit.py", "_read_ledger_events", "aegis_core.storage.read_jsonl"): (1, "read credit ledger events through the storage boundary"),
    ("aegis_core/credit_memo.py", "_snapshot", "aegis_core.atomicio._open_regular"): (1, "shared L0 regular-file descriptor delegate; caller supplies the reviewed read or private-create flags"),
    ("aegis_core/credit_memo.py", "before_read", "aegis_core.credit_memo.filesystem_now"): (1, "sample the held lock file's filesystem clock for ledger evidence"),
    ("aegis_core/credit_memo.py", "contains", "aegis_core.credit_memo._snapshot"): (1, "read-only persisted-ledger generation snapshot"),
    ("aegis_core/credit_memo.py", "remember", "aegis_core.credit_memo._snapshot"): (1, "read-only persisted-ledger generation snapshot"),
    ("aegis_core/events.py", "read", "aegis_core.storage.read_jsonl"): (1, "read stored events through the storage boundary"),
    ("aegis_core/fitness.py", "_collect_t4_events_for_rules", "aegis_core.storage.read_jsonl"): (1, "read fitness ledger events through the storage boundary"),
    ("aegis_core/gitsafe.py", "export_tree", "aegis_core.atomicio.atomic_write_bytes"): (2, "atomic L0 publication for the delegate or git tree export targets"),
    ("aegis_core/insights/capture.py", "capture_suggestion", "aegis_core.insights.keys._ensure_private_dir"): (2, "create private user insight directories and verify descriptor permissions"),
    ("aegis_core/insights/capture.py", "_known_inventory_revs", "aegis_core.storage.read_jsonl"): (1, "read stored inventory revisions through the storage boundary"),
    ("aegis_core/insights/capture.py", "_read_rows_of_session", "aegis_core.storage.read_jsonl"): (1, "read session insight rows through the storage boundary"),
    ("aegis_core/insights/capture.py", "capture_suggestion", "aegis_core.storage.read_jsonl"): (2, "read existing suggestions and hooks through the storage boundary"),
    ("aegis_core/insights/keys.py", "_append_user_insights", "aegis_core.insights.keys._ensure_private_dir"): (2, "create private user insight directories and verify descriptor permissions"),
    ("aegis_core/insights/keys.py", "_ensure_hs", "aegis_core.insights.keys.create_link_key"): (1, "initialize the user link key through storage and verify an existing key"),
    ("aegis_core/insights/keys.py", "_ensure_hs", "aegis_core.insights.keys.read_link_key"): (2, "read-only user link key for session hashing"),
    ("aegis_core/insights/keys.py", "create_link_key", "aegis_core.insights.keys._ensure_private_dir"): (1, "create private user insight directories and verify descriptor permissions"),
    ("aegis_core/insights/keys.py", "session_hs", "aegis_core.insights.keys.read_link_key"): (1, "read-only user link key for session hashing"),
    ("aegis_core/insights/keys.py", "read_insight_rows", "aegis_core.storage.read_jsonl"): (1, "read stored insight rows through the storage boundary"),
    ("aegis_core/lane_gate.py", "check_lane", "aegis_core.team.load_team"): (1, "read-only team policy for lane admission"),
    ("aegis_core/language_runtime.py", "_probe", "aegis_core.language_runtime.read_runtime_report"): (1, "read-only bounded runtime, coverage or test-runner report"),
    ("aegis_core/manager_config.py", "initialize", "aegis_core.manager_config.public_file"): (1, "read-only bounded public signer or private manager config inspection"),
    ("aegis_core/manager_config.py", "initialize.create", "aegis_core.atomicio.create_private_file"): (2, "exclusive private manager config or temporary owner-signature verifier input"),
    ("aegis_core/manager_config.py", "initialize.create", "aegis_core.manager_config.public_file"): (1, "read-only bounded public signer or private manager config inspection"),
    ("aegis_core/manager_config.py", "load_config", "aegis_core.manager_config.public_file"): (2, "read-only bounded public signer or private manager config inspection"),
    ("aegis_core/manager_config.py", "verify_owner", "aegis_core.atomicio.create_private_file"): (1, "exclusive private manager config or temporary owner-signature verifier input"),
    ("aegis_core/manager_config.py", "verify_owner", "aegis_core.manager_config.public_file"): (1, "read-only bounded public signer or private manager config inspection"),
    ("aegis_core/manager_store.py", "ManagerStore._append", "aegis_core.manager_store.ManagerStore._audit"): (1, "read or append the separate manager audit log with caller-selected flags"),
    ("aegis_core/manager_store.py", "ManagerStore._append", "aegis_core.manager_store._sync_directory"): (1, "directory durability for the separate manager audit store"),
    ("aegis_core/manager_store.py", "ManagerStore._check", "aegis_core.manager_store._sync_directory"): (1, "directory durability for the separate manager audit store"),
    ("aegis_core/manager_store.py", "ManagerStore._locked", "aegis_core.manager_store.ManagerStore._anchor"): (1, "bind directory descriptors for the separate manager audit store"),
    ("aegis_core/manager_store.py", "ManagerStore._read", "aegis_core.manager_store.ManagerStore._audit"): (1, "read or append the separate manager audit log with caller-selected flags"),
    ("aegis_core/manager_store.py", "ManagerStore.read", "aegis_core.manager_store.ManagerStore._anchor"): (1, "bind directory descriptors for the separate manager audit store"),
    ("aegis_core/message_codec_store.py", "Store._read_bytes", "aegis_core.message_codec_store.Store._open"): (1, "read or exclusively create a message record in the bound private store"),
    ("aegis_core/message_codec_store.py", "Store.write", "aegis_core.message_codec_store.Store._open"): (1, "read or exclusively create a message record in the bound private store"),
    ("aegis_core/message_codec_store.py", "Store.write", "os.link"): (1, "publish a content-addressed message record within the bound private message store"),
    ("aegis_core/migrate.py", "<module>", "aegis_core.workspace.confinement.read_confined_bytes"): (1, "read-only bounded existing config or migration source bytes"),
    ("aegis_core/migrate.py", "_plan_rules", "aegis_core.migrate._input"): (2, "bounded migration rule and target reads through the declared partial"),
    ("aegis_core/migrate.py", "apply", "aegis_core.migrate._input"): (2, "bounded config and unchanged-input reads through the declared partial"),
    ("aegis_core/model_select.py", "_input", "aegis_core.model_select._open_regular"): (1, "read-only bounded decision input config inspection"),
    ("aegis_core/model_select.py", "_publish", "aegis_core.model_select._open_log"): (1, "read-only replay of the bound decision log"),
    ("aegis_core/model_select.py", "_read_rows", "aegis_core.model_select._decision_directory"): (1, "validate and bind the caller-selected decision log directory"),
    ("aegis_core/model_select.py", "_read_rows", "aegis_core.model_select._open_log"): (3, "read-only replay of the bound decision log"),
    ("aegis_core/model_select.py", "append_decision", "aegis_core.model_select._decision_directory"): (1, "validate and bind the caller-selected decision log directory"),
    ("aegis_core/model_select.py", "append_decision", "aegis_core.model_select._publish"): (1, "atomic publication of the caller-selected decision log"),
    ("aegis_core/model_select.py", "select_and_append", "aegis_core.model_select._decision_directory"): (1, "validate and bind the caller-selected decision log directory"),
    ("aegis_core/model_select.py", "select_and_append", "aegis_core.model_select._publish"): (1, "atomic publication of the caller-selected decision log"),
    ("aegis_core/packaging.py", "_is_ours", "aegis_core.storage.read_json_dict"): (1, "read the existing export manifest through the storage boundary"),
    ("aegis_core/rule_inventory.py", "inventory_rules", "aegis_core.rule_inventory._read_stable_file"): (1, "read-only bounded stable rule inventory bytes"),
    ("aegis_core/scan_compliance.py", "_tail", "aegis_core.storage.read_tail_bytes"): (1, "read bounded compliance evidence through the storage boundary"),
    ("aegis_core/scan_compliance.py", "report", "aegis_core.storage.read_jsonl"): (1, "read stored scan activity through the storage boundary"),
    ("aegis_core/sync.py", "read_derived", "aegis_core.storage.read_json_dict"): (1, "read derived metadata through the storage boundary"),
    ("aegis_core/telemetry_engine/ledger.py", "_unread", "aegis_core.atomicio.open_regular"): (1, "read-only regular-file descriptor for bounded ledger or SARIF inspection"),
    ("aegis_core/telemetry_engine/ledger.py", "_unread", "aegis_core.credit_memo.filesystem_now"): (1, "sample the held lock file's filesystem clock for ledger evidence"),
    ("aegis_core/telemetry_engine/ledger.py", "_read_worktree_ledger", "aegis_core.storage.read_jsonl"): (1, "read the worktree ledger through the storage boundary"),
    ("aegis_core/telemetry_engine/ledger.py", "merge_rows_report", "aegis_core.storage.read_jsonl"): (1, "read existing merge rows through the storage boundary"),
    ("aegis_core/telemetry_engine/ledger.py", "read", "aegis_core.storage.read_jsonl"): (1, "read ledger rows through the storage boundary"),
    ("aegis_core/testexec.py", "_tail", "aegis_core.storage.read_tail_bytes"): (1, "read bounded test output through the storage boundary"),
    ("aegis_core/testexec.py", "parse_junit_cases", "aegis_core.testexec._inspect_junit"): (1, "read-only bounded JUnit report inspection"),
    ("aegis_core/testexec.py", "run_tests", "aegis_core.testexec._inspect_junit"): (1, "read-only bounded JUnit report inspection"),
    ("aegis_core/verification/coverage_check.py", "_module_prefix", "aegis_core.language_runtime.read_runtime_report"): (1, "read-only bounded runtime, coverage or test-runner report"),
    ("aegis_core/verification/coverage_check.py", "_native_coverage", "aegis_core.language_runtime.read_runtime_report"): (2, "read-only bounded runtime, coverage or test-runner report"),
    ("aegis_core/verification/language_tests.py", "run_language_snapshot", "aegis_core.language_runtime.read_runtime_report"): (2, "read-only bounded runtime, coverage or test-runner report"),
    ("aegis_core/verification/regression_identity.py", "_metadata", "aegis_core.language_runtime.read_runtime_report"): (2, "read-only bounded runtime, coverage or test-runner report"),
    ("aegis_core/verification/regression_identity.py", "_module_files", "aegis_core.language_runtime.read_runtime_report"): (1, "read-only bounded runtime, coverage or test-runner report"),
    ("aegis_core/verification/regression_identity.py", "_rust", "aegis_core.language_runtime.read_runtime_report"): (1, "read-only bounded runtime, coverage or test-runner report"),
    ("aegis_core/verification/runner.py", "_t7_on_index", "aegis_core.verification.runner._identical_work_file"): (1, "read-only comparison of worktree bytes with the selected git object"),
    ("aegis_core/verification/scanners.py", "_SarifLineCache.fill", "aegis_core.verification.scanners._sarif_open_artifact"): (1, "read-only descriptor-confined SARIF artifact inspection"),
    ("aegis_core/verification/scanners.py", "_sarif_open_by_path", "aegis_core.atomicio.open_regular"): (1, "read-only regular-file descriptor for bounded ledger or SARIF inspection"),
    ("aegis_core/verification/scanners.py", "ingest_sarif", "aegis_core.verification.scanners._SarifLineCache.fill"): (1, "read-only batched source excerpts for SARIF findings"),
    ("aegis_core/workspace/confinement.py", "finish_file_move", "path.rename"): (1, "normalize directory case for the same existing source and target directory during file migration"),
    ("aegis_mcp/handlers/msg.py", "_store", "aegis_core.storage.message_store"): (1, "use the required storage boundary for a workspace-bound message store"),
    ("aegis_cli/language_capabilities.py", "_package", "os.open"): (1, "read-only package metadata inspection"),
    ("aegis_core/ast/gobuild.py", "_build", "os.replace"): (1, "publish the compiled executable in the private user-cache build directory"),
    ("aegis_core/atomicio.py", "_open_regular", "os.open"): (1, "shared L0 regular-file opener delegated to by storage; flags belong to its callers"),
    ("aegis_core/atomicio.py", "_replace_with_retry", "os.replace"): (1, "shared L0 atomic publication primitive delegated to by storage"),
    ("aegis_core/atomicio.py", "atomic_write_bytes", "os.open"): (1, "shared L0 temporary-file writer re-exported by storage"),
    ("aegis_core/atomicio.py", "fsync_dir", "os.open"): (1, "read-only directory descriptor for storage's durability primitive"),
    ("aegis_core/config.py", "_read_json", "os.open"): (1, "read-only bounded config inspection"),
    ("aegis_core/credit_memo.py", "_snapshot", "os.open"): (3, "read-only ancestor walk and credit memo snapshot"),
    ("aegis_core/credit_memo.py", "filesystem_now", "os.open"): (3, "read-only ancestor walk and file timestamp inspection"),
    ("aegis_core/insights/keys.py", "_ensure_private_dir", "os.open"): (1, "read-only directory descriptor for permission checks"),
    ("aegis_core/insights/keys.py", "create_link_key", "os.open"): (1, "read-only verification of the key created through storage"),
    ("aegis_core/insights/keys.py", "read_link_key", "os.open"): (1, "read-only link key inspection"),
    ("aegis_core/language_runtime.py", "read_runtime_report", "os.open"): (1, "read-only bounded runtime report inspection"),
    ("aegis_core/lifecycle/selection.py", "_park", "os.replace"): (1, "existing rule archival moves a rule into its archive; no new content is authored"),
    ("aegis_core/manager_config.py", "public_file", "os.open"): (1, "read-only public manager config inspection"),
    ("aegis_core/manager_store.py", "ManagerStore._anchor", "os.open"): (3, "read-only directory walk for the separate manager audit store"),
    ("aegis_core/manager_store.py", "ManagerStore._audit", "os.open"): (1, "manager audit log outside repository worktrees; read/append flags supplied by callers"),
    ("aegis_core/manager_store.py", "_sync_directory", "os.open"): (1, "read-only directory descriptor for audit durability"),
    ("aegis_core/message_codec_store.py", "Store.__init__", "os.open"): (3, "read-only directory walk binding the message store root"),
    ("aegis_core/message_codec_store.py", "Store._open", "os.open"): (1, "MC-1 stdlib-only message store opener used by its reviewed writer and readers"),
    ("aegis_core/message_codec_store.py", "Store._resolve", "os.open"): (1, "read-only directory descriptor for message reference lookup"),
    ("aegis_core/model_select.py", "_decision_directory", "os.open"): (3, "read-only directory walk binding the caller's decision log directory"),
    ("aegis_core/model_select.py", "_open_log", "os.open"): (1, "read-only decision log inspection"),
    ("aegis_core/model_select.py", "_open_regular", "os.open"): (3, "read-only ancestor walk and decision config inspection"),
    ("aegis_core/model_select.py", "_publish", "os.open"): (1, "descriptor-confined temporary decision log in a caller-selected directory"),
    ("aegis_core/model_select.py", "_publish", "os.rename"): (1, "publish the decision log within the same bound directory"),
    ("aegis_core/rule_inventory.py", "_read_stable_file", "os.open"): (1, "read-only stable rule snapshot"),
    ("aegis_core/team.py", "load_team", "os.open"): (1, "read-only team metadata inspection"),
    ("aegis_core/testexec.py", "_inspect_junit", "os.open"): (1, "read-only bounded test report inspection"),
    ("aegis_core/verification/runner.py", "_identical_work_file", "os.open"): (1, "read-only working file comparison"),
    ("aegis_core/verification/scanners.py", "_SarifLineCache.fill", "os.open"): (1, "read-only SARIF root directory descriptor"),
    ("aegis_core/verification/scanners.py", "_sarif_open_artifact", "os.open"): (2, "read-only confined SARIF artifact directory walk and file inspection"),
    ("aegis_core/workspace/confinement.py", "read_confined_bytes", "os.open"): (1, "read-only bounded confined file inspection"),
}


def _sources():
    for pkg in PACKAGES:
        for path in sorted((ROOT / pkg).rglob("*.py")):
            yield path.relative_to(ROOT).as_posix(), ast.parse(path.read_text(encoding="utf-8"))


def _forwarding_exports(sources):
    exports = {}
    known = FORWARDING_OPENERS.keys() | {name.removesuffix(".__init__") for name in FORWARDING_OPENERS}
    bindings = []
    for rel, tree in sources:
        module = rel.removesuffix(".py").replace("/", ".").removesuffix(".__init__")
        for node in tree.body:
            for alias, target in import_bindings(node, rel).items():
                # Public storage entry points are the required write boundary.
                if rel != "aegis_core/storage.py" or alias.startswith("_"):
                    bindings.append((module + "." + alias, target))
    while True:
        before = dict(exports)
        for alias, target in bindings:
            target = exports.get(target, target)
            if target in known:
                exports[alias] = target
        if before == exports:
            return exports


def _forwarding_methods(sources):
    classes = set()
    def visit(node, scope):
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            scope += "." + node.name
            if isinstance(node, ast.ClassDef):
                classes.add(scope)
        for child in ast.iter_child_nodes(node):
            visit(child, scope)
    for rel, tree in sources:
        visit(tree, rel.removesuffix(".py").replace("/", "."))
    return {name for name in FORWARDING_OPENERS if name.rsplit(".", 1)[0] in classes}


class _Writes(ast.NodeVisitor):
    def __init__(self, rel="<probe>", exports=None, methods=()) -> None:
        self.rel = rel
        self.module = rel.removesuffix(".py").replace("/", ".")
        self.stack: list[str] = []
        self.found: list[tuple[str, int, str]] = []
        self.errors = []
        self.references = []
        self.callbacks = []
        self.definitions = {}
        self.forwarding = {}
        self.functions = []
        self.classes = []
        self.exports = exports or {}
        self.methods = methods

    def visit_Module(self, node):
        self.parents = {child: parent for parent in ast.walk(node) for child in ast.iter_child_nodes(parent)}
        self.names = ScopedNames(node, self.rel)
        self.generic_visit(node)

    def _refuse(self, node, reason):
        self.errors.append(f"{self.rel}:{node.lineno} {'.'.join(self.stack) or '<module>'}: {reason}")

    def visit_Import(self, node):
        if any(alias.name == "os" and alias.asname is not None for alias in node.names):
            self._refuse(node, "forbidden OS import alias")

    def visit_ImportFrom(self, node):
        if node.module == "os" and any(f"os.{alias.name}" in _OS_OPERATIONS or alias.name == "*" for alias in node.names):
            self._refuse(node, "forbidden OS operation import")

    def _builtin(self, node, name):
        if not isinstance(node, ast.Name) or node.id != name:
            return False
        scope = self.names.at[id(node)]
        while scope is not None:
            if name in scope.bound:
                return False
            scope = scope.parent
        return True

    def visit_Name(self, node):
        if not isinstance(node.ctx, ast.Load):
            return
        if "os" in self.names.resolve(node):
            parent = self.parents[node]
            attribute_base = isinstance(parent, ast.Attribute) and parent.value is node
            probe = (
                isinstance(parent, ast.Call) and not parent.keywords
                and len(parent.args) in (2, 3) and parent.args[0] is node
                and isinstance(parent.args[1], ast.Constant) and isinstance(parent.args[1].value, str)
                and ((self._builtin(parent.func, "hasattr") and len(parent.args) == 2)
                     or (self._builtin(parent.func, "getattr") and f"os.{parent.args[1].value}" not in _OS_OPERATIONS))
            )
            if not attribute_base and not probe:
                self._refuse(node, "forbidden OS module reference")
        self._check_opener_reference(node)

    def _check_opener_reference(self, node):
        operation = self._forwarding_call(node)
        if operation:
            parent = self.parents[node]
            # A constructor's class object is also used for identity checks;
            # a direct comparison does not load or call its __init__ method.
            class_object = operation.endswith(".__init__") and not (
                isinstance(node, ast.Attribute) and node.attr == "__init__")
            if class_object and isinstance(parent, ast.Compare):
                return
            if class_object and isinstance(parent, ast.Attribute) and self._forwarding_call(parent):
                return  # Namespace of a declared method, checked at that load.
            counted = isinstance(parent, ast.Call) and (parent.func is node or node in parent.args)
            if isinstance(parent, ast.keyword) and parent.value is node:
                counted = isinstance(self.parents[parent], ast.Call)
            if not counted:
                self._refuse(node, f"forbidden forwarding opener reference: {operation}")

    def visit_Assign(self, node):
        if not self.stack and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            qualified = self.module + "." + node.targets[0].id
            value = node.value
            if (qualified in _PARTIAL_OPENERS and isinstance(value, ast.Call)
                    and "functools.partial" in self.names.resolve(value.func)
                    and value.args and self._forwarding_call(value.args[0]) == _PARTIAL_OPENERS[qualified]):
                self.forwarding[qualified] = node.lineno
        self.generic_visit(node)

    def visit_Attribute(self, node):
        operation = self._descriptor_operation(node)
        if operation and isinstance(node.ctx, ast.Load):
            parent = self.parents[node]
            if isinstance(parent, ast.Call) and parent.func is node:
                allowed = True
            else:
                scope = ".".join(self.stack) or "<module>"
                allowed = isinstance(parent, ast.Compare) and node in [parent.left, *parent.comparators]
                # Only a direct first argument has the reviewed callback shape.
                if (isinstance(parent, ast.Call) and isinstance(parent.func, ast.Name)
                        and parent.args and parent.args[0] is node):
                    key = (self.rel, scope, operation, parent.func.id)
                    self.callbacks.append((self.rel, scope, node.lineno, operation, parent.func.id))
                    allowed |= key in CALLBACK_EXCEPTIONS
                while parent is not None:
                    if isinstance(parent, ast.Call) and ast.dump(parent) == _CAPABILITY_PROBE:
                        self.references.append((self.rel, scope, node.lineno, operation))
                        allowed = True
                        break
                    parent = self.parents.get(parent)
            if not allowed:
                self._refuse(node, f"forbidden OS operation reference: {operation}")
        if isinstance(node.ctx, ast.Load):
            self._check_opener_reference(node)
        self.generic_visit(node)

    def _scope(self, node) -> None:
        self.stack.append(node.name)
        qualified = self.module + "." + ".".join(self.stack)
        self.definitions[qualified] = node.lineno
        is_class = isinstance(node, ast.ClassDef)
        (self.classes if is_class else self.functions).append(qualified)
        if qualified in _ATOMIC_WRAPPERS:
            self.forwarding[qualified] = node.lineno
        self.generic_visit(node)
        (self.classes if is_class else self.functions).pop()
        self.stack.pop()

    visit_FunctionDef = visit_AsyncFunctionDef = visit_ClassDef = _scope

    def visit_Call(self, node: ast.Call) -> None:
        func, what = node.func, None
        if self._descriptor_operation(func):
            what = self._descriptor_operation(func)
        elif isinstance(func, ast.Name) and func.id == "open":
            what = self._mode(node, 1)
        elif isinstance(func, ast.Attribute):
            if func.attr in ("write_text", "write_bytes"):
                what = func.attr
            elif func.attr == "open":
                what = self._mode(node, 0)
            elif func.attr == "fdopen":
                what = self._mode(node, 1)
            elif func.attr in _COPIES and isinstance(func.value, ast.Name) and func.value.id == "shutil":
                what = f"shutil.{func.attr}"
            elif func.attr in ("rename", "replace") and (
                    (len(node.args) == 1 and not node.keywords)
                    or any(kw.arg == "target" for kw in node.keywords)):
                what = f"path.{func.attr}"
        forwarded = self._forwarding_call(func)
        if forwarded:
            what = forwarded
        if what:
            self.found.append((".".join(self.stack) or "<module>", node.lineno, what))
        if what == "os.open":
            self._check_flags(node, 1)
        elif forwarded and FORWARDING_OPENERS[forwarded] is not None:
            self._check_flags(node, self._flags_position(func, forwarded))
        # Count the existing boundary's operation as well as refusing an
        # unregistered non-call reference. An unseen form must fail closed.
        for argument in [*node.args, *(kw.value for kw in node.keywords)]:
            operation = self._descriptor_operation(argument) or self._forwarding_call(argument)
            if operation:
                self.found.append((".".join(self.stack) or "<module>", node.lineno, operation))
                if operation == "os.open":
                    self._check_flags(node, node.args.index(argument) + 2 if argument in node.args else len(node.args))
                elif operation in FORWARDING_OPENERS and FORWARDING_OPENERS[operation] is not None:
                    offset = node.args.index(argument) + 1 if argument in node.args else len(node.args)
                    self._check_flags(node, offset + self._flags_position(argument, operation))
        self.generic_visit(node)

    def _flags_position(self, func, operation):
        index = FORWARDING_OPENERS[operation]
        if (operation in self.methods and isinstance(func, ast.Attribute)
                and operation.rsplit(".", 1)[0] in self.names.resolve(func.value)):
            index += 1  # Explicit class.method(self, ...) keeps the receiver.
        return index

    def _forwarding_call(self, node):
        resolved = set(self.names.resolve(node))
        if isinstance(node, ast.Name):
            resolved |= {self.module + "." + node.id}
        elif (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
              and node.value.id in ("self", "cls") and self.classes):
            resolved |= {self.classes[-1] + "." + node.attr}
        elif isinstance(node, ast.Attribute) and not resolved and node.attr != "__init__":
            # An arbitrary receiver has no statically known type. Review all
            # matching declared method forms instead of silently losing a call.
            resolved |= {name for name in self.methods if name.endswith("." + node.attr)}
        resolved = {self.exports.get(name, name) for name in resolved}
        resolved |= {name + ".__init__" for name in resolved}
        found = resolved & FORWARDING_OPENERS.keys()
        if len(found) > 1:
            self._refuse(node, "ambiguous forwarding opener call")
        return sorted(found)[0] if found else None

    def _check_flags(self, node, index):
        flags = next((kw.value for kw in node.keywords if kw.arg == "flags"),
                     node.args[index] if len(node.args) > index else None)
        # Expansion can move runtime flags away from this AST position. Flags
        # supplied only through **kwargs already remain unknown (None).
        if any(isinstance(argument, ast.Starred) for argument in node.args[:index + 1]):
            flags = None
        if self.functions:
            function = self.functions[-1]
            if function in FORWARDING_OPENERS or not _constant_flags(flags):
                self.forwarding[function] = self.definitions[function]

    @staticmethod
    def _descriptor_operation(node):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "os":
            operation = f"os.{node.attr}"
            if operation in _OS_OPERATIONS:
                return operation
        return None

    @staticmethod
    def _mode(node: ast.Call, index: int):
        mode = node.args[index] if len(node.args) > index else None
        for kw in node.keywords:
            if kw.arg == "mode":
                mode = kw.value
        if isinstance(mode, ast.Constant) and isinstance(mode.value, str) and _WRITE_MODE.search(mode.value):
            return f"open({mode.value!r})"
        return None


def _constant_flags(node):
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return node.value.id == "os" and node.attr.startswith("O_")
    if isinstance(node, ast.Constant):
        return type(node.value) is int
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "getattr"
            and not node.keywords and len(node.args) == 3
            and isinstance(node.args[0], ast.Name) and node.args[0].id == "os"
            and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str)
            and node.args[1].value.startswith("O_")
            and isinstance(node.args[2], ast.Constant) and type(node.args[2].value) is int):
        return True
    return (isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr)
            and _constant_flags(node.left) and _constant_flags(node.right))


def _reviewed_operation(what):
    return what in _DESCRIPTOR_OPERATIONS or what in FORWARDING_OPENERS


def _descriptor_errors(sites, reviewed):
    observed = defaultdict(list)
    for rel, scope, lineno, operation in sites:
        observed[(rel, scope, operation)].append(lineno)
    errors = []
    for key, lines in sorted(observed.items()):
        rel, scope, operation = key
        location = f"{rel}:{','.join(map(str, lines))} {scope} {operation}"
        if key not in reviewed:
            errors.append(f"{location}: unreviewed descriptor operation")
        elif len(lines) > reviewed[key][0]:
            errors.append(f"{location}: reviewed count {reviewed[key][0]} -> {len(lines)}")
        elif len(lines) < reviewed[key][0]:
            errors.append(f"{location}: lower to {len(lines)} (reviewed {reviewed[key][0]})")
    for rel, scope, operation in sorted(reviewed.keys() - observed.keys()):
        errors.append(f"{rel} {scope} {operation}: stale: remove")
    return errors


def _callback_errors(sites, reviewed, scopes=None):
    observed = defaultdict(list)
    for rel, scope, line, operation, callee in sites:
        observed[(rel, scope, operation, callee)].append(line)
    errors = []
    for (rel, scope, operation, callee), lines in sorted(observed.items()):
        location = f"{rel}:{','.join(map(str, lines))} {scope} {operation} via {callee}"
        key = (rel, scope, operation, callee)
        if key not in reviewed:
            errors.append(f"{location}: unreviewed OS callback")
        elif len(lines) != reviewed[key][0]:
            errors.append(f"{location}: reviewed callback count {reviewed[key][0]} -> {len(lines)}")
    for rel, scope, operation, callee in sorted(reviewed.keys() - observed.keys()):
        line = (scopes or {}).get((rel, scope), 1)
        errors.append(f"{rel}:{line} {scope} {operation} via {callee}: stale callback: remove")
    return errors


def _capability_errors(sites, reviewed, scopes):
    observed = {(rel, scope, operation) for rel, scope, _line, operation in sites}
    errors = [
        f"{rel}:{line} {scope} {operation}: unreviewed capability reference"
        for rel, scope, line, operation in sites if (rel, scope, operation) not in reviewed
    ]
    for rel, scope, operation in sorted(reviewed.keys() - observed):
        line = scopes.get((rel, scope), 1)
        errors.append(f"{rel}:{line} {scope} {operation}: stale capability reference: remove")
    return errors


@pytest.mark.parametrize("operation", ["open", "replace", "rename", "link"])
def test_descriptor_operations_are_reviewed(operation):
    arguments = "path, flags=os.O_CREAT | os.O_WRONLY" if operation == "open" else "src=old, dst=new"
    call = f"os.{operation}({arguments})"
    visitor = _Writes()
    visitor.visit(ast.parse(f"class Store:\n    async def publish(self):\n        {call}\n"))
    assert visitor.found == [("Store.publish", 3, f"os.{operation}")]


@pytest.mark.parametrize("flags", [
    "os.O_CREAT", "os.O_WRONLY", "os.O_RDWR", "os.O_APPEND", "os.O_TRUNC",
    "os.O_WRONLY | os.O_CREAT | os.O_TRUNC", "flags", "0", "os.O_RDONLY",
])
def test_descriptor_open_flags_cannot_hide_a_site(flags):
    # Even an apparently read-only opener is reviewed: helper parameters and
    # later flag changes must not silently introduce an unregistered writer.
    visitor = _Writes()
    visitor.visit(ast.parse(f"os.open(path, {flags})"))
    assert visitor.found == [("<module>", 1, "os.open")]


def test_descriptor_detection_preserves_string_modes_and_ignores_other_methods():
    visitor = _Writes()
    visitor.visit(ast.parse("\n".join([
        "open(path, 'w')", "path.open(mode='a')", "os.fdopen(fd, 'wb')",
        "open(path, 'r')", "path.open('rb')", "text.replace('a', 'b')",
        "path.rename(destination)", "other.open(path, flags)",
    ])))
    assert visitor.found == [
        ("<module>", 1, "open('w')"), ("<module>", 2, "open('a')"),
        ("<module>", 3, "open('wb')"), ("<module>", 7, "path.rename"),
    ]


def test_descriptor_counts_refuse_new_sites_and_growth_but_allow_reduction():
    key = ("aegis_core/example.py", "publish", "os.open")
    reviewed = {key: (1, "a reviewed temporary output")}
    site = (*key[:2], 4, key[2])
    assert _descriptor_errors([site], reviewed) == []
    assert _descriptor_errors([], reviewed) == [
        "aegis_core/example.py publish os.open: stale: remove",
    ]
    assert _descriptor_errors([site], {key: (2, "reviewed output")}) == [
        "aegis_core/example.py:4 publish os.open: lower to 1 (reviewed 2)",
    ]
    assert _descriptor_errors([site, site], reviewed) == [
        "aegis_core/example.py:4,4 publish os.open: reviewed count 1 -> 2",
    ]
    assert _descriptor_errors([site], {}) == [
        "aegis_core/example.py:4 publish os.open: unreviewed descriptor operation",
    ]


@pytest.mark.parametrize("operation", ["open", "replace", "rename", "link"])
@pytest.mark.parametrize("form", [
    "import os as low; low.{op}(path, flags)",
    "from os import {op} as operation; operation(path, flags)",
    "import os as low; boundary(low.{op}, path, flags)",
    "_OP = os.{op}", "def publish(operation=os.{op}): pass",
    "operations = (os.{op},)", "operations = {{'write': os.{op}}}",
    "boundary(os.{op}, path, flags)", "boundary(operation=os.{op})",
])
def test_aliases_and_noncall_os_references_are_refused(monkeypatch, operation, form):
    tree = ast.parse(form.format(op=operation))
    monkeypatch.setattr(sys.modules[__name__], "_sources", lambda: [("aegis_core/probe.py", tree)])
    with pytest.raises(AssertionError, match=r"aegis_core/probe\.py:1 .*forbidden"):
        test_state_and_rule_writes_go_through_storage()


def test_reviewed_callbacks_are_allowed_and_still_counted_as_operations():
    visitor = _Writes("aegis_core/model_select.py")
    visitor.visit(ast.parse("def _decision_directory():\n" + "    _path_call(os.open, path, flags)\n" * 3))
    assert visitor.errors == []
    assert visitor.found == [("_decision_directory", line, "os.open") for line in (2, 3, 4)]
    key = ("aegis_core/model_select.py", "_decision_directory", "os.open", "_path_call")
    assert _callback_errors(visitor.callbacks, {key: CALLBACK_EXCEPTIONS[key]}) == []


@pytest.mark.parametrize("rel,scope,operation,callee,count,reason", [
    ("aegis_core/model_select.py", "new_scope", "os.open", "_path_call", 1, "unreviewed OS callback"),
    ("aegis_core/new.py", "_decision_directory", "os.open", "_path_call", 3, "unreviewed OS callback"),
    ("aegis_core/model_select.py", "_decision_directory", "os.open", "_path_call", 4, "reviewed callback count 3 -> 4"),
    ("aegis_core/model_select.py", "_decision_directory", "os.open", "_path_call", 2, "reviewed callback count 3 -> 2"),
    ("aegis_core/model_select.py", "_publish", "os.rename", "_other_helper", 1, "unreviewed OS callback"),
])
def test_callback_exceptions_refuse_other_sites_callees_and_counts(monkeypatch, rel, scope, operation, callee, count, reason):
    source = f"def {scope}():\n" + f"    {callee}({operation}, path, flags)\n" * count
    monkeypatch.setattr(sys.modules[__name__], "_sources", lambda: [(rel, ast.parse(source))])
    with pytest.raises(AssertionError, match=re.escape(rel) + r":\d[^\n]*" + re.escape(reason)):
        test_state_and_rule_writes_go_through_storage()


def test_removed_callback_exception_is_stale_with_a_source_location():
    key = ("aegis_core/model_select.py", "_open_log", "os.open", "_path_call")
    assert _callback_errors([], {key: (1, "reviewed log opener")}, {key[:2]: 836}) == [
        "aegis_core/model_select.py:836 _open_log os.open via _path_call: stale callback: remove",
    ]


@pytest.mark.parametrize("call", [
    "_path_call(os.replace if overwrite else os.rename, src, dst)",
    "_path_call((os.replace if overwrite else os.rename,), src, dst)",
    "_path_call(*(os.replace if overwrite else os.rename, src, dst))",
    "_path_call(lambda: os.replace if overwrite else os.rename, src, dst)",
])
def test_nested_argon_operation_loads_are_refused_inside_reviewed_scope(monkeypatch, call):
    source = f"def _publish():\n    {call}\n"
    monkeypatch.setattr(sys.modules[__name__], "_sources", lambda: [("aegis_core/model_select.py", ast.parse(source))])
    with pytest.raises(AssertionError) as refusal:
        test_state_and_rule_writes_go_through_storage()
    for operation in ("os.replace", "os.rename"):
        assert f"aegis_core/model_select.py:2 _publish: forbidden OS operation reference: {operation}" in str(refusal.value)


def test_callback_exception_preserves_the_operation_ceiling(monkeypatch):
    reviewed = dict(REVIEWED_DESCRIPTOR_OPERATIONS)
    del reviewed[("aegis_core/model_select.py", "_publish", "os.open")]
    monkeypatch.setattr(sys.modules[__name__], "REVIEWED_DESCRIPTOR_OPERATIONS", reviewed)
    with pytest.raises(AssertionError, match=r"aegis_core/model_select\.py:\d+ _publish os\.open: unreviewed descriptor operation"):
        test_state_and_rule_writes_go_through_storage()


def test_capability_exception_cannot_authorize_an_alias_at_the_same_location():
    visitor = _Writes("aegis_core/model_select.py")
    visitor.visit(ast.parse("_OPEN = os.open"))
    assert visitor.errors == [
        "aegis_core/model_select.py:1 <module>: forbidden OS operation reference: os.open",
    ]


def test_capability_probes_and_comparisons_remain_allowed():
    visitor = _Writes("aegis_core/model_select.py")
    visitor.visit(ast.parse("supported = all(fn in os.supports_dir_fd for fn in (os.open, os.stat, os.rename, os.unlink))"))
    assert visitor.errors == []
    visitor = _Writes()
    visitor.visit(ast.parse("supported = os.open in os.supports_dir_fd"))
    assert visitor.errors == []


@pytest.mark.parametrize("call,operation", [
    ("Path(tmp).replace(state)", "path.replace"),
    ("source.parent.rename(target.parent)", "path.rename"),
    ("path.rename(target=destination)", "path.rename"),
    ("path.replace(target=destination)", "path.replace"),
    ("os.link(src, dst)", "os.link"),
])
def test_destination_publication_is_detected(call, operation):
    visitor = _Writes()
    visitor.visit(ast.parse(call))
    assert visitor.found == [("<module>", 1, operation)]


@pytest.mark.parametrize("source", [
    "import os\nfrom aegis_core import atomicio\natomicio.open_regular(p, os.O_WRONLY | os.O_CREAT)",
    "import os\nfrom aegis_core.atomicio import open_regular as regular\nregular(p, os.O_WRONLY | os.O_CREAT)",
])
def test_new_forwarding_opener_call_is_refused(monkeypatch, source):
    monkeypatch.setattr(sys.modules[__name__], "_sources", lambda: [("aegis_core/probe.py", ast.parse(source))])
    with pytest.raises(AssertionError, match=r"aegis_core/probe\.py:3 .*unreviewed descriptor operation"):
        test_state_and_rule_writes_go_through_storage()


def test_new_store_method_calling_forwarding_opener_is_refused(monkeypatch):
    source = "class Store:\n    def new_method(self):\n        self._open(n, os.O_WRONLY | os.O_CREAT, fd)\n"
    monkeypatch.setattr(sys.modules[__name__], "_sources", lambda: [("aegis_core/message_codec_store.py", ast.parse(source))])
    with pytest.raises(AssertionError, match=r"aegis_core/message_codec_store\.py:3 .*unreviewed descriptor operation"):
        test_state_and_rule_writes_go_through_storage()


@pytest.mark.parametrize("call", ["regular(p, flags)", "boundary(regular, p, flags)"])
def test_forwarding_reexports_and_callbacks_cannot_hide_calls(monkeypatch, call):
    sources = [
        ("aegis_core/bridge.py", ast.parse("from aegis_core.atomicio import open_regular as regular")),
        ("aegis_core/probe.py", ast.parse(f"from aegis_core.bridge import regular\n{call}")),
    ]
    monkeypatch.setattr(sys.modules[__name__], "_sources", lambda: iter(sources))
    with pytest.raises(AssertionError, match=r"aegis_core/probe\.py:2 .*unreviewed descriptor operation"):
        test_state_and_rule_writes_go_through_storage()


def test_undeclared_forwarding_opener_is_refused(monkeypatch):
    source = "def new_opener(path, flags):\n    return os.open(path, flags)\n"
    monkeypatch.setattr(sys.modules[__name__], "_sources", lambda: [("aegis_core/probe.py", ast.parse(source))])
    with pytest.raises(AssertionError, match=r"aegis_core/probe\.py:1 .*undeclared forwarding opener"):
        test_state_and_rule_writes_go_through_storage()


def test_removed_declared_forwarding_opener_is_refused(monkeypatch):
    sources = list(_sources())
    for rel, tree in sources:
        if rel == "aegis_core/atomicio.py":
            tree.body = [node for node in tree.body if not isinstance(node, ast.FunctionDef) or node.name != "open_regular"]
    monkeypatch.setattr(sys.modules[__name__], "_sources", lambda: iter(sources))
    with pytest.raises(AssertionError, match="stale forwarding opener: aegis_core.atomicio.open_regular"):
        test_state_and_rule_writes_go_through_storage()


def test_descriptor_cannot_mask_a_stale_string_mode_exemption(monkeypatch):
    module = sys.modules[__name__]
    source = "def _build():\n    os.replace(output, binary)\n"
    monkeypatch.setattr(module, "_sources", lambda: [("aegis_core/ast/gobuild.py", ast.parse(source))])
    monkeypatch.setattr(module, "NON_AEGIS_WRITERS", {("aegis_core/ast/gobuild.py", "_build"): "compiled output"})
    with pytest.raises(AssertionError):
        test_every_allowlisted_writer_still_exists()


@pytest.mark.parametrize("rel,scope,statements,diagnostic", [
    ("aegis_core/new.py", "publish", "os.open(path, flags)", "2 publish os.open: unreviewed descriptor operation"),
    ("aegis_core/ast/gobuild.py", "_build", "os.replace(src, dst)\n    os.replace(src, dst)", "2,3 _build os.replace: reviewed count 1 -> 2"),
    ("aegis_core/ast/gobuild.py", "_build", "os.open(path, flags)", "2 _build os.open: unreviewed descriptor operation"),
    ("aegis_core/ast/gobuild.py", "new_build", "os.replace(src, dst)", "2 new_build os.replace: unreviewed descriptor operation"),
])
def test_storage_ratchet_refuses_descriptor_growth_even_in_allowlisted_scope(monkeypatch, rel, scope, statements, diagnostic):
    tree = ast.parse(f"def {scope}():\n    {statements}\n")
    monkeypatch.setattr(sys.modules[__name__], "_sources", lambda: [(rel, tree)])
    with pytest.raises(AssertionError, match=re.escape(rel + ":" + diagnostic)):
        test_state_and_rule_writes_go_through_storage()


@pytest.mark.parametrize("statement", [
    "low = os; low.open(p, os.O_WRONLY | os.O_CREAT)",
    "low = os; low.replace(p, d)",
    "low = os; low.rename(p, d)",
    "low = os; low.link(p, d)",
    "def w(o=os): o.replace(p, d)",
    'getattr(os, "replace")(p, d)',
    'getattr(os, "open", fallback)(p, flags)',
    'getattr(os, "rename")(p, d)',
    'getattr(os, "link")(p, d)',
    "boundary(os)", "modules = [os]", "return_os = lambda: os",
    "getattr(os, name)", "hasattr(os, name)",
    'boundary(os, "O_RDONLY")', 'getattr(other, "attr", os)',
    'def getattr(*args): pass\ngetattr(os, "O_RDONLY", 0)',
    'import helpers as h\nh.getattr(os, "O_RDONLY", 0)',
    'import os as low\nmodule = low',
])
def test_bare_os_loads_are_allowlisted(monkeypatch, statement):
    source = "import os\n" + statement
    monkeypatch.setattr(sys.modules[__name__], "_sources", lambda: [("aegis_core/probe.py", ast.parse(source))])
    with pytest.raises(AssertionError, match=r"aegis_core/probe\.py:\d+ .*forbidden OS module reference"):
        test_state_and_rule_writes_go_through_storage()


@pytest.mark.parametrize("statement", [
    'supported = hasattr(os, "open")',
    'supported = getattr(os, "supports_dir_fd", ())',
    'flags = getattr(os, "O_CLOEXEC", 0)',
    'flags = getattr(os, "O_NOFOLLOW")',
    'value = os.name',
])
def test_allowed_os_module_loads_remain_usable(statement):
    visitor = _Writes()
    visitor.visit(ast.parse("import os\n" + statement))
    assert visitor.errors == []


@pytest.mark.parametrize("statement,operations", [
    ("_path_call(os.replace if overwrite else os.rename, src, dst) is None", ("replace", "rename")),
    ("if (op := os.replace) is not None: op(p, d)", ("replace",)),
    ('H.update({"mv": os.rename}) is None', ("rename",)),
    ("(ops := (os.open, os.link)) is not None", ("open", "link")),
    ("if (os.open,)[0](path, os.O_CREAT | os.O_WRONLY) >= 0: pass", ("open",)),
])
def test_only_direct_comparison_operands_are_exempt(monkeypatch, statement, operations):
    source = "import os\n" + statement
    monkeypatch.setattr(sys.modules[__name__], "_sources", lambda: [("aegis_core/probe.py", ast.parse(source))])
    with pytest.raises(AssertionError) as refusal:
        test_state_and_rule_writes_go_through_storage()
    for operation in operations:
        assert f"aegis_core/probe.py:2 <module>: forbidden OS operation reference: os.{operation}" in str(refusal.value)


@pytest.mark.parametrize("statement", [
    "writer = atomicio.open_regular; writer(p, flags)",
    "def writer(op=atomicio.open_regular): pass",
    "writers = [atomicio.open_regular]",
    "writers = {'open': atomicio.open_regular}",
    "writer = atomicio.open_regular if enabled else fallback",
    "boundary((atomicio.open_regular,), p, flags)",
    "boundary(lambda: atomicio.open_regular, p, flags)",
    "(op := atomicio.open_regular) is not None",
    "writer = atomicio.atomic_write_bytes",
    "atomicio.open_regular is None",
    "from aegis_core.atomicio import open_regular as regular\nwriter = regular",
])
def test_declared_opener_noncall_loads_are_refused(monkeypatch, statement):
    source = "from aegis_core import atomicio\n" + statement
    monkeypatch.setattr(sys.modules[__name__], "_sources", lambda: [("aegis_core/probe.py", ast.parse(source))])
    with pytest.raises(AssertionError, match=r"aegis_core/probe\.py:\d+ .*forbidden forwarding opener reference"):
        test_state_and_rule_writes_go_through_storage()


@pytest.mark.parametrize("call", [
    "atomicio.open_regular(p, flags)",
    "atomicio.open_regular(p, flags=flags)",
    "atomicio._open_regular(p, flags)",
    "boundary(atomicio.open_regular, p, flags)",
    "store._audit(flags, fd)",
    "store._open(p, flags, fd)",
    "store._audit(flags=flags, anchor=fd)",
    "store._open(p, flags=flags, rootfd=fd)",
    "ManagerStore._audit(store, flags, fd)",
    "Store._open(store, p, flags, fd)",
])
def test_flags_through_declared_openers_discover_new_forwarders(monkeypatch, call):
    source = ("from aegis_core import atomicio\n"
              "from aegis_core.manager_store import ManagerStore\n"
              "from aegis_core.message_codec_store import Store\n"
              "def open_state(p, flags):\n    return " + call)
    sources = list(_sources()) + [("aegis_core/probe.py", ast.parse(source))]
    monkeypatch.setattr(sys.modules[__name__], "_sources", lambda: iter(sources))
    with pytest.raises(AssertionError, match=r"aegis_core/probe\.py:4 aegis_core\.probe\.open_state: undeclared forwarding opener"):
        test_state_and_rule_writes_go_through_storage()


@pytest.mark.parametrize("call", [
    "atomicio.open_regular(p, os.O_RDONLY)",
    "atomicio.open_regular(p, flags=os.O_RDONLY)",
    "boundary(atomicio.open_regular, p, os.O_RDONLY)",
    "store._audit(os.O_RDONLY, fd)",
    "store._open(p, os.O_RDONLY, fd)",
    "ManagerStore._audit(store, os.O_RDONLY, fd)",
    "Store._open(store, p, os.O_RDONLY, fd)",
])
def test_declared_opener_flag_positions_preserve_constant_calls(call):
    source = ("import os\nfrom aegis_core import atomicio\n"
              "from aegis_core.manager_store import ManagerStore\n"
              "from aegis_core.message_codec_store import Store\n"
              "def reader(p, store, fd):\n    return " + call)
    visitor = _Writes("aegis_core/probe.py", methods={
        "aegis_core.manager_store.ManagerStore._audit", "aegis_core.message_codec_store.Store._open",
    })
    visitor.visit(ast.parse(source))
    assert visitor.errors == []
    assert visitor.forwarding == {}
    assert len(visitor.found) == 1


@pytest.mark.parametrize("call", [
    "os.open(*(p, flags))",
    "os.open(*(p, flags), 0o600)",
    "os.open(p, **kw)",
    "atomicio.open_regular(*(p, flags), 0o600)",
    "atomicio._open_regular(*(p, flags), 0o600)",
    "atomicio.open_regular(*args, flags=os.O_RDONLY)",
    "open_regular(p, **kw)",
    "store._open(p, **kw)",
    "Store._open(store, p, **kw)",
    "store._open(*args, 0)",
    "store._open(*(p, flags), 0)",
    "Store._open(store, *args, 0)",
    "Store._open(store, *(p, flags), 0)",
    "store._audit(*args, 0)",
    "ManagerStore._audit(store, *args, 0)",
    "boundary(atomicio.open_regular, *(p, flags), 0o600)",
    "boundary(atomicio._open_regular, *(p, flags), 0o600)",
    "boundary(store._open, *(p, flags), 0)",
    "boundary(Store._open, store, *(p, flags), 0)",
    "boundary(store._audit, *args, 0)",
    "boundary(atomicio.open_regular, p, **kw)",
    "boundary(os.open, *(p, flags), 0o600)",
])
def test_expanded_flags_require_the_undeclared_forwarder_diagnostic(monkeypatch, call):
    source = ("import os\nfrom aegis_core import atomicio\n"
              "from aegis_core.atomicio import open_regular\n"
              "from aegis_core.manager_store import ManagerStore\n"
              "from aegis_core.message_codec_store import Store\n"
              "def open_state(p, flags, args, kw, store):\n    return " + call)
    sources = [
        ("aegis_core/manager_store.py", ast.parse("class ManagerStore: pass")),
        ("aegis_core/message_codec_store.py", ast.parse("class Store: pass")),
        ("aegis_core/probe.py", ast.parse(source)),
    ]
    monkeypatch.setattr(sys.modules[__name__], "_sources", lambda: iter(sources))
    with pytest.raises(AssertionError, match=r"aegis_core/probe\.py:6 aegis_core\.probe\.open_state: undeclared forwarding opener"):
        test_state_and_rule_writes_go_through_storage()


def test_reviewed_unread_opener_cannot_hide_expanded_flags(monkeypatch):
    sources = list(_sources())
    tree = dict(sources)["aegis_core/telemetry_engine/ledger.py"]
    unread = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_unread")
    optional = ast.parse("def placeholder(flags=os.O_RDONLY): pass").body[0]
    unread.args.args.append(optional.args.args[0])
    unread.args.defaults.append(optional.args.defaults[0])
    opener = next(node for node in ast.walk(unread) if isinstance(node, ast.Call)
                  and isinstance(node.func, ast.Attribute) and node.func.attr == "open_regular")
    opener.args = ast.parse("atomicio.open_regular(*(path, flags), 0o600)").body[0].value.args
    monkeypatch.setattr(sys.modules[__name__], "_sources", lambda: iter(sources))
    with pytest.raises(AssertionError, match=r"aegis_core/telemetry_engine/ledger\.py:\d+ aegis_core\.telemetry_engine\.ledger\._unread: undeclared forwarding opener"):
        test_state_and_rule_writes_go_through_storage()


@pytest.mark.parametrize("call", [
    "os.open(p, os.O_RDONLY, *args)",
    "atomicio.open_regular(p, os.O_RDONLY, *args)",
    "atomicio._open_regular(p, os.O_RDONLY, *args)",
    "store._open(p, os.O_RDONLY, *args)",
    "Store._open(store, p, os.O_RDONLY, *args)",
    "store._audit(os.O_RDONLY, *args)",
    "ManagerStore._audit(store, os.O_RDONLY, *args)",
    "boundary(atomicio.open_regular, p, os.O_RDONLY, *args)",
    "boundary(store._open, p, os.O_RDONLY, *args)",
    "boundary(Store._open, store, p, os.O_RDONLY, *args)",
    "boundary(store._audit, os.O_RDONLY, *args)",
    "os.open(p, os.O_RDONLY, **kw)",
    "atomicio.open_regular(p, flags=os.O_RDONLY, **kw)",
    "store._open(p, os.O_RDONLY, **kw)",
    "boundary(atomicio.open_regular, p, os.O_RDONLY, **kw)",
])
def test_expansion_strictly_after_constant_flags_stays_constant(call):
    source = ("import os\nfrom aegis_core import atomicio\n"
              "from aegis_core.manager_store import ManagerStore\n"
              "from aegis_core.message_codec_store import Store\n"
              "def reader(p, store, args, kw):\n    return " + call)
    visitor = _Writes("aegis_core/probe.py", methods={
        "aegis_core.manager_store.ManagerStore._audit", "aegis_core.message_codec_store.Store._open",
    })
    visitor.visit(ast.parse(source))
    assert visitor.errors == []
    assert visitor.forwarding == {}
    assert len(visitor.found) == 1


@pytest.mark.parametrize("expression,allowed", [
    ("type(store) is Store", True),
    ("writer = Store", False),
    ("(writer := Store) is not None", False),
    ("Store.__init__ is not None", False),
])
def test_constructor_class_identity_is_distinct_from_opener_reference(expression, allowed):
    visitor = _Writes("aegis_core/probe.py")
    visitor.visit(ast.parse("from aegis_core.message_codec_store import Store\n" + expression))
    assert bool(visitor.errors) is not allowed
    if not allowed:
        assert all("aegis_core/probe.py:2 <module>: forbidden forwarding opener reference" in error for error in visitor.errors)


@pytest.mark.parametrize("flags,constant", [
    ('getattr(os, "O_CLOEXEC", 0)', True),
    ('os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)', True),
    ('getattr(os, "O_CLOEXEC", flags)', False),
    ('getattr(os, name, 0)', False),
    ('getattr(os, "O_CLOEXEC", True)', False),
])
def test_constant_flag_probes_do_not_invent_forwarders(flags, constant):
    visitor = _Writes("aegis_core/probe.py")
    visitor.visit(ast.parse(f"import os\ndef reader(p):\n    return os.open(p, {flags})"))
    assert bool(visitor.forwarding) is not constant


def test_missing_and_unregistered_capability_probes_are_refused(monkeypatch):
    module = sys.modules[__name__]
    monkeypatch.setattr(module, "CAPABILITY_REFERENCES", {})
    with pytest.raises(AssertionError, match=r"aegis_core/model_select\.py:\d+ <module> os\.open: unreviewed capability reference"):
        test_state_and_rule_writes_go_through_storage()


def test_stale_capability_registration_is_refused(monkeypatch):
    registered = dict(CAPABILITY_REFERENCES)
    registered[("aegis_core/missing.py", "<module>", "os.open")] = "removed probe"
    monkeypatch.setattr(sys.modules[__name__], "CAPABILITY_REFERENCES", registered)
    with pytest.raises(AssertionError, match=r"aegis_core/missing\.py:1 <module> os\.open: stale capability reference"):
        test_state_and_rule_writes_go_through_storage()


def test_migration_partial_calls_are_counted():
    sources = list(_sources())
    visitor = _Writes("aegis_core/migrate.py", _forwarding_exports(sources), _forwarding_methods(sources))
    visitor.visit(dict(sources)["aegis_core/migrate.py"])
    calls = [(scope, operation) for scope, _line, operation in visitor.found if operation == "aegis_core.migrate._input"]
    assert calls == [("_plan_rules", "aegis_core.migrate._input")] * 2 + [("apply", "aegis_core.migrate._input")] * 2
    assert visitor.errors == []


# RF-82b runtime write census owns these intentionally unasserted examples:
# shutil.move(src, dst); os.renames(src, dst); os.symlink(src, dst);
# Path(dst).symlink_to(src); Path(dst).hardlink_to(src); io.open(p, "w");
# class Child(Store): def write(self): self._open(p, flags, fd)
# if enabled: from aegis_core.atomicio import open_regular as regular
# try: from aegis_core.atomicio import open_regular as regular
# except ImportError: pass
# from aegis_core.atomicio import *
# Path.replace(src, dst); Path.rename(src, dst);
# move = path.replace; move(dst)
# path.replace(**{"target": dst}); path.rename(**{"target": dst}).
# posix.open(p, flags); os.path.os.open(p, flags);
# atomicio._replace_with_retry(src, dst, retries, delay).


def test_state_and_rule_writes_go_through_storage():
    offenders = []
    descriptor_sites = []
    forwarding = {}
    callback_sites = []
    capability_sites = []
    scopes = {}
    sources = list(_sources())
    exports = _forwarding_exports(sources)
    methods = _forwarding_methods(sources)
    for rel, tree in sources:
        visitor = _Writes(rel, exports, methods)
        visitor.visit(tree)
        offenders.extend(visitor.errors)
        callback_sites.extend(visitor.callbacks)
        capability_sites.extend(visitor.references)
        scopes.update({(rel, name[len(visitor.module) + 1:]): line for name, line in visitor.definitions.items()})
        forwarding.update({name: (rel, line) for name, line in visitor.forwarding.items()})
        if rel == "aegis_core/storage.py":
            continue
        for scope, lineno, what in visitor.found:
            if _reviewed_operation(what):
                descriptor_sites.append((rel, scope, lineno, what))
                continue
            key = (rel, scope.split(".<")[0])
            if key in NON_AEGIS_WRITERS or (rel, scope) in NON_AEGIS_WRITERS:
                continue
            offenders.append(f"{rel}:{lineno} {scope} {what}")
    offenders.extend(_descriptor_errors(descriptor_sites, REVIEWED_DESCRIPTOR_OPERATIONS))
    offenders.extend(_callback_errors(callback_sites, CALLBACK_EXCEPTIONS, scopes))
    offenders.extend(_capability_errors(capability_sites, CAPABILITY_REFERENCES, scopes))
    for name in sorted(forwarding.keys() - FORWARDING_OPENERS.keys()):
        rel, line = forwarding[name]
        offenders.append(f"{rel}:{line} {name}: undeclared forwarding opener")
    offenders.extend(f"stale forwarding opener: {name}" for name in sorted(FORWARDING_OPENERS.keys() - forwarding.keys()))
    assert offenders == [], "write through aegis_core.storage, or list a non-.aegis writer\n" + "\n".join(offenders)


def test_every_allowlisted_writer_still_exists():
    """A writer that was removed or renamed leaves a stale exemption behind."""
    present = set()
    for rel, tree in _sources():
        visitor = _Writes(rel)
        visitor.visit(tree)
        present |= {(rel, scope) for scope, _lineno, what in visitor.found if not _reviewed_operation(what)}
    assert set(NON_AEGIS_WRITERS) - present == set()


_PATH_LITERAL = re.compile(r"^[~/\\]*\.aegis(?:[/\\][^\s]*)?$")


def _docstrings(tree: ast.AST) -> set:
    ids = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                ids.add(id(first.value))
    return ids


def test_only_layout_spells_aegis_paths():
    offenders = []
    for rel, tree in _sources():
        if rel == "aegis_core/workspace/layout.py":
            continue
        skip = _docstrings(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in skip \
                    and _PATH_LITERAL.match(node.value):
                offenders.append(f"{rel}:{node.lineno} {node.value!r}")
    assert offenders == [], "ask aegis_core.workspace.layout for the path"
