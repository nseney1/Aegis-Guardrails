"""Validate bounded measurements and provide the opt-in hosted observation plugin."""

from __future__ import annotations

from collections import ChainMap
from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import astuple, dataclass, fields, replace
import errno
from itertools import islice
import os
import re
import struct
import sys
from threading import Barrier, get_ident
from types import SimpleNamespace
from typing import Any, List, Optional, Tuple, Union
import unicodedata

import pytest

from aegis_core.primitives import redact_display_secrets
from aegis_core.redaction_patterns import (
    CONTROL_RE,
    SECRET_REDACTIONS,
    UNFINISHED_SECRET_RE,
    RedactionRefusal,
)


FAMILIES: Tuple[str, ...] = (
    "reviewed_isolated",
    "mutation_tester",
    "regression_snapshot",
)
ENV_NAME_MARKERS = frozenset({
    "NONE",
    "REDACTED_ENV_NAME",
    "INVALID_ENV_NAME",
    "OVERSIZE_ENV_NAME",
})
REFUSAL_CODES = frozenset({
    "capture_incomplete",
    "capture_unsupported",
    "invalid_family",
    "invalid_context",
    "argv_type",
    "argv_count_limit",
    "env_type",
    "env_count_limit",
    "item_type",
    "item_size_limit",
    "codec_error",
    "multiline_var_name",
    "summary_rows_limit",
    "summary_size_limit",
})

MAX_ARGV_ELEMENTS = 4096
MAX_ENV_ENTRIES = 4096
MAX_REPORTED_ARGV_ELEMENTS = 48
MAX_SINGLE_ITEM_CHARS = 4 * 1024 * 1024
MAX_SINGLE_ITEM_BYTES = 4 * 1024 * 1024
MAX_RAW_VAR_NAME_CHARS = 4096
MAX_VAR_NAME_CHARS = 64
MAX_SUMMARY_ROWS = 64
MAX_SUMMARY_BYTES = 16 * 1024
_ENCODE_CHUNK_CHARS = 65536
_LIMIT_UPPER_BOUND = 1 << 62
_NB_LOOKBEHIND = "(?<![A-Za-z0-9])"
_TEXT_AND_BINARY_SCALARS = (str, bytes, bytearray, memoryview)

_MULTILINE_SEPARATORS: Tuple[str, ...] = (
    "\n", "\r", "\x00", "\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029",
)


def _build_raw_multiline_byte_separators() -> Tuple[bytes, ...]:
    seen: List[bytes] = []
    for sep in _MULTILINE_SEPARATORS:
        utf8_b = sep.encode("utf-8")
        if utf8_b not in seen:
            seen.append(utf8_b)
        try:
            fs_b = os.fsencode(sep)
        except (UnicodeError, ValueError):
            fs_b = b""
        if fs_b and fs_b not in seen:
            seen.append(fs_b)
    return tuple(seen)


_RAW_MULTILINE_BYTE_SEPARATORS = _build_raw_multiline_byte_separators()
_SAFE_VAR_NAME_RE = re.compile(r"\A[A-Za-z_][A-Za-z0-9_().-]{0,63}\Z")
_FULL_VAR_NAME_RE = re.compile(r"\A[A-Za-z_][A-Za-z0-9_().-]*\Z")
_NUMERIC_FIELD_RE = re.compile(r"\A-?[0-9]+(?:,[0-9]+)*\Z")


def _compile_shared_credential_detectors() -> Tuple[Tuple[re.Pattern[str], ...], re.Pattern[str]]:
    complete_patterns = tuple(
        re.compile(pattern.pattern.replace(_NB_LOOKBEHIND, ""), pattern.flags)
        for pattern, _hook, _text in SECRET_REDACTIONS
    )
    unfinished_src = UNFINISHED_SECRET_RE.pattern.replace(_NB_LOOKBEHIND, "")
    if not unfinished_src.endswith(r"\Z"):
        raise RuntimeError("unexpected UNFINISHED_SECRET_RE anchor shape")
    unfinished_anywhere = re.compile(unfinished_src[:-2], UNFINISHED_SECRET_RE.flags)
    return complete_patterns, unfinished_anywhere


_RELAXED_COMPLETE_SECRET_RES, _UNFINISHED_ANYWHERE_RE = _compile_shared_credential_detectors()


class ExecMeasurementError(ValueError):
    """Structured refusal with a closed code and no echoed untrusted text."""

    def __init__(self, code: Any) -> None:
        resolved = code if type(code) is str and code in REFUSAL_CODES else "invalid_context"
        super().__init__(resolved)
        self.code = resolved


@dataclass(frozen=True)
class ExecBoundaryMeasurement:
    """Sizes are filesystem-encoded bytes, with -1 for unavailable limits or status.

    An errno of 0 means the boundary returned. An errno of -1 means
    the boundary raised without a numeric OS errno.
    """

    family: str
    py_ver: int
    in_worker: int
    error_errno: int
    child_rc: int
    argv_count: int
    argv_element_lengths: Tuple[int, ...]
    argv_omitted_count: int
    argv_max_bytes: int
    argv_bytes: int
    argv_cstr_bytes: int
    env_count: int
    env_bytes: int
    env_cstr_bytes: int
    execve_payload_bytes: int
    longest_env_name: str
    longest_env_value_bytes: int
    longest_env_entry_bytes: int
    arg_max_bytes: int
    stack_soft_bytes: int
    stack_hard_bytes: int


def _has_surrogate(text: str) -> bool:
    return any(0xD800 <= ord(ch) <= 0xDFFF for ch in text)


def _filesystem_atom(value: Any) -> Union[str, bytes]:
    """Resolve exact filesystem atoms and refuse subclass behavior at either boundary."""
    kind = type(value)
    if kind is str or kind is bytes:
        return value
    if issubclass(kind, (*_TEXT_AND_BINARY_SCALARS, int, float, complex)):
        raise ExecMeasurementError("item_type")
    try:
        raw = os.fspath(value)
    except UnicodeError:
        raise ExecMeasurementError("codec_error") from None
    except Exception:
        raise ExecMeasurementError("item_type") from None
    if type(raw) is not str and type(raw) is not bytes:
        raise ExecMeasurementError("item_type")
    return raw


def _bounded_batch(
    value: Any,
    container_type: type,
    *,
    limit: int,
    type_code: str,
    limit_code: str,
    allow_empty: bool = True,
) -> Tuple[Any, ...]:
    """Check the declared and observed size before any member is measured or rendered."""
    kind = type(value)
    if issubclass(kind, _TEXT_AND_BINARY_SCALARS) or not issubclass(kind, container_type):
        raise ExecMeasurementError(type_code)
    try:
        declared = len(value)
    except OverflowError:
        raise ExecMeasurementError(limit_code) from None
    except Exception:
        raise ExecMeasurementError(type_code) from None
    if declared > limit:
        raise ExecMeasurementError(limit_code)
    try:
        batch = tuple(islice(value, limit + 1))
    except Exception:
        raise ExecMeasurementError(type_code) from None
    if len(batch) > limit or (not allow_empty and not batch):
        raise ExecMeasurementError(limit_code)
    if len(batch) != declared:
        raise ExecMeasurementError(type_code)
    return batch


def _measure_fs_item(
    value: Any,
    *,
    env_key: bool = False,
) -> Tuple[int, str]:
    """Enforce pre-allocation size and filesystem codec closure at argv/key/value seams."""
    raw = _filesystem_atom(value)
    if type(raw) is bytes:
        if env_key and any(sep in raw for sep in _RAW_MULTILINE_BYTE_SEPARATORS):
            raise ExecMeasurementError("multiline_var_name")
        if len(raw) > MAX_SINGLE_ITEM_BYTES:
            raise ExecMeasurementError("item_size_limit")
        try:
            decoded = os.fsdecode(raw)
        except (UnicodeError, ValueError):
            raise ExecMeasurementError("codec_error") from None
        if _has_surrogate(decoded):
            raise ExecMeasurementError("codec_error")
        if env_key and any(sep in decoded for sep in _MULTILINE_SEPARATORS):
            raise ExecMeasurementError("multiline_var_name")
        return len(raw), (decoded if env_key else "")
    if env_key and any(sep in raw for sep in _MULTILINE_SEPARATORS):
        raise ExecMeasurementError("multiline_var_name")
    if len(raw) > MAX_SINGLE_ITEM_CHARS:
        raise ExecMeasurementError("item_size_limit")
    total = 0
    for offset in range(0, len(raw), _ENCODE_CHUNK_CHARS):
        piece = raw[offset:offset + _ENCODE_CHUNK_CHARS]
        if _has_surrogate(piece):
            raise ExecMeasurementError("codec_error")
        try:
            encoded = os.fsencode(piece)
        except (UnicodeError, ValueError):
            raise ExecMeasurementError("codec_error") from None
        total += len(encoded)
        if total > MAX_SINGLE_ITEM_BYTES:
            raise ExecMeasurementError("item_size_limit")
    return total, (raw if env_key else "")


def _matches_any_credential_family(text: str) -> bool:
    if _UNFINISHED_ANYWHERE_RE.search(text) is not None:
        return True
    return any(pattern.search(text) is not None for pattern in _RELAXED_COMPLETE_SECRET_RES)


def _contains_secret_or_unfinished(canonical: str, *, limit: int) -> bool:
    replacements: List[Any] = []
    try:
        redacted = redact_display_secrets(
            canonical,
            limit=limit,
            on_replacements=replacements.append,
        )
    except RedactionRefusal:
        return True
    if replacements or redacted != canonical:
        return True
    if _matches_any_credential_family(canonical):
        return True
    if CONTROL_RE.search(canonical) is not None:
        stripped = CONTROL_RE.sub("", canonical)
        if stripped and _matches_any_credential_family(stripped):
            return True
    return False


def sanitize_env_variable_name(raw_name: Any, *, refuse_multiline: bool = True) -> str:
    """Enforce strict multiline refusal, codec closure, full-identifier redaction, then truncation."""
    if refuse_multiline is not True:
        raise ExecMeasurementError("invalid_context")
    if type(raw_name) is not str:
        raise ExecMeasurementError("item_type")
    _measure_fs_item(raw_name, env_key=True)
    if len(raw_name) > MAX_RAW_VAR_NAME_CHARS:
        return "OVERSIZE_ENV_NAME"

    canonical = unicodedata.normalize("NFC", raw_name)
    if any(sep in canonical for sep in _MULTILINE_SEPARATORS):
        raise ExecMeasurementError("multiline_var_name")
    if len(canonical) > MAX_RAW_VAR_NAME_CHARS:
        return "OVERSIZE_ENV_NAME"
    if not canonical:
        return "INVALID_ENV_NAME"
    if _contains_secret_or_unfinished(canonical, limit=MAX_RAW_VAR_NAME_CHARS):
        return "REDACTED_ENV_NAME"
    if "=" in canonical or CONTROL_RE.search(canonical) is not None:
        return "INVALID_ENV_NAME"
    if not _FULL_VAR_NAME_RE.fullmatch(canonical):
        return "INVALID_ENV_NAME"
    truncated = canonical[:MAX_VAR_NAME_CHARS]
    if _contains_secret_or_unfinished(truncated, limit=MAX_VAR_NAME_CHARS):
        return "REDACTED_ENV_NAME"
    if not _SAFE_VAR_NAME_RE.fullmatch(truncated):
        return "INVALID_ENV_NAME"
    return truncated


def validate_prebuilt_env_name(name: Any) -> str:
    """Refuse any prebuilt variable name that is not already canonical, safe, redacted and bounded."""
    sanitized = sanitize_env_variable_name(name, refuse_multiline=True)
    if sanitized != name or not _SAFE_VAR_NAME_RE.fullmatch(sanitized):
        raise ExecMeasurementError("invalid_context")
    return sanitized


def _require_exact_integers(values: Sequence[Any]) -> None:
    if any(type(value) is not int for value in values):
        raise ExecMeasurementError("item_type")


def _validate_observation_metadata(
    family: str,
    py_ver: int,
    in_worker: int,
    error_errno: int,
    child_rc: int,
    limits: Tuple[int, int, int],
) -> None:
    if type(family) is not str or family not in FAMILIES:
        raise ExecMeasurementError("invalid_family")
    if (
        not 300 <= py_ver <= 9999
        or in_worker not in (0, 1)
        or not -1 <= error_errno <= 65535
        or not -2147483648 <= child_rc <= 4294967295
        or (error_errno != 0 and child_rc == 0)
    ):
        raise ExecMeasurementError("invalid_context")

    arg_max, stack_soft, stack_hard = limits
    if (
        (arg_max != -1 and not 1 <= arg_max <= _LIMIT_UPPER_BOUND)
        or not -1 <= stack_soft <= _LIMIT_UPPER_BOUND
        or not -1 <= stack_hard <= _LIMIT_UPPER_BOUND
        or (stack_soft >= 0 and stack_hard >= 0 and stack_soft > stack_hard)
    ):
        raise ExecMeasurementError("invalid_context")


def validate_measurement_row(row: Any) -> ExecBoundaryMeasurement:
    """Validate row shape, types, domains, bounded name policy and size/count invariants."""
    if type(row) is not ExecBoundaryMeasurement:
        raise ExecMeasurementError("item_type")
    if type(row.argv_element_lengths) is not tuple:
        raise ExecMeasurementError("item_type")
    if len(row.argv_element_lengths) > MAX_REPORTED_ARGV_ELEMENTS:
        raise ExecMeasurementError("argv_count_limit")
    limits = (row.arg_max_bytes, row.stack_soft_bytes, row.stack_hard_bytes)
    scalar_ints = (
        row.py_ver,
        row.in_worker,
        row.error_errno,
        row.child_rc,
        row.argv_count,
        row.argv_omitted_count,
        row.argv_max_bytes,
        row.argv_bytes,
        row.argv_cstr_bytes,
        row.env_count,
        row.env_bytes,
        row.env_cstr_bytes,
        row.execve_payload_bytes,
        row.longest_env_value_bytes,
        row.longest_env_entry_bytes,
        *limits,
    )
    _require_exact_integers(scalar_ints)
    _require_exact_integers(row.argv_element_lengths)
    _validate_observation_metadata(row.family, row.py_ver, row.in_worker, row.error_errno, row.child_rc, limits)
    safe_var = validate_prebuilt_env_name(row.longest_env_name)

    if row.argv_count < 0:
        raise ExecMeasurementError("invalid_context")
    if row.argv_count > MAX_ARGV_ELEMENTS:
        raise ExecMeasurementError("argv_count_limit")
    expected_reported = min(row.argv_count, MAX_REPORTED_ARGV_ELEMENTS)
    if len(row.argv_element_lengths) != expected_reported:
        raise ExecMeasurementError("invalid_context")
    if row.argv_omitted_count != row.argv_count - expected_reported:
        raise ExecMeasurementError("invalid_context")
    for elem_len in row.argv_element_lengths:
        if elem_len < 0:
            raise ExecMeasurementError("invalid_context")
        if elem_len > MAX_SINGLE_ITEM_BYTES:
            raise ExecMeasurementError("item_size_limit")

    if row.argv_count == 0:
        if (
            row.argv_element_lengths != ()
            or row.argv_omitted_count != 0
            or row.argv_max_bytes != 0
            or row.argv_bytes != 0
            or row.argv_cstr_bytes != 0
        ):
            raise ExecMeasurementError("invalid_context")
    else:
        reported_sum = sum(row.argv_element_lengths)
        reported_max = max(row.argv_element_lengths)
        if row.argv_max_bytes < reported_max or row.argv_max_bytes > MAX_SINGLE_ITEM_BYTES:
            raise ExecMeasurementError("invalid_context")
        if row.argv_omitted_count == 0:
            if row.argv_bytes != reported_sum or row.argv_max_bytes != reported_max:
                raise ExecMeasurementError("invalid_context")
        else:
            max_possible = reported_sum + row.argv_omitted_count * row.argv_max_bytes
            min_possible = reported_sum + (row.argv_max_bytes if row.argv_max_bytes > reported_max else 0)
            if not min_possible <= row.argv_bytes <= max_possible:
                raise ExecMeasurementError("invalid_context")
        if row.argv_cstr_bytes != row.argv_bytes + row.argv_count:
            raise ExecMeasurementError("invalid_context")

    if row.env_count < 0:
        raise ExecMeasurementError("invalid_context")
    if row.env_count > MAX_ENV_ENTRIES:
        raise ExecMeasurementError("env_count_limit")
    if row.env_count == 0:
        if (
            safe_var != "NONE"
            or row.env_bytes != 0
            or row.env_cstr_bytes != 0
            or row.longest_env_value_bytes != 0
            or row.longest_env_entry_bytes != 0
        ):
            raise ExecMeasurementError("invalid_context")
    else:
        if not 0 <= row.longest_env_value_bytes <= MAX_SINGLE_ITEM_BYTES:
            raise ExecMeasurementError("invalid_context")
        key_bytes = row.longest_env_entry_bytes - row.longest_env_value_bytes - 1
        if not 0 <= key_bytes <= MAX_SINGLE_ITEM_BYTES:
            raise ExecMeasurementError("invalid_context")
        if safe_var not in ENV_NAME_MARKERS and key_bytes < len(safe_var):
            raise ExecMeasurementError("invalid_context")
        min_env_bytes = row.longest_env_entry_bytes + row.env_count - 1
        max_env_bytes = row.env_count * row.longest_env_entry_bytes
        if not min_env_bytes <= row.env_bytes <= max_env_bytes:
            raise ExecMeasurementError("invalid_context")
        if row.env_cstr_bytes != row.env_bytes + row.env_count:
            raise ExecMeasurementError("invalid_context")

    valid_payloads = tuple(
        row.argv_cstr_bytes + row.env_cstr_bytes + (row.argv_count + row.env_count + 2) * ptr_bytes
        for ptr_bytes in (4, 8)
    )
    if row.execve_payload_bytes not in valid_payloads:
        raise ExecMeasurementError("invalid_context")

    return row


def collect_boundary_metrics(
    family: str,
    argv: Sequence[Any],
    env: Optional[Mapping[Any, Any]],
    *,
    in_worker: int,
    error_errno: int = 0,
    child_rc: int = 0,
    py_ver: Optional[int] = None,
    limits: Optional[Tuple[int, int, int]] = None,
) -> ExecBoundaryMeasurement:
    """Collect and validate bounded numeric metrics and sanitized longest variable name."""
    supplied_limits = (-1, -1, -1) if limits is None else limits
    if type(supplied_limits) is not tuple or len(supplied_limits) != 3:
        raise ExecMeasurementError("invalid_context")
    version_num = (
        sys.version_info[0] * 100 + sys.version_info[1] if py_ver is None else py_ver
    )
    _require_exact_integers((version_num, in_worker, error_errno, child_rc, *supplied_limits))
    _validate_observation_metadata(family, version_num, in_worker, error_errno, child_rc, supplied_limits)
    arg_max, stack_soft, stack_hard = supplied_limits
    argv_items = _bounded_batch(
        argv, Sequence, limit=MAX_ARGV_ELEMENTS, type_code="argv_type", limit_code="argv_count_limit",
    )
    env_keys = _bounded_batch(
        env, Mapping, limit=MAX_ENV_ENTRIES, type_code="env_type", limit_code="env_count_limit",
    )

    reported: List[int] = []
    argv_max = 0
    argv_bytes = 0
    argv_count = len(argv_items)
    for index, element in enumerate(argv_items):
        elem_len, _ = _measure_fs_item(element)
        if index < MAX_REPORTED_ARGV_ELEMENTS:
            reported.append(elem_len)
        if elem_len > argv_max:
            argv_max = elem_len
        argv_bytes += elem_len
    argv_cstr_bytes = argv_bytes + argv_count
    omitted = argv_count - len(reported)

    env_bytes = 0
    longest_rank: Optional[Tuple[int, int, str]] = None
    longest_key_text: Optional[str] = None
    env_count = len(env_keys)
    for key in env_keys:
        key_len, key_text = _measure_fs_item(key, env_key=True)
        try:
            val = env[key]
        except Exception:
            raise ExecMeasurementError("env_type") from None
        val_len, _ = _measure_fs_item(val)
        entry_len = key_len + 1 + val_len
        env_bytes += entry_len
        rank_label = unicodedata.normalize("NFC", key_text[:128])
        rank = (entry_len, val_len, rank_label)
        if longest_rank is None or rank > longest_rank:
            longest_rank = rank
            longest_key_text = key_text
    env_cstr_bytes = env_bytes + env_count
    if longest_rank is None or longest_key_text is None:
        longest_name = "NONE"
        longest_val_bytes = 0
        longest_entry_bytes = 0
    else:
        longest_name = sanitize_env_variable_name(longest_key_text, refuse_multiline=True)
        longest_val_bytes = longest_rank[1]
        longest_entry_bytes = longest_rank[0]

    ptr_size = struct.calcsize("P")
    execve_payload = argv_cstr_bytes + env_cstr_bytes + (argv_count + env_count + 2) * ptr_size

    row = ExecBoundaryMeasurement(
        family=family,
        py_ver=version_num,
        in_worker=in_worker,
        error_errno=error_errno,
        child_rc=child_rc,
        argv_count=argv_count,
        argv_element_lengths=tuple(reported),
        argv_omitted_count=omitted,
        argv_max_bytes=argv_max,
        argv_bytes=argv_bytes,
        argv_cstr_bytes=argv_cstr_bytes,
        env_count=env_count,
        env_bytes=env_bytes,
        env_cstr_bytes=env_cstr_bytes,
        execve_payload_bytes=execve_payload,
        longest_env_name=longest_name,
        longest_env_value_bytes=longest_val_bytes,
        longest_env_entry_bytes=longest_entry_bytes,
        arg_max_bytes=arg_max,
        stack_soft_bytes=stack_soft,
        stack_hard_bytes=stack_hard,
    )
    return validate_measurement_row(row)


_SUMMARY_COLUMNS: Tuple[str, ...] = (
    "family",
    "py_ver",
    "in_worker",
    "error_errno",
    "child_rc",
    "argv_count",
    "argv_max_bytes",
    "argv_bytes",
    "argv_cstr_bytes",
    "env_count",
    "env_bytes",
    "env_cstr_bytes",
    "execve_payload_bytes",
    "longest_env_name",
    "longest_env_value_bytes",
    "longest_env_entry_bytes",
    "arg_max_bytes",
    "stack_soft_bytes",
    "stack_hard_bytes",
    "argv_omitted_count",
    "argv_element_lengths",
)


def format_step_summary_metrics(rows: Sequence[ExecBoundaryMeasurement]) -> str:
    """Validate every row and format numeric metrics, family and sanitized name as Markdown."""
    batch = _bounded_batch(
        rows, Sequence, limit=MAX_SUMMARY_ROWS, type_code="item_type",
        limit_code="summary_rows_limit", allow_empty=False,
    )
    lines = [
        "### Hosted Child Exec Measurements",
        "",
        "| " + " | ".join(_SUMMARY_COLUMNS) + " |",
        "| "
        + " | ".join(
            "---" if name in ("family", "longest_env_name", "argv_element_lengths") else "---:"
            for name in _SUMMARY_COLUMNS
        )
        + " |",
    ]
    size = sum(len(line) + 1 for line in lines)
    for raw_row in batch:
        row = validate_measurement_row(raw_row)
        lengths_text = (
            ",".join(str(val) for val in row.argv_element_lengths)
            if row.argv_element_lengths
            else "-1"
        )
        spans = (
            row.family,
            str(row.py_ver),
            str(row.in_worker),
            str(row.error_errno),
            str(row.child_rc),
            str(row.argv_count),
            str(row.argv_max_bytes),
            str(row.argv_bytes),
            str(row.argv_cstr_bytes),
            str(row.env_count),
            str(row.env_bytes),
            str(row.env_cstr_bytes),
            str(row.execve_payload_bytes),
            row.longest_env_name,
            str(row.longest_env_value_bytes),
            str(row.longest_env_entry_bytes),
            str(row.arg_max_bytes),
            str(row.stack_soft_bytes),
            str(row.stack_hard_bytes),
            str(row.argv_omitted_count),
            lengths_text,
        )
        line = "| " + " | ".join(spans) + " |"
        size += len(line) + 1  # Every rendered field is ASCII.
        if size > MAX_SUMMARY_BYTES:
            raise ExecMeasurementError("summary_size_limit")
        lines.append(line)
    return "\n".join(lines) + "\n"


def _assert_summary_contains_only_allowed_tokens(
    markdown: str,
    sentinel: Optional[str] = None,
) -> List[Tuple[str, ...]]:
    if sentinel is not None:
        assert sentinel not in markdown
    lines = [line for line in markdown.strip().splitlines() if line.strip()]
    assert lines[0] == "### Hosted Child Exec Measurements"
    assert lines[1].startswith("| family | py_ver |")
    assert lines[2].startswith("| --- | ---: |")
    parsed_rows: List[Tuple[str, ...]] = []
    for line in lines[3:]:
        assert line.startswith("| ") and line.endswith(" |")
        spans = tuple(part.strip() for part in line[2:-2].split(" | "))
        assert len(spans) == len(_SUMMARY_COLUMNS)
        assert spans[0] in FAMILIES
        assert validate_prebuilt_env_name(spans[13]) == spans[13]
        for idx, value in enumerate(spans):
            if idx in (0, 13):
                continue
            assert _NUMERIC_FIELD_RE.fullmatch(value), (idx, value)
        parsed_rows.append(spans)
    return parsed_rows


def test_collection_uses_only_supplied_observations() -> None:
    row = collect_boundary_metrics("reviewed_isolated", ["python"], {}, in_worker=1)
    assert row.env_count == 0
    assert (row.arg_max_bytes, row.stack_soft_bytes, row.stack_hard_bytes) == (-1, -1, -1)
    with pytest.raises(ExecMeasurementError, match=r"\Aenv_type\Z"):
        collect_boundary_metrics("reviewed_isolated", ["python"], None, in_worker=1)


def test_filesystem_atoms_are_exact_before_measurement_or_ranking() -> None:
    class Text(str):
        pass

    class Binary(bytes):
        pass

    class GuardedText(str):
        def __len__(self) -> int:
            raise AssertionError("text subclass measured")

        def __contains__(self, item: object) -> bool:
            raise AssertionError("text subclass searched")

    class GuardedBinary(bytes):
        def __len__(self) -> int:
            raise AssertionError("binary subclass measured")

    class PathInput:
        def __init__(self, atom: Any) -> None:
            self.atom = atom

        def __fspath__(self) -> Any:
            return self.atom

    family = "reviewed_isolated"
    for atom in (Text("A"), Binary(b"A"), GuardedText("A"), GuardedBinary(b"A")):
        for value in (atom, PathInput(atom)):
            for argv, env in (
                ([value], {}),
                ([], {value: "x", "LONGER_KEY": "longer value"}),
                ([], {"SMALL": value, "LONGER_KEY": "longer value"}),
                ([], {value: "x"}),
            ):
                with pytest.raises(ExecMeasurementError, match=r"\Aitem_type\Z"):
                    collect_boundary_metrics(family, argv, env, in_worker=1)

    expected = collect_boundary_metrics(family, ("arg", b""), {"PATH": b"v"}, in_worker=1)
    measured = collect_boundary_metrics(
        family, (PathInput("arg"), PathInput(b"")), ChainMap({PathInput("PATH"): PathInput(b"v")}), in_worker=1,
    )
    assert measured == expected


def test_binary_and_text_scalars_are_refused_as_containers() -> None:
    class GuardedBuffer(bytearray):
        def __len__(self) -> int:
            raise AssertionError("binary scalar counted")

        def __iter__(self):
            raise AssertionError("binary scalar consumed")

    for scalar in ("", b"", bytearray(), bytearray(MAX_SUMMARY_ROWS + 1), memoryview(b"x"), GuardedBuffer()):
        with pytest.raises(ExecMeasurementError, match=r"\Aargv_type\Z"):
            collect_boundary_metrics("reviewed_isolated", scalar, {}, in_worker=1)
        with pytest.raises(ExecMeasurementError, match=r"\Aitem_type\Z"):
            format_step_summary_metrics(scalar)


def test_sequence_batches_reconcile_counts_before_use() -> None:
    class ReportedSequence(Sequence):
        def __init__(self, declared: int, observed: int, item: Any) -> None:
            self.declared = declared
            self.observed = observed
            self.item = item
            self.yielded = 0

        def __len__(self) -> int:
            return self.declared

        def __getitem__(self, index: int) -> Any:
            if not 0 <= index < self.observed:
                raise IndexError
            return self.item

        def __iter__(self):
            for index in range(self.observed):
                self.yielded += 1
                yield self[index]

    family = "reviewed_isolated"
    row = collect_boundary_metrics(family, (), {}, in_worker=1)
    assert collect_boundary_metrics(family, ReportedSequence(0, 0, "a"), {}, in_worker=1) == row
    assert format_step_summary_metrics(ReportedSequence(2, 2, row)) == format_step_summary_metrics([row, row])
    for declared, observed in ((2, 1), (0, 1), (1, 2)):
        with pytest.raises(ExecMeasurementError, match=r"\Aargv_type\Z"):
            collect_boundary_metrics(family, ReportedSequence(declared, observed, "a"), {}, in_worker=1)
        with pytest.raises(ExecMeasurementError, match=r"\Aitem_type\Z"):
            format_step_summary_metrics(ReportedSequence(declared, observed, row))
    with pytest.raises(ExecMeasurementError, match=r"\Asummary_rows_limit\Z"):
        format_step_summary_metrics(ReportedSequence(1, 0, row))

    over_argv = ReportedSequence(1, MAX_ARGV_ELEMENTS + 2, "a")
    with pytest.raises(ExecMeasurementError, match=r"\Aargv_count_limit\Z"):
        collect_boundary_metrics(family, over_argv, {}, in_worker=1)
    assert over_argv.yielded == MAX_ARGV_ELEMENTS + 1
    over_rows = ReportedSequence(1, MAX_SUMMARY_ROWS + 2, row)
    with pytest.raises(ExecMeasurementError, match=r"\Asummary_rows_limit\Z"):
        format_step_summary_metrics(over_rows)
    assert over_rows.yielded == MAX_SUMMARY_ROWS + 1
    declared_over = ReportedSequence(MAX_SUMMARY_ROWS + 1, 1, row)
    with pytest.raises(ExecMeasurementError, match=r"\Asummary_rows_limit\Z"):
        format_step_summary_metrics(declared_over)
    assert declared_over.yielded == 0


def test_container_conversion_refusals_do_not_echo_input() -> None:
    sentinel = "SENTINEL_CONTAINER_REFUSAL_5564"

    class MalformedSequence(Sequence):
        def __init__(self, countable: bool) -> None:
            self.countable = countable

        def __len__(self) -> int:
            if not self.countable:
                raise ValueError(sentinel)
            return 1

        def __getitem__(self, index: int) -> Any:
            raise RuntimeError(sentinel)

    class MalformedMapping(Mapping):
        def __len__(self) -> int:
            return 1

        def __iter__(self):
            return iter(("PATH",))

        def __getitem__(self, key: Any) -> Any:
            raise LookupError(sentinel)

    for container in (MalformedSequence(False), MalformedSequence(True)):
        with pytest.raises(ExecMeasurementError, match=r"\Aargv_type\Z"):
            collect_boundary_metrics("reviewed_isolated", container, {}, in_worker=1)
        with pytest.raises(ExecMeasurementError, match=r"\Aitem_type\Z"):
            format_step_summary_metrics(container)
    with pytest.raises(ExecMeasurementError, match=r"\Aenv_type\Z"):
        collect_boundary_metrics("reviewed_isolated", (), MalformedMapping(), in_worker=1)


def test_metadata_and_refusal_codes_require_exact_scalars() -> None:
    class Number(int):
        def __str__(self) -> str:
            raise AssertionError("numeric subclass rendered")

    class ErrorCode(str):
        def __hash__(self) -> int:
            raise AssertionError("code subclass hashed")

    family = "reviewed_isolated"
    row = collect_boundary_metrics(family, ("probe",), {}, in_worker=1)
    for field, value in (
        ("in_worker", True), ("error_errno", Number(0)), ("child_rc", 0.0), ("py_ver", "312"),
    ):
        options = {"in_worker": 1, field: value}
        with pytest.raises(ExecMeasurementError, match=r"\Aitem_type\Z"):
            collect_boundary_metrics(family, (), {}, **options)
        malformed = replace(row, **{field: value})
        with pytest.raises(ExecMeasurementError, match=r"\Aitem_type\Z"):
            validate_measurement_row(malformed)
        with pytest.raises(ExecMeasurementError, match=r"\Aitem_type\Z"):
            format_step_summary_metrics([malformed])

    with pytest.raises(ExecMeasurementError, match=r"\Ainvalid_context\Z"):
        collect_boundary_metrics(family, (), {}, in_worker=2)
    for code in (ErrorCode("item_type"), ["item_type"], None, "unknown"):
        error = ExecMeasurementError(code)
        assert type(error.code) is str and str(error) == error.code == "invalid_context"


def test_measurement_and_table_limits() -> None:
    with pytest.raises(ExecMeasurementError, match=r"\Aargv_count_limit\Z"):
        collect_boundary_metrics("reviewed_isolated", range(MAX_ARGV_ELEMENTS + 1), {}, in_worker=1)
    with pytest.raises(ExecMeasurementError, match=r"\Aenv_count_limit\Z"):
        env = {str(index): "x" for index in range(MAX_ENV_ENTRIES + 1)}
        collect_boundary_metrics("reviewed_isolated", [], env, in_worker=1)
    with pytest.raises(ExecMeasurementError, match=r"\Aitem_size_limit\Z"):
        collect_boundary_metrics("reviewed_isolated", [b"x" * (MAX_SINGLE_ITEM_BYTES + 1)], {}, in_worker=1)

    base = collect_boundary_metrics(
        "reviewed_isolated", ["x"] * MAX_REPORTED_ARGV_ELEMENTS, {}, in_worker=1
    )
    with pytest.raises(ExecMeasurementError, match=r"\Asummary_rows_limit\Z"):
        format_step_summary_metrics([base] * (MAX_SUMMARY_ROWS + 1))

    argv_bytes = MAX_SINGLE_ITEM_BYTES * base.argv_count
    large = replace(
        base,
        argv_element_lengths=(MAX_SINGLE_ITEM_BYTES,) * base.argv_count,
        argv_max_bytes=MAX_SINGLE_ITEM_BYTES,
        argv_bytes=argv_bytes,
        argv_cstr_bytes=argv_bytes + base.argv_count,
        execve_payload_bytes=base.execve_payload_bytes + argv_bytes - base.argv_bytes,
    )
    assert validate_measurement_row(large) == large
    with pytest.raises(ExecMeasurementError, match=r"\Asummary_size_limit\Z"):
        format_step_summary_metrics([large] * MAX_SUMMARY_ROWS)


def test_formatter_bounds_oversized_synthetic_input_and_excludes_sentinel() -> None:
    """Synthetic E2BIG-scale argv/env redact all complete+unfinished credential families and keep sentinels."""
    sentinel = "SENTINEL_NEVER_EMITTED_VALUE_887123"
    full_secret = "gh" + "p_" + ("A1b2C3d4E5f6" * 3) + sentinel
    oversized_arg = sentinel + ("x" * 160000)
    synthetic_argv = [
        "/usr/bin/python3",
        "-I",
        "-S",
        "-B",
        "-c",
        oversized_arg,
        *[f"arg_{idx}_{sentinel}" for idx in range(70)],
    ]
    long_var_name = "HOSTED_LONGEST_SYNTHETIC_VARIABLE_" + ("Z" * 80)
    synthetic_env = {
        "PATH": "/usr/bin:/bin",
        "SMALL_SENTINEL": sentinel,
        long_var_name: full_secret + ("v" * 200000),
        full_secret: "short",
    }

    row = collect_boundary_metrics(
        "reviewed_isolated",
        synthetic_argv,
        synthetic_env,
        in_worker=1,
        error_errno=errno.E2BIG,
        child_rc=-1,
        py_ver=311,
        limits=(2097152, 8388608, -1),
    )
    assert row.argv_count == 76
    assert len(row.argv_element_lengths) == MAX_REPORTED_ARGV_ELEMENTS
    assert row.argv_omitted_count == 76 - MAX_REPORTED_ARGV_ELEMENTS
    assert row.argv_max_bytes == len(oversized_arg.encode("utf-8"))
    assert row.longest_env_name == long_var_name[:MAX_VAR_NAME_CHARS]

    # Exercise all shared complete and unfinished credential families across positions, cuts, runs & transitions:
    secret_seeds = (
        "ey" + "JhbGciOiJIUzI1NiJ9",
        "AK" + "IA1234",
        "AS" + "IA" + ("B2C3" * 4),
        "AG" + "PA99",
        "AI" + "DA99",
        "AR" + "OA99",
        "AN" + "PA99",
        "AN" + "VA99",
        "AI" + "PA99",
        "gh" + "p_1234",
        "gh" + "o_" + ("a1B2c3" * 4),
        "gh" + "u_9",
        "gh" + "s_9",
        "gh" + "r_9",
        "github_" + "pat_123",
        "glpat" + "-abc123",
        "sk_" + "live_123",
        "rk_" + "test_123",
        "pk_" + "live_123",
        "sk-" + "ant-abc",
        "sk-" + "proj-abc",
        "sk-" + "short",
        "AI" + "zaSyAbc",
        "xox" + "b-123",
        "xox" + "s-123",
        "npm" + "_1234",
        "pypi" + "-AgEIcHlwaS",
        "Bearer" + "   tok",
        "https" + "://u:p",
        "://" + "u:p@host",
        "api_" + "key=xyz",
        "client_" + "secret:xyz",
        "my_" + "auth=xyz",
        "secret" + " is hunter2",
        "-----" + "BEGIN",
        "-----" + "BEGIN RSA PRIVATE " + "KEY-----body",
    )
    for seed in secret_seeds:
        variants = (
            seed,
            "ADJACENT" + seed,
            "camelCase" + seed + "lowercaseTail",
            seed + "__DOUBLE_SEP",
            seed + "$punct",
            ("Q" * 61) + seed,  # straddling 64-char display cut
            ("Q" * 75) + seed,  # completely past 64-char display cut
            ("Q" * 70) + seed + ("m" * 700) + "_LONG_RUN",
        )
        for candidate in variants:
            assert sanitize_env_variable_name(candidate) == "REDACTED_ENV_NAME", candidate
            collected = collect_boundary_metrics("reviewed_isolated", ["python"], {candidate: "1"}, in_worker=1)
            assert collected.longest_env_name == "REDACTED_ENV_NAME"

    signed_signal_row = collect_boundary_metrics(
        "mutation_tester",
        ["pytest"],
        {"ProgramFiles(x86)": r"C:\Program Files (x86)"},
        in_worker=0,
        error_errno=0,
        child_rc=-9,
        py_ver=309,
        limits=(-1, -1, -1),
    )
    assert signed_signal_row.child_rc == -9
    assert signed_signal_row.longest_env_name == "ProgramFiles(x86)"

    empty_env_row = collect_boundary_metrics(
        "regression_snapshot",
        [],
        {},
        in_worker=0,
        error_errno=0,
        child_rc=0,
        py_ver=312,
        limits=(-1, -1, -1),
    )
    assert empty_env_row.longest_env_name == "NONE"
    assert empty_env_row.argv_element_lengths == ()

    for marker in ENV_NAME_MARKERS:
        assert sanitize_env_variable_name(marker) == marker
        assert validate_prebuilt_env_name(marker) == marker

    markdown = format_step_summary_metrics([row, signed_signal_row, empty_env_row])
    assert len(markdown.encode("utf-8")) <= MAX_SUMMARY_BYTES
    assert sentinel not in markdown
    assert full_secret not in markdown
    parsed = _assert_summary_contains_only_allowed_tokens(markdown, sentinel=sentinel)
    assert len(parsed) == 3
    assert parsed[1][4] == "-9"
    assert parsed[1][13] == "ProgramFiles(x86)"
    assert parsed[2][-1] == "-1"


def test_validation_invariants_codec_closure_and_multiline_refusal() -> None:
    """Enforce one bounded name policy across all entry points alongside codec and multiline bounds."""
    sentinel = "SENTINEL_REFUSAL_LEAK_CHECK_7712"

    valid_empty = collect_boundary_metrics(
        "reviewed_isolated", [], {}, in_worker=0, error_errno=0, child_rc=-15, py_ver=309, limits=(-1, -1, -1)
    )
    valid_prog = collect_boundary_metrics(
        "mutation_tester",
        [b"python", "-c", "pass"],
        {"ProgramFiles(x86)": r"C:\Program Files (x86)"},
        in_worker=1,
        error_errno=errno.E2BIG,
        child_rc=-1,
        py_ver=312,
        limits=(2097152, 8388608, 16777216),
    )
    valid_long = collect_boundary_metrics(
        "regression_snapshot",
        ["pytest"],
        {"ORDINARY_LONG_IDENTIFIER_" + ("K" * 60): "1"},
        in_worker=0,
        error_errno=0,
        child_rc=0,
        py_ver=311,
        limits=(131072, 0, -1),
    )
    rendered = format_step_summary_metrics([valid_empty, valid_prog, valid_long])
    parsed = _assert_summary_contains_only_allowed_tokens(rendered)
    assert len(parsed) == 3
    assert parsed[0][4] == "-15"

    assert sanitize_env_variable_name("VALID_" + ("A" * 64) + "|bad_suffix") == "INVALID_ENV_NAME"
    assert sanitize_env_variable_name("VALID_" + ("A" * 64) + " bad_space") == "INVALID_ENV_NAME"
    assert sanitize_env_variable_name("A\u030a_" + ("B" * 80)) == "INVALID_ENV_NAME"
    assert sanitize_env_variable_name("X" * (MAX_RAW_VAR_NAME_CHARS + 1)) == "OVERSIZE_ENV_NAME"

    for sep in _MULTILINE_SEPARATORS:
        for candidate in (
            f"VAR{sep}{sentinel}",
            ("X" * (MAX_RAW_VAR_NAME_CHARS + 200)) + sep + sentinel,
            ("X" * (MAX_SINGLE_ITEM_CHARS + 32)) + sep + sentinel,
        ):
            with pytest.raises(ExecMeasurementError) as ml_err:
                sanitize_env_variable_name(candidate)
            assert ml_err.value.code == "multiline_var_name"
            assert sentinel not in str(ml_err.value)

    with pytest.raises(ExecMeasurementError) as non_longest_ml:
        collect_boundary_metrics(
            "reviewed_isolated",
            ["python"],
            {"SHORT\nKEY": "1", "MUCH_LONGER_VALID_KEY": "x" * 200},
            in_worker=1,
        )
    assert non_longest_ml.value.code == "multiline_var_name"
    for oversize_key in (
        ("L" * MAX_SINGLE_ITEM_CHARS) + "\n",
        (b"L" * MAX_SINGLE_ITEM_BYTES) + b"\r",
    ):
        with pytest.raises(ExecMeasurementError) as oversize_ml:
            collect_boundary_metrics("reviewed_isolated", [], {oversize_key: "x"}, in_worker=1)
        assert oversize_ml.value.code == "multiline_var_name"

    for bad_token in ("\ud800", "\udcff", b"\xff\xfe"):
        with pytest.raises(ExecMeasurementError) as argv_codec:
            collect_boundary_metrics("reviewed_isolated", [bad_token], {}, in_worker=1)
        assert argv_codec.value.code == "codec_error"
        with pytest.raises(ExecMeasurementError) as key_codec:
            collect_boundary_metrics("reviewed_isolated", ["python"], {bad_token: "ok"}, in_worker=1)
        assert key_codec.value.code == "codec_error"
        with pytest.raises(ExecMeasurementError) as val_codec:
            collect_boundary_metrics("reviewed_isolated", ["python"], {"OK_KEY": bad_token}, in_worker=1)
        assert val_codec.value.code == "codec_error"

    class InvalidPath(os.PathLike):
        def __fspath__(self) -> str:
            raise ValueError(sentinel)

    with pytest.raises(ExecMeasurementError, match=r"\Aitem_type\Z") as path_err:
        collect_boundary_metrics("reviewed_isolated", [InvalidPath()], {}, in_worker=1)
    assert sentinel not in str(path_err.value)

    # Refuse unsafe prebuilt names in direct validation and table formatting.
    unsafe_prebuilt_names = (
        "FOO" + "gh" + "p_1234",
        "AK" + "IA1234lower",
        "gh" + "p__SUFFIX",
        "ORDINARY_" + ("Z" * 64),
        "BAD|NAME",
        "LINE1\nLINE2",
    )
    for bad_name in unsafe_prebuilt_names:
        broken_row = replace(valid_long, longest_env_name=bad_name)
        expected_code = "multiline_var_name" if "\n" in bad_name else "invalid_context"
        for check in (validate_measurement_row, lambda row: format_step_summary_metrics([valid_empty, row])):
            with pytest.raises(ExecMeasurementError, match=rf"\A{expected_code}\Z"):
                check(broken_row)

    malformed_overrides = (
        ({"family": "unknown_family"}, "invalid_family"),
        ({"in_worker": True}, "item_type"),
        ({"py_ver": 99}, "invalid_context"),
        ({"error_errno": -2}, "invalid_context"),
        ({"error_errno": errno.E2BIG, "child_rc": 0}, "invalid_context"),
        ({"argv_count": 5}, "invalid_context"),
        ({"argv_omitted_count": 2}, "invalid_context"),
        ({"argv_cstr_bytes": valid_prog.argv_cstr_bytes + 1}, "invalid_context"),
        ({"env_cstr_bytes": valid_prog.env_cstr_bytes + 1}, "invalid_context"),
        ({"longest_env_entry_bytes": valid_prog.longest_env_value_bytes}, "invalid_context"),
        ({"longest_env_name": "LONGER_THAN_KEY_BYTES_EXAMPLE"}, "invalid_context"),
        ({"execve_payload_bytes": valid_prog.execve_payload_bytes + 3}, "invalid_context"),
        ({"arg_max_bytes": 0}, "invalid_context"),
        ({"stack_soft_bytes": -2}, "invalid_context"),
        ({"stack_soft_bytes": 9000, "stack_hard_bytes": 4000}, "invalid_context"),
    )
    for changes, code in malformed_overrides:
        broken_row = replace(valid_prog, **changes)
        with pytest.raises(ExecMeasurementError, match=rf"\A{code}\Z"):
            validate_measurement_row(broken_row)
        with pytest.raises(ExecMeasurementError, match=rf"\A{code}\Z"):
            format_step_summary_metrics([valid_empty, broken_row])

    with pytest.raises(ExecMeasurementError) as str_rows_err:
        format_step_summary_metrics("not-a-row-sequence")  # type: ignore[arg-type]
    assert str_rows_err.value.code == "item_type"

    with pytest.raises(ExecMeasurementError) as bool_limits_err:
        collect_boundary_metrics(
            "reviewed_isolated", ["python"], {}, in_worker=1, limits=(True, -1, -1)  # type: ignore[arg-type]
        )
    assert bool_limits_err.value.code == "item_type"

    class _SubStr(str):
        pass

    with pytest.raises(ExecMeasurementError) as substr_err:
        validate_prebuilt_env_name(_SubStr("PATH"))
    assert substr_err.value.code == "item_type"


# Capture observes these trials within ordinary full-shard execution.
_HOSTED_TRIALS = {
    "tests/unit/core/test_redaction.py::test_redaction_isolated_import_bootstrap[parent]":
        ("unit-core-a", "normal", "run_isolated_test"),
    "tests/unit/core/test_redaction.py::test_private_name_census_rejects_an_unreviewed_importer_path":
        ("unit-core-a", "error", "run_isolated_test"),
    "tests/unit/verification/test_mutation_tester.py::TestMutationTesterContract::test_real_test_passes":
        ("unit-rest", "normal", "_check_tests"),
    "tests/unit/verification/test_mutation_tester.py::TestMutationTesterFailsClosed::test_baseline_assertion_failure_fails_closed":
        ("unit-rest", "error", "_check_tests"),
}
# Builder name -> family and module containing the reviewed exec site.
_HOSTED_SITES = {
    "run_isolated_test": ("reviewed_isolated", "tests.helpers_reviewed_sources"),
    "_check_tests": ("mutation_tester", "aegis_core.verification.mutation_tester"),
}
_HOSTED_CALLERS = frozenset((module, builder) for builder, (_, module) in _HOSTED_SITES.items())
_HOSTED_REPORT = "aegis_hosted_exec_observations"
_HOSTED_OBSERVER = "hosted-exec-observer"
_HOSTED_SHARDS = ("unit-core-a", "unit-rest")
# Keep the existing per-summary limits for the retained shards.
_HOSTED_ROW_LIMIT = 10
_HOSTED_BYTE_LIMIT = 2730
_MEASUREMENT_FIELDS = len(fields(ExecBoundaryMeasurement))


def _hosted_trials(shard):
    return {node: (trial, builder) for node, (owner, trial, builder) in _HOSTED_TRIALS.items() if owner == shard}


def _format_hosted_capture(shard, in_worker, reports):
    trials = _hosted_trials(shard)
    if not trials or reports.keys() != trials.keys():
        raise ExecMeasurementError("capture_incomplete")
    context = "worker" if in_worker else "fresh"
    sections = [
        f"## Hosted isolated child capture ({shard}, {context})\n\n",
        "| Trial | Builder | Exec site | E2BIG status | Measurement rows |\n",
        "| --- | --- | --- | --- | ---: |\n",
    ]
    rows = []
    for node, (trial, builder) in trials.items():
        attempts = reports[node]
        if len(rows) + len(attempts) > _HOSTED_ROW_LIMIT:
            raise ExecMeasurementError("summary_rows_limit")
        if not attempts:
            raise ExecMeasurementError("capture_incomplete")
        family, module = _HOSTED_SITES[builder]
        line = attempts[0][0]
        first = len(rows) + 1
        for observed_line, raw_row in attempts:
            row = validate_measurement_row(raw_row)
            if (type(observed_line) is not int or not 1 <= observed_line <= 2147483647
                    or observed_line != line or row.family != family or row.in_worker != in_worker):
                raise ExecMeasurementError("capture_incomplete")
            rows.append(row)
        observed = rows[first - 1:]
        if trial == "error" and not any(row.error_errno or row.child_rc for row in observed):
            raise ExecMeasurementError("capture_incomplete")
        status = "E2BIG reproduced" if any(row.error_errno == errno.E2BIG for row in observed) else "E2BIG not reproduced"
        sections.append(f"| {trial} | {builder} | {module}.{builder}:{line} | {status} | {first}-{len(rows)} |\n")
    sections.extend(("\n", format_step_summary_metrics(rows), "\n"))
    if sum(map(len, sections)) > _HOSTED_BYTE_LIMIT:
        raise ExecMeasurementError("summary_size_limit")
    return "".join(sections)


def _qualify_hosted_trial(passed, failed, rows):
    if (not rows or any(type(row.child_rc) is not int or row.error_errno not in (0, errno.E2BIG)
                        or (row.error_errno == 0 and row.child_rc < 0)
                        or (row.error_errno == errno.E2BIG and row.child_rc != -1) for row in rows)
            or not (passed or (failed and any(row.error_errno == errno.E2BIG for row in rows)))):
        raise ExecMeasurementError("capture_incomplete")


def _hosted_limits():
    # Imported only in a Linux observer, where an unavailable limit uses the
    # existing -1 sentinel. Each process measures its own limits.
    import resource

    try:
        arg_max = os.sysconf("SC_ARG_MAX")
    except (OSError, ValueError):
        arg_max = -1
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_STACK)
    except (OSError, ValueError):
        soft, hard = -1, -1
    return (
        arg_max if 1 <= arg_max <= _LIMIT_UPPER_BOUND else -1,
        soft if soft != resource.RLIM_INFINITY and 0 <= soft <= _LIMIT_UPPER_BOUND else -1,
        hard if hard != resource.RLIM_INFINITY and 0 <= hard <= _LIMIT_UPPER_BOUND else -1,
    )


@dataclass
class _HostedAttempt:
    line: int
    process: Any
    metrics: Optional[ExecBoundaryMeasurement] = None
    exec_error: Optional[OSError] = None
    launch_finished: bool = False
    constructor_finished: bool = False
    constructor_saw_exec_error: bool = False
    indeterminate: bool = False

    def trace_constructor(self, _frame, event, arg):
        if event == "exception":
            if arg[1] is self.exec_error:
                self.constructor_saw_exec_error = True
            else:
                self.indeterminate = True
        elif event == "return":
            self.constructor_finished = True
        return self.trace_constructor

    def trace_launch(self, frame, event, arg):
        if event == "exception":
            error = arg[1]
            # The fork/exec error-pipe payload ends at the colon for an exec
            # failure. Earlier failures either have a noexec suffix or never
            # received a child error-pipe payload. All reviewed calls fork/exec.
            exec_error = f"OSError:{errno.E2BIG:x}:".encode("ascii")
            if (isinstance(error, OSError) and error.errno == errno.E2BIG
                    and frame.f_locals.get("errpipe_data") == exec_error and self.exec_error is None):
                self.exec_error = error
            else:
                self.indeterminate = True
        elif event == "return":
            self.launch_finished = True
        return self.trace_launch

    def wire_row(self):
        if (self.metrics is None or not self.launch_finished or not self.constructor_finished
                or self.indeterminate or (self.exec_error is not None) != self.constructor_saw_exec_error):
            raise ExecMeasurementError("capture_incomplete")
        error_errno = errno.E2BIG if self.exec_error is not None else 0
        rc = -1 if error_errno else self.process.returncode
        # An empty exec error pipe cannot distinguish exec from a pre-exec
        # signal death. A signed status alone supplies no exec evidence.
        if type(rc) is not int or (not error_errno and rc < 0):
            raise ExecMeasurementError("capture_incomplete")
        row = replace(self.metrics, error_errno=error_errno, child_rc=rc)
        return self.line, astuple(validate_measurement_row(row))


class _HostedCapture:
    def __init__(self, config, shard):
        import subprocess

        self.constructor_code = subprocess.Popen.__init__.__code__
        self.in_worker = int(hasattr(config, "workerinput"))
        self.worker_context = int(self.in_worker or bool(config.getoption("numprocesses")))
        self.shard = shard
        self.trials = _hosted_trials(self.shard)
        self.summary = b""
        self.builder = None
        self.thread = None
        self.attempts = []
        self.trial_refusal = None
        self.reports = {}
        self.refusal = None
        self.row_count = 0
        if self.in_worker or not self.worker_context:
            sys.addaudithook(self.audit)

    def _reviewed_caller(self, constructor):
        if constructor is None or constructor.f_code is not self.constructor_code:
            return None
        caller = constructor.f_back
        if (caller.f_globals.get("__name__"), caller.f_code.co_name) == ("subprocess", "run"):
            caller = caller.f_back
        location = caller.f_globals.get("__name__"), caller.f_code.co_name
        if location not in _HOSTED_CALLERS:
            return None
        family, module = _HOSTED_SITES[self.builder]
        if location != (module, self.builder):
            self.trial_refusal = "capture_incomplete"
            return None
        return family, caller.f_lineno

    def trace_entry(self, frame, event, _arg):
        if event != "call" or self.trial_refusal:
            return None
        site = self._reviewed_caller(frame)
        if site is None:
            return None
        if len(self.attempts) >= _HOSTED_ROW_LIMIT:
            self.trial_refusal = "summary_rows_limit"
            return None
        _, line = site
        attempt = _HostedAttempt(line, frame.f_locals["self"])
        self.attempts.append(attempt)
        frame.f_trace_lines = False
        return attempt.trace_constructor

    def audit(self, event, args):
        if event != "subprocess.Popen" or self.thread != get_ident() or self.trial_refusal:
            return
        launch = sys._getframe(1)
        if (launch.f_globals.get("__name__"), launch.f_code.co_name) != ("subprocess", "_execute_child"):
            return
        constructor = launch.f_back
        site = self._reviewed_caller(constructor)
        if site is None:
            return
        family, line = site
        process = constructor.f_locals["self"]
        attempt = next((entry for entry in self.attempts if entry.process is process), None)
        if attempt is None or attempt.line != line or attempt.metrics is not None:
            self.trial_refusal = "capture_incomplete"
            return
        try:
            _, argv, _, env = args
            # CPython exposes normalized inputs before fork/exec. The reviewed
            # callers supply explicit maps, so no environment reconstruction is needed.
            attempt.metrics = collect_boundary_metrics(family, argv, env, in_worker=self.in_worker,
                                                       limits=_hosted_limits())
        except ExecMeasurementError as error:
            self.trial_refusal = error.code
            return
        launch.f_trace_lines = False
        launch.f_trace = attempt.trace_launch

    @pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_call(self, item):
        case = self.trials.get(item.nodeid)
        if case is None:
            yield
            return
        if sys.gettrace() is not None:
            yield
            item.user_properties.append((_HOSTED_REPORT, "capture_unsupported"))
            return
        self.builder = case[1]
        self.thread = get_ident()
        try:
            sys.settrace(self.trace_entry)
            yield
        finally:
            self.thread = None
            self.builder = None
            sys.settrace(None)
        try:
            payload = self.trial_refusal or tuple(attempt.wire_row() for attempt in self.attempts)
        except ExecMeasurementError as error:
            payload = error.code
        self.attempts.clear()
        self.trial_refusal = None
        item.user_properties.append((_HOSTED_REPORT, payload))

    def pytest_runtest_logreport(self, report):
        if self.in_worker or report.nodeid not in self.trials or self.refusal:
            return
        if report.when != "call":
            if not report.passed:
                self.refusal = "capture_incomplete"
            return
        payloads = [value for key, value in report.user_properties if key == _HOSTED_REPORT]
        if len(payloads) != 1 or report.nodeid in self.reports:
            self.refusal = "capture_incomplete"
            return
        payload = payloads[0]
        if type(payload) is not tuple:
            self.refusal = ExecMeasurementError(payload).code
            return
        self.row_count += len(payload)
        if self.row_count > _HOSTED_ROW_LIMIT:
            self.refusal = "summary_rows_limit"
            return
        rows = []
        for attempt in payload:
            if type(attempt) is not tuple or len(attempt) != 2:
                self.refusal = "capture_incomplete"
                return
            line, values = attempt
            if type(values) is not tuple or len(values) != _MEASUREMENT_FIELDS:
                self.refusal = "capture_incomplete"
                return
            rows.append((line, ExecBoundaryMeasurement(*values)))
        try:
            _qualify_hosted_trial(report.passed, report.failed, tuple(row for _, row in rows))
        except ExecMeasurementError as error:
            self.refusal = error.code
            return
        self.reports[report.nodeid] = tuple(rows)

    @pytest.hookimpl(optionalhook=True)
    def pytest_xdist_setupnodes(self, specs):
        for spec in specs:
            if not spec.popen or spec.chdir or spec.via:
                raise pytest.UsageError("capture_unsupported")
            # execnet passes -B at interpreter startup. xdist retains the
            # gateway spec when it starts a replacement worker.
            spec.dont_write_bytecode = True

    @pytest.hookimpl(optionalhook=True)
    def pytest_testnodedown(self, error):
        if error is not None:
            self.refusal = "capture_incomplete"

    @pytest.hookimpl(trylast=True)
    def pytest_sessionfinish(self, exitstatus):
        if self.in_worker or self.refusal or exitstatus not in (pytest.ExitCode.OK, pytest.ExitCode.TESTS_FAILED):
            return
        try:
            self.summary = _format_hosted_capture(self.shard, self.worker_context, self.reports).encode("ascii")
        except ExecMeasurementError as error:
            self.refusal = error.code


class _HostedResult:
    # Installed in the controller only. Workers return the existing bounded
    # test report properties through xdist.
    observer: Optional[_HostedCapture] = None

    @pytest.hookimpl(trylast=True)
    def pytest_configure(self, config):
        self.observer = config.pluginmanager.get_plugin(_HOSTED_OBSERVER)


def _supports_hosted_capture():
    return sys.platform == "linux" and sys.implementation.name == "cpython"


def pytest_addoption(parser):
    parser.addoption("--aegis-hosted-workers", choices=("0", "auto"))


def _outside_hosted_checkouts(path, *, replaces_tree=False):
    from pathlib import Path

    try:
        raw = os.fspath(path)
        if len(raw) > 4096:
            raise ExecMeasurementError("capture_incomplete")
        # Pytest resolves the default root directly, but normalizes an
        # explicit basetemp first. Check both orders when a symlink meets '..'.
        lexical = Path(os.path.abspath(raw))
        resolved = Path(raw).resolve()
        spellings = (lexical, lexical.resolve(), resolved)
        roots = (Path.cwd(), Path(__file__).resolve().parents[3],
                 os.environ.get("GITHUB_WORKSPACE"), os.environ.get("RUNNER_TOOL_CACHE"))
        for raw_root in roots:
            if not raw_root:
                continue
            root = Path(raw_root).resolve()
            if any(candidate.is_relative_to(root)
                   or (replaces_tree and root.is_relative_to(candidate)) for candidate in spellings):
                raise ExecMeasurementError("capture_incomplete")
        return resolved
    except ExecMeasurementError:
        raise
    except (OSError, RuntimeError, ValueError):
        raise ExecMeasurementError("capture_incomplete") from None


def _validate_hosted_default_temp():
    import tempfile

    if tempfile.tempdir is None:
        # Let CPython select the usual default, including fallback after a
        # failed writable-directory probe. Refuse unsafe probes before open.
        thread = get_ident()

        def check_probe(event, args):
            if event != "open" or thread != get_ident():
                return
            path, _, flags = args
            # CPython 3.9 also audits io.open wrapping the existing probe fd.
            if not isinstance(path, int) and flags & os.O_CREAT:
                _outside_hosted_checkouts(os.path.dirname(path))

        sys.addaudithook(check_probe)
        try:
            tempfile.gettempdir()
        except OSError:
            raise ExecMeasurementError("capture_incomplete") from None
        finally:
            thread = None
    return _outside_hosted_checkouts(tempfile.gettempdir())


def _hosted_pytest_users():
    import getpass

    try:
        user = getpass.getuser() or "unknown"
    except (ImportError, OSError, KeyError):
        user = "unknown"
    if not 1 <= len(user) <= 128 or not re.fullmatch(r"[A-Za-z0-9_.-]+", user):
        raise ExecMeasurementError("capture_incomplete")
    return tuple(dict.fromkeys(("pytest-of-" + user, "pytest-of-unknown")))


def _validate_hosted_pytest_temp(basetemp):
    if basetemp is not None:
        # xdist supplies the effective worker base before configuring the worker.
        _outside_hosted_checkouts(basetemp, replaces_tree=True)
        return
    default = _validate_hosted_default_temp()
    root = _outside_hosted_checkouts(os.environ.get("PYTEST_DEBUG_TEMPROOT") or default)
    for name in _hosted_pytest_users():
        _outside_hosted_checkouts(root / name, replaces_tree=True)


@pytest.hookimpl(tryfirst=True)
def pytest_load_initial_conftests():
    # This plugin loads before initial conftests on the controller and in
    # each xdist worker. Protect library temp selection without overriding it.
    if not _supports_hosted_capture():
        raise pytest.UsageError("capture_unsupported")
    try:
        _validate_hosted_default_temp()
    except ExecMeasurementError as error:
        raise pytest.UsageError(error.code) from None


@pytest.hookimpl(tryfirst=True)
def pytest_configure(config):
    if not _supports_hosted_capture() or not sys.dont_write_bytecode:
        raise pytest.UsageError("capture_unsupported")
    shard = os.environ.get("TEST_VALIDATE_SHARD")
    workers = "auto" if hasattr(config, "workerinput") or config.getoption("numprocesses") else "0"
    if shard not in _HOSTED_SHARDS or workers != config.getoption("aegis_hosted_workers"):
        raise pytest.UsageError("capture_incomplete")
    try:
        _validate_hosted_pytest_temp(config.getoption("basetemp"))
    except ExecMeasurementError as error:
        raise pytest.UsageError(error.code) from None
    config.pluginmanager.register(_HostedCapture(config, shard), _HOSTED_OBSERVER)


def capture_validate_shard(shard, paths, attempt):
    """Observe one full Validate invocation, returning its status and bounded evidence."""
    import tempfile

    if not _supports_hosted_capture() or os.environ.get("EXECNET_DEBUG"):
        raise ExecMeasurementError("capture_unsupported")
    if (shard not in _HOSTED_SHARDS or type(paths) not in (list, tuple)
            or not 1 <= len(paths) <= MAX_ARGV_ELEMENTS
            or any(type(path) is not str or not path for path in paths)
            or sum(map(len, paths)) > MAX_SINGLE_ITEM_CHARS
            or type(attempt) is not str or attempt not in ("1", "2")):
        raise ExecMeasurementError("capture_incomplete")
    runner_temp = os.environ.get("RUNNER_TEMP", "")
    if not os.path.isabs(runner_temp):
        raise ExecMeasurementError("capture_incomplete")
    runner_temp = _outside_hosted_checkouts(runner_temp, replaces_tree=True)
    _validate_hosted_default_temp()
    try:
        # Runner teardown owns this directory, including when the job times out.
        cache = tempfile.mkdtemp(prefix="aegis-child-exec-", dir=runner_temp)
    except OSError:
        raise ExecMeasurementError("capture_incomplete") from None
    workers = "auto" if attempt == "1" else "0"
    result = _HostedResult()
    status = int(pytest.main([
        "-n", workers, "--durations=25", "-p", __name__, "--aegis-hosted-workers", workers,
        "-o", "cache_dir=" + cache, "--", *paths,
    ], plugins=[result]))
    if result.observer is None or status not in (pytest.ExitCode.OK, pytest.ExitCode.TESTS_FAILED):
        return status, b""
    return status, result.observer.summary


def test_hosted_capture_renders_distinct_trials_and_contexts() -> None:
    assert (_HOSTED_ROW_LIMIT, _HOSTED_BYTE_LIMIT) == (10, 2730)
    summaries = []
    for shard in ("unit-core-a", "unit-rest"):
        trials = _hosted_trials(shard)
        for worker, context in enumerate(("fresh", "worker")):
            results = {}
            for node, (trial, builder) in trials.items():
                family, _ = _HOSTED_SITES[builder]
                failure = worker == 1 and trial == "error"
                row = collect_boundary_metrics(
                    family, ["private/path/to/child"], {"PATH": "private/environment/value"},
                    in_worker=worker, error_errno=errno.E2BIG if failure else 0,
                    child_rc=-1 if failure else int(trial == "error"),
                )
                results[node] = ((42, row),)
            summary = _format_hosted_capture(shard, worker, results)
            for trial, builder in trials.values():
                family, module = _HOSTED_SITES[builder]
                status = "reproduced" if worker and trial == "error" else "not reproduced"
                assert f"{trial} | {builder} | {module}.{builder}:42 | E2BIG {status}" in summary
                assert f"| {family} |" in summary
            assert f"({shard}, {context})" in summary
            summaries.append(summary)
    assert sum(map(len, summaries)) <= MAX_SUMMARY_BYTES
    assert "private/" not in "".join(summaries)


def test_hosted_capture_refuses_missing_and_oversized_trials_then_recovers() -> None:
    shard = "unit-rest"
    results = {
        node: ((42, collect_boundary_metrics(
            _HOSTED_SITES[builder][0], ["python"], {}, in_worker=1, child_rc=int(trial == "error"),
        )),)
        for node, (trial, builder) in _hosted_trials(shard).items()
    }
    key = next(iter(results))
    row = results.pop(key)
    with pytest.raises(ExecMeasurementError, match=r"\Acapture_incomplete\Z"):
        _format_hosted_capture(shard, 1, results)
    results[key] = row * MAX_SUMMARY_ROWS
    with pytest.raises(ExecMeasurementError, match=r"\Asummary_rows_limit\Z"):
        _format_hosted_capture(shard, 1, results)
    results[key] = row
    assert "E2BIG not reproduced" in _format_hosted_capture(shard, 1, results)


def test_hosted_capture_refuses_unsupported_platform(monkeypatch) -> None:
    monkeypatch.setattr("tests.unit.core.test_hosted_child_exec_measurements._supports_hosted_capture", lambda: False)
    with pytest.raises(pytest.UsageError, match=r"\Acapture_unsupported\Z"):
        pytest_configure(None)
    with pytest.raises(ExecMeasurementError, match=r"\Acapture_unsupported\Z"):
        capture_validate_shard("unit-core-a", ["tests"], "1")


def test_hosted_capture_refuses_failed_trial_without_exec_e2big_then_recovers() -> None:
    row = collect_boundary_metrics("reviewed_isolated", ["python"], {}, in_worker=0)
    with pytest.raises(ExecMeasurementError, match=r"\Acapture_incomplete\Z"):
        _qualify_hosted_trial(False, True, (row,))
    _qualify_hosted_trial(True, False, (row,))
    refused = replace(row, error_errno=errno.E2BIG, child_rc=-1)
    _qualify_hosted_trial(False, True, (refused,))
    with pytest.raises(ExecMeasurementError, match=r"\Acapture_incomplete\Z"):
        _qualify_hosted_trial(False, False, (refused,))
    with pytest.raises(ExecMeasurementError, match=r"\Acapture_incomplete\Z"):
        _qualify_hosted_trial(True, False, (row, replace(row, error_errno=errno.EMFILE, child_rc=-1)))


@pytest.mark.skipif(not _supports_hosted_capture(), reason="requires the Linux CPython exec boundary")
def test_hosted_capture_observes_real_errno_and_recovers_in_independent_trials(tmp_path) -> None:
    from tests.helpers_reviewed_sources import run_isolated_test

    # Linux MAX_ARG_STRLEN is 32 pages, including the terminating NUL.
    limit = 32 * os.sysconf("SC_PAGESIZE")
    if not 0 < limit <= MAX_SINGLE_ITEM_CHARS:
        pytest.skip("Linux single-argument limit exceeds the measurement budget")
    shard = "unit-core-a"
    node = next(iter(_hosted_trials(shard)))
    start = Barrier(2, timeout=5)

    def measure(worker):
        config = SimpleNamespace(getoption=lambda _name: 0)
        if worker:
            config.workerinput = {}
        capture = _HostedCapture(config, shard)
        if worker:
            incomplete = SimpleNamespace(nodeid=node, user_properties=[])
            with contextmanager(capture.pytest_runtest_call)(incomplete):
                with pytest.raises(FileNotFoundError):
                    run_isolated_test("pass", cwd=tmp_path / "absent")
            assert incomplete.user_properties == [(_HOSTED_REPORT, "capture_incomplete")]
        item = SimpleNamespace(nodeid=node, user_properties=[])
        with contextmanager(capture.pytest_runtest_call)(item):
            start.wait()
            if worker:
                with pytest.raises(OSError) as failure:
                    run_isolated_test("pass", "x" * limit)
                assert failure.value.errno == errno.E2BIG
            assert run_isolated_test("pass").returncode == 0
        [(key, payload)] = item.user_properties
        assert key == _HOSTED_REPORT
        return [ExecBoundaryMeasurement(*values) for _, values in payload]

    with ThreadPoolExecutor(max_workers=2) as pool:
        fresh = pool.submit(measure, False)
        worker = pool.submit(measure, True)
        fresh_row, = fresh.result(timeout=15)
        failure, retry = worker.result(timeout=15)
    assert (fresh_row.in_worker, fresh_row.error_errno, fresh_row.child_rc) == (0, 0, 0)
    assert (failure.in_worker, failure.error_errno, failure.child_rc) == (1, errno.E2BIG, -1)
    assert failure.argv_max_bytes == limit
    assert (retry.in_worker, retry.error_errno, retry.child_rc) == (1, 0, 0)
    assert (retry.arg_max_bytes, retry.stack_soft_bytes, retry.stack_hard_bytes) == _hosted_limits()


@pytest.mark.skipif(not _supports_hosted_capture(), reason="requires the Linux CPython exec boundary")
@pytest.mark.parametrize("preaudit_first", [True, False])
def test_hosted_capture_refuses_mixed_constructor_outcomes(preaudit_first):
    from tests.helpers_reviewed_sources import run_isolated_test

    limit = 32 * os.sysconf("SC_PAGESIZE")
    if not 0 < limit <= MAX_SINGLE_ITEM_CHARS:
        pytest.skip("Linux single-argument limit exceeds the measurement budget")
    fail_open = False
    thread = get_ident()

    def fail_before_audit(event, args):
        if fail_open and get_ident() == thread and event == "open" and args[0] == os.devnull:
            raise OSError(errno.EMFILE, "test pre-audit failure")

    sys.addaudithook(fail_before_audit)
    capture = _HostedCapture(SimpleNamespace(getoption=lambda _name: 0), "unit-core-a")
    node = next(iter(capture.trials))
    item = SimpleNamespace(nodeid=node, user_properties=[])
    with contextmanager(capture.pytest_runtest_call)(item):
        for before_audit in (preaudit_first, not preaudit_first):
            fail_open = before_audit
            try:
                with pytest.raises(OSError) as failure:
                    run_isolated_test("pass", "x" * limit)
                assert failure.value.errno == (errno.EMFILE if before_audit else errno.E2BIG)
            finally:
                fail_open = False
    assert item.user_properties == [(_HOSTED_REPORT, "capture_incomplete")]
    retry = SimpleNamespace(nodeid=node, user_properties=[])
    with contextmanager(capture.pytest_runtest_call)(retry):
        assert run_isolated_test("pass").returncode == 0
    [(key, ((_, values),))] = retry.user_properties
    assert key == _HOSTED_REPORT
    assert ExecBoundaryMeasurement(*values).child_rc == 0


@pytest.mark.skipif(not _supports_hosted_capture(), reason="requires the Linux CPython exec boundary")
@pytest.mark.parametrize("signal_first", [True, False])
def test_hosted_capture_refuses_signal_only_outcome_even_beside_exec_e2big(signal_first):
    import signal

    from tests.helpers_reviewed_sources import run_isolated_test

    limit = 32 * os.sysconf("SC_PAGESIZE")
    if not 0 < limit <= MAX_SINGLE_ITEM_CHARS:
        pytest.skip("Linux single-argument limit exceeds the measurement budget")
    capture = _HostedCapture(SimpleNamespace(getoption=lambda _name: 0), "unit-core-a")
    node = next(iter(capture.trials))
    item = SimpleNamespace(nodeid=node, user_properties=[])
    program = "import os, signal\nos.kill(os.getpid(), signal.SIGKILL)"
    with contextmanager(capture.pytest_runtest_call)(item):
        for signal_only in (signal_first, not signal_first):
            if signal_only:
                assert run_isolated_test(program).returncode == -signal.SIGKILL
            else:
                with pytest.raises(OSError) as failure:
                    run_isolated_test("pass", "x" * limit)
                assert failure.value.errno == errno.E2BIG
    assert item.user_properties == [(_HOSTED_REPORT, "capture_incomplete")]
    row = collect_boundary_metrics("reviewed_isolated", ["python"], {}, in_worker=0,
                                   child_rc=-signal.SIGKILL)
    assert validate_measurement_row(row).child_rc == -signal.SIGKILL


def _hosted_validate_step():
    from pathlib import Path

    import yaml

    workflow = Path(__file__).resolve().parents[3] / ".github" / "workflows" / "validate.yml"
    job = yaml.safe_load(workflow.read_text())["jobs"]["validate"]
    [step] = (step for step in job["steps"] if step.get("id") == "test")
    return job, step


def _hosted_workflow_body():
    _, step = _hosted_validate_step()
    return step["run"].split(" <<'PYTHON'\n", 1)[1].rsplit("\nPYTHON", 1)[0]


@pytest.fixture
def hosted_shard(tmp_path):
    """A small full shard with ordinary queued work and both reviewed trials."""
    from pathlib import Path

    checkout = tmp_path / "checkout"
    core = checkout / "tests" / "unit" / "core"
    core.mkdir(parents=True)
    runtime, ordinary_temp, traces = (tmp_path / name for name in ("runner", "ordinary-temp", "traces"))
    for path in (runtime, ordinary_temp, traces):
        path.mkdir()
    (checkout / "pytest.ini").write_text("[pytest]\naddopts = --import-mode=importlib\n", encoding="utf-8")
    (checkout / "conftest.py").write_text(
        "import os, sys, pytest\n"
        "import tests.helpers_reviewed_sources\n"
        "assert sys.dont_write_bytecode\n"
        "@pytest.fixture(autouse=True)\n"
        "def selected_setup(request):\n"
        "    if os.environ['CAPTURE_TEST_SCENARIO'] == 'setup' and 'isolated_import' in request.node.name:\n"
        "        pytest.fail('selected setup failed')\n",
        encoding="utf-8",
    )
    (core / "test_a_queued.py").write_text(
        "import os, pytest\n"
        "from pathlib import Path\n"
        "from tests.helpers_reviewed_sources import run_isolated_test\n"
        "@pytest.mark.parametrize('case', range(24))\n"
        "def test_queued(case):\n"
        "    worker = os.environ.get('PYTEST_XDIST_WORKER', 'fresh')\n"
        "    with Path(os.environ['CAPTURE_TEST_TRACES'], str(case)).open('a') as record:\n"
        "        record.write(worker + '\\n')\n"
        "    if case == 0:\n"
        "        assert run_isolated_test('raise SystemExit(19)').returncode == 19\n"
        "        assert os.environ['CAPTURE_TEST_SCENARIO'] != 'other-failure'\n",
        encoding="utf-8",
    )
    (core / "test_redaction.py").write_text(
        "import os, pytest\n"
        "from tests.helpers_reviewed_sources import run_isolated_test\n"
        "scenario = os.environ['CAPTURE_TEST_SCENARIO']\n"
        "@pytest.mark.parametrize('case', ['other' if scenario == 'missing' else 'parent'])\n"
        "def test_redaction_isolated_import_bootstrap(case, tmp_path):\n"
        "    if scenario == 'worker-loss':\n"
        "        os._exit(88)\n"
        "    if scenario == 'interrupt':\n"
        "        pytest.exit('stop the ordinary run', returncode=pytest.ExitCode.INTERRUPTED)\n"
        "    if scenario == 'exec-too-big':\n"
        "        run_isolated_test('pass', 'x' * (32 * os.sysconf('SC_PAGESIZE')))\n"
        "    assert run_isolated_test('pass', tmp_path).returncode == 0\n"
        "def test_private_name_census_rejects_an_unreviewed_importer_path(tmp_path):\n"
        "    assert run_isolated_test('raise SystemExit(1)', tmp_path).returncode == 1\n",
        encoding="utf-8",
    )
    env = {
        "PATH": os.defpath, "HOME": str(tmp_path), "PYTHONPATH": str(Path(__file__).resolve().parents[3]),
        "RUNNER_TEMP": str(runtime), "TMPDIR": str(ordinary_temp), "TEST_VALIDATE_SHARD": "unit-core-a",
        "CAPTURE_HOSTED_CHILD_EXEC": "true", "GITHUB_STEP_SUMMARY": str(runtime / "summary"),
        "GITHUB_REF": "refs/heads/feature/teams-t2a-hosted-ci-isolated-child-e2big-hosted-capture",
        "CAPTURE_TEST_TRACES": str(traces), "PYTEST_XDIST_AUTO_NUM_WORKERS": "2",
    }
    return checkout, traces, runtime / "summary", env


def _run_hosted_dispatch(hosted_shard, attempt, scenario, *, program=None, **environment):
    import subprocess

    checkout, _, _, env = hosted_shard
    return subprocess.run(
        [sys.executable, "-"], cwd=checkout,
        env={**env, "GITHUB_RUN_ATTEMPT": attempt, "CAPTURE_TEST_SCENARIO": scenario, **environment},
        input=_hosted_workflow_body() if program is None else program,
        text=True, capture_output=True, timeout=45,
    )


def test_hosted_dispatch_uses_the_existing_job_deadline_and_attempt_scope():
    job, step = _hosted_validate_step()
    assert job["timeout-minutes"] == 360
    guard = step["env"]["CAPTURE_HOSTED_CHILD_EXEC"]
    for clause in ("github.event_name == 'workflow_dispatch'",
                   "runner.environment == 'github-hosted'", "runner.os == 'Linux'",
                   "(github.run_attempt == '1' || github.run_attempt == '2')"):
        assert clause in guard
    assert not step.get("continue-on-error", False)


@pytest.mark.skipif(not _supports_hosted_capture(), reason="requires the Linux diagnostic workflow")
@pytest.mark.parametrize("ref_prefix", ["refs/tags/feature/", "refs/heads/Feature/"], ids=["tag", "case"])
def test_hosted_dispatch_uses_ordinary_pytest_on_other_refs(hosted_shard, ref_prefix):
    _, traces, summary, env = hosted_shard
    ref = ref_prefix + env["GITHUB_REF"].rsplit("/", 1)[-1]
    result = _run_hosted_dispatch(hosted_shard, "2", "pass", GITHUB_REF=ref, PYTHONDONTWRITEBYTECODE="1")
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert len(list(traces.iterdir())) == 24
    assert not summary.exists()


@pytest.mark.skipif(not _supports_hosted_capture(), reason="requires the Linux diagnostic workflow")
@pytest.mark.parametrize("attempt", ["1", "2"])
@pytest.mark.parametrize("failing", [False, True])
def test_hosted_dispatch_leaves_core_b_in_ordinary_validate(hosted_shard, attempt, failing):
    checkout, traces, summary, _ = hosted_shard
    core = checkout / "tests" / "unit" / "core"
    (core / "test_a_queued.py").rename(core / "test_z_ordinary.py")
    result = _run_hosted_dispatch(
        hosted_shard, attempt, "other-failure" if failing else "pass",
        TEST_VALIDATE_SHARD="unit-core-b", PYTHONDONTWRITEBYTECODE="1",
    )
    assert result.returncode == int(failing), result.stdout + result.stderr
    completed = {path.name: path.read_text().splitlines() for path in traces.iterdir()}
    assert completed.keys() == {str(case) for case in range(24)}
    assert all(len(executions) == 1 for executions in completed.values())
    assert {executions[0] for executions in completed.values()} == {"gw0", "gw1"}
    assert not list(summary.parent.iterdir())
    assert REFUSAL_CODES.isdisjoint(result.stderr.splitlines())


@pytest.mark.skipif(not _supports_hosted_capture(), reason="requires the Linux CPython exec boundary")
@pytest.mark.parametrize("attempt,context,workers", [("1", "worker", {"gw0", "gw1"}), ("2", "fresh", {"fresh"})])
def test_hosted_dispatch_runs_one_full_shard_with_ordinary_scheduler(hosted_shard, attempt, context, workers):
    checkout, traces, summary, _ = hosted_shard
    result = _run_hosted_dispatch(hosted_shard, attempt, "pass")
    assert result.returncode == 0, result.stderr
    completed = {path.name: path.read_text().splitlines() for path in traces.iterdir()}
    assert completed.keys() == {str(case) for case in range(24)}
    assert all(len(executions) == 1 for executions in completed.values())
    assert {executions[0] for executions in completed.values()} == workers
    output = summary.read_bytes()
    assert len(output) <= _HOSTED_BYTE_LIMIT
    assert output.count(b"## Hosted isolated child capture") == 1
    assert f"(unit-core-a, {context})".encode("ascii") in output
    assert output.count(b"E2BIG not reproduced") == 2
    assert len(re.findall(rb"(?m)^\| reviewed_isolated \|", output)) == 2
    assert not list(checkout.rglob("*.pyc"))


@pytest.mark.skipif(not _supports_hosted_capture(), reason="requires the Linux CPython exec boundary")
@pytest.mark.parametrize("attempt,scenario,status,publish", [
    ("2", "setup", 1, False), ("2", "missing", 1, False), ("1", "worker-loss", 1, False),
    ("2", "other-failure", 1, True), ("1", "exec-too-big", 1, True), ("2", "exec-too-big", 1, True),
    ("2", "interrupt", 2, False),
])
def test_hosted_dispatch_preserves_pytest_failure_and_qualifies_evidence(hosted_shard, attempt, scenario, status, publish):
    _, _, summary, _ = hosted_shard
    result = _run_hosted_dispatch(hosted_shard, attempt, scenario)
    assert result.returncode == status, (result.stdout, result.stderr)
    assert summary.is_file() is publish
    if publish:
        assert "capture_incomplete" not in result.stderr
        if scenario == "exec-too-big":
            assert b"E2BIG reproduced" in summary.read_bytes()
    else:
        assert result.stderr.splitlines().count("capture_incomplete") == 1


@pytest.mark.skipif(not _supports_hosted_capture(), reason="requires the Linux CPython temp guard")
def test_hosted_dispatch_accepts_existing_descriptor_open_during_default_temp_probe(hosted_shard):
    from textwrap import indent

    _, _, summary, _ = hosted_shard
    setup = (
        "import io, os, sys, tempfile\n"
        "with tempfile.TemporaryFile(dir=os.environ['RUNNER_TEMP']) as witness:\n"
        "    wrapped = []\n"
        "    def wrap_probe(event, args):\n"
        "        if not wrapped and event == 'open' and isinstance(args[0], str) and args[2] & os.O_CREAT:\n"
        "            wrapped.append(True)\n"
        "            with io.open(witness.fileno(), 'wb', closefd=False):\n"
        "                print('descriptor observed')\n"
        "    sys.addaudithook(wrap_probe)\n"
    )
    result = _run_hosted_dispatch(hosted_shard, "2", "pass", program=setup + indent(_hosted_workflow_body(), "    "))
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines().count("descriptor observed") == 1
    assert summary.is_file()


@pytest.mark.skipif(not _supports_hosted_capture(), reason="requires Linux diagnostic startup")
@pytest.mark.parametrize("refusal", ["attempt", "default-temp", "pytest-temp", "runner-temp"])
def test_hosted_dispatch_refuses_invalid_startup_without_running_ordinary_pytest(hosted_shard, refusal):
    checkout, traces, summary, _ = hosted_shard
    overrides = {
        "attempt": ("3", {}),
        "default-temp": ("2", {"TMPDIR": str(checkout)}),
        "pytest-temp": ("2", {"PYTEST_DEBUG_TEMPROOT": str(checkout)}),
        "runner-temp": ("2", {"RUNNER_TEMP": str(checkout)}),
    }
    attempt, env = overrides[refusal]
    result = _run_hosted_dispatch(hosted_shard, attempt, "pass", **env)
    assert result.returncode in (1, int(pytest.ExitCode.USAGE_ERROR))
    assert result.stderr.splitlines().count("capture_incomplete") == 1
    assert not summary.exists()
    assert not list(traces.iterdir())
    assert not list(checkout.glob("pytest-*"))
