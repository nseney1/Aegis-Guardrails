"""Validate bounded process measurements and their numeric table on synthetic data."""

from __future__ import annotations

from collections import ChainMap
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
import errno
from itertools import islice
import os
import re
import struct
import sys
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
