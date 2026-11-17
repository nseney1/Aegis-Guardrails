"""Dense colour must retain benign bytes without weakening attribution proofs."""
from concurrent.futures import ThreadPoolExecutor
import inspect
from itertools import product
import re

import pytest

from aegis_core import display_attribution as attribution, primitives
from tests.unit.cli import test_cli_helpers as legacy
from tests.unit.core import test_primitives as regressions


LINE = "\x1b[32m+    value = compute(item, index)  # benign diff line\x1b[0m\n"
PROJECTION = "+    value = compute(item, index)  # benign diff line "


@pytest.mark.parametrize("count", [16, 159, 1000, 1600, 4444, 5000])
def test_dense_benign_projection(count):
    shown = primitives.sanitize_display(LINE * count, max_len=None)
    assert shown == PROJECTION * count
    assert "[REDACTED]" not in shown


@pytest.mark.parametrize("size", [1000, 10000, 100000, 280000])
def test_exact_input_sizes_keep_dense_projection(size):
    count, tail = divmod(size, len(LINE))
    value = LINE * count + "b" * tail
    assert len(value) == size
    assert primitives.sanitize_display(value, max_len=None) == PROJECTION * count + "b" * tail


def test_dense_split_secret_and_retry_in_parallel():
    key = "AK" + "IA" + "A" * 16
    values = [LINE * 1600, LINE * 500 + key[:2] + "\x1b[32m" + key[2:] + LINE * 500] * 3
    expected = [PROJECTION * 1600, "[REDACTED]"] * 3
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(lambda value: primitives.sanitize_display(value, max_len=None), values)) == expected
    assert [primitives.sanitize_display(value, max_len=None) for value in values[:2]] == expected[:2]


def test_width_and_small_exact_window_do_not_compile_graph(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("width lookup or exact interpretation compiled attribution graph")

    primitives._display_attribution_tables.cache_clear()
    primitives._display_attribution_width.cache_clear()
    monkeypatch.setattr("aegis_core.display_attribution.compile_possible", forbidden)
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(lambda _: primitives.sanitize_display("left\x1b[31mright", max_len=None),
                             range(6))) == ["leftright"] * 6
    assert primitives.sanitize_display("left\x1b[31mright", max_len=None) == "leftright"


@pytest.mark.parametrize("limit", [0, 1, 4])
def test_memo_cap_falls_back_to_local_budget_and_retries(limit, monkeypatch):
    monkeypatch.setattr("aegis_core.display_attribution._DFA_STATE_LIMIT", limit)
    monkeypatch.setattr("aegis_core.primitives._DISPLAY_ATTRIBUTION_CEILING", 50000)
    # Keep the window below the ceiling so it reaches the capped DFA before
    # the ordinary NFA fallback exhausts its remaining budget.
    first = "before\x1b]title\x07" + LINE * 100 + "\x1b]title\x07after"
    expected = "before[REDACTED]after"
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(lambda _: primitives.sanitize_display(first, max_len=None), range(3))) == [expected] * 3
    assert primitives.sanitize_display("safe\x1b[31mtext", max_len=None) == "safetext"


def test_memo_member_cap_falls_back_without_changing_proof(monkeypatch):
    monkeypatch.setattr("aegis_core.display_attribution._DFA_UNIT_LIMIT", 1)
    grammar = attribution.compile_possible([re.compile("needle")])
    runs = [(0, 1000, 0, True, None, 0)]
    assert not attribution.may_match_visible(grammar, "z" * 1000, runs, lambda _: True)
    assert attribution.may_match_visible(grammar, "z" * 1000, runs, lambda _: False)


def test_cached_proof_still_refuses_when_hit_budget_is_exhausted():
    remaining = [100]

    def charge(amount):
        if amount > remaining[0]:
            return False
        remaining[0] -= amount
        return True

    grammar = attribution.compile_possible([re.compile("needle")])
    runs = [(0, 1000, 0, True, None, 0)]
    assert attribution.may_match_visible(grammar, "z" * 1000, runs, charge)
    assert remaining == [0]
    assert not attribution.may_match_visible(grammar, "z" * 1000, runs, lambda _: True)


def test_budget_refusal_stays_in_affected_window(monkeypatch):
    monkeypatch.setattr("aegis_core.primitives._DISPLAY_ATTRIBUTION_CEILING", 0)
    value = "before\x1b]title\x07" + LINE * 20 + "\x1b]title\x07after"
    assert primitives.sanitize_display(value, max_len=None) == "before[REDACTED]after"


@pytest.mark.parametrize("pattern", [r"(?<!x)a[bc]{1,2}", r"(?i)(?<![a-z])ab", r"a(?:bc|d){1,3}"])
def test_memo_matches_uncached_optional_and_lookbehind_states(pattern):
    grammar = attribution.compile_possible([re.compile(pattern)])
    for value in ("abc", "xabc", "abcbcd", "ABC", "zzz", "xabc" * 20):
        for visible in (True, False):
            runs = [(i, i + 1, i % 2, visible or i % 3 == 0, None, 0) for i in range(len(value))]
            for start in (0, 1):
                expected = attribution.may_match_visible(grammar, value, runs, lambda _: True,
                                                         start_at=start, memoize=False)
                assert attribution.may_match_visible(grammar, value, runs, lambda _: True,
                                                     start_at=start) == expected


def regression_cases():
    """Replay unedited display assertions that do not require a patch fixture."""
    functions = [function for name, function in inspect.getmembers(regressions, inspect.isfunction)
                 if name.startswith("test_display_") and "monkeypatch" not in inspect.signature(function).parameters]
    functions.append(legacy.test_display_matches_legacy_output_for_supported_escape_corpus)
    for function in functions:
        groups = []
        for mark in getattr(function, "pytestmark", ()):
            if mark.name != "parametrize":
                continue
            names, rows = mark.args[:2]
            names = names.split(",") if isinstance(names, str) else names
            names = [name.strip() for name in names]
            groups.append([dict(zip(names, row.values if hasattr(row, "values") else
                                    (row,) if len(names) == 1 else row)) for row in rows])
        for index, combination in enumerate(product(*groups)):
            arguments = {name: value for group in combination for name, value in group.items()}
            yield pytest.param(function, arguments, id=f"{function.__name__}-{index}")


@pytest.mark.parametrize("function,arguments", regression_cases())
@pytest.mark.parametrize("memoize", [True, False], ids=["memo", "nfa"])
def test_unedited_regression_corpus_memo_parity(function, arguments, memoize, monkeypatch):
    # Each original assertion still checks the complete public display output.
    # At every graph search also compare cached/uncached language acceptance
    # without exhaustion, then use the real caller's budget for its result.
    original = attribution.may_match_visible

    def checked(grammar, text, runs, charge, **kwargs):
        expected = original(grammar, text, runs, lambda _: True, memoize=False, **kwargs)
        assert original(grammar, text, runs, lambda _: True, **kwargs) == expected
        return original(grammar, text, runs, charge, memoize=memoize, **kwargs)

    primitives._display_attribution_tables.cache_clear()
    monkeypatch.setattr("aegis_core.display_attribution.may_match_visible", checked)
    try:
        function(**arguments)
    finally:
        primitives._display_attribution_tables.cache_clear()


def instrumented_cases():
    """Inputs from the fixture-based regressions; their instrumentation stays in the original file."""
    key = "AK" + "IA" + "A" * 16
    candidate = "\x1b[" + key[:4] + "\x1b[31m" + key[4:]
    yield "before\x1b]title\x07" + candidate + "\x1b]title\x07after"
    for count in (128, 1024, 8192):
        yield "gh" + "p_" + "\x1b[a" * count + "!"
    for value in ("plain", "\r\x00safe", "before\x1b]title", "\x9b31mplain",
                  "before\x1b]title\x07after", "\t\n"):
        yield value
    part = "z" * (2 * primitives._display_attribution_width() + 77)
    yield part + "\x1b[31m" + part + "\x1b[31m" + part
    for count in (5000, 50000):
        gap = "\x00" * count
        yield "\x1b[" + key[:1] + gap + key[1:4] + "\x1b[31m" + key[4:]
        yield "\x1b[" + key[:4] + gap + "\x1b[31m" + key[4:]
        yield "\x1b[" + key[:4] + "\x1b[31m" + gap + key[4:]
    prefix = "git" + "hub_pat_"
    yield prefix + "a" * 200 + "_" + prefix + "\x1b[b" + "b" * 99


@pytest.mark.parametrize("value", [pytest.param(value, id=f"case-{index}")
                                    for index, value in enumerate(instrumented_cases())])
def test_instrumented_regression_inputs_have_identical_output(value, monkeypatch):
    expected = primitives.sanitize_display(value, max_len=None)
    monkeypatch.setattr("aegis_core.display_attribution._DFA_STATE_LIMIT", 0)
    assert primitives.sanitize_display(value, max_len=None) == expected
