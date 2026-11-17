"""Keep the shipped attribution grammar supported, with 10% graph headroom."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import re
import subprocess
import sys

from aegis_core import display_attribution, primitives


def test_shipped_rules_keep_ten_percent_graph_headroom():
    # Pin the safety limit so raising it cannot hide growth in the shared rows.
    limit = display_attribution._GRAPH_LIMIT
    assert limit == 32768, "review the graph budget; do not raise it to pass this contract"
    _width, grammar, _match = primitives._display_attribution_tables()
    assert grammar is not None, "shipped display rules must compile without conservative whole-window masking"
    nodes = len(grammar[0])
    ceiling = limit * 9 // 10
    assert nodes <= ceiling, (
        f"shipped display rules use {nodes}/{limit} graph nodes; maximum {ceiling} "
        "to retain at least 10% headroom. Reduce graph growth; do not raise the limit."
    )


def test_parser_import_and_behavior_with_deprecations_as_errors():
    # Fresh interpreters cannot hide a deprecated import in sys.modules. Repeat
    # concurrently, and reload inside each child to cover repeated initialization.
    script = r'''
import importlib
import re
from aegis_core import display_attribution as attribution, primitives
for _ in range(2):
    importlib.reload(attribution)
    assert attribution.max_match_width([re.compile(r"a{7}(?:bc|d)")], unbounded_cap=64) == 9
    assert attribution.max_match_width([re.compile(r"a*")], unbounded_cap=64) == 64
    grammar = attribution.compile_possible([re.compile(r"(?<!x)a[bc]{1,2}")])
    assert grammar is not None
    runs = [(0, 3, 0, True, None, 0)]
    assert attribution.may_match_visible(grammar, "abc", runs, lambda amount: True)
    assert not attribution.may_match_visible(grammar, "xyz", runs, lambda amount: True)
    assert attribution.compile_possible([re.compile(r"(ab)\1")]) is None
    assert primitives.sanitize_display("safe colour \x1b[31mtext\x1b[0m", max_len=None) == "safe colour text"
'''

    def run(_index):
        return subprocess.run(
            [sys.executable, "-W", "error::DeprecationWarning", "-c", script],
            cwd=Path(__file__).resolve().parents[2], capture_output=True, text=True, timeout=30,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(run, range(2)))
    for result in results:
        assert result.returncode == 0, result.stderr
        assert result.stdout == ""


def test_graph_limit_refusal_and_retry_are_isolated_in_parallel():
    chunk = re.compile(r"a{2048}")
    at_limit = [chunk] * 15 + [re.compile(r"a{2047}")]
    over_limit = [chunk] * 16

    def compile_and_retry(_index):
        assert display_attribution.compile_possible(over_limit) is None
        grammar = display_attribution.compile_possible(at_limit)
        assert grammar is not None
        assert len(grammar[0]) == 32768
        small = display_attribution.compile_possible([re.compile("abc")])
        assert small is not None
        assert len(small[0]) == 4

    with ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(compile_and_retry, range(3)))
