"""Unit and behavioral tests for the pure-stdlib frontmatter engine."""
from __future__ import annotations

import pytest
from aegis_core.yaml_engine.parser import FrontmatterError, parse_yaml_subset
from aegis_core.yaml_engine.serializer import dump_frontmatter
from aegis_core.yaml_engine.frontmatter import parse_frontmatter, parse_rule_frontmatter, split_frontmatter


class TestFrontmatterParser:
    """Tests for parse_yaml_subset and parse_frontmatter."""

    def test_flat_scalars(self):
        text = """
id: rule-123
name: 'Special Rule'
count: 42
pi: 3.14159
is_active: true
is_dormant: false
extra: null
"""
        data = parse_yaml_subset(text)
        assert data["id"] == "rule-123"
        assert data["name"] == "Special Rule"
        assert data["count"] == 42
        assert data["pi"] == 3.14159
        assert data["is_active"] is True
        assert data["is_dormant"] is False
        assert data["extra"] is None

    def test_wrapped_plain_scalars(self):
        text = """
hypothesis: A persona specialized in bash scripting improves the quality of shell-based
  automation.
prediction: Deploying this persona will increase the robustness of install and safety
  scripts.
falsification: Shell scripts are deprecated and no longer used.
"""
        data = parse_yaml_subset(text)
        assert data["hypothesis"] == (
            "A persona specialized in bash scripting improves the quality of shell-based "
            "automation."
        )
        assert data["prediction"] == (
            "Deploying this persona will increase the robustness of install and safety "
            "scripts."
        )
        assert data["falsification"] == "Shell scripts are deprecated and no longer used."

    def test_same_indent_sequences(self):
        text = """
target_paths:
- verifiers/*.sh
- install/*.sh
- verifiers/safety_gate.sh
"""
        data = parse_yaml_subset(text)
        assert data["target_paths"] == [
            "verifiers/*.sh",
            "install/*.sh",
            "verifiers/safety_gate.sh",
        ]

    def test_indented_sequences(self):
        text = """
tags:
  - rule
  - governance
  - zero-deps
"""
        data = parse_yaml_subset(text)
        assert data["tags"] == ["rule", "governance", "zero-deps"]

    def test_literal_block_scalar_pipe(self):
        text = """
activation: |
  Any git tag creation, version bump (pyproject.toml, VERSION),
  release branch creation, or merge to main.
enforcement: gate
"""
        data = parse_yaml_subset(text)
        assert data["activation"] == (
            "Any git tag creation, version bump (pyproject.toml, VERSION),\n"
            "release branch creation, or merge to main.\n"
        )
        assert data["enforcement"] == "gate"

    def test_literal_block_scalar_chomping(self):
        text_strip = """
body: |-
  line one
  line two
"""
        data = parse_yaml_subset(text_strip)
        assert data["body"] == "line one\nline two"

    def test_folded_block_scalar_greater_than(self):
        text = """
summary: >
  This is a long sentence
  that spans across multiple lines
  in folded style.
"""
        data = parse_yaml_subset(text)
        assert data["summary"] == (
            "This is a long sentence that spans across multiple lines in folded style.\n"
        )

    def test_multiline_quoted_strings_with_escapes(self):
        text = r"""
falsification: "Platform count matches between install.sh and uninstall.sh for 10\
  \ sessions \u2192 maintain"
"""
        data = parse_yaml_subset(text)
        assert data["falsification"] == (
            "Platform count matches between install.sh and uninstall.sh for 10 sessions \u2192 maintain"
        )

    def test_sequences_of_mappings(self):
        text = """
rules:
  - id: rule-1
    weight: 1.0
  - id: rule-2
    weight: 0.5
"""
        data = parse_yaml_subset(text)
        assert data["rules"] == [
            {"id": "rule-1", "weight": 1.0},
            {"id": "rule-2", "weight": 0.5},
        ]

    def test_nested_mappings(self):
        text = """
fitness:
  score: 0.95
  signals:
    tp: 19
    fp: 1
"""
        data = parse_yaml_subset(text)
        assert data["fitness"]["score"] == 0.95
        assert data["fitness"]["signals"]["tp"] == 19
        assert data["fitness"]["signals"]["fp"] == 1

    def test_flow_collections(self):
        text = """
tags: [alpha, beta, gamma]
options: {enabled: true, max_depth: 3}
"""
        data = parse_yaml_subset(text)
        assert data["tags"] == ["alpha", "beta", "gamma"]
        assert data["options"] == {"enabled": True, "max_depth": 3}

    def test_comments_and_blank_lines(self):
        text = """
# Header comment
id: test-rule # inline comment

# Another comment
tags: # comment on tag
  - tag1 # comment 1
  - tag2
"""
        data = parse_yaml_subset(text)
        assert data["id"] == "test-rule"
        assert data["tags"] == ["tag1", "tag2"]

    def test_parse_frontmatter_wrapper(self):
        content = """---
id: test
enforcement: advisory
---

# Rule Body
This is markdown content.
"""
        meta = parse_frontmatter(content)
        assert meta == {"id": "test", "enforcement": "advisory"}

    def test_parse_frontmatter_empty_or_missing(self):
        assert parse_frontmatter("# Just markdown\nNo frontmatter") == {}
        assert parse_frontmatter("---\n---\nBody") == {}
        assert parse_frontmatter("---\nopened but never closed") is None

    def test_leading_whitespace_before_the_first_key_is_ignored_as_the_rule_loader_ignores_it(self):
        text = "---\n  id: a\ntype: trap\n---\nbody\n"
        assert parse_frontmatter(text) == {"id": "a", "type": "trap"}
        assert parse_rule_frontmatter(text) == ({"id": "a", "type": "trap"}, "body\n")

    def test_a_directory_path_is_read_as_text_not_opened(self, tmp_path):
        with pytest.raises(ValueError, match="^No frontmatter delimiter$"):
            parse_rule_frontmatter(str(tmp_path))

    def test_parse_rule_frontmatter_body_separation(self, tmp_path):
        rule_file = tmp_path / "rule.md"
        rule_file.write_text(
            "---\nid: rule-file\ntype: invariant\n---\n\n# Body Heading\nBody content\n",
            encoding="utf-8",
        )
        meta, body = parse_rule_frontmatter(str(rule_file))
        assert meta == {"id": "rule-file", "type": "invariant"}
        assert body == "# Body Heading\nBody content\n"

    def test_anchored_delimiter_with_inline_dashes(self):
        content = """---
title: "hello --- world"
desc: foo
---

# Body
Content with --- inside.
"""
        meta = parse_frontmatter(content)
        assert meta == {"title": "hello --- world", "desc": "foo"}

    def test_comments_in_multiline_quotes(self):
        text = """
desc: "line one with # inside quote
  line two with # also inside
  line three"
other: 42
"""
        data = parse_yaml_subset(text)
        assert data["desc"] == "line one with # inside quote\nline two with # also inside\nline three"
        assert data["other"] == 42

    def test_comments_in_block_scalars(self):
        text = """
code: |
  # shell comment
  echo hello # inline comment
  # another comment
enforcement: gate
"""
        data = parse_yaml_subset(text)
        assert data["code"] == "# shell comment\necho hello # inline comment\n# another comment\n"
        assert data["enforcement"] == "gate"

    def test_blank_lines_and_relative_indent_in_block_scalars(self):
        text = """
code: |
  def foo():

      # blank line above, indented line here
      return 42
enforcement: gate
"""
        data = parse_yaml_subset(text)
        assert data["code"] == "def foo():\n\n    # blank line above, indented line here\n    return 42\n"
        assert data["enforcement"] == "gate"

    def test_single_quoted_escaped_single_quotes(self):
        text = """
msg: 'it''s a test with ''escaped'' quotes'
multi: 'first line with ''
  second line'
"""
        data = parse_yaml_subset(text)
        assert data["msg"] == "it's a test with 'escaped' quotes"
        assert data["multi"] == "first line with '\nsecond line"

    def test_unclosed_quote_boundary_check(self):
        text = """
desc: "unclosed quote
sibling_key: 123
"""
        with pytest.raises(FrontmatterError):
            parse_yaml_subset(text)

    def test_crlf_delimiter_parsing(self):
        content = "---\r\nid: test-crlf\r\ncount: 5\r\n---\r\n# Body Content\r\n"
        meta, body = parse_rule_frontmatter(content)
        assert meta == {"id": "test-crlf", "count": 5}
        assert body == "# Body Content\r\n"

    def test_multiline_quote_with_blank_lines(self):
        text = """
desc: "paragraph 1

  paragraph 2"
sibling: 100
"""
        data = parse_yaml_subset(text)
        assert data["desc"] == "paragraph 1\n\nparagraph 2"
        assert data["sibling"] == 100

    def test_parse_yaml_subset_with_bom(self):
        text = "\ufeffid: bom-test\ncount: 42\n"
        data = parse_yaml_subset(text)
        assert data == {"id": "bom-test", "count": 42}

    def test_crlf_escaped_newline_in_double_quotes(self):
        text = 'desc: "part 1\\\r\n  part 2"\n'
        data = parse_yaml_subset(text)
        assert data["desc"] == "part 1part 2"

    def test_multiline_quotes_in_sequence_items(self):
        text = """
items:
  - "first line
    second line"
  - 'single line'
"""
        data = parse_yaml_subset(text)
        assert data["items"] == ["first line\nsecond line", "single line"]


class TestSplitFrontmatter:
    """split_frontmatter, the one delimiter scanner: (status, frontmatter text, body)."""

    @pytest.mark.parametrize("content, expected", [
        ("---", ("unterminated", None, "---")),  # an opening line and nothing after it
        ("---\nid: a\n", ("unterminated", None, "---\nid: a\n")),
        ("---\n---\nbody", ("ok", "", "\nbody")),  # the closer can be the very next line
        ("---\nid: a\n---\nbody\n---\n", ("ok", "id: a\n", "\nbody\n---\n")),  # the first closer wins
        ("\ufeff---\nid: a\n---\n", ("ok", "id: a\n", "\n")),  # a BOM is not part of the text
        ("# title\n---\n", ("none", None, "# title\n---\n")),
    ])
    def test_split(self, content, expected):
        assert split_frontmatter(content) == expected


class TestFrontmatterDumper:
    """Tests for dump_frontmatter."""

    def test_dump_roundtrip_simple(self):
        data = {
            "id": "my-rule",
            "type": "invariant",
            "weight": 1.5,
            "count": 10,
            "active": True,
            "tags": ["invariant", "security"],
        }
        dumped = dump_frontmatter(data)
        parsed = parse_frontmatter(f"---\n{dumped}---\n")
        assert parsed == data

    def test_dump_roundtrip_nested(self):
        data = {
            "id": "nested-rule",
            "fitness": {
                "score": 0.85,
                "history": [1, 2, 3],
                "meta": {"verified": False},
            },
        }
        dumped = dump_frontmatter(data)
        parsed = parse_frontmatter(f"---\n{dumped}---\n")
        assert parsed == data

    def test_dump_escaping(self):
        data = {
            "title": "Rule: Always Check Inputs",
            "note": "Line 1\nLine 2",
        }
        dumped = dump_frontmatter(data)
        parsed = parse_frontmatter(f"---\n{dumped}---\n")
        assert parsed == data

    def test_dump_quotes_strings_with_dashes(self):
        data = {
            "title": "hello --- world",
            "delim": "---",
        }
        dumped = dump_frontmatter(data)
        assert '"hello --- world"' in dumped
        assert '"---"' in dumped
        parsed = parse_frontmatter(f"---\n{dumped}---\n")
        assert parsed == data
