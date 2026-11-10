"""Tests for aegis_core.yaml — Pure-Python AegisYAML engine & unified domain model."""
from __future__ import annotations

from pathlib import Path
import pytest

from conftest import symlink_or_skip
from aegis_core.yaml_engine.frontmatter import AegisYAML, parse_frontmatter, parse_rule_frontmatter, _get_body
from aegis_core.yaml_engine.document import AegisDocument
from aegis_core.yaml_engine.parser import (
    AegisYAMLError,
    FrontmatterError,
    parse_yaml_subset,
    MAX_DOC_BYTES,
    MAX_SCALAR_CHARS,
    MAX_LINES,
    MAX_DEPTH,
)
from aegis_core.yaml_engine.serializer import dump_frontmatter
from aegis_core.workspace.base import Workspace


class TestAegisYAMLCoreParsing:
    """Test standard YAML subset parsing capabilities."""

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

    def test_block_scalars_literal_and_folded(self):
        text = """
literal: |
  line 1
  line 2
folded: >
  line 1
  line 2
"""
        data = parse_yaml_subset(text)
        assert data["literal"] == "line 1\nline 2\n"
        assert data["folded"] == "line 1 line 2\n"

    def test_nested_mappings_and_sequences(self):
        text = """
id: rule-complex
target_paths:
  - "aegis_core/*.py"
  - "aegis_cli/*.py"
fitness:
  triggers: 10
  score: 0.95
tags: [security, gates, v1]
"""
        data = parse_yaml_subset(text)
        assert data["target_paths"] == ["aegis_core/*.py", "aegis_cli/*.py"]
        assert data["fitness"]["triggers"] == 10
        assert data["fitness"]["score"] == 0.95
        assert data["tags"] == ["security", "gates", "v1"]

    def test_unquoted_apostrophes_and_ratios(self):
        text = """
desc: project's DNA
ratio: 1:1
"""
        data = parse_yaml_subset(text)
        assert data["desc"] == "project's DNA"
        assert data["ratio"] == "1:1"


class TestAegisYAMLSafetyAndDoSGuards:
    """Security, anti-poisoning, and denial-of-service controls."""

    def test_max_doc_bytes_limit(self):
        oversized = "a: " + ("x" * (MAX_DOC_BYTES + 10))
        with pytest.raises(AegisYAMLError, match="exceeds maximum allowed size"):
            AegisYAML.parse_text(oversized)

    def test_max_lines_limit(self):
        too_many_lines = "\n".join(f"k{i}: v" for i in range(MAX_LINES + 5))
        with pytest.raises(AegisYAMLError, match="exceeds maximum line limit"):
            AegisYAML.parse_text(too_many_lines)

    def test_max_scalar_chars_limit(self):
        long_scalar = "key: " + ("A" * (MAX_SCALAR_CHARS + 1))
        with pytest.raises(AegisYAMLError, match=r"Scalar length \(\d+\) exceeds maximum limit"):
            AegisYAML.parse_text(long_scalar)

    def test_max_depth_block_limit(self):
        nested = ""
        for i in range(MAX_DEPTH + 2):
            nested += f"{'  ' * i}nest_{i}:\n"
        nested += f"{'  ' * (MAX_DEPTH + 2)}val: leaf\n"
        with pytest.raises(AegisYAMLError, match="Maximum YAML nesting depth exceeded"):
            AegisYAML.parse_text(nested)

    def test_max_depth_flow_limit(self):
        nested_flow = "a: " + ("[" * (MAX_DEPTH + 2)) + ("0" * 1) + ("]" * (MAX_DEPTH + 2))
        with pytest.raises(AegisYAMLError, match="Maximum YAML nesting depth exceeded"):
            AegisYAML.parse_text(nested_flow)

    def test_duplicate_key_prohibition_block(self):
        text = """
id: invariant-1
enforcement: advisory
enforcement: gate
"""
        with pytest.raises(AegisYAMLError, match="Duplicate key 'enforcement' detected"):
            AegisYAML.parse_text(text)

    def test_duplicate_key_prohibition_flow(self):
        text = "map: {key: 1, key: 2}"
        with pytest.raises(AegisYAMLError, match="Duplicate key 'key' detected"):
            AegisYAML.parse_text(text)

    def test_zero_width_handling(self):
        # Review M5: stripping zero-width characters inside values silently changed data. Only a
        # leading document BOM is stripped; values keep them; a raw invisible character in a key
        # is rejected so it cannot spoof a visually identical key.
        doc = AegisYAML.parse_text("\ufeffid: rule\u200b-x\ntier: \u200dmethod")
        assert doc["id"] == "rule\u200b-x"
        assert doc["tier"] == "\u200dmethod"
        with pytest.raises(AegisYAMLError, match="invisible"):
            AegisYAML.parse_text("id: rule\n\u200ctier: method")

    def test_control_character_rejection(self):
        text = "key: bad\x07bell"
        with pytest.raises(AegisYAMLError, match="Control character"):
            AegisYAML.parse_text(text)

    def test_null_byte_escape_rejection(self):
        text = 'key: "null\\0byte"'
        with pytest.raises(AegisYAMLError, match="Escape sequence \\\\0 is not permitted"):
            AegisYAML.parse_text(text)


class TestAegisDocumentAndDomainModel:
    """Test polymorphic document models, schema inference, and mapping interface."""

    def test_rule_kind_auto_inference(self):
        text = """---
id: invariant-symlink
type: invariant
enforcement: gate
---
# Invariant Symlink
"""
        doc = AegisYAML.parse_text(text)
        assert isinstance(doc, AegisDocument)
        assert doc.kind == "rule"
        assert doc.id == "invariant-symlink"
        assert doc.enforcement == "gate"
        assert doc.type == "invariant"
        assert doc.decay is True
        assert doc.target_paths == []
        assert doc["id"] == "invariant-symlink"
        assert "Invariant Symlink" in doc.body

    def test_a_skill_is_a_document_with_kind_skill_and_gets_no_injected_keys(self):
        text = """---
id: tdd-cycle
kind: skill
---
# TDD Cycle
"""
        doc = AegisYAML.parse_text(text)
        assert doc.kind == "skill"
        assert doc.id == "tdd-cycle"
        assert doc.decay is False
        # The v4 skill graph is gone: no tier, consumes, produces or handoff_targets default.
        assert doc.to_dict() == {"id": "tdd-cycle", "kind": "skill"}

    def test_the_removed_handoff_keys_no_longer_make_a_document_a_skill(self):
        text = """---
id: legacy-skill
tier: method
consumes: [FeatureSpec]
produces: [VerifiedPatch]
handoff_targets: [staff-review]
---
"""
        doc = AegisYAML.parse_text(text)
        assert doc.kind == "rule"
        assert doc["consumes"] == ["FeatureSpec"]  # kept as data, read by nothing

    def test_mapping_interface(self):
        doc = AegisDocument(metadata={"id": "test", "num": 42}, body="# Body", kind="generic")
        assert len(doc) == 2
        assert "id" in doc
        assert "missing" not in doc
        assert doc["id"] == "test"
        assert doc.get("num") == 42
        assert doc.get("missing", "default") == "default"
        assert list(doc.keys()) == ["id", "num"]
        assert list(doc.values()) == ["test", 42]
        assert list(doc.items()) == [("id", "test"), ("num", 42)]
        assert doc.metadata == {"id": "test", "num": 42}
        assert doc.body == "# Body"

    def test_parse_file_confined_workspace(self, tmp_path: Path):
        ws = Workspace(tmp_path)
        rule_file = tmp_path / "rule.md"
        rule_file.write_text("---\nid: local-rule\n---\n# Body\n", encoding="utf-8")

        doc = AegisYAML.parse_file("rule.md", ws)
        assert doc.id == "local-rule"

    def test_parse_file_rejects_symlinks(self, tmp_path: Path):
        ws = Workspace(tmp_path)
        real_file = tmp_path / "real.md"
        real_file.write_text("---\nid: real\n---\n", encoding="utf-8")

        symlink_file = tmp_path / "symlink.md"
        try:
            symlink_file.symlink_to(real_file)
        except OSError:
            pytest.skip("Symlinks not supported on this platform")

        with pytest.raises(AegisYAMLError, match="Symlink parsing prohibited"):
            AegisYAML.parse_file("symlink.md", ws)


class TestBackwardCompatibilityParity:
    """Ensure exact drop-in parity with legacy frontmatter API."""

    def test_parse_frontmatter_and_get_body(self):
        text = "---\nid: legacy-rule\nversion: 1.0\n---\n# Rule Content\nLine 2"
        meta = parse_frontmatter(text)
        assert meta["id"] == "legacy-rule"
        assert meta["version"] == 1.0
        assert _get_body(text) == "# Rule Content\nLine 2"

    def test_parse_rule_frontmatter_file_and_str(self, tmp_path: Path):
        f = tmp_path / "rule.md"
        f.write_text("---\nid: from-file\n---\n# Body from file", encoding="utf-8")

        meta1, body1 = parse_rule_frontmatter(str(f))
        assert meta1["id"] == "from-file"
        assert body1 == "# Body from file"

        meta2, body2 = parse_rule_frontmatter("---\nid: from-str\n---\n# Body from str")
        assert meta2["id"] == "from-str"
        assert body2 == "# Body from str"

    def test_dump_frontmatter_roundtrip(self):
        data = {
            "id": "roundtrip-rule",
            "active": True,
            "score": 0.88,
            "tags": ["alpha", "beta"],
            "nested": {"key": "val"},
        }
        body = "# Header\nBody text"
        dumped = dump_frontmatter(data, body=body)
        meta, parsed_body = parse_rule_frontmatter(dumped)
        assert meta == data
        assert parsed_body == body

    def test_dump_frontmatter_edge_scalars(self):
        assert dump_frontmatter({"empty": ""}).strip() == 'empty: ""'
        assert dump_frontmatter({"spaced": " hello "}).strip() == 'spaced: " hello "'
        assert dump_frontmatter({"colon": "a: b"}).strip() == 'colon: "a: b"'
        assert dump_frontmatter({"hyphens": "---"}).strip() == 'hyphens: "---"'

    def test_parse_frontmatter_delimiters_and_edges(self):
        assert parse_frontmatter("---") is None
        assert parse_frontmatter("---\nfoo: bar") is None
        assert parse_frontmatter("---\n---\nbody") == {}
        assert parse_frontmatter("not frontmatter") == {}

    def test_parse_yaml_subset_unparsed_trailing(self):
        with pytest.raises(FrontmatterError, match="unparsed content"):
            parse_yaml_subset("  key1: val1\nkey2: val2")

    def test_string_escapes_and_comments(self):
        with pytest.raises(AegisYAMLError, match="Escape sequence \\\\0"):
            parse_yaml_subset('key: "\\0"')

        # line continuation
        res_cr = parse_yaml_subset('key: "line1\\\r\n  line2"')
        assert res_cr["key"] == "line1line2"
        res_lf = parse_yaml_subset('key: "line1\\\n  line2"')
        assert res_lf["key"] == "line1line2"

        # unicode escapes
        res_u = parse_yaml_subset('key: "\\u0041"')
        assert res_u["key"] == "A"
        res_big_u = parse_yaml_subset('key: "\\U00000041"')
        assert res_big_u["key"] == "A"

        # comments inside quotes
        res_comment = parse_yaml_subset('key: "val # not comment" # real comment')
        assert res_comment["key"] == "val # not comment"

        # unterminated quotes
        with pytest.raises(FrontmatterError, match="unterminated"):
            parse_yaml_subset('key: "unclosed')
        with pytest.raises(FrontmatterError, match="unterminated"):
            parse_yaml_subset("key: 'unclosed")


import datetime


class TestAegisYAMLBranchHardening:
    """Systematic branch coverage hardening for aegis_core.yaml."""

    def test_aegis_document_comprehensive_properties(self, tmp_path: Path):
        doc = AegisDocument(metadata={"kind": "skill", "id": "s1", "type": "invariant"}, body="body text", source_path="/tmp/doc.md")
        assert doc.kind == "skill"
        assert doc.id == "s1"
        assert doc.name == "s1"
        assert doc.type == "invariant"
        assert doc.body == "body text"
        assert doc.source_path == "/tmp/doc.md"
        assert doc.to_dict() == {"kind": "skill", "id": "s1", "type": "invariant"}
        assert list(iter(doc)) == ["kind", "id", "type"]
        assert ("AegisDocument" in repr(doc) or "AegisDocument" in repr(doc))
        assert doc["id"] == "s1"
        assert doc.get("nonexistent", "fallback") == "fallback"
        assert "id" in doc.keys()
        assert "s1" in list(doc.values())
        assert len(doc.items()) >= 3
        assert doc.enforcement is None
        assert doc.target_paths == []
        assert doc.decay is False

        # rule kind auto inference
        doc_rule = AegisDocument(metadata={"id": "r1", "type": "invariant", "enforcement": "strict", "target_paths": ["a.py"]})
        assert doc_rule.kind == "rule"
        assert doc_rule.enforcement == "strict"
        assert doc_rule.target_paths == ["a.py"]
        assert doc_rule.decay is True

        # explicit kind
        doc_explicit = AegisDocument(metadata={"id": "e1"}, kind="custom_kind")
        assert doc_explicit.kind == "custom_kind"

    def test_ruleyaml_parse_text(self):
        # parse_text with frontmatter and body
        doc = AegisYAML.parse_text("---\nid: rule-abc\nkind: skill\n---\n# Markdown Body\nHello world")
        assert doc.id == "rule-abc"
        assert doc.body == "# Markdown Body\nHello world"

        # parse_text with only yaml mapping
        doc_raw = AegisYAML.parse_text("id: rule-raw\nscore: 1.0\n")
        assert doc_raw.id == "rule-raw"
        assert doc_raw.body == ""

        # parse_text error branches
        with pytest.raises(FrontmatterError, match="Expected YAML mapping at document root"):
            AegisYAML.parse_text("---\n- item 1\n- item 2\n---\n")

        with pytest.raises(FrontmatterError, match="Expected YAML mapping at document root"):
            AegisYAML.parse_text("- item 1\n- item 2\n")

    def test_ruleyaml_parse_file_and_write_frontmatter(self, tmp_path: Path):
        # workspace without confine_path raises AegisYAMLError
        class BadWS:
            pass
        with pytest.raises(AegisYAMLError, match="confine_path"):
            AegisYAML.parse_file("foo.md", BadWS())

        # real Workspace
        ws = Workspace(tmp_path)

        # nonexistent file
        with pytest.raises(FileNotFoundError, match="File does not exist"):
            AegisYAML.parse_file("missing.md", ws)

        # valid file
        real_file = tmp_path / "target.md"
        real_file.write_text("---\nid: sym-target\n---\n", encoding="utf-8")
        doc = AegisYAML.parse_file("target.md", ws)
        assert doc.id == "sym-target"
        assert doc.source_path == str(real_file.resolve())

        # workspace returning string path (not tuple)
        class StringWS:
            def confine_path(self, p):
                return str(real_file.resolve())
        doc_str = AegisYAML.parse_file("target.md", StringWS())
        assert doc_str.id == "sym-target"

    def test_parse_file_rejects_symlinks_branch_hardening(self, tmp_path: Path):
        ws = Workspace(tmp_path)
        real_file = tmp_path / "target.md"
        real_file.write_text("---\nid: sym-target\n---\n", encoding="utf-8")
        symlink_file = tmp_path / "link.md"
        symlink_or_skip(real_file, symlink_file)
        with pytest.raises(AegisYAMLError, match="Symlink parsing prohibited"):
            AegisYAML.parse_file("link.md", ws)

        # workspace returning symlink path
        class SymlinkReturnWS:
            def confine_path(self, p):
                return str(symlink_file)
        with pytest.raises(AegisYAMLError, match="Symlink parsing prohibited"):
            AegisYAML.parse_file("link.md", SymlinkReturnWS())

    def test_parse_rule_frontmatter_branches(self, tmp_path: Path):
        with pytest.raises(ValueError, match="No frontmatter delimiter"):
            parse_rule_frontmatter("not frontmatter content")

        with pytest.raises(ValueError, match="Unclosed frontmatter"):
            parse_rule_frontmatter("---")

        with pytest.raises(ValueError, match="Unclosed frontmatter"):
            parse_rule_frontmatter("---\nid: unclosed\nline 2")

        with pytest.raises(ValueError, match="Expected YAML mapping"):
            parse_rule_frontmatter("---\n- item1\n- item2\n---\n")

        # Zero-width spaces stripping
        zw_text = "\u200b---\nid: zw\n---\nBody"
        meta, body = parse_rule_frontmatter(zw_text)
        assert meta["id"] == "zw"
        assert body == "Body"

    def test_helpers_get_body_and_parse_frontmatter(self):
        # _get_body branches
        assert _get_body("\u200bhello") == "hello"
        assert _get_body("no delimiters") == "no delimiters"
        assert _get_body("---") == "---"
        assert _get_body("---\nid: 1\nno closing delim") == "---\nid: 1\nno closing delim"

        # parse_frontmatter branches
        assert parse_frontmatter(123) is None  # type: ignore
        assert parse_frontmatter("\u200b---\nid: zw-fm\n---\n") == {"id": "zw-fm"}
        assert parse_frontmatter("---\n---\n") == {}
        assert parse_frontmatter("---\ninvalid: [unclosed\n---\n") is None

    def test_dump_frontmatter_edge_types(self):
        # null scalar
        assert "null_val: null" in dump_frontmatter({"null_val": None})

        # datetime scalar
        dt = datetime.datetime(2026, 1, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)
        assert "2026-01-01" in dump_frontmatter({"timestamp": dt})

        # empty map and empty list
        dumped = dump_frontmatter({"empty_map": {}, "empty_list": []})
        assert "empty_map: {}" in dumped
        assert "empty_list: []" in dumped

        # sequence of mappings
        dumped_seq = dump_frontmatter({"items": [{"name": "alice", "score": 10}, {"name": "bob", "score": 20}]})
        assert "items:" in dumped_seq
        assert "name: alice" in dumped_seq
        assert "name: bob" in dumped_seq

    def test_parse_yaml_subset_syntax_and_depth_errors(self):
        # Tab error
        with pytest.raises(FrontmatterError, match="tab characters are not allowed"):
            parse_yaml_subset("key:\n\tval: 1")

        # Escapes
        with pytest.raises(AegisYAMLError, match="Escape sequence \\\\0"):
            parse_yaml_subset('key: "\\0"')

        # Invalid hex/unicode escape fallback
        res_bad_hex = parse_yaml_subset('key: "\\xZZ"')
        assert res_bad_hex["key"] == "xZZ"
        res_bad_u = parse_yaml_subset('key: "\\uZZZZ"')
        assert res_bad_u["key"] == "uZZZZ"

        # Trailing content after flow collection
        with pytest.raises(FrontmatterError, match="trailing content after flow collection"):
            parse_yaml_subset("key: [1, 2] extra_stuff")

        # Flow sequence errors
        with pytest.raises(FrontmatterError, match="unterminated flow sequence"):
            parse_yaml_subset("key: [1, 2")

        with pytest.raises(FrontmatterError, match="expected ',' in flow sequence"):
            parse_yaml_subset("key: [[1] [2]]")

        with pytest.raises(FrontmatterError, match="empty entry in flow collection"):
            parse_yaml_subset("key: [1,,2]")

        # Flow mapping errors
        with pytest.raises(FrontmatterError, match="unterminated flow mapping"):
            parse_yaml_subset("key: {a: 1")

        with pytest.raises(FrontmatterError, match="expected ':' in flow mapping"):
            parse_yaml_subset("key: {a 1}")

        with pytest.raises(FrontmatterError, match="empty key in flow mapping"):
            parse_yaml_subset("key: {: 1}")

        with pytest.raises(FrontmatterError, match="expected ',' in flow mapping"):
            parse_yaml_subset("key: {a: [1] b: [2]}")

        # Block mapping syntax errors
        with pytest.raises(FrontmatterError, match="unexpected indentation"):
            parse_yaml_subset("  key: val\n    unexpected: 1")

        with pytest.raises(FrontmatterError, match="unexpected sequence item inside a mapping"):
            parse_yaml_subset("key: val\n- item")

        with pytest.raises(FrontmatterError, match="expected 'key: value'"):
            parse_yaml_subset("key: val\njustastring")

        with pytest.raises(FrontmatterError, match="missing key"):
            parse_yaml_subset(": val")

        # Sequence with None items and nested items
        seq_yaml = """
items:
  -
  - foo: bar
    baz: qux
"""
        parsed_seq = parse_yaml_subset(seq_yaml)
        assert parsed_seq["items"][0] is None
        assert parsed_seq["items"][1] == {"foo": "bar", "baz": "qux"}

        # Duplicate keys in sequence item mapping
        dup_seq_yaml = """
items:
  - dup: 1
    dup: 2
"""
        with pytest.raises(AegisYAMLError, match="Duplicate key 'dup'"):
            parse_yaml_subset(dup_seq_yaml)

        # Unterminated quote in sequence
        with pytest.raises(FrontmatterError, match="unterminated quoted string"):
            parse_yaml_subset("items:\n  - \"unclosed\n  - next")

        # Empty document returns {}
        assert parse_yaml_subset("") == {}
        assert parse_yaml_subset("   ") == {}

        # Root document is sequence error
        with pytest.raises(FrontmatterError, match="Expected YAML mapping at document root"):
            parse_yaml_subset("- a\n- b")

        # Depth limits (nest > MAX_DEPTH=30)
        deep_flow = "[" * 35 + "1" + "]" * 35
        with pytest.raises(AegisYAMLError, match="nesting depth"):
            parse_yaml_subset(f"key: {deep_flow}")

        # Unterminated / mismatched quote scalar in _parse_scalar
        from aegis_core.yaml_engine.parser import _parse_scalar
        with pytest.raises(FrontmatterError, match="unterminated quoted scalar"):
            _parse_scalar("\"mismatched'")

        # Big unicode escape invalid
        res_bad_big_u = parse_yaml_subset('key: "\\U000000ZZ"')
        assert res_bad_big_u["key"] == "U000000ZZ"

        # CRLF line continuation
        from aegis_core.yaml_engine.parser import _unescape_double
        assert _unescape_double("line1\\\r\n  line2") == "line1  line2"

        # _strip_comment quote escaping
        from aegis_core.yaml_engine.parser import _strip_comment, _is_quote_closed, _parse_flow
        assert _strip_comment(r'key: "val \"with\" quotes" # c') == r'key: "val \"with\" quotes" '
        assert _strip_comment("key: 'it''s awesome' # c") == "key: 'it''s awesome' "

        # Flow collections escaped quotes and unclosed flow string
        res_flow_quotes = parse_yaml_subset('key: ["escaped \\" quote", \'escaped \'\' quote\']')
        assert len(res_flow_quotes["key"]) == 2
        with pytest.raises(FrontmatterError, match="unterminated quoted string"):
            parse_yaml_subset('key: ["unclosed flow string ]')

        # _is_quote_closed edge cases
        assert _is_quote_closed('"', '"') is False
        assert _is_quote_closed('foo\\"', '"') is False
        assert _is_quote_closed('foo\\\\"', '"') is True
        assert _is_quote_closed("''", "'") is True
        assert _is_quote_closed("'''", "'") is False

        # Unsupported prefixes
        with pytest.raises(FrontmatterError, match="unsupported YAML construct"):
            parse_yaml_subset("key: &anchor")

        # _parse_flow unexpected end
        with pytest.raises(FrontmatterError, match="unexpected end of flow collection"):
            _parse_flow("[ ", 2)

        # Empty flow collections and trailing commas
        assert parse_yaml_subset("key: []") == {"key": []}
        assert parse_yaml_subset("key: [1, 2,]") == {"key": [1, 2]}
        assert parse_yaml_subset("key: {}") == {"key": {}}
        assert parse_yaml_subset("key: {a: 1,}") == {"key": {"a": 1}}

        # Block scalar styles |+ and |-
        res_plus = parse_yaml_subset("key: |+\n  line 1\n  line 2\n")
        assert res_plus["key"].endswith("\n")
        res_minus = parse_yaml_subset("key: |-\n  line 1\n  line 2\n")
        assert not res_minus["key"].endswith("\n")

        # Key with no value and no children
        res_none_val = parse_yaml_subset("key1:\nkey2: val2")
        assert res_none_val["key1"] is None
        assert res_none_val["key2"] == "val2"

        # Unexpected indentation in sequence
        with pytest.raises(FrontmatterError, match="unexpected indentation in sequence"):
            parse_yaml_subset("items:\n  - a\n    - b")

        # Sequence with - followed by indented mapping
        res_nested_map = parse_yaml_subset("items:\n  -\n    nested: val")
        assert res_nested_map["items"] == [{"nested": "val"}]

        # Unterminated sequence string at EOF and before sibling
        with pytest.raises(FrontmatterError, match="unterminated quoted string"):
            parse_yaml_subset("items:\n  - \"unclosed at eof")
        with pytest.raises(FrontmatterError, match="unterminated quoted string before sibling item"):
            parse_yaml_subset("items:\n  - \"unclosed\n  - sibling")

        # Depth limits on helper functions directly
        from aegis_core.yaml_engine.parser import _parse_flow_map, _parse_block_map, _parse_block_seq
        with pytest.raises(AegisYAMLError, match="nesting depth"):
            _parse_flow("a", 0, depth=35)
        with pytest.raises(AegisYAMLError, match="nesting depth"):
            _parse_flow_map("{a: 1}", 0, depth=35)
        with pytest.raises(AegisYAMLError, match="nesting depth"):
            _parse_block_map([], 0, 0, depth=35)
        with pytest.raises(AegisYAMLError, match="nesting depth"):
            _parse_block_seq([], 0, 0, depth=35)
        with pytest.raises(AegisYAMLError, match="Escape sequence"):
            _unescape_double(r"\0")
