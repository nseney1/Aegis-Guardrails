"""aegis_sdk.parse_rule_file must tolerate a UTF-8 BOM (PowerShell 5.1)."""
from aegis_sdk import parse_rule_file


def test_bom_prefixed_rule_parses(tmp_path):
    f = tmp_path / "rule.md"
    f.write_bytes(b"\xef\xbb\xbf---\nid: bom-rule\ntype: trap\n---\n# Body\n")
    fm, body = parse_rule_file(str(f))
    assert fm["id"] == "bom-rule"
    assert "# Body" in body


def test_bomless_rule_unchanged(tmp_path):
    f = tmp_path / "rule.md"
    f.write_text("---\nid: plain\n---\n# Body\n", encoding="utf-8")
    fm, body = parse_rule_file(str(f))
    assert fm["id"] == "plain"
    assert "# Body" in body
