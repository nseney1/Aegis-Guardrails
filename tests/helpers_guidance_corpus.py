"""Shared differential inputs for lint and scan's served guidance grammar.

Consumers import this corpus rather than maintaining their own heading/control
tables. Repository inputs reuse a captured inventory and require no version-control history.
"""
from dataclasses import dataclass
import json

from aegis_core.yaml_engine.frontmatter import split_frontmatter

__all__ = ["GuidanceCase", "guidance_corpus", "repository_guidance_corpus"]


@dataclass(frozen=True)
class GuidanceCase:
    name: str
    field: str
    value: object

    def rule_bytes(self):
        meta = {"id": "sample", "type": "trap", "enforcement": "advisory",
                "hypothesis": "A bounded check prevents mistakes.",
                "prediction": "Invalid changes are caught.", "target_paths": ["src/**"]}
        body = "## Do\nRead safely.\n"
        if self.field == "body":
            body = self.value
        else:
            meta[self.field] = self.value
        header = "\n".join(key + ": " + json.dumps(value, ensure_ascii=True)
                           for key, value in meta.items())
        return ("---\n" + header + "\n---\n" + body).encode("utf-8", "surrogatepass")


def guidance_corpus():
    """Five block forms, caller/control matrix, and D-bc predicate disagreements."""
    cases = []
    for name, template in (
        ("plain", "## Do\nRead{point} safely.\n"),
        ("indented", "## Do\nRead safely.\n    Detail{point}.\n"),
        ("quoted", "## Do\nRead safely.\n> Detail{point}.\n"),
        ("fenced", "## Do\nRead safely.\n```text\nDetail{point}.\n```\n"),
        ("html", "## Do\nRead safely.\n<pre>\nDetail{point}.\n</pre>\n"),
    ):
        for marker, point in (("clean", ""), ("format", "\u200c"), ("tab", "\t")):
            cases.append(GuidanceCase(name + "_" + marker, "body", template.format(point=point)))
    points = (("zwnj", "\u200c"), ("zwj", "\u200d"), ("rtl", "\u200f"),
              ("soft_hyphen", "\u00ad"), ("bom", "\ufeff"), ("c0", "\x01"),
              ("escape", "\x1b"), ("delete", "\x7f"), ("c1", "\x80"),
              ("surrogate", "\ud800"), ("tab", "\t"), ("lf", "\n"),
              ("nbsp", "\u00a0"), ("private_use", "\ue000"))
    for field in ("body", "hypothesis", "prediction", "title", "tags", "notes"):
        for name, point in points:
            value = "Read" + point + " safely."
            if field == "body":
                value = "## Do\n" + value + "\n"
            elif field in {"tags", "notes"}:
                value = ["Keep context.", value]
            cases.append(GuidanceCase(field + "_" + name, field, value))
    for field in ("body", "hypothesis", "prediction", "title", "tags", "notes"):
        value = "## Do\nRead safely.\n## Evidence\n\x01\u200c"
        if field in {"tags", "notes"}:
            value = ["Read safely.", "## Evidence", "\x01\u200c\ud800"]
        cases.append(GuidanceCase(field + "_evidence_only", field, value))
        value = "guidance withheld: control characters"
        if field == "body":
            value = "## Do\n" + value
        elif field in {"tags", "notes"}:
            value = [value]
        cases.append(GuidanceCase(field + "_literal_notice", field, value))
    for name, block in (
        ("plain", "## Evidence\n\u200c"),
        ("indented", "    ## Evidence\n\u200c"),
        ("quoted", "> ## Evidence\n\u200c"),
        ("fenced", "```text\n## Evidence\n\u200c\n```"),
        ("html", "<pre>\n## Evidence\n\u200c\n</pre>"),
    ):
        cases.append(GuidanceCase("evidence_" + name, "body", "## Do\nRead safely.\n" + block))
    return tuple(cases)


def repository_guidance_corpus(snapshot):
    """Project bounded captured bytes without traversing or opening any path."""
    for entry in snapshot.entries:
        parts = entry.relative_path.split("/")
        if (parts[:2] != [".aegis", "rules"] or parts[-1] == "README.md"
                or any(part.startswith(".") for part in parts[2:])):
            continue
        raw = entry.content
        yield entry.relative_path, raw, split_frontmatter(raw.decode("utf-8-sig"))[2]
