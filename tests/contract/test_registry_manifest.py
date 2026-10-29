"""server.json (the MCP Registry entry) stays in step with the release (4.4.0 plan, registry listing)."""
from __future__ import annotations

import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SERVER = json.loads((REPO / "server.json").read_text(encoding="utf-8"))
VERSION = re.search(r'__version__\s*=\s*"([^"]+)"', (REPO / "aegis_core" / "_version.py").read_text(encoding="utf-8")).group(1)
PYPROJECT = (REPO / "pyproject.toml").read_text(encoding="utf-8")


def test_the_registry_versions_equal_the_package_version():
    (package,) = SERVER["packages"]
    assert (SERVER["version"], package["version"]) == (VERSION, VERSION)


def test_the_registry_package_is_this_distribution():
    (package,) = SERVER["packages"]
    assert package["registryType"] == "pypi" and package["transport"] == {"type": "stdio"}
    assert package["identifier"] == re.search(r'^name\s*=\s*"([^"]+)"', PYPROJECT, re.M).group(1)


def test_the_identifier_is_a_console_script_that_starts_the_mcp_server():
    # uvx and pipx run the script named like the package; the registry has no field for another name.
    scripts = dict(re.findall(r'^([\w-]+)\s*=\s*"([\w.:]+)"$', PYPROJECT.split("[project.scripts]")[1].split("[")[0], re.M))
    assert scripts[SERVER["packages"][0]["identifier"]] == scripts["aegis-mcp"]


def test_the_readme_carries_the_ownership_marker_the_registry_reads_from_pypi():
    # Same boundary rule as the registry: the name is followed by whitespace, "<", end of text or "-->".
    marker = re.escape("mcp-name: " + SERVER["name"])
    assert re.search(marker + r"(?=\s|<|-->|\Z)", (REPO / "README.md").read_text(encoding="utf-8"))


def test_the_entry_obeys_the_registry_limits():
    assert re.fullmatch(r"io\.github\.nseney1/[a-zA-Z0-9._-]+", SERVER["name"])
    assert 1 <= len(SERVER["description"]) <= 100 and len(SERVER["title"]) <= 100
    assert SERVER["repository"] == {"url": "https://github.com/nseney1/Aegis-Guardrails", "source": "github"}
