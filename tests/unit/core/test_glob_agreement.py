"""All lane-glob surfaces share decisions without changing their own refusal text."""
import pytest

from aegis_core import lane_gate, partition, team


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    for key in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(key, str(home))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(home / "gitconfig"))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for key in ("CLAUDE_CONFIG_DIR", "CODEX_HOME", "XDG_CONFIG_HOME"):
        monkeypatch.delenv(key, raising=False)


@pytest.mark.parametrize("glob,accepted", [
    ("", False), ("a/../b", False), ("/", False), ("a\x1bb", False),
    ("src/\x9b[2J*", False), ("a\x85b", False), ("a\\b", True), ("src/**", True), ("src/é*", True),
])
def test_glob_surfaces_agree(glob, accepted):
    calls = (
        lambda: team._claim_paths([glob]),
        lambda: lane_gate._cli_globs([glob]),
        lambda: partition.parse_splits(["A=" + glob, "B=z"]),
    )
    for call in calls:
        if accepted:
            assert call()
        else:
            with pytest.raises((team.TeamUsageError, lane_gate.LaneGateUsage, partition.PartitionUsage)):
                call()


@pytest.mark.parametrize("paths,message", [
    ([""], "--paths: glob 1 is empty"),
    (["a\x1bb"], "--paths: glob 1 is not text without control characters"),
    (["a", "../b"], "--paths: glob 2 climbs out of the repository with '..'"),
])
def test_lane_refusal_words_are_preserved(paths, message):
    with pytest.raises(lane_gate.LaneGateUsage) as caught:
        lane_gate._cli_globs(paths)
    assert str(caught.value) == message


@pytest.mark.parametrize("value,message", [("a,\tb", "control character"), ("a, ,b", "empty glob"),
                                            ("a,\x85b", "control character")])
def test_partition_checks_controls_before_stripping(value, message):
    with pytest.raises(partition.PartitionUsage, match=message):
        partition.parse_splits(["A=" + value, "B=z"])
    assert partition.parse_splits(["A=a, b", "B=z"])["A"] == ("a", "b")


def test_glob_kind_order_and_non_text():
    assert team.glob_problem(7) == "not_text"
    assert team.glob_problem("\x85") == "control"
    assert team.glob_problem("/") == "empty"
    assert team.glob_problem("../x") == "climbs"
    assert team.glob_problem("src/**") is None
