"""Home-relative path normalization for isolation test fixtures."""

from pathlib import PurePosixPath
import posixpath

__all__ = ["catalogue_config_parts", "home_config_parts"]


def home_config_parts(config_path, home):
    """Return the case-preserved components strictly below the fixture home.

    Ignore non-home spellings. Split after "~/" so extra leading separators in
    the suffix stay relative. Normalize before checking containment and depth.
    """
    if type(config_path) is not str or not config_path.startswith("~/"):
        return None
    home = PurePosixPath(home)
    absolute = home.joinpath(*config_path[2:].split("/"))
    normalized = PurePosixPath(posixpath.normpath(str(absolute)))
    try:
        below = normalized.relative_to(home)
    except ValueError:
        raise AssertionError("catalogue-defect: config path normalizes outside the home directory") from None
    if not below.parts:
        raise AssertionError("catalogue-defect: config path normalizes to the home directory")
    return below.parts


def catalogue_config_parts(rows, home):
    """Yield normalized home-relative components from every host row."""
    for host in rows:
        paths = host.config_paths
        if type(paths) not in (tuple, list):
            continue
        for config_path in paths:
            parts = home_config_parts(config_path, home)
            if parts is not None:
                yield parts
