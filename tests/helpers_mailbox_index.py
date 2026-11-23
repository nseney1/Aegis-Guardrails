"""Shared mailbox fixtures and the approved shadow-reader roster."""

from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
import gc
from pathlib import Path
import sys
from threading import Lock
from traceback import walk_stack
import weakref

__all__ = ["SHADOW_READERS", "construction_ledger", "make_mailbox", "publish"]

# Explicit production history reads through each factory. Router status and
# delivery read pinned history directly, so the explicit shadow factory has zero.
SHADOW_READERS = {
    "hierarchy_jobs": 5,
    "hierarchy_sweep": 2,
    "hierarchy_provision": 3,
    "hierarchy_provider_recovery": 1,
    "hierarchy_router": 0,
}


def make_mailbox(root, mailbox_type=None):
    import hierarchy_mailbox as hm

    endpoints = {"a/front-door": {}, "a/orchestrator": {}, "a/lane/review": {"kind": "reviewer"}}
    hm.initialize(root, {"schema": "aegis.hierarchy-pilot/v1", "writer_limit": 3,
                         "endpoints": endpoints, "counterparts": []})
    mailbox = (hm.Mailbox if mailbox_type is None else mailbox_type)(root)
    for endpoint in endpoints:
        mailbox.bind({"endpoint": endpoint, "host": "test-host", "session": endpoint,
                      "expected_generation": 0})
    return mailbox


def publish(mailbox, identifier="seed", *, body="original body"):
    mailbox.publish({"message_id": identifier, "from": "a/orchestrator", "to": "a/lane/review",
                     "host": "test-host", "session": "a/orchestrator", "binding_generation": 1,
                     "type": "info", "body": body})


_REPO = Path(__file__).resolve().parents[1]
_INDEX = "tools/hierarchy_mailbox_index.py"
_ROUTER = "tools/hierarchy_router.py"
_OWNERS = frozenset(f"tools/{name}.py" for name in SHADOW_READERS)


@dataclass(frozen=True)
class _Construction:
    site: tuple
    creator: tuple
    index: weakref.ReferenceType
    shadow: object


def _product_stack():
    # A package import and the standalone script share one source identity.
    for frame, line in walk_stack(sys._getframe(1)):
        path = Path(frame.f_code.co_filename)
        if path.is_relative_to(_REPO):
            relative = path.relative_to(_REPO)
            if relative.parts[0] == "tests" and relative.name != Path(__file__).name:
                break
            if relative.parts[0] == "tools" or relative.parts[0].startswith("aegis_"):
                yield relative.as_posix(), line


class _Ledger:
    def __init__(self):
        self.entries = []
        self.lock = Lock()

    def record(self, index, mailbox):
        stack = [site for site in _product_stack() if site[0] != _INDEX]
        site = stack[0] if stack else ("<test driver>", 0)
        creator = next((location for location in stack if location[0] != site[0]), site)
        shadow = weakref.ref(mailbox) if site[0] == _ROUTER else None
        with self.lock:
            self.entries.append(_Construction(site, creator, weakref.ref(index), shadow))

    def findings(self, *, doctor_site=None):
        gc.collect()
        with self.lock:
            entries = tuple(self.entries)
        findings = []
        for entry in entries:
            if entry.creator[0] not in _OWNERS and entry.site != doctor_site:
                findings.append(("RF24_READER_OWNER", entry.creator))
            if entry.index() is not None:
                findings.append(("RF24_READER_CACHE", entry.site))
            if entry.shadow is not None and entry.shadow() is not None:
                findings.append(("RF24_READER_CACHE", entry.site))
        return findings


@contextmanager
def construction_ledger(indexes):
    """Observe each shadow-index construction, including calls on other threads."""
    ledger = _Ledger()

    def wrap(original):
        def initialize(instance, mailbox, *, mode="shadow"):
            if mode == "shadow":
                ledger.record(instance, mailbox)
            original(instance, mailbox, mode=mode)
        return initialize

    with ExitStack() as patches:
        for cls in set(indexes):
            original = cls.__init__
            patches.callback(setattr, cls, "__init__", original)
            cls.__init__ = wrap(original)
        yield ledger
