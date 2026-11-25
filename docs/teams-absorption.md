# Teams tooling absorption

TA-0 established the package boundary and mandatory size rule for the accepted
tools absorption ADR (2026-11-11, sections 2 and 5). TA-4 owns migration of the
legacy templates, including the leased model bindings.

## Package layout and size rule

Put shared services in `aegis_core/team_<family>.py`, or split a family into
`aegis_core/team_<family>/` with explicitly listed subpackages in
`pyproject.toml`. Existing profile, status and host services remain in
`team_profile.py`, `team_status.py` and `team_hosts.py`. CLI and MCP adapters call
the same public core service; adapters do not duplicate validation or storage.
Read paths, hosts, models, budgets and intervals from the team profile. Never
embed an owner's environment in product defaults.

`tests/contract/test_module_size.py` recursively measures every Python module
under `aegis_core`. For every `aegis_core/team_*` module, including package
initializers and nested modules, both physical lines and AST statement counts
must be at most 1,000 per module and 100 per function (including async functions,
methods and nested functions). Decorator lines count. Same-name definitions
(properties, overloads and conditional definitions) retain each metric's maximum;
a later small definition cannot hide an oversized one. Neither a ratchet entry
nor a grandfathered name can waive these caps, and `--write` refuses oversized
ports. Split before porting; do not add an exemption to `size_ratchet.json`.
Grandfathering is restricted to `tools/` keys, including absent pending entries.
Product pins are restricted to the five module and nineteen function names in
the guard's explicit pre-absorption baseline. Each pin's lines and statements
are capped at its values in `size_ratchet.json` at `df8232ec` and can only
shrink. Both checks and `--write` refuse any record metric above its ceiling,
even when the measured size matches or the pinned name is absent. Adding an
exemption for a CLI, MCP or storage port fails even if it is absent or its
measurement matches.

## Templates and distribution

`aegis_core.team_templates` ships `role-registry.json` and `job-recipes.json`.
[`team_roles.registry()`](../aegis_core/team_roles.py) reads the installed role
registry using a fixed resource name.

1. Add the resource under `aegis_core/team_templates/`. The package-data
   patterns in [`pyproject.toml`](../pyproject.toml) cover root and nested assets.
   The `recursive-include aegis_core *` directive in
   [`MANIFEST.in`](../MANIFEST.in) includes them in the sdist. Register any new
   Python family package in the explicit setuptools package list.
2. For a resource added at `roles/builder.md`, read the installed bytes with
   one fixed child per `joinpath` call for Python 3.9 compatibility. Keep user
   input out of resource lookup.

   ```python
   from importlib import resources

   package = resources.files("aegis_core.team_templates")
   template = package.joinpath("roles").joinpath("builder.md")
   template_bytes = template.read_bytes()
   ```

3. Follow the [offline build and readback](#offline-build-and-readback) recipe.
   It checks every selected template against the wheel, the sdist and the
   installed package.
   The real-source test snapshots reviewed templates before staging and checks
   their exact inventories and bytes in both verified archives. The independent
   dirty-checkout test checks for representative root and nested wheel members
   and confirms cache and bytecode exclusions. A separate pattern test checks
   root-only and recursive matches. Synthetic inventory and byte parity across
   both archive formats moves from 5.0 to `TEAM-TEMPLATE-SYNTHETIC-ARCHIVE-PARITY`.
   See the [packaging tests](../tests/unit/cli/test_install_package_data.py).

### Offline build and readback

Use a build environment with `build`, `setuptools>=68.0` and `wheel` already
installed, including their own dependencies. Use Python with `venv` and `pip`
available for the install check. The project has zero runtime dependencies.
From the source root, set `TMPDIR` to the absolute path of a writable directory
outside the checkout and run this POSIX shell recipe. It first reads the
selected regular files from the reviewed checkout, including dot-prefixed
files and directories. It rejects links and unsupported entries, prunes
cache directories, and applies bytecode exclusions to files. The build uses
a staged copy checked against that snapshot. It compares both verified
archives with the snapshot before installing that wheel and checking the
installed resources.

```sh
(
    set -eu
    umask 022
    work=$(mktemp -d)
    dist="$work/dist"
    reviewed="$work/reviewed"
    staged="$work/source"
    verifier="$PWD/.github/scripts/verify_dist.py"

    cat > "$work/check_templates.py" <<'PY'
from contextlib import contextmanager
import fnmatch
from importlib import resources
import os
from pathlib import Path
import runpy
import shutil
import stat
import sys
import tarfile
import zipfile
import zlib

try:
    from lzma import LZMAError
except ImportError:
    LZMAError = RuntimeError  # zipfile refuses the codec when it is unavailable.

package = "aegis_core.team_templates"
prefix = package.replace(".", "/")
read_errors = (OSError, EOFError, tarfile.TarError, zipfile.BadZipFile, zlib.error, LZMAError)


def refuse(reason, path, public_text):
    raise SystemExit(f"{reason}: {public_text(str(path))}")


def supports_confined_walk():
    return (os.open in os.supports_dir_fd and os.stat in os.supports_dir_fd
            and os.stat in os.supports_follow_symlinks and os.scandir in os.supports_fd
            and all(hasattr(os, flag) for flag in ("O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK")))


@contextmanager
def open_at(parent, name, label, directory, public_text):
    flags = os.O_RDONLY | os.O_NOFOLLOW | (os.O_DIRECTORY if directory else os.O_NONBLOCK)
    try:
        mode = os.stat(name, dir_fd=parent, follow_symlinks=False).st_mode
        if stat.S_ISLNK(mode):
            refuse("linked template path", label, public_text)
        is_expected = stat.S_ISDIR if directory else stat.S_ISREG
        if not is_expected(mode):
            refuse("unsupported template entry", label, public_text)
        fd = os.open(name, flags, dir_fd=parent)
    except OSError:
        refuse("cannot open template path", label, public_text)
    try:
        if not is_expected(os.fstat(fd).st_mode):
            refuse("unsupported template entry", label, public_text)
        yield fd
    finally:
        os.close(fd)


def walk_directory(parent, relative, excludes, consume, public_text):
    try:
        with os.scandir(parent) as entries:
            for entry in entries:
                path = relative / entry.name
                label = Path(prefix) / path
                try:
                    mode = entry.stat(follow_symlinks=False).st_mode
                except OSError:
                    refuse("cannot inspect template path", label, public_text)
                if stat.S_ISLNK(mode):
                    refuse("linked template path", label, public_text)
                if stat.S_ISDIR(mode):
                    if excludes is None or entry.name != "__pycache__":
                        with open_at(parent, entry.name, label, True, public_text) as directory:
                            walk_directory(directory, path, excludes, consume, public_text)
                    continue
                if not stat.S_ISREG(mode):
                    refuse("unsupported template entry", label, public_text)
                if excludes is not None and (entry.name == "__pycache__" or any(
                        fnmatch.fnmatch(path.as_posix(), pattern) for pattern in excludes)):
                    continue
                with open_at(parent, entry.name, label, False, public_text) as fd:
                    try:
                        with open(fd, "rb", closefd=False) as member:
                            consume(path, member)
                    except OSError:
                        refuse("cannot read template file", label, public_text)
    except OSError:
        refuse("cannot read template directory", Path(prefix) / relative, public_text)


def walk_templates(checkout, excludes, consume, public_text, *, supports=supports_confined_walk):
    if not supports():
        raise SystemExit("template source scan requires descriptor-relative no-follow support")
    with open_at(None, checkout, "checkout", True, public_text) as root:
        with open_at(root, "aegis_core", "aegis_core", True, public_text) as core:
            with open_at(core, "team_templates", prefix, True, public_text) as templates:
                walk_directory(templates, Path(), excludes, consume, public_text)


def snapshot_sources(checkout, reviewed, public_text):
    if sys.version_info >= (3, 11):
        import tomllib
    else:
        import tomli as tomllib  # A build dependency on Python 3.9 and 3.10.

    with (checkout / "pyproject.toml").open("rb") as config:
        settings = tomllib.load(config)["tool"]["setuptools"]
    manifest = (checkout / "MANIFEST.in").read_text(encoding="utf-8").splitlines()
    if not settings.get("include-package-data") or "recursive-include aegis_core *" not in manifest:
        raise SystemExit("template snapshot requires the recursive aegis_core package-data rule")
    excludes = settings.get("exclude-package-data", {}).get(package, [])

    def save(relative, member):
        target = reviewed / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as handle:
            shutil.copyfileobj(member, handle, length=64 * 1024)
        target.chmod(stat.S_IMODE(os.fstat(member.fileno()).st_mode))

    walk_templates(checkout, excludes, save, public_text)
    if not reviewed.is_dir():
        raise SystemExit("No selected Teams templates")


def stage_checkout(checkout, staged, reviewed):
    staged.mkdir()

    def ignore(directory, names):
        parent = Path(directory)
        ignored = {name for name in names if name == "__pycache__"
                   or (fnmatch.fnmatch(name, "*.py[cod]") and (parent / name).is_file())}
        if parent == checkout / "aegis_core":
            ignored.add("team_templates")
        return ignored

    for name in ("aegis_cli", "aegis_core", "aegis_mcp", "aegis_sdk", "rules", "skills"):
        shutil.copytree(checkout / name, staged / name, symlinks=True, ignore=ignore)
    for name in ("pyproject.toml", "MANIFEST.in", "README.md", "LICENSE", "NOTICE", "Makefile"):
        shutil.copyfile(checkout / name, staged / name)
    shutil.copytree(reviewed, staged / prefix)


def compare_streams(label, name, source, member, public_text):
    with source.open("rb") as expected:
        while True:
            block = expected.read(64 * 1024)
            if member.read(len(block) or 1) != block:
                refuse(f"{label}: template bytes differ from source", name, public_text)
            if not block:
                return


def compare(label, name, source, open_member, public_text, *args):
    try:
        member = open_member(*args)
        if member is None:
            refuse(f"{label}: missing template", name, public_text)
        with member:
            compare_streams(label, name, source, member, public_text)
    except (FileNotFoundError, KeyError):
        refuse(f"{label}: missing template", name, public_text)
    except read_errors:
        refuse(f"{label}: cannot read template", name, public_text)


def check_staged(staged, reviewed, expected, public_text):
    remaining = set(expected)

    def check(relative, member):
        if relative not in remaining:
            refuse("staged: unexpected template", relative, public_text)
        compare_streams("staged", relative, reviewed / relative, member, public_text)
        remaining.remove(relative)

    walk_templates(staged, None, check, public_text)
    if remaining:
        refuse("staged: missing template", min(remaining), public_text)


def check_archives(wheel_path, sdist_path, reviewed, expected, public_text):
    with zipfile.ZipFile(wheel_path) as wheel, tarfile.open(sdist_path, "r:gz") as sdist:
        first = sdist.next()
        if first is None:
            raise SystemExit("sdist: no archive root")
        tar_prefix = f"{first.name.split('/', 1)[0]}/{prefix}/"
        wheel_prefix = f"{prefix}/"
        members = {wheel_prefix + relative.as_posix() for relative in expected}
        for relative in expected:
            name = relative.as_posix()
            source = reviewed / relative
            compare("wheel", name, source, wheel.open, public_text, wheel_prefix + name)
            compare("sdist", name, source, sdist.extractfile, public_text, tar_prefix + name)
        wheel_members = {item.filename for item in wheel.infolist()
                         if not item.is_dir() and item.filename.startswith(wheel_prefix)}
        if wheel_members != members:
            raise SystemExit("wheel: template inventory differs from source")
        sdist_members = {item.name for item in sdist.getmembers()
                         if item.isfile() and item.name.startswith(tar_prefix)}
        if sdist_members != {tar_prefix + relative.as_posix() for relative in expected}:
            raise SystemExit("sdist: template inventory differs from source")
    print(f"Wheel and sdist match all {len(expected)} selected source templates")


def check_installed(reviewed, expected, public_text):
    installed = resources.files("aegis_core").joinpath("team_templates")
    for relative in expected:
        resource = installed
        for part in relative.parts:
            resource = resource.joinpath(part)
        compare("installed wheel", relative.as_posix(), reviewed / relative, resource.open, public_text, "rb")
    print(f"Installed wheel matches all {len(expected)} selected source templates")


def main():
    verifier, phase, snapshot, *inputs = sys.argv[1:]
    public_text = runpy.run_path(verifier)["public_text"]
    reviewed = Path(snapshot)
    if phase == "snapshot":
        snapshot_sources(Path("."), reviewed, public_text)
        return
    if phase == "stage":
        stage_checkout(Path.cwd(), Path(inputs[0]), reviewed)
        return

    expected = sorted(path.relative_to(reviewed) for path in reviewed.rglob("*") if path.is_file())
    if not expected:
        raise SystemExit("No selected Teams templates")
    if phase == "staged":
        check_staged(Path(inputs[0]), reviewed, expected, public_text)
    elif phase == "archives":
        check_archives(*inputs, reviewed, expected, public_text)
    elif phase == "installed":
        check_installed(reviewed, expected, public_text)
    else:
        raise SystemExit("unknown template verification phase")


if __name__ == "__main__":
    try:
        main()
    except (*read_errors, ImportError, RuntimeError, ValueError):
        raise SystemExit("cannot complete template verification") from None
PY

    python -I "$work/check_templates.py" "$verifier" snapshot "$reviewed"
    python -I "$work/check_templates.py" "$verifier" stage "$reviewed" "$staged"
    python -I "$work/check_templates.py" "$verifier" staged "$reviewed" "$staged"
    (cd "$staged" && python -m build --no-isolation --outdir "$dist")
    python "$verifier" record "$dist"
    python "$verifier" verify "$dist"
    set -- "$dist"/*.whl "$dist"/*.tar.gz
    wheel=$1
    python -I "$work/check_templates.py" "$verifier" archives "$reviewed" "$wheel" "$2"

    python -m venv "$work/venv"
    cd "$work"
    "$work/venv/bin/python" -I -m pip install --no-index --no-deps "$wheel"
    "$work/venv/bin/python" -I "$work/check_templates.py" "$verifier" installed "$reviewed"
)
```

`record` checks both archives before writing `dist/SHA256SUMS`. `verify`
checks the recorded digests and archive contents again. Use its printed paths
only after it exits successfully. The [validation workflow](../.github/workflows/validate.yml)
builds and records the artifacts. The [publish workflow](../.github/workflows/publish.yml)
downloads that artifact and verifies it before staging files for upload.

### Archive admission

[`verify_dist.py`](../.github/scripts/verify_dist.py) shares checks for portable
names, member shape, namespace collisions and protected locations across both
formats. Member shape is checked against ZIP metadata for the wheel and tar
metadata for the sdist. The sdist applies these checks beneath its single
validated root. Every component must match one portable grammar (ASCII letters,
digits, and `._+-`, or an NFKC-stable letter), must not be a Windows device name
(`CON`, `NUL`, `AUX`, `PRN`, `COM1`–`COM9`, `LPT1`–`LPT9`) in any case or with
any extension. One protected-prefix table lists `aegis_core/ast/drivers/templates`,
`aegis_core/team_templates`, `aegis_core/_data`, the package roots (`aegis_core`,
`aegis_cli`, `aegis_mcp`, `aegis_sdk`) and the forbidden directories. That table
supplies canonical component spellings and protected location matches using
NFC and case folding before generic package `.py` admission. Within each
parent, files and directories share one case-folded namespace, including
directories implied by children. A case alias, a file/directory collision or a
duplicate archive entry is refused.

Template files under `aegis_core/team_templates/` must be regular files with
normalized relative POSIX names, a `.json`, `.md` or `.py` suffix and no execute
bit. The verifier refuses trailing spaces or dots, ZIP Unicode Path extra
records, `_data` components within the template tree, special members,
traversal, `__pycache__`, bytecode and forbidden suffixes. Directory entries
must have consistent metadata, zero bytes and an admitted descendant.

Ordinary sdist source files that pass the shared checks are admitted without a
whole-tree file allowlist. The wheel uses a closed file allowlist covering the
named driver templates, permitted `.dist-info` entries, explicit assets,
eligible package `.py` files and admitted team templates. The wheel must contain
the complete driver-template inventory (`TEMPLATES`), one `.dist-info` root and
exactly one `METADATA` file bounded to 1 MiB and validated for package name,
extras and dependency declarations.

Both commands require exactly one regular wheel and one regular sdist. Extra
entries with either archive suffix count even when dot-prefixed or differently
cased.

`tools/`, the coordinator kit, GCP/VM runners and test harnesses stay outside
the package list. Replay and fixture harnesses move to `tests/support/` in
their owning items.

## CLI and MCP registration pattern

For each port, use this sequence:

1. Define a bounded public core operation in its `team_*` family. Validate sizes
   and types before parsing or allocating. Open untrusted paths by descriptor
   from a trusted root, protecting every component against symlink and rename
   races. Close descriptors even if wrapping them with `os.fdopen` fails.
2. Add `aegis team <noun> <verb>` in `TeamCommand.configure_parser` and
   `run_team` in `aegis_cli/team.py`, splitting adapter modules as needed to meet
   the size rules. Preserve the existing lease, host-capacity and model exit
   contracts. New absorbed verbs use 0 for success, 1 for an operational refusal,
   and 2 for invalid usage. Return a structured `status="refused"`, `reason` and
   `next_action`; never publish a raw exception or echo rejected input.
3. If MCP exposure is appropriate, declare `aegis_team_<noun>_<verb>` in
   `aegis_mcp/schemas.py` with a closed `inputSchema`
   (`additionalProperties: false`), required fields, bounds and accurate
   read-only/destructive annotations. `aegis_mcp/registry.py` re-exports the
   definitions. Register the handler in `aegis_mcp/tools.py` and route through
   `execute_tool`. Server-injected context is not a client argument. Use the
   existing config schema/handler as the read-only registration example; it is
   not a grant to expose writes. Role authorization belongs at the service
   boundary; landing and approvals remain human CLI actions.
4. Test both public surfaces against the same core outcomes: success, exact
   refusal, malformed and oversized input, missing files, unsupported platform,
   timeout, retry and concurrent writers. Bound waits and assert that refusal
   leaves state unchanged. Do not mock global OS or builtin functions; replace
   the tested module's boundary reference. Gate POSIX descriptor, mode and
   symlink tests with existing `make_store`, `symlink_or_skip` and `os.name`
   checks, and test unsupported-platform refusal with its probe monkeypatched.
   Check the installed CLI and MCP with source hidden, on Python 3.9 and Windows
   as well as the primary development platform.

Canonicalize every displayed untrusted string, then redact, then truncate.
Reject multiline text when a signed single-line field is required; do not join
lines. MCP annotations advertise behavior; they do not authorize an operation.
Native commands remain explicitly `unqualified` until TA-3's owner-run real-host
qualification record passes. TA-0 registers no new CLI or MCP surface, so these
are acceptance requirements for the family ports rather than new runtime claims.

TA-7b stores a version 2 report receipt under the user Aegis state root from
`UserLayout.aegis_dir`, at `host-qualification/<resolved-host-id>.json`, mode
0600 and owner UID only. Recording and reading refuse when the record path lies
inside the workspace or the workspace lies inside the record directory. The
adapter accepts the producer's report without a top-level host and requires
any explicit host to match the requested kind. A report must be bounded,
completed, producer-reported passing and non-fake. ROOT settings and permission
entries are producer data within the bounded JSON and ROOT observation
envelopes. Reports with roles require login data. A ROOT-only report requires
a complete ROOT observation and null login.

The receipt carries the report digest, all reported role rows, owner
timestamp, host version and version source. ROOT-only v2 receipts carry
`root_only: true` and `roles: {}`. Role-bearing receipts retain their existing
fields and format. The receipt's `enforcement_claim` is `report-only`, and
`require_qualified` always raises `HostUnqualified`. Version 1 receipts are
refused and their bytes are left in place. The record byte budget
`MAX_RECORD_BYTES = 6 * MAX_REPORT_BYTES + 768` applies to encoding, reads,
validation and replacement.

An injected core version reader binds writes and matching reads to one live
version. Those operations return unqualified `receipt_recorded` and
`receipt_current`. A different version produces `version_changed`, and a
recording request with a matching new version can atomically replace the
prior v2 receipt. The shipping `aegis team qualify host` always supplies an
unavailable reader. Operations requiring a live version return unqualified
`version_unavailable` and exit 1 without publication or renewal. Native
version transport and positive host qualification are deferred to
TA-7B-RUNTIME-QUALIFICATION with TA-7c and TA-3.

Team prefixes before child selection follow the integration-base parser and
its composed policies for usage, help and workspace errors. The fixed qualify
refusal applies once argparse enters the qualify child. A dedicated team
prefix refusal is deferred to TA-7B-TEAM-PREFIX-REFUSAL.

## Install and upgrade switch contract

The round-3 coordinator ruling assigns COORD-LIVE-PREFLIGHT implementation and
its acceptance tests to TA-4, whose brief was amended accordingly. TA-0 records
the contract here and makes no implementation or execution claim. It applies
to every install or upgrade that switches absorbed
tooling into a run. Before any switch, perform a read-only live preflight of
leases, target paths, the source and installed byte census, and relevant host
environment (including DNS and mounts). Record a rollback to the exact previous
package/venv and run binding before switching. Missing, stale or inconsistent
evidence refuses with a reason and next action and leaves the active binding
unchanged. Revalidate under the switch's serialization boundary so concurrent
lease, target or package changes cannot reuse a stale preflight. Retry must
start with fresh live evidence; partial failure must preserve or restore the
recorded prior binding, with its result recorded.

The run records its installed package version and file hashes at initialization;
spawns compare those bytes and refuse drift with a restore-or-reinitialize next
action. Each version uses its own venv. The installed package, venv and
site-packages are run controls outside every role's write roots. TA-4 implements
the run/provisioning binding change and its preflight/rollback acceptance tests;
each family must qualify its install/upgrade before switching. This skeleton
does not add a package manager hook or perform an install/upgrade.

## Removal and pruning

A temporary legacy wrapper delegates to the public packaged core and adds no
second implementation. In the same item that ports its last caller, remove the
wrapper, its references and any interim exec exemption; search all callers and
test the packaged entry point before removal. TA-2 retires the wake exec
exemption, TA-4 retires the runtime-source exemption, and TA-8 verifies zero
product exec exemptions and deletes the emptied `tools/` directory. Preserve
the seven pinned foundation sources and `tests/fixtures/**` until the owner
approves the exact successor bytes and relocation batch.

Each family handoff records `PRUNE-LEDGER` lines removed and added, retired
wrappers and remaining callers, with command-derived counts. TA-0 retires no
wrapper or legacy source; its additions are packaging, guard tests and this
contract. TA-1 and TA-4 follow this skeleton when their family leases clear;
TA-2 and TA-5 precede their dependent GM items, and TA-8 follows all family ports.

## TA-1b index and pager services

`aegis_core.team_mailbox_index.Index` accepts the TA-1a `Mailbox`, whose store,
role table, host table and clock remain the only sources of authority. The
scanner and bounded change evidence live in `team_mailbox_index_scan`; the
inbox selection and flush accounting live in `team_mailbox_pager`. No core
module imports the local tools. These modules register no CLI or MCP entry
point and change no host-plan discovery or existing adapter behavior. The
legacy index adoption gate remains unchanged.

The core index reads and hashes every live record through the store's held
root before reusing a parsed header. It checks policy, routing, duplicate IDs
and reply targets on every call. The legacy tool's pathname metadata reuse is
not carried into this service: the store provides descriptor-confined bytes,
and a matching pathname stat is insufficient authority to skip that read.
Complete scans publish the parsed memo; record count and aggregate history
bytes remain capped. Returned objects are independent copies. Shadow mode
compares with the product mailbox; explicit indexed mode uses the same live
validation. Unknown IDs and malformed history produce `MailboxRefusal` with
code 1, reason and next action. Busy writers retain the TA-1a `BusyError` type;
the index and pager do not create locks or match exception text.

The pager accepts a sized history of at most 10,000 records, checks the entire
history before selection, and bounds brief bytes before decoding. A preview
validates and sorts once, then walks that ordered history without sorting per
page. Live reads validate their newly supplied history each time. The O97
measurement covers 100 pages of 10,000 keys, with timings and sort counts in
the writer handoff. Cursor pairs and retained binding cutoffs have count caps;
only a successfully staged and flushed response commits delivery state.
Each pager belongs to one serialized transport connection; concurrent previews
use isolated copies and confer no read or delivery authority.

PRUNE-LEDGER TA-1b: replaced one legacy import line with four package/script
compatible import lines (net +3), and retired 0 wrappers in this part.
The 1,000-line index and 326-line pager remain in tools until their callers are
ported and the family switch is qualified. The index scanner, evidence, query
and comparison implementations and the pager selection/flush implementation
can then be dropped from those copies. TA-1h owns the pinned mailbox relocation;
this part changes no pinned bytes. Added-line counts and remaining callers are
recorded from the candidate tree in the handoff.

Preview accepts the same injected brief-status port as live paging. Checkpoint
brief/pending lists retain the store's 256-entry cap, and decoded brief bytes
share an allocation budget derived from 100 message briefs plus 256 checkpoint
briefs. Missing ports and transport I/O failures refuse
through the same typed boundary before staging delivery state.

The pager keeps stored bytes, decoded structure and transport bytes separate.
The TA-1a store/publisher enforce the stored-record and aggregate stored-history
byte ceilings. Pager history validation bounds decoded message characters,
nodes, containers and depth, allowing the body and record wrapper added after
header parsing. It never ASCII-serializes history to enforce a storage budget.
Endpoint selection precedes all expanded-row checks. Each selected response row
has its own structural budget; metadata has a separate budget allowing expanded
checkpoint briefs. A combined candidate page does not inherit one record's node
ceiling. The supplied renderer and byte pager enforce the response ceiling,
including mandatory metadata and the first message. Accepted Unicode bodies and
maximum-size briefs remain readable, and their expansion cannot refuse another
endpoint's read.

The index coalesces coverage loss in a bounded pending record independent of
the latest reconciliation diagnostic. An ordinary matching read cannot recover
an earlier canonical scan's original bytes or clear that record. A successful
`verify()` includes `verification_unavailable` with reason `baseline_unavailable`
and scope `all_returned_records` before acknowledging evidence. It retires the
gap only when its current indexed/canonical scans match; a verification that
reconciles again reports the gap and keeps it pending. Failed verification
preserves it for retry, including when bytes A were returned as canonical B and
subsequently restored to A.
