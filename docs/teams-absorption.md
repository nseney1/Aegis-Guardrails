# Teams tooling absorption

TA-0 establishes the package boundary for the accepted tools absorption ADR
(2026-11-11, sections 2 and 5). It adds the template resource namespace and a
mandatory size rule. It does not move templates, port commands, register tools,
switch an existing run, or change host-plan discovery. TA-4 owns the template
move, including the currently leased model bindings.

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

`aegis_core.team_templates` is an explicitly registered Python package. Its
package-data patterns cover root and nested assets; explicit package-data
exclusions keep `__pycache__` contents and `.pyc`/`.pyo`/`.pyd` out of wheels
built directly from dirty checkouts. The existing
`recursive-include aegis_core *` in `MANIFEST.in` carries those sources into the
sdist; no additional manifest directive is needed. Read installed trusted assets
with `importlib.resources.files("aegis_core.team_templates").joinpath(...)` using
fixed resource names. Python 3.9 supports this API. User paths must never become
resource names. Do not resolve templates relative to the working directory or
import from an editable checkout at runtime.

The namespace is empty until TA-4 moves the templates. Its installation does not
make legacy tooling available. Each future family package must be added to the
explicit setuptools package list. Packaging tests catch an unlisted package and
check anchored root/nested coverage with a top-level-only negative control and
always check the parsed exclusion patterns against source-directory-joined
cache, bytecode and nested template paths with `fnmatch`. They also build a
wheel from a temporary dirty checkout to verify nested assets and reject
bytecode. The wheel regression uses available declared build dependencies and
skips explicitly if neither the test interpreter nor its base has them; it
never installs dependencies. Family acceptance must also build a wheel from an
sdist and read the moved assets from that wheel with the checkout hidden.
`tools/`, the coordinator kit, GCP/VM runners and test harnesses are not added to
the package list. Testing and GCP/VM tooling stay local; replay and fixture
harnesses move to `tests/support/` in their owning items.

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
