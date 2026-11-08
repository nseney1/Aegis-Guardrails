# Optional Teams container isolation

C1 supplies a library and a read-only planning/verification CLI. It does not yet change `aegis team`, start a
container, check engine availability, or build an image. Team config/init integration arrives in C3 and run
lifecycle integration in C4. Missing isolation keeps host mode.

## Prerequisites

- Linux, Python 3.9 or later, and a source checkout of Aegis.
- Rootless Podman on PATH. Check `podman info --format '{{.Host.Security.Rootless}}'`: it must say `true`.
  The adapter constructs argv; it does not attest that an installed engine is rootless.
- A locally available image with a repository SHA-256 digest, `/bin/sleep`, and the tools the run needs.
- A run folder, project clone, runtime source, Python/venv prefix and live checkouts with no symlink components.
  A mount must not equal or contain any owner home: the supplied home, environment HOME or password-database home.
  Changing HOME does not hide the password-database home. Mounts overlapping an existing secret path under any
  owner home refuse in either direction (equal to, inside or containing): `.claude`, `.codex`, `.ssh`, `.gnupg`,
  `.config`, `.aws`, `.kube`, `.docker`, `.netrc` and `.git-credentials`. Dangling secret symlinks protect their
  resolved targets too. Other missing secret paths are absent; planning never creates or enumerates them.
  Every existing source component, from `/` down, must be owned by root or the effective user. Write-bit checks
  apply to ancestors, since a leaf's write permission cannot replace its own directory entry. Effective group
  write is allowed for the owner's primary user-private group only when its name equals the user's name, `grp`
  shows no other members, and `pwd` shows no other account using it as a primary group. This is a local NSS
  check and naming convention, not exhaustive proof about hidden remote accounts.
  Every existing ancestor's `system.posix_acl_access` is read using `os.getxattr(..., follow_symlinks=False)`.
  Linux **ENODATA** establishes absence. Present ACLs must be valid Linux UAPI v2 bytes and agree with `lstat`;
  stat group bits alone can represent a mask granting access to named users. The mask limits named-user,
  owning-group and named-group rights; it does not limit owner or other rights. Named root/current-UID write
  grants and verified private-group write grants are trusted. Harmless foreign read/search grants and masked-off
  write grants are accepted, preserving valid `0775` ancestors. Effective foreign write requires a sticky
  ancestor and an existing next component owned by root or the effective user (for example `/tmp`).
  Unavailable, failed or unsupported queries, malformed bytes and ACL/mode disagreement refuse with distinct
  diagnostics **before** sticky handling. Make metadata readable/supported, or revalidate inconsistent metadata;
  the adapter never changes permissions or ACLs. Other filesystems/ACL schemes are not qualified by the local
  Linux evidence.
  See [acl(5)](https://man7.org/linux/man-pages/man5/acl.5.html) for the mask semantics and
  [Linux vfs_get_acl](https://github.com/torvalds/linux/blob/master/fs/posix_acl.c) for absence/error handling.
  Other ownership or unsafe ancestors refuse by path/UID.

ACL decoding requires a little-endian 32-bit version of 2 followed by complete 8-byte `<HHI>` entries. It checks
the owner, named-user, owning-group, named-group, optional-mask and other section order; required singleton
entries; unique named IDs in `0..4294967294`; undefined ID `0xffffffff` for unqualified entries; and permissions
in `0..7`. Named entries require a mask. Owner/other permissions must match their mode bits, and group mode bits
must match the mask when present or the owning-group entry otherwise. ACL failures are refusals, never absence.

Keep the runtime source and Python/venv separate from the writable run/project: read-only and read-write mounts
may not overlap. For example, use `/srv/aegis-runs/demo`, `/srv/aegis-projects/demo`, `/opt/aegis-runtime`,
`/opt/aegis-python` and `/srv/live-project`. Non-secret paths inside owner homes are allowed, including project
clones and venvs under `~/Documents`. The adapter checks real paths and directory identities of every existing
ancestor to reject aliases of home/secret roots and their represented ancestors, including missing tails. A bind
of a secret's descendant is not discovered without its original ancestors. Planning may describe missing paths
under trusted private ancestors; executing the plan requires preparing them first and recomputing the plan.

An inferred Python prefix must contain `pyvenv.cfg`. Otherwise set the explicit top-level `python_prefix` key.
Mounts of `/`, `/usr`, `/usr/local` and any owner home's `.local` refuse. Any mount equal to or containing an
image system directory also refuses: `/bin`, `/sbin`, `/lib`, `/lib64`, `/usr`, `/etc`, `/var`, `/opt`, `/run`,
`/proc`, `/sys`, `/dev`, `/tmp`. Such binds would replace image userland and invalidate the digest pin. Subfolders
such as `/opt/aegis-python` remain usable. The interpreter named by a venv's `pyvenv.cfg` `home` must exist at the
same path in the image; checking that is recorded for C2/C4 and is not solved by C1.

## Building the image — coming in C2

The shipped Containerfile and executable `build-image` CLI are coming in C2. C1 provides only
`build_image_argv(engine, context=..., containerfile=..., tag=...)`, which returns a list without executing it.
After an image exists, `podman image inspect IMAGE` supplies its `RepoDigests`. Use a repository digest reference,
not a mutable tag or the image's config ID. C1 neither pulls nor builds images.

## Configuration and dry run

Add the following fields to a v2 team config, retaining the other required team fields. This fragment is enough
for the standalone C1 planner. The example digest is illustrative; replace it with the actual local RepoDigest.

```json
{
  "schema": "aegis.team-run/v2",
  "run": "/srv/aegis-runs/demo",
  "project": "/srv/aegis-projects/demo",
  "source": "/opt/aegis-runtime",
  "recipes": {"python": "/opt/aegis-python/bin/python"},
  "python_prefix": "/opt/aegis-python",
  "live_checkouts": ["/srv/live-project"],
  "isolation": {
    "mode": "container",
    "engine": "podman",
    "image": "localhost/aegis-teams@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "cpus": 1,
    "memory": "1g",
    "pids": 4096
  }
}
```

`cpus` must be at least 0.01 and no greater than `os.cpu_count()`; smaller values can round to an unlimited quota.
An unknown CPU count refuses. `memory` is a positive
integer followed by lowercase `k`, `m` or `g`; zero is refused because it would disable the cap. `pids` is an
integer at least 64. Boolean numbers, unknown isolation fields and missing container fields refuse. Optional
`allow_unqualified` defaults to false and must be a boolean. Host mode is an absent isolation object or exactly
`{"mode":"host"}`. A present `isolation` key with null or any non-object value refuses; it never selects
legacy host mode. The library's `read_isolation(None, ...)` retains its absent-input API meaning. The standalone
CLI refuses isolation on a v1 config.

```sh
python3 tools/hierarchy_container.py plan --config /absolute/path/team-run.json
```

Output is one JSON object containing `mode`, normalized `isolation`, sorted `mounts`, `create_argv` and, for
container mode, `run`. Nothing is executed or written. Host output has null isolation/argv and no mounts.
The pure planner does not emit a complete expected record: `expected_plan` requires `image_inspect`, and
`verify` obtains that image response before constructing the comparison record.
Without explicit `python_prefix`, the prefix comes from the configured interpreter's `bin` parent and requires
`pyvenv.cfg`, without executing or resolving the interpreter. This retains a real venv prefix when its Python
executable is a symlink. If `source` is omitted,
the current adapter's repository is used. The CLI validates this subset, not the complete team config.

The engine argv creates one long-lived container named `aegis-team-<sha256(run)[:12]>`, labelled
`aegis.team.run=<run>`. It uses a read-only root, explicit writable `/tmp` and `/dev/shm` tmpfs, init,
CPU/memory/PID limits and `/bin/sleep infinity`.
Podman uses `--userns=keep-id`, `--security-opt=unmask=/proc/*`, `--read-only-tmpfs=false`,
`--env-host=false` and `--http-proxy=false`; no capabilities are added. Podman explicitly uses `--pid=private`;
Docker omits that unsupported Moby flag and retains the private PID default (`PidMode=""`). Both engines use
explicit `--ipc=private` and `--network=bridge`. Docker uses the host's numeric `uid:gid` and
`--security-opt systempaths=unconfined`, with no Podman-only flags.

The run and project are read-write binds. Runtime source, Python/venv prefix and every live checkout are read-only
binds. Sources and destinations are identical absolute paths. Duplicate binds of the same access mode collapse;
the plan is sorted by source. Commas, CR/LF and colons in mount paths refuse: commas/newlines alter `--mount`
parsing, and colons are separators in inspect's `HostConfig.Binds` representation.

`HOME=<run>/home`, `CODEX_HOME=<run>/codex-home` and `CLAUDE_CONFIG_DIR=<run>/claude-home` are fixed. The library's
explicit environment allowlist is `HOME`, `CODEX_HOME`, `CLAUDE_CONFIG_DIR`, `PATH`, `LANG`, `LC_ALL`, `TERM`, `TZ`
and `PYTHONDONTWRITEBYTECODE`. PATH defaults to `/usr/local/bin:/usr/bin:/bin`; bytecode writes default off.
The builder copies no ambient values and disables Podman's host-env and proxy defaults. Additional allowed
values must be supplied explicitly; alternate home paths and unlisted keys refuse. Values use `--env NAME=value`.
`expected_plan(..., env=None)` takes the same optional create environment as `create_argv`. Existing callers that
omit it retain the builder's defaults. The standalone plan/verify CLI uses those defaults; it adds no config key
for environment overrides. Later lifecycle callers must pass the same explicit `env` to both library functions.
The normalized record stores SHA-256 fingerprints of canonical JSON `[name,value]` pairs (`ensure_ascii=True`,
compact separators), never raw image credentials. `environment` witnesses the required create variables;
`image_info.env_fingerprints` witnesses the pinned image defaults. Old records without value witnesses refuse.

Verification uses the following finite precedence and requires agreement from every applicable witness:

| Witness | Value rule |
| --- | --- |
| `HOME`, `CODEX_HOME`, `CLAUDE_CONFIG_DIR` | Required exact run-home paths, even if an expected record is altered |
| Other create environment | Required fingerprint equality; only the existing allowlist may override an image default |
| Remaining image environment | Required pinned fingerprint equality; declaring a name grants no override |
| Engine-only variables | Optional named exceptions only when neither create nor image supplied a value witness |
| Podman recorded `--env` | Exactly the create-environment keys and fingerprints; missing, duplicate, inherited-host or extra declarations refuse |

The named `ENGINE_ENV_KEYS` exceptions remain `container`, `HOSTNAME`, `HOME`, `TERM`, `PWD`; HOME is always
covered by the stronger required run-home rule. These optional engine-only values are not authenticated host
identity evidence. The policy source is
[podman-run(1), ENVIRONMENT](https://docs.podman.io/en/latest/markdown/podman-run.1.html#environment); the exact
engine keys appear in the official [container-inspect example](https://docs.podman.io/en/v4.9.3/markdown/podman-container-inspect.1.html#example).
`PWD` and `container` were observed in the owner's `real-podman-4.9.3/inside.txt` capture (2026-11-07).
Unknown or unrequested keys, missing required variables and changed pinned values refuse as `environment`.
An image's synthetic `ANTHROPIC_API_KEY=placeholder` may remain unchanged; it cannot admit an ambient credential
under the same name. An explicitly approved PATH/LANG override is checked against its own create witness.
Errors report mismatch names, not credential values. Fingerprints prove equality of the supplied metadata, not
authenticity against a hostile owner/root. Docker can inject client `proxies` configuration too and remains
unqualified; its primary inspect schema supplies no Podman `CreateCommand` witness.

## Verifying ownership

Capture an engine inspect result in a file, then check it against the current config:

```sh
python3 tools/hierarchy_container.py verify --config /absolute/path/team-run.json --inspect /absolute/path/inspect.json
```

This command reads the files and makes one read-only `ENGINE image inspect IMAGE@sha256:...` call, with a
30-second timeout. `plan` executes nothing. The image response must match the configured digest directly or in
`RepoDigests`; that ties a multi-arch manifest list to the platform digest/container image ID. A manifest/config
hash mismatch refuses. Config IDs are canonicalized across bare and `sha256:`-prefixed forms. The image inspect
must supply a nonempty config ID; all supplied ID/digest aliases must be valid and agree. Container `Image` must
match that config ID, and every supplied digest, RepoDigest or image-reference witness must belong to the
inspected association. A matching digest never waives a contradictory config hash or an explicitly empty digest.
Docker's absent Digest is allowed only with the pinned RepoDigest/config-ID association. The call also provides
fingerprints of the pinned image's environment values.

Before comparing container fields, `expected_plan` and `verify` apply one contract to the existing comparison
record. Unknown expected fields refuse; missing or malformed values never become empty/absent witnesses.
This is structural validation of supplied evidence, not authentication against a hostile owner or root.

| Expected input | Required domain and absence rule | Mismatch label |
| --- | --- | --- |
| Record and engine | Object with only the existing fields; engine is `podman` or `docker` | `expected`, `engine` |
| Run and name | Absolute run with a representable derived `container_name(run)` | `label`, `name`, `environment` |
| Image association | Required config ID, digest-or-explicit-null, repository digest list and fingerprint map; pin belongs to the inspected association | `image`, `environment` |
| Image Config | Raw image response requires an object; missing/null/empty-list Env are supported empty representations, other malformed Env refuses | CLI refusal |
| Environment | Typed name-to-SHA256 maps; create defaults, fixed homes and the allowlist remain mandatory; pinned defaults may be known-empty | `environment` |
| Mount rows | Exact existing row keys, absolute same paths and literal boolean access; existing character/system-directory/duplicate rules apply | `mounts` |
| Root and user | Literal read-only true; both numeric IDs in the existing Linux bounds | `read_only`, `user`, `userns_mode` |
| Limits | Existing finite CPU range; positive integer memory bytes representable by `k`/`m`/`g`; integer PID limit at least 64; booleans refuse | `cpus`, `memory`, `pids` |

Known bad fields retain their individual labels. A matching invalid actual value, such as memory 0 or PID
limit -1, cannot authorize unlimited resources. `image_info.digest=null` is a supported absent platform digest
only with the pinned RepoDigest association; a missing key or empty string is different and refuses.

Verification compares the derived name, label, image identity, exact bind set (source/destination/access), read-only root,
numeric user, environment values, CPU/memory/PID limits, Privileged=false, empty CapAdd/Devices, private PID/IPC,
keep-id mappings for Podman (the default userns record for Docker), and forced bridge networking.
The observed Name must equal `container_name(run)`. Podman's captured name is plain. The modelled Docker
branch allows one leading slash, following [Moby v27.5.1 reserveName](https://github.com/moby/moby/blob/v27.5.1/daemon/names.go),
which prefixes names with `/`; additional slashes refuse. Every supplied Podman recorded `--name` must agree too.
The label cannot waive a contradictory name, and neither field authenticates ownership against a hostile owner.
Podman 4.9.3 reports `UsernsMode="private"` for keep-id, including the `real-podman-fix7-native` capture.
Verification requires exactly that string **and** valid keep-id mappings. Missing, malformed, host, shared or
unknown modes refuse; `keep-id` is a create request, not an admitted inspect alias. Docker's empty default
mode remains a separate, unqualified branch. The captured `HostConfig.IDMappings.UidMap` and
`GidMap` contain `1000:0:1`, matching `/proc/self/uid_map` in `inside.txt`. These inspect mappings are relative to
the rootless engine's parent namespace, where the invoking owner is ID 0. Verification requires non-overlapping
valid ranges and the expected owner's UID/GID each mapped to parent ID 0 as a singleton. Both starts and every
included ID must be in `0..4294967294`; Linux deliberately leaves `4294967295` unmapped
([user_namespaces(7)](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)). Missing, malformed,
zero-sized, reserved-ID, overflowing, root-wide or conflicting mappings refuse. No extra exec or engine call
is needed for this proof.

Every supplied Podman recorded namespace request must also agree with the plan: `--userns=keep-id`,
`--pid=private`, `--ipc=private`, `--network=bridge`. Both existing parser forms (`--flag=value` and
`--flag value`) are checked, including contradictory duplicates. Valid actual mappings/private/bridge fields
cannot waive a recorded host/shared request. These optional recorded requests add no effective proof when
absent; actual namespace witnesses and the existing mandatory recorded security/false flags still apply.

Both numeric UID/GID arguments must be in `0..4294967294` before either engine's create argv or expected plan
can be returned. Types, booleans and negatives retain `user must be a numeric uid:gid`; reserved/larger IDs
refuse with `user uid and gid must be < 4294967295`. Verification also revalidates the expected numeric
`UID:GID` record before comparing `Config.User`: matching invalid strings cannot waive the bound in Docker.
Boundary and high-ID tests are modelled; they do not qualify actual high-ID accounts or native engine behavior.

The capture's `SecurityOpt=[]` does not report partial `unmask=/proc/*`. The verifier instead checks that
`Config.CreateCommand` records exactly that security-option request, `--read-only-tmpfs=false`,
`--env-host=false` and `--http-proxy=false`, and refuses contradictory requests or other reported security
relaxations. Option values are parsed by arity so a label equal to the image cannot conceal later options.
This verifies recorded argv intent only: effective `/proc` masking and suppression of implicit writable tmpfs
mounts are **not verifiable from these inspect fields**. Docker's reported `SecurityOpt` must still equal
`systempaths=unconfined`.
Docker's `Image` is a config hash, not a manifest digest. Both NanoCpus and quota/period CPU representations are
supported. Podman uses `quota=int(float(cpus)*100000)` and derives NanoCpus from that quota: the capture's
`cpus=0.29` yields `CpuQuota=28999`, `CpuPeriod=100000`, `NanoCpus=289990000`. Either representation suffices;
when both are present they must agree. `Mounts`, `HostConfig.Tmpfs` and `HostConfig.Binds` are normalized together.
Captured Podman bind options include `rprivate,rbind`, and tmpfs options include `rprivate,tmpcopyup`.
For binds and tmpfs, supplied `Mode` strings and Podman `Options` lists must be well typed. Any explicit `ro`/`rw` flag
must agree with `RW`, the planned access and `HostConfig.Binds`. Conflicting or duplicate access flags refuse.
Omitted fields, empty Mode and Options containing only `rbind` assert no additional access mode; they do not
turn a read-only bind into a writable one. Serialized Binds without access flags retain their engine rw default.
Identical cross-references
agree; conflicting declarations, duplicates within a representation or extra mounts refuse. Only the declared
rw binds and the explicitly declared `/tmp` and `/dev/shm` tmpfs may be reported writable. Both scratch mounts
must be present and writable with `nosuid,nodev` option evidence; supplied option declarations must agree and
must not include `suid`, `dev`, `ro` or contradictory `exec,noexec`. A partial or empty tmpfs Mode supplies no
positive safety proof; only a complete
`rw,nosuid,nodev` Mode, Options list or HostConfig.Tmpfs declaration does. Every supplied witness is checked,
including contradictions across representations. There is no mandatory `noexec` policy: either `exec` or
`noexec` alone is admitted, while explicitly requesting both refuses. Automatic mounts absent from inspect are not
attested by this comparison. The old capture with read-only shm therefore differs from the revised plan.
Additional read-only binds also refuse. Unknown engine metadata is ignored; malformed required fields produce mismatches. A matching
result is `{"mismatches":[]}`. Mismatches name the affected field, such as `image`, `mounts`, `environment`,
`privileged`, `pid_mode`, `security_opt`, `cpus`, `memory` or `pids`. Exit codes are 0 valid/equal, 2 refused/mismatched
and 3 internal failure.

The library also returns argv for exec (absolute workdir and explicit env), inspect, timed stop, rm and image
inspect. Later callers must verify immediately before exec, stop or removal and leave a mismatched container
alone. Builders execute nothing. They revalidate the image pattern and every mount row's keys, absolute paths,
same-path equality, characters and boolean access. These structural checks do not attest filesystem custody:
C4 must recompute `mount_plan` from config immediately before `run`, rather than trust a stored plan.

## Protection and limits

When applied by a later lifecycle caller, this plan rejects mounts containing owner homes and mounts overlapping
listed secret paths in either direction. It keeps host agent sockets out of the passed environment, makes source/live checkouts
read-only and caps the run's resources. Same-path mounts can create otherwise empty ancestor directories inside
the container. The engine provides a separate PID namespace. The only permitted writable scratch destinations
are explicit `/tmp` and `/dev/shm`, in addition to the two rw binds. Podman's `--read-only-tmpfs=false` requests
suppression of writable `/run` and `/var/tmp`; inspect verifies the recorded request, not its effective enforcement.
`--tmpfs /dev/shm:rw,nosuid,nodev` explicitly requests writable shared memory instead of relying on the engine's
default shm mount. Writable shm is a prerequisite for POSIX semaphores; semaphore behavior is not qualified here.
Runtime/image content, and any credentials already inside an explicitly mounted
project/run/source, remain visible to its processes.

All roles in a run share its container and writable binds. This does not enforce separate writer scopes inside
the container; that is T2(b). The argv forces `--network=bridge`; it does not follow the rootless engine default.
It does not protect against host root,
an engine administrator or a hostile same-user process replacing paths after validation. The ancestor checks
protect against replacement by other users under the checked Linux metadata. Private-group membership relies
on the local NSS view plus the user-private naming convention; hidden remote NSS membership is not qualified.
An access ACL is checked together with its mode bits, not inferred from the mask alone. Directory-identity checks do not enumerate
a secret tree: a bind of a secret's DESCENDANT, such as `~/.codex/sessions`, whose original ancestors are not represented cannot be
discovered by inode comparison alone. The spec treats owner-created bind aliases as
outside the misconfiguration and accident threat model. A parent mount containing a relocated secret is refused:
if `~/.codex` links to `~/Documents/credentials`, mounting `~/Documents` refuses. These checks use real paths and
directory identities in both directions. Ordinary mounts inside HOME remain allowed when they do not overlap
an existing secret path. The mount plan and verification are separate from native behavior, login qualification
and resource-limit enforcement evidence.

Environment-variable relocations (`CODEX_HOME`, `CLAUDE_CONFIG_DIR`, `XDG_CONFIG_HOME`, `GNUPGHOME` and agent
sockets under `XDG_RUNTIME_DIR`) are not discovered/protected beyond the explicit environment allowlist. A secret
relocated into an otherwise allowed bind can remain visible even if its relocation variable is not forwarded.

The relevant source-bound baseline is the owner's 2026-11-07 Podman 4.9.3 capture:
`aegis-guides/v5.0-teams-t2a-evidence-20261107/c1-container-adapter/real-podman-4.9.3/` (`container-inspect.json`,
`image-inspect.json`, `inside.txt`, `capture.json`). It qualifies the recorded older argv only and showed shm
read-only. The revised argv adds an explicit writable shm mount; the later owner-observed `native-c1` result is
reported below separately from historical replay. The earlier C0 combined bwrap probe used different defaults and does
**not** qualify this argv. The full loop/wake/jobs lifecycle, effective unmask behavior and host logins remain
gates before C4.

## Docker is unqualified

Set `"engine":"docker"` and explicitly add `"allow_unqualified":true` to opt in. Otherwise validation refuses.
Rootful Docker group access is root-equivalent, and Docker has not received the rootless Podman qualification.
The override is an acknowledgement of that status, not evidence of equivalent isolation.
The modelled positive inspect test follows [Moby v27.5.1 MountPoint](https://github.com/moby/moby/blob/v27.5.1/api/types/types.go)
(`Mode`/`RW`, no `Options`) and [HostConfig.Tmpfs](https://github.com/moby/moby/blob/v27.5.1/api/types/container/hostconfig.go).
Both `--tmpfs` safety witnesses come from `HostConfig.Tmpfs`; the test adds no synthetic shm `Mounts` row or
Docker `Mounts.Options`. This schema-based model is separate from native Docker qualification.

## Tests

Run the focused integration test with pytest from the repository's test venv. The executable
`tests/integration/hierarchy_fake_engine.py` can be copied to a temporary PATH as `podman` or `docker`. Set
`AEGIS_FAKE_ENGINE_STATE` and `AEGIS_FAKE_ENGINE_LOG` to absolute temporary paths. It logs argv, models image
inspect/run/inspect/stop/rm, and executes commands locally with the recorded env and requested cwd. Unknown
commands/options refuse. This fake provides no isolation and must never be used for real team runs.

The real test requires `AEGIS_TEST_CONTAINER=podman`, Podman on PATH and a locally available `ubuntu:24.04` with
a RepoDigest. It captures the real engine path before installing fakes and uses real ownership checks for native
mount admission. It never pulls or builds an image. It verifies inspect, execs `id -u`, then stops and removes its
own test container. Otherwise it skips with a reason. A fake-engine pass is not native Podman qualification.

The fake embeds the captured Podman 4.9.3 HostConfig/Config/mount structure with its source SHA256. It substitutes
test paths, IDs and limits, preserves the observed namespace/security/CPU/options shape, and adds the newly
declared shm tmpfs. Docker has a separate inspect shape and rejects Podman-only flags; ambient host proxies are
copied only by Podman's unsuppressed default, not by Docker. No capture file is placed under `tests/fixtures`.
The historical capture-replay test is explicitly opt-in through `AEGIS_TEST_C1_HISTORICAL_CAPTURE_DIR`, pointing
to the external `real-podman-4.9.3` capture directory. It skips only when the variable is absent. An empty value,
missing directory/file, malformed JSON or invalid inspect fields fails with a diagnostic naming the variable and
input. The directory must contain the original `container-inspect.json` and `image-inspect.json`: replay preserves
the mount mismatch before the in-memory shm update and the empty mismatch list afterward. It never rewrites the
capture files. The newer `native-c1` capture already verifies the current writable-shm argv and must not replace
the historical input. The orchestrator reports that newer capture succeeded with an ordinary Documents venv
mount plan, `verify=[]` and writable `/dev/shm`; this is owner-observed native evidence, separate from replay.
The embedded fake-source provenance and unconditional fake-engine coverage remain unchanged. Optional
`AEGIS_FAKE_ENGINE_IMAGE` names a temporary image-inspect JSON fixture, including Config.Env and manifest-list
RepoDigests, for testing pinned-image environment and platform identity without a real engine.

The fake and positive inspect helper model 65536 subordinate IDs in the engine-parent range `1..65536`, plus
the exact owner singleton mapped to parent ID 0. Empty segments are omitted. For owner IDs at/above 65536,
the subordinate allocation stays bounded and a sparse unmapped gap precedes the owner singleton. UID and GID
are tested independently at 0, 1000, 65536, 70000 and 4294967294 through pure verification and public fake
create/inspect calls. These modelled allocations neither read host subuid/subgid configuration nor qualify real
high-ID Podman accounts. The captured profile constants remain unchanged.

The owner's host-escalated `real-acl-host-fix5/capture.json` (2026-11-08) observed successful installation and
readback of exact Linux UAPI bytes for named UID 65534 on fresh owned directories. Write permission 7 with mask
7 produced `0775` and refused; read/search permission 5 with mask 7 also produced `0775` and exposed the interim
adapter's blanket-presence compatibility defect; permission 7 masked by 5 produced `0755` and was accepted.
That immutable capture used adapter SHA256
`f4368160b7ebed0a4b9018b84cd4eb787820cf5178de147ac5d778709a83c45c`; no foreign-user process ran. The tests embed
its portable raw bytes/modes and replay them at the OS query boundary through the public mount plan and CLI.
Additional named-group, trusted-grant, malformed, mismatch and error cases are explicitly modelled; ACL absence
is also tested with a real OS query. The earlier virtualized sandbox's EINVAL is not host ACL capability evidence.
Existing native captures remain evidence for their recorded source/argv; the updated parser still requires the
orchestrator's fresh native recapture. Docker remains modelled and unqualified.
