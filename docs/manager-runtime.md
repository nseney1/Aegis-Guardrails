# Pinned manager runtime

Use a clean checkout at the full Git commit you reviewed. Use a full local
repository and install Git on the default system executable search path.
Keep the artifact and runtime output roots in separate,
owner-private directories outside the checkout. Use their physical absolute
paths. Keep the roots and their ancestors under owner custody from build
through host use.

Provision a separate offline build environment with setuptools, wheel,
packaging, and pip. Use the same base CPython installation for it and the
verifier. The builder may be the base executable or an external virtual
environment with a copied or symlinked executable. An alias to a builder
preserves its package policy. System package directories are added only for
a base builder or a virtual environment that permits them.

Use Linux with executable procfs descriptors and the required no-follow
filesystem operations. The installed verifier proves its CPython base
against its running executable. The base executable's physical location
must agree with both reported prefixes and the versioned executable name.
Keep that base, its standard library, native dependencies, selected builder packages, verifier
installation, and their ancestors under owner custody outside all three
roots. Keep the verifier and builder environments separate. The verifier
requires a physical installed prefix with matching prefix and exec-prefix
and a determinable `lib` or `lib64` startup layout. It checks both
configuration positions, alternate startup landmarks, the standard library
and archive, encodings, and the dynamic module directory before any child
launch. A virtual environment's `home` must resolve to the same physical
base executable directory. Every child uses that profile's executable name
and library paths. Builder packages come from the bound builder environment
and any system sites its policy allows.
Use an offline environment for the build. The command clears inherited Python,
pip, Git and manager configuration from its Python children and disables the
pip index, dependency resolution and cache for installation. Reviewed build
code runs as the invoking user. The tool relies on the caller's offline
environment for network isolation.

## Build and verify

Set `VERIFIER_PYTHON` to the absolute Python in a trusted isolated virtual
environment with Aegis installed and system site-packages disabled. Keep the
verifier outside the checkout and both roots. Set `TRUSTED_PATH` to the trusted
system executable search path. The remaining shell variables contain
owner-selected absolute paths and a full reviewed Git object ID. Both roots
must already exist with owner-only access.

```sh
env -i PATH="$TRUSTED_PATH" LC_ALL=C \
    "$VERIFIER_PYTHON" -I -B -m aegis_core.manager_runtime build \
    --source "$SOURCE_CHECKOUT" --commit "$REVIEWED_COMMIT" \
    --build-python "$OFFLINE_BUILD_PYTHON" \
    --artifact-root "$ARTIFACT_ROOT" --output-root "$RUNTIME_ROOT"

env -i PATH="$TRUSTED_PATH" LC_ALL=C \
    "$VERIFIER_PYTHON" -I -B -m aegis_core.manager_runtime verify \
    --source "$SOURCE_CHECKOUT" --commit "$REVIEWED_COMMIT" \
    --artifact-root "$ARTIFACT_ROOT" --output-root "$RUNTIME_ROOT"
```

Pass `--python` to verify when you need to check an interpreter path already
selected by a caller. The command compares that exact absolute path with the
pin before starting its interpreter. `build_pin` and `verify_pin` provide the
same operations for callers in Python and raise `RuntimeRefusal` with the
same reason and recovery action.

Build authenticates the commit, every tree and each tracked file, and checks
that the staged entries match. Review a checkout with the exact committed file
bytes and executable modes. The source check uses Git index and object reads
and hashes physical files without running checkout filters. Build verifies the
private export against the same authenticated tree entries. It uses the
project's setuptools backend to produce its pure wheel and sdist. It then
creates a dedicated virtual environment without bundled pip, checks the
wheel inventory, and installs the captured wheel using the offline builder
without starting the candidate Python.
The generated runtime and artifacts live in directories identified by the
same generation ID. The output root's `pin.json` binds the source commit and
tree, artifact paths and SHA-256 digests, Python executable digest, and
virtual environment configuration digest.

Build publishes `pin.json` atomically after verification. Failed candidate
builds leave the current pin in place. Successful replacements retain prior
generation directories so an existing registration can keep using its exact
interpreter. Keep those directories while a host still references them. If
publication durability is uncertain, both generations are retained and the
command reports a refusal so the owner can read back the current pin.

Both operations return one JSON object. A verified result includes the
absolute interpreter, source commit and tree, artifact digests, installed
import origins, and manager smoke result. Verification checks the installed
package file set and bytes against the wheel and checks the full startup
layout before and after launching the pinned Python with `-I -S -B`.
Both probe children execute the anchored generation file descriptor. Its
identity and digest must match the reported name after each child and again
after the final source check, at publication or return. The process uses the
physical base path for CPython startup and adds only the verified wheel's
package directory. Verification runs the real manager stdio server for
`initialize` and `tools/list`. The smoke uses a disposable registration
selector, without enrolling or activating a workspace. Verification reads
the published generation and uses temporary scratch storage.

Use the verified generation under continuous owner custody through host use.
Set `PINNED_PYTHON` to the reported
interpreter and `PINNED_SITE` to the absolute site-packages directory containing
the reported package origins. Supply the owner-approved manager configuration
and digest. Use the same installed verifier for the host bootstrap. It keeps
the verified launch binding through the transfer, checks the requested site
against the verified origins, and executes the generation descriptor using
that binding's identity, digest, and base startup profile. The host must
retain custody of the generation and trusted base while the process runs.

```sh
env -i PATH="$TRUSTED_PATH" LC_ALL=C \
    AEGIS_MANAGER_CONFIG="$MANAGER_CONFIG" AEGIS_MANAGER_CONFIG_SHA256="$MANAGER_CONFIG_SHA256" \
    "$VERIFIER_PYTHON" -I -B -c '
import json
import os
from pathlib import Path
import sys
from aegis_core import manager_runtime as runtime

source, artifacts, output, binary, site, commit = sys.argv[1:]
try:
    with runtime._verified_pin(source, commit, artifacts, output, binary) as (report, launch):
        verified_site = Path(report["import_origins"]["aegis_mcp"]).parent.parent
        if str(verified_site) != site:
            raise runtime.RuntimeRefusal("install_mismatch")
        with launch.open() as fd:
            os.execve(f"/proc/self/fd/{fd}", launch.base.command(runtime._MCP_BOOT, str(verified_site)), os.environ)
except runtime.RuntimeRefusal as error:
    print(json.dumps(error.as_dict()), file=sys.stderr)
    raise SystemExit(1)
' "$SOURCE_CHECKOUT" "$ARTIFACT_ROOT" "$RUNTIME_ROOT" "$PINNED_PYTHON" "$PINNED_SITE" "$REVIEWED_COMMIT"
```

See [manager workspaces](manager-workspaces.md) for approval, activation, and
host configuration.

## Refusals

A refused operation exits with code 1 and returns a JSON object with status
refused, reason and `next_action`. It withholds the runtime result. Refusal
text is fixed and omits child output.

| Reason | Recovery |
|---|---|
| invalid_input | Supply a full reviewed commit and canonical, distinct absolute paths. |
| unsupported_platform | Run on a POSIX host with descriptor-relative no-follow storage and descriptor execution. |
| unsafe_root | Restore the physical roots and owner-only access to the artifact and output roots. |
| source_changed | Restore the clean reviewed checkout and its local Git objects. |
| build_backend_unavailable | Provision the offline build Python with the required tools. |
| build_failed | Check the reviewed project's build requirements and packaging configuration. |
| artifact_mismatch | Restore both exact artifacts or rebuild. |
| invalid_manifest | Restore the owner-custodied manifest or build a new pin. |
| wrong_interpreter | Use the generation's pinned interpreter or rebuild. |
| install_failed | Check venv creation and offline wheel installation. |
| install_mismatch | Restore the exact installed files or rebuild. |
| smoke_failed | Check manager-mode startup and the manager `tools/list` surface. |
| runtime_io | Check root access and available storage. |
| publication_uncertain | Read back the current pin and check storage durability. |
