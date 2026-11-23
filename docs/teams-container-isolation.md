# Optional Teams container isolation

## Prerequisites

Continue only when all four conditions are met.

- Keep credentials out of every mounted tree, including read-only mounts and any live checkouts.
- Use absolute paths with symlink-free directory components, including every operator and capture
  directory component. Use regular, non-symlink files for `team-run.json` and the saved inspection.
- Use run, project, runtime source and Python prefix paths owned by root or the effective user.
  Require the same ownership for their ancestors and protect those ancestors from foreign writes,
  including writes granted through access ACLs.
- Use Linux with descriptor-relative observation and filesystems that allow queries for POSIX access
  ACL metadata.

Use the following owner-approved installation layout. Stop if any required path is unavailable or
fails the custody requirements.

- Use `/usr/bin/podman` as an executable regular file. Require real directories from `/` through
  `/usr/bin`, with the executable and its ancestor directories owned by root or the effective user
  and free of group or other write permissions. Keep `/usr/bin` and the executable outside the
  workspace and every child-writable mount.
  [Engine custody check](../tests/unit/cli/test_cli_team_isolation.py#L421)
- Use the approved `/usr/bin/mktemp` and the installed `/opt/aegis-cli/bin/aegis`. Keep them, the Aegis
  interpreter and their resolved paths under trusted ownership outside the workspace and every
  child-writable mount.
- Use the initialized workspace at `/srv/aegis-workspaces/demo`. If you use an `AEGIS_WORKSPACE`
  pin, set it to the same workspace.
  [Explicit target and matching pin](../tests/unit/core/test_workspace_binding.py#L464)

Set `PATH` in the shell where you run the walkthrough. An earlier child-writable `PATH` directory
could supply a different `podman` for the check's image inspection.
[Search path from the environment](../tests/unit/core/test_pathlookup.py#L1325) ·
[First matching program](../tests/unit/core/test_pathlookup.py#L1302)

```sh
export PATH=/usr/bin
```

Run `/usr/bin/podman info --format '{{.Host.Security.Rootless}}'` and confirm the result is `true`
before continuing. Choose a locally available image that contains `/bin/sleep` and the tools your
run needs. Run `/usr/bin/podman image inspect IMAGE` with your local image name. Use a repository
digest reference from `RepoDigests` in the configuration.

## Plan the container

Prepare separate run, project, runtime source and Python prefix directories. Use real absolute paths
and keep the runtime source and Python prefix separate from the writable run and project. Prepare
`/srv/aegis-operator/demo` as an owner-only directory (mode `0700`) under trusted ancestors outside
every child-writable mount. Save this v2 configuration there as `team-run.json`, replacing the
example digest with your image reference.

```json
{
  "schema": "aegis.team-run/v2",
  "run": "/srv/aegis-runs/demo",
  "project": "/srv/aegis-projects/demo",
  "source": "/opt/aegis-runtime",
  "recipes": {"python": "/opt/aegis-python/bin/python"},
  "python_prefix": "/opt/aegis-python",
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

```sh
/opt/aegis-cli/bin/aegis team isolation check --workspace /srv/aegis-workspaces/demo --config /srv/aegis-operator/demo/team-run.json --json
```

Run `/opt/aegis-cli/bin/aegis team isolation check --help` for the available options.
[CLI contract](../tests/contract/test_cli_contract.py#L138)

Review `mounts` and `create_argv` in the container plan. Treat `create_argv` as display output
when `create_argv_display_only` is true.
[Plan mount and argv](../tests/unit/cli/test_cli_team_isolation.py#L388) ·
[Display-only flag](../tests/unit/cli/test_cli_team_isolation.py#L232)

## Capture and verify the inspection

After creating the container, copy the value after `--name` in the plan's `create_argv` into
`container_name`. Keep the capture private.
[Name in the creation argv](../tests/integration/test_hierarchy_container.py#L697) ·
[Podman container inspection argv](../tests/integration/test_hierarchy_container.py#L808)

```sh
container_name='aegis-team-aaaaaaaaaaaa'
(
  umask 077 &&
  capture_dir=$(/usr/bin/mktemp -d /srv/aegis-operator/demo/inspect.XXXXXXXXXX) &&
  /usr/bin/podman container inspect "$container_name" > "$capture_dir/container.json" &&
  /opt/aegis-cli/bin/aegis team isolation check --workspace /srv/aegis-workspaces/demo --config /srv/aegis-operator/demo/team-run.json --inspect "$capture_dir/container.json" --json
)
```

Pass the absolute path to the saved container inspection after a successful capture. For the
comparison, the check asks Podman for image metadata using the repository digest reference in
`isolation.image`. A matching snapshot returns `{"status":"ok","mismatches":[]}` and establishes
agreement of that snapshot with the expected metadata.
[Podman digest-qualified request](../tests/unit/core/test_team_isolation.py#L191) ·
[Digest-qualified CLI request](../tests/unit/cli/test_cli_team_isolation.py#L191) ·
[Matching saved snapshot](../tests/unit/cli/test_cli_team_isolation.py#L207)
