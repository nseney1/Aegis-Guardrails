"""Read-only container plan and verification with caller-supplied observations."""
from pathlib import PurePosixPath
import stat

from aegis_core import team_isolation_mounts as mount_policy
from aegis_core.team_isolation_refusal import IsolationRefusal
from aegis_core.team_isolation_verify import container_name, container_user, expected_plan, load_inspection, verify

__all__ = ["build_image_argv", "check", "create_argv", "exec_argv", "image_inspect_argv",
           "inspect_argv", "rm_argv", "stop_argv"]

_RUN_FIELDS = frozenset({
    "schema", "run", "project", "source", "recipes", "python_prefix", "live_checkouts", "isolation",
    # Recognized fields of the full legacy run document, unused for isolation.
    "base", "branch", "initiative", "roles", "lanes", "limits", "preflight", "team",
    "base_tree", "min_free_gb", "loop", "lease_ttl_seconds", "hosts",
})
_RECIPE_FIELDS = frozenset({"keep", "commit_identity", "template", "python"})
_SCHEMA = "aegis.team-run/v2"


def _command(command):
    mount_policy.require(type(command) in (list, tuple) and 0 < len(command) <= 4096, "isolation_command")
    mount_policy.bounded_value(command)
    mount_policy.require(all(type(word) is str and "\x00" not in word for word in command), "isolation_command")
    _operand(command[0], "isolation_command")
    return list(command)


def _operand(value, code):
    mount_policy.require(type(value) is str and 0 < len(value) <= 4096 and not value.startswith("-")
                   and all(ord(char) >= 32 and not 127 <= ord(char) <= 159
                           and not 0xD800 <= ord(char) <= 0xDFFF for char in value), code)
    return value


def _env_argv(run, env, host_table):
    values = mount_policy.container_env(run, env, host_table=host_table)
    return [word for key, value in sorted(values.items()) for word in ("--env", key + "=" + value)]


def create_argv(isolation, *, run, mounts, host_table, cpu_count, platform, uid, gid,
                home, observed, owner_uid, owner_homes=None, private_gids=(), env=None, command=None):
    """Validate mount safety against trusted observations before formatting engine argv."""
    isolation = mount_policy.read_isolation(isolation, cpu_count=cpu_count, platform=platform)
    mount_policy.require(isolation is not None, "container_required")
    policy = mount_policy.host_policy(host_table)
    rows = mount_policy.validate_mounts(mounts, home=home, observed=observed, owner_uid=owner_uid,
                                       owner_homes=owner_homes, private_gids=private_gids,
                                       protected_names=policy.protected_names)
    return _create_argv(isolation, run, rows, policy, uid, gid, env, command)


def _create_argv(isolation, run, rows, host_table, uid, gid, env=None, command=None):
    run = str(mount_policy.absolute_path(run))
    user = container_user(uid, gid)
    engine = isolation["engine"]
    argv = [engine, "run", "-d", "--name", container_name(run), "--label", "aegis.team.run=" + run,
            "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev", "--tmpfs", "/dev/shm:rw,nosuid,nodev",
            "--init", "--cpus", str(isolation["cpus"]), "--memory", isolation["memory"],
            "--pids-limit", str(isolation["pids"]), "--ipc=private", "--network=" + mount_policy.NETWORK_MODE]
    if engine == "podman":
        argv += ["--pid=private", "--userns=keep-id", "--security-opt=unmask=/proc/*", "--env-host=false",
                 "--http-proxy=false", "--read-only-tmpfs=false"]
    else:
        argv += ["--user", user, "--security-opt", "systempaths=unconfined"]
    argv += _env_argv(run, env, host_table)
    for row in rows:
        argv += ["--mount", "type=bind,src={source},dst={destination}".format(**row)
                 + ("" if row["rw"] else ",readonly")]
    return argv + [isolation["image"]] + _command(["/bin/sleep", "infinity"] if command is None else command)


def exec_argv(engine, run, command, *, workdir, host_table, env=None):
    return [mount_policy.engine(engine), "exec", "--workdir", str(mount_policy.absolute_path(workdir)),
            *_env_argv(run, env, host_table), container_name(run), *_command(command)]


def inspect_argv(engine, run):
    return [mount_policy.engine(engine), "container", "inspect", container_name(run)]


def stop_argv(engine, run, *, timeout=10):
    mount_policy.require(type(timeout) is int and timeout > 0 and timeout.bit_length() <= 128, "stop_timeout")
    return [mount_policy.engine(engine), "stop", "--time", str(timeout), container_name(run)]


def rm_argv(engine, run):
    return [mount_policy.engine(engine), "rm", container_name(run)]


def image_inspect_argv(engine, image):
    return [mount_policy.engine(engine), "image", "inspect", _operand(image, "isolation_image")]


def build_image_argv(engine, *, context, containerfile, tag):
    return [mount_policy.engine(engine), "build", "--file", str(mount_policy.absolute_path(containerfile)),
            "--tag", _operand(tag, "image_tag"), str(mount_policy.absolute_path(context))]


def _read_run(config):
    """Bound the legacy v2 input before interpreting its closed isolation schema."""
    if type(config) is bytes:
        config = mount_policy.load_document(config)
        mount_policy.require(type(config) is dict, "document_invalid")
    else:
        mount_policy.require(type(config) is dict, "document_invalid")
        mount_policy.bounded_value(config)
    mount_policy.require(config.keys() <= _RUN_FIELDS, "team_run_fields")
    if "isolation" in config:
        mount_policy.require(type(config["isolation"]) is dict, "isolation_object")
        mount_policy.require(config.get("schema") == _SCHEMA, "team_run_schema")
    elif "schema" in config:
        mount_policy.require(config["schema"] in ("aegis.team-run/v1", _SCHEMA), "team_run_schema")
    if type(config.get("recipes")) is dict:
        mount_policy.require(config["recipes"].keys() <= _RECIPE_FIELDS, "team_run_fields")
    return config


def _plan(config, *, source, owner_homes, owner_uid, observer, private_groups, policy):
    recipes = config.get("recipes")
    mount_policy.require(type(recipes) is dict and "python" in recipes, "team_run_recipes")
    python = mount_policy.absolute_path(recipes["python"])
    mount_policy.require(python.parent.name == "bin", "python_bin")
    prefix = mount_policy.absolute_path(config.get("python_prefix", str(python.parent.parent)))
    marker = str(prefix / "pyvenv.cfg") if "python_prefix" not in config else None
    run = str(mount_policy.absolute_path(config.get("run")))
    project = str(mount_policy.absolute_path(config.get("project")))
    source = str(mount_policy.absolute_path(config.get("source", source)))
    live = config.get("live_checkouts", [])
    mount_policy.require(type(live) in (list, tuple) and len(live) <= 124, "mount_rows")
    live = [str(mount_policy.absolute_path(path)) for path in live]
    paths = (run, project, source, str(prefix), *live)
    for path in paths:
        mount_policy.system_mount(PurePosixPath(path))

    homes = owner_homes()
    home = homes.get("explicit") if type(homes) is dict else None
    owners = mount_policy.validated_owner_homes(home, homes)
    observed = observer(paths, tuple(map(str, owners)), marker=marker, protected_names=policy.protected_names)
    mount_policy.bounded_value(observed)
    mount_policy.require(type(observed) is dict, "mount_metadata")
    context = dict(home=home, observed=observed, owner_uid=owner_uid, owner_homes=homes,
                   private_gids=private_groups(observed) if private_groups else ())
    rows = mount_policy.mount_plan(run=run, project=project, source=source, python_prefix=str(prefix),
                             live_checkouts=live, protected_names=policy.protected_names, **context)
    if marker is not None:
        info = observed.get(marker)
        mount_policy.require(info is not None, "python_prefix")
        info = mount_policy.metadata(PurePosixPath(marker), observed, directory=False)
        mount_policy.require(stat.S_ISREG(info["mode"]), "python_prefix")
    return run, rows, context


def check(config, *, observer, owner_homes, cpu_count, platform, host_table, source,
          owner_uid=None, owner_gid=None, owner_identity=None, inspect=None, inspector=None, private_groups=None):
    """Plan or compare one container using observations injected by the adapter.

    Inspect and inspector are deferred readers. Host mode never uses container
    dependencies and a rejected inspection never reaches the image engine.
    """
    try:
        config = _read_run(config)
        raw_isolation = config.get("isolation")
        if type(raw_isolation) is dict and raw_isolation.get("mode") == "container" and callable(cpu_count):
            cpu_count = cpu_count()
        isolation = mount_policy.read_isolation(raw_isolation, cpu_count=cpu_count, platform=platform)
        if isolation is None:
            mount_policy.require(inspect is None, "container_required")
            return dict(status="ok", mode="host", isolation=None, mounts=[], create_argv=None)
        inspected = None
        if inspect is not None:
            inspected = load_inspection(inspect())
            if inspected is None:
                return dict(status="mismatch", mismatches=["inspect"])
            mount_policy.require(inspector is not None, "image_inspect")

        policy = mount_policy.host_policy(host_table() if callable(host_table) else host_table)
        if owner_identity is not None:
            owner_uid, owner_gid = owner_identity()
        run, rows, context = _plan(config, source=source, owner_homes=owner_homes, owner_uid=owner_uid,
                                   observer=observer, private_groups=private_groups, policy=policy)
        if inspect is None:
            argv = _create_argv(isolation, run, rows, policy, owner_uid, owner_gid)
            return dict(status="ok", mode="container", run=run, isolation=isolation, mounts=rows, create_argv=argv)
        image = inspector(image_inspect_argv(isolation["engine"], isolation["image"]))
        expected = expected_plan(isolation, run=run, mounts=rows, image_inspect=image, host_table=policy,
                                 cpu_count=cpu_count, platform=platform, uid=owner_uid, gid=owner_gid, **context)
        mismatches = verify(inspected, expected, host_table=policy, **context)
        return dict(status="mismatch" if mismatches else "ok", mismatches=mismatches)
    except IsolationRefusal as error:
        return dict(status=error.status, code=error.code, reason=error.message, next_action=error.next_action)
