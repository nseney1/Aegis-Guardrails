#!/usr/bin/env python3
"""Test-only podman/docker stand-in. Copy onto PATH, chmod +x, and set both absolute paths:

AEGIS_FAKE_ENGINE_STATE: JSON state file; AEGIS_FAKE_ENGINE_LOG: JSONL argv log.
No engine, namespace or isolation is provided. exec runs a real local command with the recorded environment.
Only the adapter's explicit option vocabulary is accepted; unknown commands/options fail closed with exit 2.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from fractions import Fraction

# Podman 4.9.3 structure copied from owner evidence real-podman-4.9.3/container-inspect.json.
# SHA256 94799e114181523063121eae3852f9db29d09e63fd3d3e8d5870d7f843950e7e.
# Only run-specific paths/identifiers are blanked; resources, mappings and tmpfs are filled from argv below.
PODMAN_493_HOST_CONFIG = {'Binds': [],
 'CgroupManager': 'systemd',
 'CgroupMode': 'private',
 'ContainerIDFile': '',
 'LogConfig': {'Type': 'journald', 'Config': None, 'Path': '', 'Tag': '', 'Size': '0B'},
 'NetworkMode': 'bridge',
 'PortBindings': {},
 'RestartPolicy': {'Name': '', 'MaximumRetryCount': 0},
 'AutoRemove': False,
 'VolumeDriver': '',
 'VolumesFrom': None,
 'CapAdd': [],
 'CapDrop': [],
 'Dns': [],
 'DnsOptions': [],
 'DnsSearch': [],
 'ExtraHosts': [],
 'GroupAdd': [],
 'IpcMode': 'private',
 'Cgroup': '',
 'Cgroups': 'default',
 'Links': None,
 'OomScoreAdj': 0,
 'PidMode': 'private',
 'Privileged': False,
 'PublishAllPorts': False,
 'ReadonlyRootfs': True,
 'SecurityOpt': [],
 'Tmpfs': {'/tmp': 'rw,nosuid,nodev,rprivate,tmpcopyup'},
 'UTSMode': 'private',
 'UsernsMode': 'private',
 'IDMappings': {'UidMap': ['0:1:1000', '1000:0:1', '1001:1001:64536'],
                'GidMap': ['0:1:1000', '1000:0:1', '1001:1001:64536']},
 'ShmSize': 65536000,
 'Runtime': 'oci',
 'ConsoleSize': [0, 0],
 'Isolation': '',
 'CpuShares': 0,
 'Memory': 1073741824,
 'NanoCpus': 289990000,
 'CgroupParent': 'user.slice',
 'BlkioWeight': 0,
 'BlkioWeightDevice': None,
 'BlkioDeviceReadBps': None,
 'BlkioDeviceWriteBps': None,
 'BlkioDeviceReadIOps': None,
 'BlkioDeviceWriteIOps': None,
 'CpuPeriod': 100000,
 'CpuQuota': 28999,
 'CpuRealtimePeriod': 0,
 'CpuRealtimeRuntime': 0,
 'CpusetCpus': '',
 'CpusetMems': '',
 'Devices': [],
 'DiskQuota': 0,
 'KernelMemory': 0,
 'MemoryReservation': 0,
 'MemorySwap': 2147483648,
 'MemorySwappiness': -1,
 'OomKillDisable': False,
 'Init': True,
 'PidsLimit': 4096,
 'Ulimits': [{'Name': 'RLIMIT_NOFILE', 'Soft': 1048576, 'Hard': 1048576},
             {'Name': 'RLIMIT_NPROC', 'Soft': 114474, 'Hard': 114474}],
 'CpuCount': 0,
 'CpuPercent': 0,
 'IOMaximumIOps': 0,
 'IOMaximumBandwidth': 0,
 'CgroupConf': None}
PODMAN_493_CONFIG = {'Hostname': '',
 'Domainname': '',
 'User': '',
 'AttachStdin': False,
 'AttachStdout': False,
 'AttachStderr': False,
 'Tty': False,
 'OpenStdin': False,
 'StdinOnce': False,
 'Env': [],
 'Cmd': ['/bin/sleep', 'infinity'],
 'Image': '',
 'Volumes': None,
 'WorkingDir': '/',
 'Entrypoint': '',
 'OnBuild': None,
 'Labels': {},
 'Annotations': {'io.container.manager': 'libpod',
                 'io.podman.annotations.init': 'TRUE',
                 'org.opencontainers.image.stopSignal': '15'},
 'StopSignal': 15,
 'HealthcheckOnFailureAction': 'none',
 'CreateCommand': [],
 'Umask': '0022',
 'Timeout': 0,
 'StopTimeout': 10,
 'Passwd': True,
 'sdNotifyMode': 'container'}
PODMAN_493_MOUNT = {'Type': 'bind',
 'Source': '',
 'Destination': '',
 'Driver': '',
 'Mode': '',
 'Options': ['rbind'],
 'RW': False,
 'Propagation': 'rprivate'}


def refuse(message):
    raise ValueError(message)


def read_state(path):
    if not path.exists():
        return {"containers": {}}
    return json.loads(path.read_text(encoding="utf-8"))


def write_state(path, state):
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
    os.replace(str(temporary), str(path))


def options(argv, flags, values):
    parsed = {}
    index = 0
    while index < len(argv) and argv[index].startswith("-"):
        word = argv[index]
        if word in flags:
            parsed.setdefault(word, []).append(True)
            index += 1
        elif word in values and index + 1 < len(argv):
            parsed.setdefault(word, []).append(argv[index + 1])
            index += 2
        else:
            refuse("unsupported option: " + word)
    return parsed, argv[index:]


def one(parsed, name):
    values = parsed.get(name, [])
    if len(values) != 1:
        refuse("expected exactly one " + name)
    return values[0]


def environment(parsed):
    result = {}
    for value in parsed.get("--env", []):
        key, separator, content = value.partition("=")
        if not separator or not key:
            refuse("--env requires NAME=value")
        result[key] = content
    return result


def bind_mount(value, engine):
    pieces = value.split(",")
    parts = dict(piece.split("=", 1) for piece in pieces if "=" in piece)
    if (parts.keys() != {"type", "src", "dst"} or parts["type"] != "bind"
            or not Path(parts["src"]).is_absolute() or not Path(parts["dst"]).is_absolute()
            or any("=" not in piece and piece != "readonly" for piece in pieces)):
        refuse("unsupported mount: " + value)
    row = copy.deepcopy(PODMAN_493_MOUNT) if engine == "podman" else {"Type": "bind", "Propagation": "rprivate"}
    row.update(Source=parts["src"], Destination=parts["dst"], RW="readonly" not in pieces)
    if engine == "docker":
        row["Mode"] = "rw" if row["RW"] else "ro"
    return row


def find(state, name):
    for key, value in state["containers"].items():
        if name in (key, value["Id"]):
            return key, value
    refuse("no such container: " + name)


def image_record(image, engine):
    override = os.environ.get("AEGIS_FAKE_ENGINE_IMAGE")
    if override:
        value = json.loads(Path(override).read_text(encoding="utf-8"))
        if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
            refuse("image fixture must contain exactly one image")
        return value[0]
    digest = image.rsplit("@", 1)[-1]
    if re.fullmatch(r"sha256:[0-9a-fA-F]{64}", digest) is None:
        digest = "sha256:" + hashlib.sha256(image.encode("utf-8")).hexdigest()
        image = image + "@" + digest
    config_id = hashlib.sha256(("config:" + image).encode("utf-8")).hexdigest()
    info = {"Id": config_id if engine == "podman" else "sha256:" + config_id, "RepoDigests": [image],
            "Config": {"Env": ["PATH=/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                               "PYTHONDONTWRITEBYTECODE=1"]}}
    if engine == "podman":
        info["Digest"] = digest
    return info


def image_inspect(argv, engine):
    if len(argv) != 1 or argv[0].startswith("-"):
        refuse("image inspect requires one image")
    print(json.dumps([image_record(argv[0], engine)]))


def id_map(identity):
    # Model only the captured 65536 subordinate IDs (parent 1..65536), plus the invoking owner at parent 0.
    # High owners leave sparse unmapped gaps; this is not a claim about real host subuid/subgid allocation.
    before = min(identity, 65536)
    rows = (["0:1:%d" % before] if before else []) + ["%d:0:1" % identity]
    remaining = 65536 - before
    if remaining:
        rows.append("%d:%d:%d" % (identity + 1, before + 1, remaining))
    return rows


def run_container(argv, state, path, engine):
    flags = {"-d", "--read-only", "--init", "--ipc=private", "--network=bridge"}
    if engine == "podman":
        flags |= {"--userns=keep-id", "--security-opt=unmask=/proc/*", "--env-host=false", "--http-proxy=false",
                  "--read-only-tmpfs=false", "--pid=private"}
    parsed, tail = options(argv, flags, {"--name", "--label", "--tmpfs", "--cpus", "--memory", "--pids-limit",
                                       "--user", "--security-opt", "--env", "--mount"})
    one(parsed, "-d")
    if len(tail) < 2:
        refuse("run -d requires an image and command")
    name = one(parsed, "--name")
    if name in state["containers"]:
        refuse("container already exists: " + name)
    if "--security-opt" in parsed and one(parsed, "--security-opt") != "systempaths=unconfined":
        refuse("unsupported --security-opt")
    image = tail[0]
    if "@sha256:" not in image:
        refuse("run image must carry a digest")
    info = image_record(image, engine)
    env = dict(item.split("=", 1) for item in info.get("Config", {}).get("Env", []))
    # Podman's defaults copy ambient proxies; Docker does not copy its client's ambient proxy environment.
    if engine == "podman" and "--http-proxy=false" not in parsed:
        env.update((key, os.environ[key]) for key in ("HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY",
                   "https_proxy", "http_proxy", "no_proxy") if key in os.environ)
    env.update(environment(parsed))
    labels = {}
    for label in parsed.get("--label", []):
        key, separator, value = label.partition("=")
        if not separator:
            refuse("--label requires NAME=value")
        labels[key] = value
    identity = hashlib.sha256(name.encode("utf-8")).hexdigest()
    env["HOSTNAME"] = identity[:12]
    if engine == "podman":
        env["container"] = "podman"
    user = one(parsed, "--user") if "--user" in parsed else "%d:%d" % (os.getuid(), os.getgid())
    host = copy.deepcopy(PODMAN_493_HOST_CONFIG) if engine == "podman" else {
        "Binds": None, "ReadonlyRootfs": False, "Privileged": False, "CapAdd": None, "Devices": None,
        "PidMode": "", "IpcMode": "private", "UsernsMode": "", "NetworkMode": "bridge", "SecurityOpt": [],
        "CpuPeriod": 0, "CpuQuota": 0}
    host.update(ReadonlyRootfs="--read-only" in parsed, Tmpfs={},
                Memory=int(one(parsed, "--memory")[:-1]) * {"k": 1024, "m": 1024 ** 2,
                                                          "g": 1024 ** 3}[one(parsed, "--memory")[-1]],
                PidsLimit=int(one(parsed, "--pids-limit")))
    for value in parsed.get("--tmpfs", []):
        destination, separator, opts = value.partition(":")
        if not separator or not Path(destination).is_absolute() or destination in host["Tmpfs"]:
            refuse("unsupported tmpfs: " + value)
        host["Tmpfs"][destination] = opts + (",rprivate,tmpcopyup" if engine == "podman" else "")
    mounts = [bind_mount(value, engine) for value in parsed.get("--mount", [])]
    config = copy.deepcopy(PODMAN_493_CONFIG) if engine == "podman" else {}
    config.update(Image=image, Labels=labels, Env=[key + "=" + value for key, value in sorted(env.items())], User=user)
    if engine == "podman":
        uid, gid = map(int, user.split(":"))
        host["IDMappings"] = {"UidMap": id_map(uid), "GidMap": id_map(gid)} if "--userns=keep-id" in parsed else {
            "UidMap": ["0:0:65536"], "GidMap": ["0:0:65536"]}
        host["CpuPeriod"] = 100000
        host["CpuQuota"] = int(float(one(parsed, "--cpus")) * 100000)
        host["NanoCpus"] = host["CpuQuota"] * 10000
        host["Binds"] = ["%s:%s:%s,rprivate,rbind" % (m["Source"], m["Destination"], "rw" if m["RW"] else "ro")
                         for m in mounts]
        config["CreateCommand"] = [engine, "run", *argv]
        config["Cmd"] = tail[1:]
        config["Hostname"] = identity[:12]
    else:
        host["NanoCpus"] = int(Fraction(one(parsed, "--cpus")) * 1000000000)
        host["SecurityOpt"] = parsed.get("--security-opt", [])
    container = {"Id": identity, "Name": name, "Image": info["Id"], "Config": config, "HostConfig": host,
                 "Mounts": mounts, "State": {"Running": True}, "Command": tail[1:]}
    if engine == "podman":
        container["ImageDigest"] = info["Digest"]
        container["ImageName"] = image
    state["containers"][name] = container
    write_state(path, state)
    print(identity)

def exec_command(argv, state):
    parsed, tail = options(argv, set(), {"--workdir", "--env"})
    if len(tail) < 2:
        refuse("exec requires a container and command")
    _, container = find(state, tail[0])
    if not container["State"]["Running"]:
        refuse("container is stopped: " + tail[0])
    env = dict(value.split("=", 1) for value in container["Config"]["Env"])
    env.update(environment(parsed))
    workdir = one(parsed, "--workdir")
    if not Path(workdir).is_absolute():
        refuse("exec workdir must be absolute")
    env["PWD"] = workdir
    try:
        return subprocess.run(tail[1:], env=env, cwd=workdir, timeout=60).returncode
    except subprocess.TimeoutExpired:
        refuse("exec timed out after 60 seconds")
    except OSError as exc:
        refuse("exec failed: " + str(exc))


def main(argv):
    try:
        engine = "docker" if Path(sys.argv[0]).name == "docker" else "podman"
        state_path, log_path = (Path(os.environ[key]) for key in ("AEGIS_FAKE_ENGINE_STATE", "AEGIS_FAKE_ENGINE_LOG"))
        if not state_path.is_absolute() or not log_path.is_absolute():
            refuse("state and log paths must be absolute")
        with log_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(argv) + "\n")
        state = read_state(state_path)
        if argv[:2] == ["image", "inspect"]:
            image_inspect(argv[2:], engine)
        elif argv[:1] == ["run"]:
            run_container(argv[1:], state, state_path, engine)
        elif argv[:1] == ["inspect"] and len(argv) == 2:
            print(json.dumps([find(state, argv[1])[1]]))
        elif argv[:2] == ["container", "inspect"] and len(argv) == 3:
            print(json.dumps([find(state, argv[2])[1]]))
        elif argv[:1] == ["exec"]:
            return exec_command(argv[1:], state)
        elif argv[:1] == ["stop"]:
            parsed, tail = options(argv[1:], set(), {"--time"})
            if len(tail) != 1 or not one(parsed, "--time").isdigit() or int(one(parsed, "--time")) < 1:
                refuse("stop requires --time SECONDS and one container")
            _, container = find(state, tail[0])
            container["State"]["Running"] = False
            write_state(state_path, state)
            print(tail[0])
        elif argv[:1] == ["rm"] and len(argv) == 2:
            name, container = find(state, argv[1])
            if container["State"]["Running"]:
                refuse("cannot remove a running container: " + name)
            del state["containers"][name]
            write_state(state_path, state)
            print(name)
        else:
            refuse("unsupported command: " + (argv[0] if argv else "<empty>"))
        return 0
    except (ValueError, KeyError, OSError) as exc:
        sys.stderr.write("fake engine: " + str(exc) + "\n")
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
