"""Every route to a provisioned wake verifies its source before host or mailbox effects.

The controller is the trusted test checkout; the provision points at a separate pinned checkout.
Host launches and controls are small Python canaries at the actual subprocess boundary.
"""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from tests.integration.test_hierarchy_mailbox import ROOT
from tests.integration.test_hierarchy_sweep import Fleet

pytestmark = pytest.mark.skipif(os.name != "posix", reason="wake process groups require POSIX")
WAKE = ROOT / "tools" / "hierarchy_wake.py"
TARGET = "pilot/orchestrator"
HOST = '''import json, pathlib, sys
record, mode, session = sys.argv[1:4]
with open(record, 'a') as stream:
    stream.write(json.dumps(sys.argv[2:]) + '\\n')
if mode == 'control':
    print(json.dumps([{'id': 'owned', 'sessionId': session, 'status': 'busy', 'kind': 'background'}]))
else:
    sys.exit(7)
'''


def files(folder):
    return {str(path.relative_to(folder)): path.read_bytes() for path in folder.rglob('*') if path.is_file()}


@pytest.mark.parametrize('route', ['direct', 'sweep', pytest.param('loop', marks=pytest.mark.skipif(
    not sys.platform.startswith('linux'), reason='loop job runner reads Linux /proc'))])
@pytest.mark.parametrize('mode', ['print', 'background'])
def test_provisioned_wake_refuses_drift_before_host_controls_or_receipts(tmp_path, route, mode):
    if route == 'loop':
        from tests.integration.test_hierarchy_loop import World
        built = World(tmp_path)
    else:
        built = Fleet(tmp_path)
        built.init()
        built.front_door = built.add_role('pilot/front-door', cwd=str(tmp_path))
        built.orchestrator = built.add_role(TARGET, cwd=str(tmp_path))
    role = built.orchestrator
    profile_path = Path(role['wake_profile'])
    profile = json.loads(profile_path.read_text())
    host = tmp_path / 'host-canary.py'
    host.write_text(HOST)
    calls = tmp_path / 'host-canary.log'
    profile.update(argv=[sys.executable, str(host), str(calls), 'launch', role['session']], prompt_via='argv', mode=mode)
    if mode == 'background':
        profile['control'] = [sys.executable, str(host), str(calls), 'control', role['session']]
    profile_path.write_text(json.dumps(profile))
    built.send('pilot/front-door', TARGET, 'still-unread')
    before = files(built.base / 'delivery')
    marker = built.source / 'tools' / 'hierarchy_roles.py'
    marker.write_text(marker.read_text() + '\n# runtime changed after provisioning\n')

    if route == 'direct':
        ran = subprocess.run([sys.executable, '-I', '-B', str(WAKE), '--root', str(built.root), '--delivery-dir',
                              str(built.base / 'delivery'), '--endpoint', TARGET, '--profile', str(profile_path)],
                             capture_output=True, text=True, timeout=20, env=built.env())
        assert ran.returncode == 2, ran.stdout + ran.stderr
        answer = json.loads(ran.stdout)
    elif route == 'sweep':
        result = built.sweep(expect=3)
        answer = next(row for row in result['rows'] if row['endpoint'] == TARGET)
        assert answer['state'] == 'refused'
    else:
        result = built.once(expect=3)
        answer = next(row for row in result['holds'] if row.get('endpoint') == TARGET)
        assert answer['kind'] == 'refused'
        answer = {'error': answer['detail']}
    assert 'runtime source verification failed' in answer['error']
    assert not calls.exists(), 'neither host launch nor host list/stop may run after source drift'
    assert not built.launches()
    assert not list(built.root.glob('.wake-*'))
    assert files(built.base / 'delivery') == before
