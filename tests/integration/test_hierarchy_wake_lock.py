"""A woken host must be able to read its mail at once.

The mailbox writer lock fails at once when held ("mailbox writer is busy"). If the wake tool starts the
host while it still holds that lock, a host that reads its inbox before the wake process lets go gets a
busy refusal and its mail stays unread. Under load that race made
test_hierarchy_delivery.py::test_a_session_that_reads_its_mail_is_reported_as_read fail about one run
in three. The wrapper below makes the race certain: the wake process pauses right after starting the
host, as a descheduled parent would.
"""
import json
import os
import subprocess
import sys

import pytest

from tests.integration.test_hierarchy_delivery import TARGET, WAKE, Pilot


pytestmark = pytest.mark.skipif(os.name == "nt", reason="the wake tool supports POSIX process groups only")
SLOW_PARENT = r'''
import runpy, subprocess, sys, time
wake_path = sys.argv[1]
sys.argv = [wake_path] + sys.argv[2:]
real_popen = subprocess.Popen
def popen(*args, **kwargs):
    process = real_popen(*args, **kwargs)
    if kwargs.get("start_new_session"):
        time.sleep(1.5)
    return process
subprocess.Popen = popen
runpy.run_path(wake_path, run_name="__main__")
'''


# argv only: a stdin host blocks until the prompt is written, which already came after the release.
def test_a_host_that_reads_at_once_is_not_refused_by_the_wakes_own_lock(tmp_path):
    pilot = Pilot(tmp_path)
    pilot.publish()
    wrapper = tmp_path / "slow_parent.py"
    wrapper.write_text(SLOW_PARENT, encoding="utf-8")
    result = subprocess.run([sys.executable, "-I", str(wrapper), str(WAKE), "--root", str(pilot.root),
                             "--delivery-dir", str(pilot.delivery), "--endpoint", TARGET,
                             "--profile", str(pilot.profile(prompt_via="argv"))],
                            capture_output=True, text=True, timeout=60,
                            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert not result.stderr, result.stderr
    answer = json.loads(result.stdout)
    assert result.returncode == 0, answer
    assert answer["state"] == "read" and answer["read"] == ["note-1"] and answer["still_unread"] == []
    assert pilot.state()["state"] == "read"
