"""Installed, isolated Linux custody holder; imports only the standard library.

The receipt and status writer reach only this process. close_fds prevents
either from reaching the effect; setsid separates holder and effect groups.
"""
import ctypes, os, signal, subprocess, sys, time

__all__ = ["main"]


def main():
    status_fd, duration = int(sys.argv[1]), float(sys.argv[2])
    stopping = False
    def stop(*_):
        nonlocal stopping
        stopping = True
    for sig in (signal.SIGUSR1, signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, stop)
    def report(message):
        try:
            os.write(status_fd, message.encode('ascii'))
        except BrokenPipeError:
            pass  # The owner died; all descendants have already been reaped.
        finally:
            os.close(status_fd)
    def kill(pid, group=False):
        try:
            (os.killpg if group else os.kill)(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0:
        report('unsupported')
        sys.exit(125)
    try:
        if sys.argv[3] != '-1':
            for key, fd in zip(('GIT_DIR', 'GIT_WORK_TREE'), (sys.argv[3], sys.argv[5])):
                os.putenv(key, '/proc/'+str(os.getpid())+'/fd/'+str(int(fd)))
        command = sys.argv[8:]
        for index, value in enumerate(command):
            prefix = 'core.sshCommand=/proc/self/fd/'+sys.argv[7]+' '
            if sys.argv[7] != '-1' and value.startswith(prefix):
                command[index] = 'core.sshCommand=/proc/'+str(os.getpid())+'/fd/'+sys.argv[7]+' '+value[len(prefix):]
        child = subprocess.Popen(command, executable='/proc/'+str(os.getpid())+'/fd/'+sys.argv[6], close_fds=True, start_new_session=True)
    except (OSError, ValueError):
        report('spawn')
        sys.exit(125)
    try:
        os.write(status_fd, b'started\n')
    except BrokenPipeError:
        pass  # Owner death must not interrupt custody or reaping.
    deadline, code, failure, group_killed = time.monotonic()+duration, None, None, False
    while True:
        if stopping or time.monotonic() >= deadline:
            failure = failure or ('cancelled' if stopping else 'timeout')
        if failure:
            if not group_killed:
                if code is None:  # Never signal a group ID after its leader was reaped.
                    kill(child.pid, True)
                group_killed = True
            # Killing each direct child also reparents its detached children here.
            # Until waitpid reaps them these child PIDs cannot be reused.
            try:
                with open('/proc/self/task/'+str(os.getpid())+'/children') as stream:
                    children = stream.read(65536).rsplit(' ', 1)[0].split()
            except OSError:
                children = []  # Retain custody and reap; never exit over an unreadable procfs.
            for pid in children:
                kill(int(pid))
        try:
            pid, status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            break
        if pid:
            result = os.waitstatus_to_exitcode(status)
            if pid == child.pid:
                code = result
            if result != 0:
                failure = failure or 'child_failed'
        else:
            time.sleep(0.01)
    report(failure if failure in ('timeout', 'cancelled') else 'exit:'+str(code if code is not None else 125))
    # The protocol carries negative signal codes without conflating child 124/125
    # with timeout/spawn failures. The parent propagates the actual child status.
    sys.exit(0)


if __name__ == "__main__":
    main()
