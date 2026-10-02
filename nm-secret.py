"""Native nmcli --ask over private pipes; stdout is a secret-free panel protocol."""
import os
import re
import resource
import secrets
import selectors
import signal
import subprocess
import sys
import time
import uuid
import ovpn_source


def run(profile, command='nmcli', timeout=90):
    if str(uuid.UUID(profile)) != profile:
        return 1
    cancelled = False

    def interrupted(signum, frame):
        nonlocal cancelled
        cancelled = True
        raise KeyboardInterrupt()  # selectors treats InterruptedError as a retry.

    old_signals = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGTERM, signal.SIGHUP)}
    env = dict(os.environ, LC_ALL='C', TERM='dumb')
    child = subprocess.Popen([command, '--ask', '--colors', 'no', '--wait', '90',
                              'connection', 'up', 'uuid', profile],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, env=env, start_new_session=True)
    selector = selectors.DefaultSelector()
    output = bytearray()
    response = bytearray()
    pending = ''
    file_attempted = False
    deadline = time.monotonic() + timeout

    def done():
        nonlocal pending
        if pending:
            try:
                os.write(sys.stdout.fileno(), ('DONE ' + pending + '\n').encode())
            except OSError:
                pass
            pending = ''

    try:
        selector.register(child.stdout, selectors.EVENT_READ)
        selector.register(sys.stdin.fileno(), selectors.EVENT_READ)
        while time.monotonic() < deadline:
            for key, _ in selector.select(0.1):
                chunk = os.read(key.fd, 4096)
                if key.fileobj is child.stdout:
                    if not chunk:
                        done()
                        return {0: 0, 3: 2}.get(child.wait(), 1)
                    output.extend(chunk)
                    chunk = b''
                    # ponytail: only this native secret type; reject other prompts,
                    # add explicit mappings only when another secret is requested.
                    while b'\n' in output:
                        _, _, rest = output.partition(b'\n')
                        output[:] = rest
                    if output == b'Certificate password (vpn.secrets.cert-pass): ':
                        if pending:
                            return 1
                        output.clear()
                        if not file_attempted:
                            file_attempted = True
                            value = ovpn_source.password(profile)
                            if value is not None:
                                try:
                                    child.stdin.write(value + b'\n')
                                    child.stdin.flush()
                                finally:
                                    value[:] = b'\0' * len(value)
                                continue
                        pending = secrets.token_hex(16)
                        os.write(sys.stdout.fileno(), ('REQUEST ' + pending + '\n').encode())
                    elif output.endswith(b': ') or len(output) > 8192:
                        return 3
                else:
                    if not chunk:
                        cancelled = True
                        return 1
                    response.extend(chunk)
                    chunk = b''
                    if len(response) > 4224:
                        return 1
                    while b'\n' in response:
                        line, _, rest = response.partition(b'\n')
                        response[:] = rest
                        if line == b'CANCEL':
                            cancelled = True
                            return 1
                        ident, sep, value = line.partition(b'\t')
                        try:
                            if not pending or ident != pending.encode():
                                continue
                            if not sep or not value or len(value) > 4092 or any(c < 32 or c == 127 for c in value):
                                cancelled = True
                                return 1
                            child.stdin.write(value + b'\n')
                            child.stdin.flush()
                            done()
                        finally:
                            line[:] = b'\0' * len(line)
                            value[:] = b'\0' * len(value)
            if child.poll() is not None:
                done()
                return {0: 0, 3: 2}.get(child.returncode, 1)
        return 2  # Helper deadline, not evidence of a wrong password.
    except (OSError, KeyboardInterrupt):
        return 1
    finally:
        done()
        output[:] = b'\0' * len(output)
        response[:] = b'\0' * len(response)
        selector.close()
        # Close/reload/cancel must not leave a credential reader behind.
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait()
        child.stdin.close()
        child.stdout.close()
        if cancelled:
            # Killing the reader is not NM rollback. Request native down, then
            # let the panel's active-state poll establish the actual outcome.
            try:
                subprocess.run([command, '--wait', '5', 'connection', 'down', 'uuid', profile],
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, env=env, timeout=5)
            except (OSError, subprocess.TimeoutExpired, KeyboardInterrupt):
                pass
        for sig, previous in old_signals.items():
            signal.signal(sig, previous)


if __name__ == '__main__':
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    try:
        sys.exit(run(sys.argv[1]) if len(sys.argv) == 2 else 1)
    except (OSError, ValueError):
        # No backend output or exception text (which could contain credentials).
        sys.exit(1)
