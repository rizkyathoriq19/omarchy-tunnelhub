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
import secrets_store

# The two masked prompts this helper answers, in prompt-string order. The
# index names the NetworkManager secret property so a saved value can be
# matched to the right field.
PROMPTS = ((b'Certificate password (vpn.secrets.cert-pass): ', 'cert-pass'),
           (b'Certificate password: (vpn.secrets.tls-user-key-secret): ', 'tls-user-key-secret'))


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
    prompt_key = ''
    offered = None
    consent_this_attempt = False
    deadline = time.monotonic() + timeout

    def persist(code):
        # Save only a value the user typed in this attempt, and only after
        # nmcli confirmed activation.
        nonlocal offered
        if code != 0 or offered is None or not prompt_key:
            return
        value = bytes(offered)
        extra = {"secret": prompt_key}
        if secrets_store.keyring_available():
            secrets_store.store("nm", profile, value, extra, plaintext=False)
        else:
            # The panel only sends the third field when the user chose the
            # unencrypted store, so this records the consent they gave.
            if consent_this_attempt and not secrets_store.consent_allowed():
                try:
                    secrets_store.record_consent()
                except OSError:
                    pass
            if secrets_store.consent_allowed():
                secrets_store.nm_store(profile, prompt_key, value)
        offered[:] = b'\0' * len(offered)
        offered = None

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
                        code = {0: 0, 3: 2}.get(child.wait(), 1)
                        persist(code)
                        return code
                    output.extend(chunk)
                    chunk = b''
                    while b'\n' in output:
                        _, _, rest = output.partition(b'\n')
                        output[:] = rest
                    # OpenVPN cert-pass and SSTP tls-user-key-secret share the
                    # masked certificate-password field. nmcli --ask renders
                    # "<Label> (vpn.secrets.<key>): "; under LC_ALL=C the SSTP
                    # auth dialog labels tls-user-key-secret "Certificate
                    # password:" (GNOME/network-manager-sstp auth-dialog/main.c,
                    # NM_SSTP_KEY_TLS_USER_KEY_SECRET). Pipe reads can split a
                    # prompt mid-line, and the SSTP label itself contains ": ",
                    # so a buffer that is only a strict prefix of a known
                    # prompt waits for the rest instead of tripping the
                    # fail-closed arm. Waiting stays bounded by the child poll
                    # below and the helper deadline. No other prompt is
                    # answered; add explicit mappings only when another native
                    # secret is requested and its bytes are verified.
                    prompts = tuple(prompt for prompt, _ in PROMPTS)
                    prompt = bytes(output)
                    if prompt in prompts:
                        if pending:
                            return 1
                        output.clear()
                        secret_key = PROMPTS[prompts.index(prompt)][1]
                        if not file_attempted and prompt.endswith(b'cert-pass): '):
                            file_attempted = True
                            value = ovpn_source.password(profile)
                            if value is not None:
                                try:
                                    child.stdin.write(value + b'\n')
                                    child.stdin.flush()
                                finally:
                                    value[:] = b'\0' * len(value)
                                continue
                        # A saved value answers the native prompt without a panel
                        # round-trip. Keyring first, then the consented file.
                        saved, _reason = secrets_store.lookup("nm", profile, {"secret": secret_key})
                        if saved:
                            child.stdin.write(saved + b'\n')
                            child.stdin.flush()
                            continue
                        prompt_key = secret_key
                        pending = secrets.token_hex(16)
                        os.write(sys.stdout.fileno(), ('REQUEST ' + pending + '\n').encode())
                    elif len(output) > 8192:
                        return 3
                    elif any(len(known) > len(prompt) and known.startswith(prompt) for known in prompts):
                        pass  # Partial prompt; wait for more input.
                    elif output.endswith(b': ') and not output.startswith((b'Connection ', b'Error: ')):
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
                        parts = line.split(b'\t')
                        if len(parts) not in (2, 3):
                            continue
                        ident, value = parts[0], parts[1]
                        save_this = len(parts) == 3 and parts[2] == b'1'
                        try:
                            if not pending or ident != pending.encode():
                                continue
                            if not value or len(value) > 4092 or any(c < 32 or c == 127 for c in value):
                                cancelled = True
                                return 1
                            child.stdin.write(value + b'\n')
                            child.stdin.flush()
                            if save_this and prompt_key:
                                # Keep the user-entered value only until the child exits.
                                offered = bytearray(value)
                                consent_this_attempt = True
                            done()
                        finally:
                            line[:] = b'\0' * len(line)
                            value[:] = b'\0' * len(value)
            if child.poll() is not None:
                done()
                code = {0: 0, 3: 2}.get(child.returncode, 1)
                persist(code)
                return code
        return 2  # Helper deadline, not evidence of a wrong password.
    except (OSError, KeyboardInterrupt):
        return 1
    finally:
        done()
        output[:] = b'\0' * len(output)
        response[:] = b'\0' * len(response)
        if offered is not None:
            offered[:] = b'\0' * len(offered)
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
