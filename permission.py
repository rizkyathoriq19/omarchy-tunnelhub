"""Ephemeral, same-owner sudo askpass relay. No credential files or logging."""
import collections
import hashlib
import resource
import os
from pathlib import Path
import secrets
import selectors
import socket
import stat
import struct
import sys
import time

TIMEOUT = 90
LIMIT = 4096
BASE = Path(__file__).resolve().parent


def endpoint():
    directory = Path(os.environ.get("XDG_RUNTIME_DIR", "/run/user/" + str(os.getuid())))
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("Unsafe runtime directory")
    return directory / "airzy.vpn-permission.sock"


def peer(sock):
    pid, uid, _ = struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    if uid != os.getuid():
        raise ValueError("Wrong owner")
    return pid


def supervisor(pid):
    # Register only the existing plugin supervisor; never an arbitrary IPC caller.
    try:
        args = Path('/proc', str(pid), 'cmdline').read_bytes().split(b'\0')
        return (args[:2] == [b'/usr/bin/python3', os.fsencode(BASE / 'profiles.py')]
                and ((len(args) == 5 and args[2] == b'run' and args[3].startswith(b'/'))
                     or (len(args) == 4 and args[2] == b'disconnect')))
    except OSError:
        return False


def requester(pid):
    try:
        return Path('/proc', str(pid), 'cmdline').read_bytes().split(b'\0') == [
            b'/usr/bin/python3', os.fsencode(BASE / 'permission.py'), b'askpass', b'']
    except OSError:
        return False


def connect():
    path = endpoint()
    info = path.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("Unsafe permission socket")
    sock = socket.socket(socket.AF_UNIX)
    sock.settimeout(TIMEOUT + 2)
    try:
        sock.connect(str(path))
        peer(sock)
        return sock
    except BaseException:
        sock.close()
        raise


class Lease:
    """A live supervisor connection authorizes its native child's askpass calls."""
    def __enter__(self):
        self.sock = connect()
        self.token = secrets.token_hex(32)
        try:
            self.sock.sendall(('LEASE ' + self.token + '\n').encode())
            if self.sock.recv(16) != b'OK\n':
                raise ValueError('VPN permission panel unavailable. Open the VPN widget and retry.')
            return self.token
        except BaseException:
            self.sock.close()
            self.token = ''
            raise

    def __exit__(self, *args):
        self.sock.close()
        self.token = ''


def askpass():
    # Sudo's prompt argv is deliberately ignored; sudo alone checks the response.
    token = os.environ.get('AIRZY_VPN_PERMISSION', '')
    if len(token) != 64 or any(c not in '0123456789abcdef' for c in token):
        return 1
    with connect() as sock:
        sock.sendall(('ASK ' + token + '\n').encode())
        response = bytearray()
        value = bytearray()
        try:
            deadline = time.monotonic() + TIMEOUT + 2
            while len(response) <= LIMIT:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return 1
                sock.settimeout(remaining)
                chunk = sock.recv(LIMIT + 1 - len(response))
                if not chunk:
                    break
                response.extend(chunk)
                chunk = b''
            if not response.startswith(b'OK ') or not response.endswith(b'\n'):
                return 1
            value = response[3:-1]
            if not value or any(c in value for c in (0, 10, 13)):
                return 1
            os.write(sys.stdout.fileno(), value + b'\n')
            return 0
        finally:
            response[:] = b'\0' * len(response)
            value[:] = b'\0' * len(value)


def serve(timeout=TIMEOUT):
    """One active prompt, bounded FIFO; stdin EOF/reload cancels everything."""
    path = endpoint()
    lock = socket.socket(socket.AF_UNIX)
    # Abstract socket is an atomic owner-lifetime lock (no lock file/stale PID).
    lock.bind('\0airzy.vpn-permission-' + hashlib.sha256(os.fsencode(path)).hexdigest())
    listener = socket.socket(socket.AF_UNIX)
    selector = selectors.DefaultSelector()
    clients = {}
    leases = {}
    pending = collections.deque()
    active = None
    input_buffer = bytearray()
    bound = False

    def emit(kind, ident):
        print(kind + ' ' + ident, flush=True)

    def close(sock):
        nonlocal active
        if sock not in clients:
            return
        token = clients[sock].get('lease')
        if token:
            leases.pop(token, None)
            for entry in list(pending):
                if entry['token'] == token:
                    finish(entry)
        selector.unregister(sock)
        clients.pop(sock)
        sock.close()

    def finish(entry, value=None):
        nonlocal active
        if entry not in pending:
            return
        pending.remove(entry)
        if active is entry:
            emit('DONE', entry['id'])
            active = None
        sock = entry['sock']
        try:
            sock.sendall(b'OK ' + value + b'\n' if value else b'CANCEL\n')
        except OSError:
            pass
        close(sock)

    try:
        if path.exists() or path.is_symlink():
            info = path.lstat()
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid():
                raise ValueError('Unsafe stale socket')
            path.unlink()
        old = os.umask(0o077)
        try:
            listener.bind(str(path))
            bound = True
        finally:
            os.umask(old)
        listener.listen(8)
        listener.setblocking(False)
        selector.register(listener, selectors.EVENT_READ)
        selector.register(sys.stdin.fileno(), selectors.EVENT_READ)
        while True:
            now = time.monotonic()
            for entry in list(pending):
                if now >= entry['until']:
                    finish(entry)
            for sock, state in list(clients.items()):
                if not state.get('lease') and not state.get('asked') and now >= state['until']:
                    close(sock)
            if active is None and pending:
                active = pending[0]
                emit('REQUEST', active['id'])
            for key, _ in selector.select(0.1):
                obj = key.fileobj
                if obj is listener:
                    sock, _ = listener.accept()
                    sock.settimeout(0.2)
                    try:
                        pid = peer(sock)
                        if len(clients) >= 12:
                            raise ValueError('Too many peers')
                        clients[sock] = {'pid': pid, 'buffer': bytearray(), 'until': now + 2}
                        selector.register(sock, selectors.EVENT_READ)
                    except (OSError, ValueError):
                        sock.close()
                elif obj == sys.stdin.fileno():
                    chunk = os.read(obj, LIMIT + 128)
                    if not chunk:
                        return
                    input_buffer.extend(chunk)
                    chunk = b''
                    if len(input_buffer) > LIMIT + 128:
                        return
                    while b'\n' in input_buffer:
                        line, _, rest = input_buffer.partition(b'\n')
                        input_buffer[:] = rest
                        ident, sep, value = line.partition(b'\t')
                        if active and ident == active['id'].encode():
                            valid = sep and 0 < len(value) <= LIMIT - 4 and not any(c in value for c in (0, 10, 13))
                            finish(active, value if valid else None)
                        line[:] = b'\0' * len(line)
                        value[:] = b'\0' * len(value)
                elif obj in clients:
                    state = clients[obj]
                    try:
                        chunk = obj.recv(128)
                        if not chunk or state.get('lease') or state.get('asked'):
                            for entry in list(pending):
                                if entry['sock'] is obj:
                                    finish(entry)
                            close(obj)
                            continue
                        state['buffer'].extend(chunk)
                        if len(state['buffer']) > 80:
                            close(obj)
                            continue
                        if b'\n' not in state['buffer']:
                            continue
                        message = bytes(state['buffer'])
                        state['buffer'].clear()
                        verb, _, token = message.removesuffix(b'\n').partition(b' ')
                        token = token.decode('ascii')
                        if len(token) != 64 or any(c not in '0123456789abcdef' for c in token):
                            close(obj)
                        elif verb == b'LEASE' and supervisor(state['pid']) and token not in leases:
                            leases[token] = obj
                            state['lease'] = token
                            obj.sendall(b'OK\n')
                        elif verb == b'ASK' and token in leases and requester(state['pid']) and len(pending) < 4:
                            state['asked'] = True
                            pending.append({'sock': obj, 'token': token, 'id': secrets.token_hex(16), 'until': now + timeout})
                        else:
                            close(obj)
                    except (OSError, UnicodeError):
                        close(obj)
    finally:
        for sock in list(clients):
            close(sock)
        input_buffer[:] = b'\0' * len(input_buffer)
        selector.close()
        listener.close()
        if bound and path.exists() and path.is_socket():
            path.unlink()
        lock.close()


if __name__ == '__main__':
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    try:
        if sys.argv[1:] == ['serve']:
            serve()
        elif sys.argv[1:] == ['askpass']:
            sys.exit(askpass())
        else:
            sys.exit(1)
    except (OSError, ValueError, IndexError):
        # Never print exceptions or backend data into the shell/journal.
        sys.exit(1)
