"""Paths only in state; read OpenVPN askpass locally only on a cert-pass request."""
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import uuid

STORE = Path(os.environ.get('XDG_STATE_HOME', str(Path.home() / '.local/state'))) / 'airzy.vpn/openvpn-sources.json'


def valid_uuid(value):
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value
    except ValueError:
        return False


def load():
    if not STORE.exists():
        return {}
    data = json.loads(STORE.read_text())
    if not isinstance(data, dict) or any(not valid_uuid(k) or not isinstance(v, str) or not v.startswith('/') or any(c in v for c in '\0\r\n') or Path(v).suffix.lower() != '.ovpn' for k, v in data.items()):
        raise ValueError('Invalid OpenVPN source registry; reimport the profile after restoring the registry.')
    return data


def save(data):
    STORE.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temp = tempfile.mkstemp(dir=STORE.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(data, stream)
        os.replace(temp, STORE)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def option_tokens(line):
    """OpenVPN parse_line rules: comments/quotes start only between tokens."""
    tokens = []
    while line:
        line = line.lstrip()
        if not line or line[0] in '#;':
            break
        if line[0] == "'":
            match = re.match(r"'([^']*)'", line)
        elif line[0] == '"':
            match = re.match(r'"((?:\\[\\"\s]|[^"\\])*)"', line)
        else:
            match = re.match(r'((?:\\[\\"\s]|[^\s\\])+)', line)
        if not match:
            raise ValueError('Invalid OpenVPN option syntax.')
        token = match[1]
        if line[0] != "'":
            token = re.sub(r'\\([\\"\s])', r'\1', token)
        tokens.append(token)
        line = line[match.end():]
    return tokens


def password(profile):
    """Return a bounded first line, or None for the normal masked prompt."""
    try:
        source = load().get(profile)
        if source is None:
            return None
        # Bound total input and each line; never parse inline certificate/key data.
        fd = os.open(source, os.O_RDONLY | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                return None
            raw = stream.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            return None
        block = None
        askpass = None
        for line in raw.decode('utf-8').splitlines():
            stripped = line.strip()
            if block:
                if stripped.startswith('</' + block + '>'):
                    block = None
                continue
            tokens = option_tokens(stripped)
            if not tokens:
                continue
            match = re.fullmatch(r'<([A-Za-z0-9_-]+)>', tokens[0])
            if match and len(tokens) == 1:
                block = match[1]
                continue
            if tokens[0] not in ('askpass', '--askpass'):
                continue
            if len(tokens) != 2:
                return None
            askpass = tokens[1]
        if block or not askpass:
            return None
        path = Path(askpass)
        if not path.is_absolute():
            path = Path(source).parent / path
        # Refuse devices/FIFOs before opening so an unreadable source cannot hang.
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                return None
            value = bytearray(stream.readline(4095).removesuffix(b'\n').removesuffix(b'\r'))
        if not value or len(value) > 4092 or any(c < 32 or c == 127 for c in value):
            return None
        return value
    except (OSError, ValueError, UnicodeError):
        return None
