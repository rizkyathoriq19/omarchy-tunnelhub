"""Interactive GlobalProtect launcher; credentials stay in the terminal/browser."""
import re
import subprocess
import sys


def connect_command(portal):
    if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?(?::[0-9]{1,5})?', portal):
        raise ValueError('Enter a portal hostname, optionally followed by :port (no URL).')
    return ['/usr/bin/sudo', '--', '/usr/bin/gpclient', 'connect',
            '--browser=default', '--auto-gateway', portal]


def _pause_before_close():
    if not sys.stdin.isatty():
        return
    try:
        input('Press Enter to close...')
    except (EOFError, KeyboardInterrupt):
        pass


def main():
    print('GlobalProtect: use Ctrl+C to disconnect. The widget does not track this tunnel.')
    try:
        portal = input('Portal hostname: ').strip()
        command = connect_command(portal)
        code = subprocess.call(command)
        print('GlobalProtect exited with status', code)
    except (EOFError, KeyboardInterrupt):
        return 1
    except (ValueError, OSError) as error:
        print(error, file=sys.stderr)
        _pause_before_close()
        return 1
    if code != 0:
        _pause_before_close()
    return code


if __name__ == '__main__':
    sys.exit(main())
