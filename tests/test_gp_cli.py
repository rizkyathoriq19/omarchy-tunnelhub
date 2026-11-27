import importlib.util
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

PLUGIN_DIR = pathlib.Path(__file__).resolve().parents[1]
if str(PLUGIN_DIR) not in sys.path:
    sys.path.insert(0, str(PLUGIN_DIR))

spec = importlib.util.spec_from_file_location('gp_cli', PLUGIN_DIR / 'gp_cli.py')
gp_cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gp_cli)

import permission
import profiles


class GlobalProtectCliTest(unittest.TestCase):
    def test_builds_safe_browser_command(self):
        self.assertEqual(gp_cli.connect_command('vpn.example.org'),
                         ['/usr/bin/sudo', '--', '/usr/bin/gpclient', 'connect',
                          '--browser=default', '--auto-gateway', 'vpn.example.org'])
        for invalid in ('', '-h', 'vpn.example.org;id', 'https://vpn.example.org', 'vpn.example.org\n--help'):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                gp_cli.connect_command(invalid)

    def test_pauses_on_nonzero_exit_in_tty(self):
        with mock.patch('builtins.input', side_effect=['vpn.example.org', '']) as mock_input, \
                mock.patch.object(gp_cli.subprocess, 'call', return_value=1), \
                mock.patch.object(gp_cli.sys.stdin, 'isatty', return_value=True):
            self.assertEqual(gp_cli.main(), 1)
        self.assertEqual(mock_input.call_count, 2)

    def test_does_not_pause_on_clean_exit(self):
        with mock.patch('builtins.input', side_effect=['vpn.example.org']) as mock_input, \
                mock.patch.object(gp_cli.subprocess, 'call', return_value=0), \
                mock.patch.object(gp_cli.sys.stdin, 'isatty', return_value=True):
            self.assertEqual(gp_cli.main(), 0)
        self.assertEqual(mock_input.call_count, 1)

    def test_pauses_on_invalid_portal_in_tty(self):
        with mock.patch('builtins.input', side_effect=['https://bad', '']) as mock_input, \
                mock.patch.object(gp_cli.sys.stdin, 'isatty', return_value=True):
            self.assertEqual(gp_cli.main(), 1)
        self.assertEqual(mock_input.call_count, 2)


class GlobalProtectProfileTest(unittest.TestCase):
    def test_normalize_portal_strips_scheme_and_rejects_invalid(self):
        self.assertEqual(profiles.gp_normalize_portal('https://vpn.example.org/'), 'vpn.example.org')
        self.assertEqual(profiles.gp_normalize_portal('vpn.example.org:443'), 'vpn.example.org:443')
        for bad in ('', 'https://vpn.example.org/path', 'vpn.example.org;id', '-h'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                profiles.gp_normalize_portal(bad)

    def test_register_and_remove_portal(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = pathlib.Path(tmp) / 'gp-profiles.json'
            with mock.patch.object(profiles, 'GP_STORE', store), \
                    mock.patch.object(profiles, 'gp_status', return_value={
                        'installed': True, 'known': True, 'state': 'disconnected',
                        'connected': False, 'running': False, 'stopping': False,
                        'portal': '', 'interface': '', 'address': '', 'error': '',
                    }):
                self.assertEqual(profiles.gp_register('https://vpn.example.org/'), ['vpn.example.org'])
                self.assertEqual(profiles.gp_register('vpn.example.org'), ['vpn.example.org'])
                self.assertEqual(oct(store.stat().st_mode & 0o777), '0o600')
                res = profiles.gp_remove('vpn.example.org')
                self.assertEqual(res['gp'], [])

    def test_permission_supervisor_allows_gp_actions(self):
        fake_py = os.fsencode(PLUGIN_DIR / 'profiles.py')
        for cmdline, expected in (
            (b'/usr/bin/python3\0' + fake_py + b'\0run-gp\0vpn.example.org\0', True),
            (b'/usr/bin/python3\0' + fake_py + b'\0disconnect-gp\0', True),
            (b'/usr/bin/python3\0' + fake_py + b'\0run-gp\0\0', False),
            (b'/usr/bin/python3\0' + fake_py + b'\0evil\0', False),
        ):
            with self.subTest(cmdline=cmdline), \
                    mock.patch.object(pathlib.Path, 'read_bytes', return_value=cmdline):
                self.assertEqual(permission.supervisor(12345), expected)


if __name__ == '__main__':
    unittest.main()
