"""python3 test_status.py — mocked probes only, no network mutations."""
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import profiles as p

with patch.object(p, 'require', return_value='/mock/openp2s'), patch.object(Path, 'iterdir', return_value=[]), patch.object(p, 'load', return_value=[]), patch.object(p.subprocess, 'run') as run:
    for state in ['connected', 'disconnected', 'disconnecting', 'reconnecting', 'stale']:
        run.return_value = SimpleNamespace(returncode=0 if state == 'connected' else 1, stdout=json.dumps(dict(state=state, connected=state == 'connected', interface='tun0', address='10.1.2.3/24', profile='DO NOT DISPLAY', account='SECRET', gateway='SECRET')))
        s = p.status()
        assert s['state'] == state and s['connected'] == (state == 'connected')
        assert s['address'] == ('10.1.2.3' if state == 'connected' else '')
        assert 'SECRET' not in json.dumps(s) and 'DO NOT DISPLAY' not in json.dumps(s)
        assert run.call_args.args[0] == ['/mock/openp2s', 'status', '--json']
    for raw, code in [('not json SECRET', 1), ('{}', 0), ('null', 0), ('{"state":"connected","connected":false}', 0), ('{"state":"connected","connected":true}', 1)]:
        run.return_value = SimpleNamespace(returncode=code, stdout=raw)
        assert p.status()['state'] == 'unknown'
    run.side_effect = subprocess.TimeoutExpired('mock', 5)
    assert p.status()['state'] == 'unknown'
with patch.object(p, 'require', side_effect=ValueError('missing')):
    assert p.status()['state'] == 'unknown'
with patch.object(p, 'control'), patch.object(p, 'operation_status', return_value={'running': False, 'stopping': False}), patch.object(p, 'status', side_effect=[{'state': 'connected'}, {'state': 'disconnected'}]), patch.object(p, 'require', return_value='/mock/openp2s'), patch.object(p, 'supervise', return_value=0) as spawn:
    p.disconnect()
    assert spawn.call_args.args[0] == ['/mock/openp2s', 'disconnect']
# Match path metadata only; native profile display name cannot identify XML.
import os
fake = SimpleNamespace(name='123', stat=lambda: SimpleNamespace(st_uid=os.getuid()),
    joinpath=lambda name: SimpleNamespace(resolve=lambda: Path("/mock/openp2s"), read_text=lambda: 'MainThread\n', read_bytes=lambda: b'/mock/openp2s\x00connect\x00/mock/profile.xml\x00'))
with patch.object(p, 'require', return_value='/mock/openp2s'), patch.object(p, 'load', return_value=['/mock/profile.xml']), patch.object(Path, 'iterdir', return_value=[fake]), patch.object(p.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout='{"state":"connected","connected":true,"interface":"tun0","address":"10.1.2.3"}')):
    assert p.status()['path'] == '/mock/profile.xml'
    with patch.object(p, 'load', return_value=['/different/profile.xml']):
        assert p.status()['path'] == ''
with patch.object(p, 'operation_status', return_value={'running': False, 'stopping': False}), patch.object(p, 'status', return_value={'state': 'unknown'}), patch.object(p, 'supervise') as spawn:
    try:
        p.disconnect()
        assert False
    except ValueError:
        pass
    spawn.assert_not_called()
base = Path(__file__).parent
panel = (base / 'Panel.qml').read_text()
service = (base / 'Service.qml').read_text()
assert panel.index('model: vpn.profiles') < panel.index('model: vpn.azureProfiles') < panel.index('text: vpn.importing ?')
assert 'ToolTip.text: modelData.split("/").pop()' in panel
assert 'Accessible.name: modelData.split("/").pop()' in panel
assert 'status not tracked' not in panel
for branded in ['Connect Azure', 'Cancel Azure', 'Azure VPN active', 'NetworkManager VPN active', 'Enter connect NM / Azure', 'Azure connection requested']:
    assert branded not in panel + service + (base / 'profiles.py').read_text()
assert 'VPN Connected' in service and 'VPN Disconnected' in service
assert 'Accessible.name: modelData.name.split("/").pop()' in panel
assert panel.count('ToggleSwitch {') == 2
assert 'onCheckedChanged' not in panel and 'MouseArea {' not in panel
assert 'vpn.rowAction(' not in panel
assert 'text: "Disconnect' not in panel
assert 'checked: vpn.nmProfile === modelData.name' in panel
assert 'checked: vpn.azure.connected && vpn.azure.path === modelData' in panel
assert 'readonly property bool active: azure.connected || nmProfile !== ""' in service
assert 'readonly property string tunnelIp: azure.connected ? azure.address : nmTunnelIp' in service
assert 'readonly property string interfaceName: azure.connected ? azure.interface : nmInterface' in service
assert 'if (nmProfile === name) {\n      disconnectNm()' in service
# Exact owned supervisor path, wrong owner/path rejection; no XML reads.
argv = b'/usr/bin/python3\x00' + str(Path(p.__file__).resolve()).encode() + b'\x00run\x00/mock/profile.xml\x00'
proc = SimpleNamespace(stat=lambda: SimpleNamespace(st_uid=os.getuid()), joinpath=lambda name: SimpleNamespace(read_bytes=lambda: argv))
with patch.object(p, 'load', return_value=['/mock/profile.xml']), patch.object(Path, '__truediv__', return_value=proc):
    assert p.supervisor_path('123') == '/mock/profile.xml'
    with patch.object(p, 'load', return_value=['/other.xml']):
        assert p.supervisor_path('123') == ''
    proc.stat = lambda: SimpleNamespace(st_uid=os.getuid() + 1)
    assert p.supervisor_path('123') == ''
# A second unrelated native client must not be attributed to the registered row.
other = SimpleNamespace(name='124', stat=lambda: SimpleNamespace(st_uid=os.getuid()),
    joinpath=lambda name: SimpleNamespace(resolve=lambda: Path('/mock/openp2s'), read_bytes=lambda: b'/mock/openp2s\x00connect\x00/unregistered.xml\x00'))
with patch.object(p, 'require', return_value='/mock/openp2s'), patch.object(p, 'load', return_value=['/mock/profile.xml']), patch.object(Path, 'iterdir', return_value=[fake, other]), patch.object(p.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout='{"state":"connected","connected":true}')):
    assert p.status()['path'] == ''
print('PASS: native schema/exit codes/liveness states, redaction, malformed/missing/timeout probes, mocked disconnect routing, UI ordering and hover/accessibility regression')
