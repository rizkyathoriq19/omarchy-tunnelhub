# AGENTS.md

Agent guide for this repository. `README.md` is the user manual; this file is
the contract an agent needs before changing or installing anything here.

## What this repository is

An Omarchy shell plugin for Hyprland and Quickshell. The marketplace ID is
`airzy.vpn` even though the display name is TunnelHub, and the ID must not
change: bar settings, the profile registry, the permission broker and the
systemd unit name all depend on it.

It manages three backends:

- NetworkManager VPN profiles (OpenVPN, SSTP, WireGuard).
- Azure Point-to-Site through the community `openp2s` client.
- FortiClient SSL-VPN through the FortiClient CLI.

The plugin runs unsandboxed as the logged-in user. There is no daemon. The QML
panel spawns short-lived Python helpers for every action.

## Hard rules

- Do not commit passwords, certificates, keys, gateway hostnames or personal
  profile data. Issues and pull requests are public.
- Do not add a plugin-owned credential file. A marketplace review already
  rejected plaintext credential storage once. GNOME Keyring, or NetworkManager's
  own keyfile with explicit consent, are the only accepted stores.
- Do not edit anything under `/usr/share/omarchy/`. Reading it is fine.
- Keep `manifest.json` `id` at `airzy.vpn`.
- Keep `askpass` and `gui-bin/sudo` executable.
- Do not add install hooks or run package installation from plugin code.
- Never print a secret, its length beyond the status contract, or a command line
  that contains one. Never write one to argv, environment, logs or temp files.
- Helpers that can hold a password must keep core dumps disabled.

## File map

| Path | Responsibility |
|---|---|
| `manifest.json` | Marketplace metadata, bar widget entry point, settings schema |
| `Panel.qml` | Bar icon and popup panel: rows, prompts, consent choice, Forget |
| `Service.qml` | Panel state, subprocess orchestration, polling, profile switching |
| `profiles.py` | Backend CLI. Actions print one JSON object. Import, Forti, Azure and secret logic |
| `nm-secret.py` | Bridges `nmcli --ask` to the panel over private pipes. Answers only two verified prompts |
| `secrets_store.py` | Keyring probe and storage, NetworkManager keyfile storage, consent policy |
| `permission.py` | Sudo askpass broker over a same-user Unix socket with a lease capability |
| `ovpn_source.py` | Source-`.ovpn` registry and askpass-file lookup |
| `tests/test_secret_storage.py` | Command-surface tests for the password store |
| `docs/specs/` | Design specs. Read before changing a described behavior |

## Python CLI contract

Run helpers as `/usr/bin/python3 profiles.py <action> [args]`. Every action
prints one JSON object to stdout and exits `0` on success.

Actions in use:

```text
status                    Azure state, operation state, Forti state
list                      Forti profiles and Azure registry paths
nm-types                  NetworkManager VPN UUID -> service type
details-nm <uuid>         active tunnel address and interface
delete-nm <uuid>          delete a NetworkManager profile
remove <path>             unregister an Azure XML path
launch <path>             start the OpenP2S user unit
disconnect                stop the OpenP2S unit
connect-forti <name>      connect with the stored Forti password
connect-forti-pass        connect with a password read from stdin
disconnect-forti          disconnect Forti
delete-forti <name>       remove a Forti profile and its saved password
form-forti                zenity form for a new Forti profile
clear-forti-auth          cancel a pending Forti prompt
approve-forti-cert        pin host and SHA-1 for a Forti gateway
forget-forti-cert         drop that pin
secret-status             backend, consent flag, per-profile saved map
secret-consent            record consent for NetworkManager keyfile storage
secret-clear <kind> <id>  remove a saved password (kind: forti or nm)
import                    zenity picker, then import
```

Errors print `{"error": "fixed message"}` and exit `1`. Keep messages fixed and
free of profile contents, backend diagnostics and paths the user did not choose.

## Secret handling

`secrets_store.py` probes GNOME Keyring by storing, reading and clearing a
throwaway item. `secret-tool` on PATH does not prove a usable collection, so the
probe is required.

- FortiClient passwords: Keyring only, attributes `service=airzy.vpn`,
  `kind=forti`, profile name, gateway host and username. When the probe fails,
  the password is used for one attempt and the panel reports it was not saved.
- NetworkManager passwords: Keyring first. If the probe fails, the panel offers
  NetworkManager's own keyfile once, then `nmcli connection modify` writes the
  secret with the `*-flags` property set to `0`. The value appears in that
  call's argv for its short lifetime; this is documented and accepted.
- `secret-policy.json` records only `networkManagerStorageAllowed` and a
  timestamp. Mode `0600`, state directory `0700`, atomic replace, no secrets.
- Forget removes the Keyring item, the NetworkManager keyfile copy, and restores
  the ask-every-time flag.
- `nm-secret.py` answers a prompt from the store before asking the panel. A
  typed value is saved only after `nmcli` reports activation.
- `nm-secret.py` stdin protocol: `REQUEST <id>` out, `<id>\t<value>\t<save>` in,
  `DONE <id>` out. A third field of `1` means save after success.

## Connection paths

NetworkManager. `Service.qml` starts `nm-secret.py`, which runs
`nmcli --ask --wait 90 connection up uuid <uuid>` and parses output. It answers
only `Certificate password (vpn.secrets.cert-pass): ` and
`Certificate password: (vpn.secrets.tls-user-key-secret): `. Any other prompt
fails closed with exit `3`. An OpenVPN source file's `askpass FILE` is resolved
by `ovpn_source.py` and never echoed.

FortiClient. A PTY helper drives `forticlient vpn connect NAME -p`. It answers a
`Password:` prompt with the stored password, fails closed on unknown prompts,
and surfaces untrusted-certificate warnings to the panel instead of answering
them. Approving pins host and SHA-1 in `forti-pins.json`. Connect has a
90-second deadline; disconnect restores DNS without prompting.

Azure. `launch` starts the transient user unit `airzy-vpn-azure.service`, which
runs `openp2s` as the normal user. Browser OAuth is OpenP2S's own flow. Sudo
requests run through `gui-bin/sudo` and the `permission.py` broker, which asks
inside the panel. `azureCaPath` must be an absolute existing certificate path,
read from the widget entry in `~/.config/omarchy/shell.json`.

The plugin never runs `pkexec` and never asks for the system password outside
the panel broker.

## Development loop

```bash
# local install for testing
cp Panel.qml Service.qml profiles.py nm-secret.py secrets_store.py permission.py \
   ovpn_source.py askpass manifest.json README.md AGENTS.md \
   ~/.config/omarchy/plugins/airzy.vpn/
omarchy-shell shell rescanPlugins

# QML changes need a full shell restart; a rescan alone keeps old delegates
omarchy-restart-shell

# shell logs
journalctl -t omarchy-shell --since "5 minutes ago" --no-pager

# tests, before every commit
python3 -m unittest discover -s tests -v
```

Tests must use a temporary `XDG_STATE_HOME`. Anything that touches real
NetworkManager state must create a throwaway profile and delete it in the same
run. Never modify the user's existing VPN profiles in a test.

## Environment assumptions

Required: Omarchy with Quickshell, `/usr/bin/python3`, `nmcli`, `zenity`, a
desktop session. Optional per backend: `secret-tool` with a working Keyring,
`forticlient` CLI, `openp2s`, `systemd-run`/`systemctl --user`, `curl` for the
public IP.

A box without a polkit agent is normal here. Do not replace the panel broker
with `pkexec`; it cannot prompt.

## Verification before claiming done

1. `python3 -m py_compile profiles.py nm-secret.py secrets_store.py`
2. `python3 -m unittest discover -s tests -v`
3. Install to the plugin directory and restart the shell.
4. `omarchy-shell shell ping` returns `ok`.
5. `journalctl -t omarchy-shell` shows no QML error for `airzy.vpn`.
6. Open the panel and check rows, prompts and toggles render without clipping.
7. State which parts were verified live and which were not. Secrets paths need
   a real password, so say so when it was not exercised.

## Known limitations

- `nmcli` accepts VPN secrets only as arguments, so the NetworkManager keyfile
  fallback exposes the value in argv for one short call.
- Saved NetworkManager secrets live in NetworkManager's keyfile; only root can
  read that file. The plugin reads it back through `nmcli --show-secrets`.
- NetworkManager imports do not preserve an `.ovpn` `askpass FILE` password;
  the plugin answers from the recorded source file instead.
- SSTP client certificates from enterprise gateways expire quickly. Check dates
  before debugging the tunnel.
- `omarchy plugin enable airzy.vpn` can overwrite inline widget settings such as
  `azureCaPath`. Re-apply with `omarchy bar set` if Azure asks for a CA path.
- Only OpenVPN, SSTP, WireGuard, Azure P2S and FortiClient are supported. No
  PPTP, L2TP or IKEv2 path exists.
- The threat model is same-user code. Keyring and file permissions do not stop
  a process already running as the user.
