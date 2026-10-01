# TunnelHub — Omarchy VPN Widget

## Install / remove the plugin

After the maintainer publishes the plugin source, install it with:

```bash
omarchy plugin add https://github.com/rizkyathoriq19/omarchy-tunnelhub
```

Review the source, then run `omarchy plugin enable airzy.vpn`.
TunnelHub retains the stable internal ID `airzy.vpn` to preserve existing bar
settings, profile registry, permission broker and running VPN unit identities.
For a local checkout, place this directory at
`~/.config/omarchy/plugins/airzy.vpn`, run `omarchy-shell shell rescanPlugins`, then
`omarchy plugin enable airzy.vpn`. Install the dependencies below separately;
there are no installation hooks. Keep `askpass` and `gui-bin/sudo` executable.

Disconnect and confirm native cleanup before removal, then run
`omarchy plugin remove airzy.vpn`. Removal does not delete original private profiles,
the path registry or OpenP2S authentication state; manage those separately if needed.

## Marketplace preparation

Submission requires a public GitHub repository with this manifest, README and
license at its root. The configured repository is
<https://github.com/rizkyathoriq19/omarchy-tunnelhub>; local preparation does not
mean the plugin source has been published.
After an authorized commit/publication, check ID availability and submit through
<https://github.com/omacom/omarchy-plugin-marketplace/issues/new?template=submit-plugin.yml>.
Suggested listing category: `System`; tags: `bar`, `vpn`, `quickshell`.
The owner must confirm the checklist and approve submission first. Publication
requires a fresh exact-commit baseline scan and an `approved-and-verified`
maintainer decision; local tests do not establish marketplace approval.
Source: <https://github.com/omacom/omarchy-plugin-marketplace/blob/main/SUBMISSION.md>.


TunnelHub (`airzy.vpn`) manages existing NetworkManager VPN and WireGuard
profiles through `nmcli`. It requires NetworkManager, the relevant VPN backend,
and `curl` for the public-IP display.

- Left click: open panel; right click: disconnect the shown VPN (Azure first when both are active).
- Middle click or `R`: refresh.
- Arrow keys: select a profile; Enter: connect/disconnect NetworkManager or connect/disconnect imported XML profiles.
- `I` or **Import profile…**: choose `.ovpn`, `.conf` or `.xml`.
- `D`: disconnect; Escape: close.
- Switching profiles disconnects the current NetworkManager VPN first.

## Azure VPN with OpenP2S

The panel imports OpenVPN `.ovpn` and WireGuard `.conf` through native `nmcli connection import type openvpn/wireguard file PATH` using zenity. Backend/permission failures are shown without logging profile contents. WireGuard filenames must be valid interface names followed by `.conf`. Cancellation does nothing. No other file formats are imported.

Azure `.xml` import registers only the absolute path in `$XDG_STATE_HOME/airzy.vpn/azure-profiles.json` (default `~/.local/state/airzy.vpn/azure-profiles.json`, mode 0600); it never opens, parses or copies XML. Keep the original file in place. Turning on the profile switch starts an ordinary-user OpenP2S process in the native transient user unit `airzy-vpn-azure.service`, without a terminal. The unit owns a foreground supervisor until OpenP2S exits, so the VPN survives the launching helper finishing and shell/plugin reloads. Its fixed name and OpenP2S's native connection lock prevent duplicate sessions. Starting a process is not connection success; only native status earns an active indicator.

OpenP2S 0.2.1 first attempts silent Entra token acquisition; a usable cached session skips browser sign-in. Otherwise its default loopback/PKCE flow opens your browser. Browser SSO can also avoid entering credentials. The plugin does not clear caches, log out, or force login. The OAuth client remains your normal user, never root.

For privilege requests, the plugin passes `SUDO_ASKPASS` and prepends its `gui-bin` only to the backend environment. OpenP2S 0.2.1 has no CLI/environment askpass mode; its elevator invokes `sudo -- ABSOLUTE_COMMAND ARGS`. The bridge preserves those arguments and executes `/usr/bin/sudo -A`. Its askpass helper requests a **masked system-password field inside this VPN panel**, opening/focusing the panel automatically, not a separate zenity window. Submit/Enter supplies the response; Cancel/Escape or closing the panel denies the request. The field clears immediately on submit, cancel, close, completion or timeout. Sudo alone validates passwords and owns authentication/retry rules; sudoers is unchanged. Browser OAuth still runs as your normal user. More than one prompt may be needed for tunnel, DNS and cleanup operations.

The Service's unprivileged Python broker uses a same-owner runtime Unix socket (owner-only permissions and `SO_PEERCRED` uid checks). Only the existing `profiles.py run`/`disconnect` supervisor may register a live lease; a random in-memory capability authorizes its backend's askpass requests. This capability, **not a password**, is inherited by the child environment. Passwords travel only through QML memory → broker stdin pipe → local socket → askpass's stdout pipe to sudo. They never enter command arguments, environment variables, files, logs, general shell IPC or status JSON. The plugin does not store/cache responses or manually authenticate them. Qt/Python memory cannot promise cryptographic erasure; fields and response buffers are cleared promptly, and the Python entry points disable core dumps. OS swap and other same-user processes remain outside this UI's security boundary.

One prompt is shown at a time, with a bounded FIFO of four requests; each request expires 90 seconds after arrival, including queue time. Unknown/stale request IDs and capabilities are rejected. Closing the supervisor's lease cancels its requests. Broker stdin EOF, shell exit or plugin destruction cancels pending requests; if reload retains a process, the same timeout bounds any orphan. A replacement broker cannot take over a live socket. Unavailable permissions UI fails closed, never falling back to a terminal/zenity password dialog. The VPN widget must be loaded for privileged backend actions; supervisor survival across reload still preserves the normal-user OAuth process.

The profile switch, right-click or `D` stops the owned unit even while awaiting browser sign-in. The supervisor forwards SIGTERM to OpenP2S, whose native teardown owns tunnel/DNS/credential cleanup; the user unit allows 120 seconds before bounded cgroup cleanup. A lost browser response, denied privileges or incomplete cleanup is not reported as connected. For external OpenP2S sessions, disconnect invokes the native backend with the same graphical sudo bridge. Use `D` or right-click to retry cleanup of a recovery/stale session. Native output is discarded rather than saved to the journal or leaked into QML; only fixed, sanitized errors and native exit/liveness states reach the panel. Abrupt process death or denied cleanup can still leave native recovery state; refresh and retry cleanup.

Installation and run instructions are documented here only. OpenP2S is an independent community
Linux client for Azure Point-to-Site VPN with Microsoft Entra ID authentication.
It is **not integrated with NetworkManager**: the widget polls native `openp2s status --json` independently. Only connected state earns an active indicator; unavailable/invalid probes show unknown, while stale/reconnecting/disconnecting do not claim connectivity. Only state, internal matched path, interface and tunnel address reach QML; account/gateway/DNS/routes are discarded. Native status calls the profile XML display name, not its path: rows are matched against a same-user running OpenP2S executable and connect argv (not its mutable thread name); owned-unit MainPID/supervisor argv attributes pending operations and the registered paths without reading XML. Unmatched sessions still show Azure active, but do not falsely mark a row. Hover/accessibility use basename only. Generic disconnect targets Azure first if connected or starting; each profile has its own switch when both are active. Process launch never implies connection or disconnection success. Microsoft retired its official Linux
client; this does not make Azure VPN unsupported by community clients.

### Requirements

Profile import requires Python 3 and `zenity`, plus the relevant NetworkManager
backend. Azure connect additionally requires `openp2s` on PATH, an active systemd
user manager (`systemd-run` / `systemctl --user`), the loaded VPN widget and
`/usr/bin/sudo`, and a desktop session/browser opener (`xdg-open`). Keep the plugin's
`askpass` and `gui-bin/sudo` executable. Check with `openp2s --help`.
OpenP2S requires Linux,
`systemd-resolved` (`resolvectl`) for split DNS, `sudo` for tunnel/DNS operations,
and an Entra ID-enabled Azure P2S gateway. Run it as your normal user, **not**
`sudo openp2s`: it handles privilege elevation itself.

### Fresh installation on Omarchy / Arch (manual steps only)

Upstream documents a portable **Linux amd64** bundle; its Debian package is not
an Arch installation method. Download the matching tarball and `SHA256SUMS` from
<https://github.com/wyruweso/openp2s/releases>. In a dedicated download directory,
verify the selected archive's checksum against `SHA256SUMS` before extracting.
Upstream's checksum command is `sha256sum --check SHA256SUMS`; entries for other
release artifacts will fail if those artifacts were not downloaded, so verify
your selected archive explicitly and do not ignore a mismatch.

The following are upstream's portable-bundle commands, to run manually:

```bash
tar xf openp2s-*-linux-amd64.tar.gz
cd openp2s-*-linux-amd64
./openp2s --help
```

Keep `openp2s`, the supplied `openvpn-openp2s`, and its original `BUILDINFO`
together: the client discovers that binary in-place. `BUILDINFO` records the
credential limit and patch capabilities; a binary alone is not a complete installation.
The launcher preflight checks the selected binary's `binary_sha256` against
`BUILDINFO` and requires `azure_compat_available=1` only when experimental
compatibility is enabled, before requesting a user process. It does not read XML or establish a connection.
It honors `OPENP2S_OPENVPN_BINARY` before the client's installed-path lookup.
This check targets the installed OpenP2S 0.2.1 bundle layout, not arbitrary clients.

If metadata is missing or mismatched, recover the original verified release
bundle or build output. Restore `BUILDINFO` only when its `binary_sha256` matches
both that original binary and the installed binary (`sha256sum`); release version
or `openvpn --version` alone does not prove matching patch capabilities. If that
link cannot be established, replace the complete installation from a verified
bundle manually. Never invent BUILDINFO or bypass the client's provenance guard.
A matching hash links metadata to bytes; it does not authenticate an untrusted
bundle, so verify the archive against the upstream release checksum first.

Do not substitute stock OpenVPN; Azure Entra tokens require the
bundled build's raised limits. If you want upstream's system-wide installation,
run these manually **from the extracted bundle directory**:

```bash
sudo install -D -m 0755 openp2s         /usr/local/bin/openp2s
sudo install -D -m 0755 openvpn-openp2s /usr/local/lib/openp2s/openvpn
sudo install -D -m 0644 BUILDINFO       /usr/local/lib/openp2s/BUILDINFO
```

Source: <https://github.com/wyruweso/openp2s#installation>.
These instructions do not install packages or change resolver configuration.

### Run your Azure profile

Obtain `azurevpnconfig.xml` from your administrator or Azure portal:
**VPN gateway → Point-to-site configuration → Download VPN client**.
Keep it private. The plugin stores only its path; OpenP2S reads the XML only when you explicitly launch it.

Example command (adjust the profile and CA paths for your gateway):

```bash
openp2s connect "$HOME/VPN/azurevpnconfig.xml" --ca /absolute/path/to/trusted-root.pem
```

For this manual CLI command, complete Microsoft Entra sign-in in the browser if
requested and leave the terminal open. The panel's **profile switch** needs no terminal. The CA must be appropriate for your gateway, not just an existing
file. Configure the widget's `azureCaPath` (default empty) with an absolute path
to your administrator-approved trusted root certificate. Empty or missing CA
configuration blocks connection; the plugin never enables system-store or insecure
verification fallbacks. Enable `azureExperimentalCompat` (default false) only if
your gateway requires OpenP2S's `--experimental-azure-compat` workaround.

Settings are inline on the `airzy.vpn` entry in `~/.config/omarchy/shell.json`,
under `bar.layout.left`, `center` or `right`, for example:

```json
{"id": "airzy.vpn", "azureCaPath": "/absolute/path/to/trusted-root.pem", "azureExperimentalCompat": false}
```

Both the launch action and durable supervisor read that entry independently;
settings changes apply to the next connection, not an existing session. Existing
installations moving from hardcoded settings should copy their previously working
CA path and compatibility choice into this local entry before updating. Never
include user configuration or certificates in the plugin repository.

Press **Ctrl+C** in the running terminal to disconnect, or use another terminal:

```bash
openp2s status
openp2s disconnect
```

Use **Import profile…** or `I`, then use its switch. The launcher uses your configured trusted CA and optional compatibility setting. Status is polled independently for Azure and NetworkManager; right-click/`D` disconnect the shown VPN.
Changes to this user plugin hot-reload; no shell restart is required.

### Verification

Development regression tests are maintained separately and are not shipped with
this plugin. Real compositor/sudo authentication, retry and cleanup still require
manual UAT; synthetic checks do not establish live VPN connectivity.
