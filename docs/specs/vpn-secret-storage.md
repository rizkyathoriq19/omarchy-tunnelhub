# VPN secret storage

Status: draft for review

## Problem statement

TunnelHub can save one kind of secret today. A FortiClient profile saves its
VPN password in GNOME Keyring through `secret-tool`. Every other kind asks the
user again on each connection.

The NetworkManager path covers OpenVPN `cert-pass` and SSTP
`tls-user-key-secret`, and both run through `nmcli --ask`. Nothing stores the
answer. That is why the HIRO-GW SSTP profile, whose
`tls-user-key-secret-flags` is `2`, prompts on every connect even though GNOME
Keyring works on the machine.

The same profile also shows the second gap. When Keyring is missing or locked,
Forti saving fails with a warning and there is no alternative. The plugin
silently has nowhere to put the password, and the user has no way to accept a
weaker store.

## Solution

Add one secret store shared by every profile kind, with two backends and an
explicit consent gate.

1. GNOME Keyring is the preferred backend. The plugin probes it by storing,
   reading, and clearing a probe item, because `secret-tool` on PATH does not
   prove a usable default collection. If the probe passes, the plugin saves
   secrets there without asking.
2. If the probe fails, the panel shows a consent card. The card names the
   exact store, the path, and the risk, then offers three choices: store
   unencrypted, use this password for this attempt only, or cancel. The plugin
   records consent so the card does not repeat on every connect, and a Forget
   saved password action revokes both the consent and the stored value.
3. NetworkManager profiles keep NetworkManager as the store of record. The
   plaintext fallback for those profiles writes through `nmcli` secret
   properties, so NetworkManager owns the file and the plugin removes its own
   copy on delete. FortiClient profiles use a plugin-owned JSON file, because
   FortiClient has no NetworkManager entry.

No backend ever writes a secret without either a working Keyring probe or a
recorded consent.

## User stories

1. As a user with a working Keyring, I want my SSTP private-key passphrase
   saved after the first successful connection, so that I stop retyping it.
2. As a user with a working Keyring, I want my FortiClient password saved as it
   is today, so that behavior does not regress.
3. As a user with a working Keyring, I want the plugin to detect the backend
   itself, so that I never configure a storage path.
4. As a user with a locked Keyring, I want the connect attempt to tell me the
   Keyring is unavailable, so that I know why saving fails.
5. As a user without Keyring, I want the panel to ask before storing an
   unencrypted secret, so that a file on disk is my decision, not a default.
6. As a user without Keyring, I want the consent card to name the file path,
   so that I can inspect or delete it later.
7. As a user without Keyring, I want the consent card to explain that storing
   the SSTP passphrase next to the encrypted private key removes the benefit of
   that encryption, so that I understand what I trade away.
8. As a user without Keyring, I want a use-once option, so that I can connect
   without creating any stored copy.
9. As a user who previously consented, I want the stored secret used without a
   new prompt, so that connections stay one click.
10. As a user who changes their mind, I want a Forget saved password action for
    each profile, so that I can remove the stored value and the consent.
11. As a user who deletes a profile, I want its stored secret removed in the
    same action, so that no orphaned password stays behind.
12. As a user who deletes a FortiClient profile outside the plugin, I want the
    next refresh to stop claiming a saved password exists, so that the panel
    shows the truth.
13. As a user with several NetworkManager profiles, I want each saved secret
    keyed by profile UUID, so that two profiles of the same kind cannot mix
    their passwords.
14. As a user who imports or creates a profile, I want existing Keyring or file
    entries for that identifier cleared, so that a reused name cannot inherit a
    stale password.
15. As a user whose saved password stops working, I want the connect failure to
    clear the saved value only after the backend rejects it, so that a network
    outage does not delete a correct password.
16. As a user who edits a profile's certificate password, I want the new value
    to replace the old one in the same store, so that a single action leaves no
    mixture.
17. As a user on a machine where `secret-tool` is installed but the collection
    is locked, I want a clear unavailable state rather than a silent miss, so
    that the consent card explains the real cause.
18. As a user who cancels the consent card, I want the connection attempt to
    stop, so that nothing connects with an empty password.
19. As a user who closes the panel while the consent card is open, I want the
    pending connect attempt cancelled, so that no background prompt survives.
20. As an operator reviewing the plugin, I want secrets kept out of argv,
    environment, journal logs, and status JSON, so that process listings and
    logs cannot leak them.
21. As an operator reviewing the plugin, I want the consent decision stored as
    a plain boolean with no secret material, so that the policy file can be
    inspected without exposing anything.
22. As an operator, I want normal file permissions and atomic replacement on
    the fallback file, so that a crash cannot leave a partially written store.
23. As a user of an OpenVPN profile with an `askpass` file, I want the existing
    file-based path to keep working unchanged, so that no new prompt appears
    where a source file already answers.
24. As a user of an unencrypted private key, I want the plugin to ask for
    nothing, so that no consent card appears without a real secret request.
25. As a user connecting a NetworkManager profile while another VPN is active,
    I want the existing switch and disconnect behavior unchanged, so that
    secret storage does not alter connection order.
26. As a maintainer, I want a single function pair for lookup and store, so
    that adding a fourth profile kind does not duplicate Keyring code.
27. As a maintainer, I want the backend choice visible in the credential status
    action, so that support questions can be answered from one command.
28. As a user, I want the panel to show which profiles have a saved password,
    so that I can tell saved from always-prompt without connecting.

## Implementation decisions

**One secret store module surface.** `profiles.py` gains a backend-neutral API
with four operations: detect, lookup, store, clear. Each operation takes a
profile kind and an identifier. The kind is `forti` or `nm`. The identifier is
the Forti profile name for FortiClient and the profile UUID for
NetworkManager. Existing Forti-specific functions become thin callers of this
API, so the Keyring attribute layout moves into one place.

**Detection is a probe, not a path check.** Detection runs a store, lookup, and
clear of a unique probe item with the same attributes a real save would use.
Binary presence alone reports available when the default collection is locked
or absent, which is the failure this feature exists to explain. Probe failures
return a reason: `keyring-unavailable` for a missing tool, a locked collection,
or a failed write, and `no-credential` for a clean miss.

**Keyring attributes identify the secret precisely.** Attributes carry
`service=airzy.vpn`, `kind=<forti|nm>`, and the profile identifier. For
NetworkManager the identifier is the UUID. For FortiClient the identity keeps
the existing profile name, host, and username attributes, because a Forti
profile rename can otherwise match the wrong entry.

**Fallback for NetworkManager profiles is NetworkManager's own store.**
NetworkManager already persists VPN secrets in its keyfile when the matching
secret flag is `0`. For SSTP the property is `tls-user-key-secret-flags`. For
OpenVPN it is `cert-pass-flags`. Storing through `nmcli connection modify`
requires user rights on the profile, which the plugin already exercises for
`cert-pass-flags`. This keeps NetworkManager as the owner, survives plugin
removal, and avoids a second plaintext file. The panel reports the profile's
system keyfile as the location, since the plugin cannot read that path without
root.

**Fallback for FortiClient is a plugin-owned file.** The file lives beside the
existing state files under `$XDG_STATE_HOME/airzy.vpn/`, is created with mode
`0600`, and is replaced atomically through a temporary file in the same
directory. The content is a JSON object keyed by profile identity, and each
value is the secret. No other profile data is copied there.

**Consent is one recorded boolean.** A separate policy file records that the
user accepted an unencrypted store, with the time it was accepted. The file
contains no secret and no profile identifier. The consent card appears only
when a real secret request exists, the Keyring probe failed, and no consent is
recorded. Cancelling records nothing and fails the connection attempt.

**The panel owns the consent card.** The card reuses the existing prompt card
layout and focus handling. It shows the backend name, the destination path, and
the encryption warning for SSTP. Buttons are Store unencrypted, This attempt
only, and Cancel. Escape cancels. Closing the panel cancels through the same
path as the existing auth prompt.

**Use-once responses are not stored.** The existing masked field already
carries a response through a private pipe. The use-once choice keeps that
behavior and skips the store call. The response buffer is cleared as it is
today.

**Failed-credential cleanup is evidence-based.** A saved secret is cleared only
when the backend reports an authentication rejection, matching the current
Forti reason handling. Timeouts and transport failures leave the saved value in
place.

**Deletion and replacement clear both stores.** Deleting a profile clears the
Keyring entry and the fallback entry before the native delete runs, following
the current Forti rule that keeps the profile when the secret cannot be
cleared. Reimporting or recreating a profile clears entries for the same
identifier first. NetworkManager profile deletion already removes its own
secrets with the profile.

**Status output is secret-free.** The credential status action returns the
backend name, a saved boolean, the secret length, and a reason string. It never
returns the secret. The panel uses it to mark profiles that have a saved
password and to decide whether the consent card is needed.

**The broker and lease path is unchanged.** Saved secrets are read by the
plugin process before the connection starts. They do not travel through the
sudo askpass broker, do not enter the lease, and do not alter the permission
card behavior.

**Known limitation to document.** `nmcli` accepts VPN secrets only as command
arguments, so the fallback write for NetworkManager profiles exposes the secret
in that process's argv for the duration of one short call. The Keyring backend
has no such exposure. The README must state this, and the consent card must
name it before the user accepts.

## Testing decisions

Tests target the command surface, not internal functions. Each test invokes
`profiles.py` as a subprocess and reads its JSON, matching how the panel drives
the backend. This is the same approach the existing import and status actions
use.

Backend behavior to test with a temporary `XDG_STATE_HOME` and unique probe
identifiers:

1. Detection reports the working Keyring on a machine where `secret-tool`
   store, lookup, and clear succeed.
2. Detection reports unavailable when `secret-tool` is absent, simulated with a
   `PATH` that resolves `nmcli` but not `secret-tool`.
3. Store and lookup round-trip through Keyring, and clear removes the entry.
4. Store without Keyring and without consent fails with the consent reason and
   writes no file.
5. Store without Keyring after consent writes a file with mode `0600`, and
   lookup returns the same value.
6. File content is valid JSON with no profile metadata beyond the identity key.
7. Replacing a stored value leaves one entry, not two.
8. Clear removes the file entry and an empty file, or an empty object, does not
   break lookup.
9. A missing file is a clean miss, not an error.
10. A corrupt file reports a fixed error and no secret.
11. A NetworkManager profile store call changes the secret flag to `0` and the
    secret reads back through `nmcli --show-secrets` on a throwaway profile.
12. A stale saved value is not cleared after a timeout result.

Panel behavior to verify by hand on this machine, since no QML test harness
exists:

1. HIRO-GW connects without a prompt after the first saved passphrase.
2. The consent card appears with Keyring made unavailable, names the path, and
   cancels the attempt when Cancel is pressed.
3. The panel marks profiles that have a saved password.
4. Forget saved password removes the Keyring entry or file entry, and the next
   connect prompts again.

Every test that writes real state uses a throwaway profile and removes it in the
same run. The machine's existing HIRO-GW profile is not modified by tests.

## Out of scope

- Microsoft Entra tokens for Azure Point-to-Site. OpenP2S owns that cache, and
  the plugin never reads it.
- The sudo password used by the askpass broker.
- Storing usernames, gateway addresses, or certificate contents.
- Synchronizing saved secrets between machines.
- Encryption of the plugin-owned file beyond file permissions. The Keyring path
  provides encryption; the fallback does not.
- Migrating an existing NetworkManager keyfile secret into Keyring.
- Any change to profile import formats or to the Forti certificate pinning
  rules.

## Further notes

The test machine used for this spec has a working GNOME Keyring, so the Keyring
backend can be verified directly. The SSTP profile there is HIRO-GW, a
system-wide NetworkManager connection with
`tls-user-key-secret-flags = 2`. Its private key is encrypted with the
passphrase in question, which is why the consent card must state that a
plaintext copy beside the key cancels the key's encryption.

The plugin already treats `secret-tool` failures as a warning rather than a
hard error during Forti connect. The consent card replaces that dead end, but
the warning text should be reused for the case where the user declines.
