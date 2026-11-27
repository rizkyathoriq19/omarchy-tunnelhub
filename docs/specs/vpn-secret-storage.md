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
Forti saving fails with a warning and NetworkManager prompts on every connect,
because the plugin has no way to hand the secret to NetworkManager deliberately.
The user cannot choose NetworkManager's own keyfile, and the panel does not
explain why saving failed.

## Solution

Add one secret store shared by every profile kind. GNOME Keyring is the only
store for FortiClient passwords and the preferred store for NetworkManager
passwords. NetworkManager's own keyfile is the gated fallback for NetworkManager
profiles only. The plugin owns no password file.

1. GNOME Keyring is the preferred backend. The plugin probes it by storing,
   reading, and clearing a probe item, because `secret-tool` on PATH does not
   prove a usable default collection. If the probe passes, the plugin saves
   secrets there without asking.
2. If the probe fails for a NetworkManager profile, the panel shows one consent
   choice on the password card. The card explains that NetworkManager will keep
   the secret in its own keyfile, that only root can read it, and that a stored
   SSTP passphrase beside the encrypted key removes the benefit of that
   encryption. The user can accept, use the password once, or cancel. Consent is
   recorded so the card does not repeat.
3. If the probe fails for a FortiClient profile, the password is used for that
   attempt only and the panel reports that it was not saved. There is no
   plaintext fallback, because the plugin has no store of its own.
4. NetworkManager profiles keep NetworkManager as the store of record. The
   accepted fallback writes through `nmcli` secret properties, so
   NetworkManager owns the keyfile and removes the secret with the profile. The
   plugin removes its copy on Forget.

No backend writes a secret without either a working Keyring probe or a recorded
consent.

## User stories

1. As a user with a working Keyring, I want my SSTP private-key passphrase
   saved after the first successful connection, so that I stop retyping it.
2. As a user with a working Keyring, I want my FortiClient password saved as it
   is today, so that behavior does not regress.
3. As a user with a working Keyring, I want the plugin to detect the backend
   itself, so that I never configure a storage path.
4. As a user with a locked Keyring, I want the connect attempt to tell me the
   Keyring is unavailable, so that I know why saving fails.
5. As a user without Keyring, I want the panel to ask before NetworkManager
   stores the secret in its own keyfile, so that an on-disk copy is my decision.
6. As a user without Keyring, I want the consent card to name the store and say
   only root can read it, so that I know where the password goes.
7. As a user without Keyring, I want the consent card to explain that storing
   the SSTP passphrase next to the encrypted private key removes the benefit of
   that encryption, so that I understand what I trade away.
8. As a user without Keyring, I want a use-once option, so that I can connect
   without creating any stored copy.
9. As a user who previously consented, I want the stored secret used without a
   new prompt, so that connections stay one click.
10. As a user who changes their mind, I want a Forget saved password action for
    each profile, so that I can remove the stored value.
11. As a user who deletes a profile, I want its stored secret removed in the
    same action, so that no orphaned password stays behind.
12. As a user who deletes a FortiClient profile outside the plugin, I want the
    next refresh to stop claiming a saved password exists, so that the panel
    shows the truth.
13. As a user with several NetworkManager profiles, I want each saved secret
    keyed by profile UUID, so that two profiles of the same kind cannot mix
    their passwords.
14. As a user who imports or creates a profile, I want existing Keyring entries
    for that identifier cleared, so that a reused name cannot inherit a stale
    password.
15. As a user whose saved password stops working, I want the connect failure to
    clear the saved value only after the backend rejects it, so that a network
    outage does not delete a correct password.
16. As a user who edits a profile's certificate password, I want the new value
    to replace the old one in the same store, so that a single action leaves no
    mixture.
17. As a user on a machine where `secret-tool` is installed but the collection
    is locked, I want a clear unavailable state rather than a silent miss, so
    that the consent card explains the real cause.
18. As a user who declines the consent choice, I want the connection attempt to
    continue with a one-use password, so that no stored copy is created.
19. As a user who closes the panel while the consent choice is open, I want the
    pending connect attempt cancelled, so that no background prompt survives.
20. As an operator reviewing the plugin, I want secrets kept out of argv,
    environment, journal logs, and status JSON, so that process listings and
    logs cannot leak them.
21. As an operator reviewing the plugin, I want the consent decision stored as
    a plain boolean with no secret material, so that the policy file can be
    inspected without exposing anything.
22. As an operator, I want the policy file protected by owner-only permissions
    and atomic replacement, so that a crash cannot leave a partially written
    file.
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
removal, and avoids a plugin-owned password file. The consent card says the
keyfile is readable only by root.

**FortiClient has no fallback store.** When the Keyring probe fails, the typed
password reaches the FortiClient helper through the existing private stdin pipe
and is used for that attempt only. The panel reports that it was not saved.
No plugin-owned credential file exists.

**Consent is one recorded boolean.** A separate policy file records that the
user accepted NetworkManager's own keyfile, with the time it was accepted. The
file contains no secret and no profile identifier. The consent choice appears
only for a NetworkManager password request when the Keyring probe failed and no
consent is recorded. Declining keeps the password for one attempt.

**The panel owns the consent choice.** The card reuses the existing prompt card
layout and focus handling. It names NetworkManager's keyfile, states that only
root can read it, and states the encryption warning for SSTP. A single toggle
plus Submit covers accept and use-once. Escape cancels. Closing the panel
cancels through the same path as the existing auth prompt.

**Use-once responses are not stored.** The existing masked field already
carries a response through a private pipe. The use-once choice keeps that
behavior and skips the store call. The response buffer is cleared as it is
today.

**Failed-credential cleanup is evidence-based.** A saved secret is cleared only
when the backend reports an authentication rejection, matching the current
Forti reason handling. Timeouts and transport failures leave the saved value in
place.

**Deletion and replacement clear every store.** Deleting a profile clears the
Keyring entry and the NetworkManager keyfile copy before the native delete runs,
following the current Forti rule that keeps the profile when the secret cannot
be cleared. Reimporting or recreating a profile clears entries for the same
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
4. A FortiClient store without Keyring fails with `keyring-unavailable` and
   writes no password file anywhere under the state directory.
5. The consent action records `networkManagerStorageAllowed` with mode `0600`
   and no secret material.
6. A symlinked policy file is refused.
7. Status output contains no secret.
8. A NetworkManager profile store call changes the secret flag to `0` and the
   secret reads back through `nmcli --show-secrets` on a throwaway profile.
9. A NetworkManager clear restores the ask-every-time flag and empties the
   secret.
10. A stale saved value is not cleared after a timeout result.

Panel behavior to verify by hand on this machine, since no QML test harness
exists:

1. HIRO-GW connects without a prompt after the first saved passphrase.
2. The consent choice appears with Keyring made unavailable, names
   NetworkManager's keyfile, and keeps a one-use password when left off.
3. The panel marks profiles that have a saved password.
4. Forget removes the Keyring entry and the NetworkManager keyfile copy, and the
   next connect prompts again.

Every test that writes real state uses a throwaway profile and removes it in the
same run. The machine's existing HIRO-GW profile is not modified by tests.

## Out of scope

- Microsoft Entra tokens for Azure Point-to-Site. OpenP2S owns that cache, and
  the plugin never reads it.
- The sudo password used by the askpass broker.
- Storing usernames, gateway addresses, or certificate contents.
- Synchronizing saved secrets between machines.
- A plugin-owned password file, encrypted or not. The plugin has none.
- Migrating an existing NetworkManager keyfile secret into Keyring.
- Any change to profile import formats or to the Forti certificate pinning
  rules.

## Further notes

The test machine used for this spec has a working GNOME Keyring, so the Keyring
backend can be verified directly. The SSTP profile there is HIRO-GW, a
system-wide NetworkManager connection with
`tls-user-key-secret-flags = 2`. Its private key is encrypted with the
passphrase in question, which is why the consent card must state that a stored
passphrase beside the key cancels the key's encryption.

The plugin already treats `secret-tool` failures as a warning rather than a
hard error during Forti connect. That warning is the FortiClient behavior when
the Keyring probe fails; no fallback store replaces it.
