# Windows GUI readiness and repair boundary

The existing Windows updater does not retain a previous installer with its
original version-bound signing envelope. Therefore an already-installed 0.1.27
cannot safely acquire automatic downgrade merely by adding a watchdog. This
change prepares authenticated cached packages and finite readiness detection;
it uses explicit repair guidance while automatic installer rollback remains
unaccepted.

`windows_gui_rollback` caches the exact downloaded NSIS bytes, original base64
signature and SHA256 under a fixed per-owner recovery directory. Every cache
read re-verifies the original embedded updater key, `requireSignedVersion`,
exact signed version and content SHA256. No signature/key is replaced, no feed
floor is lowered, and no WebView-supplied path reaches the filesystem. Version
names are canonical stable semantic versions. Reparse points, foreign ownership,
non-private files, oversized inputs and overlapping updater processes are
rejected. Windows files use an explicit current-user/SYSTEM ACL, no-write/delete
sharing on reads, a locked operation file, atomic replacement and write-through.
Cached packages are limited to two known versions; cleanup removes only fixed
known filenames from the recorded obsolete version directory.

Preparation saves a durable receipt before installation. The caller saves the
latest encrypted profile and disconnects the actual core/proxy guardian, then
arms the receipt before the existing NSIS updater launch. Installation still
uses the updater's explicit `/UPDATE` and passive NSIS mode. This module does
not execute an installer, terminate a GUI, delete/import a profile or reconnect
VPN. An installer launch failure marks the receipt failed. A new GUI has a
bounded 270-second installation/readiness window and confirms that its WebView
has initialized through the shared readiness hook. Missing readiness or a return
to the predecessor produces a failed receipt and suppresses automatic connection
until the user explicitly acknowledges the repair state. Receipt IDs prevent a
stale acknowledgement clearing a later update.

When no original predecessor envelope exists, the UI explains that automatic
return is unavailable and directs the user to the signed installer for the
intended version from the official release, preserving the profile. If a prior
verified cache does exist, the receipt pins its SHA256 and original signature;
automatic downgrade still stays disabled until a native Windows installer
recovery path and cancellation/restart matrix have been accepted. This is a
partial implementation of readiness task 2.6, not a completed GUI rollback.

Local evidence: five policy/privacy/expiry/lock and signed-package tests passed using the actual module
in an isolated harness on macOS. An original locally published 0.1.26 signed NSIS
installer and the original signed 0.1.27 installer passed original-key verification,
private-cache/receipt preparation, captured predecessor pinning and tampered
payload/version/cache rejection; the profile fixture remained unchanged.
The actual Windows ACL module and tests passed Windows-target API checking and
clippy with warnings denied in the same isolated harness. These checks do not
run SCM, NSIS, a Windows WebView or physical-device recovery. Native CI and the
user's deferred Windows-PC acceptance remain separate gates.
