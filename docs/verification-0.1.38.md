# foxVPN 0.1.38 — Windows proxy route verification

## Confirmed source defects

The managed Windows proxy previously retained the previous proxy bypass list. A wildcard or site exception could send browser requests directly while the proxy address, guardian and local VPN core all appeared healthy. Read-only status did not inspect this bypass list. Separately, runtime readiness did not recheck Windows proxy settings after initial acquisition, so another program could change them while foxVPN continued to show connected.

These are reproducible source defects, not a confirmed diagnosis of the user's physical Windows PC. Its installed version, effective settings and failing destination have not been collected in this session.

## Changes

During the consented managed proxy lease, only loopback bypasses are installed. LAN and site routing decisions remain inside the core, respecting explicit foxVPN rules. The complete previous bypass/PAC/server/flags configuration is still journalled and restored on normal stop or parent death. Concurrent external changes remain preserved. A broad or unrecognised bypass makes diagnostics unconfirmed.

Managed Windows runtime checks proxy readiness during normal UI polling. Changed or unreadable settings return an unconfirmed state and an actionable error without silently overwriting external changes. Fixing the setting can restore readiness on the next poll. Explicit local-proxy-only mode retains its intended scope.

## Validation

Local workspace tests: 234 passed; UI: 128 passed; Clippy passed before the dependency overlay upgrade. Final native Windows CI, Chrome regression, updated-core matrices, installer, signed update and release acceptance remain pending. Regression fixtures cover wildcard/site bypass rejection, replacement for the managed lease, complete recovery, and the visible bypass warning. No user's Windows settings or Mac connection were modified during development.

## Limits

Windows remains an HTTP/SOCKS proxy for compatible apps. Applications ignoring system proxy settings and browser extensions can choose another path. This change does not implement Windows TUN/WFP or a system Kill Switch. Smart mode and explicit direct rules intentionally produce direct traffic. The physical Windows PC still requires an end-to-end check with its installed browser and profile.

Core 1.14.3-foxVPN.6 upgrades Go to 1.26.11, Brotli to 1.2.7, compress to 1.20.2 and x/crypto to 0.59.0 after a fresh audit rejected the former versions. The former OpenPGP wildcard exception is removed from the release gate.
