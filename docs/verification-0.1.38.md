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

Fresh November RustSec checks also required rustix 1.1.6. Chrono 0.4.45 is unmaintained but absent from all three production/build target trees; its exact absence assessment remains visible. The newly reviewed picomatch advisory has no upstream patched version. A temporary exact-version review until 24 November covers only dev-only lockfile nodes in the build/test toolchain, not runtime dependencies. New advisories, versions, non-dev nodes or expiry still fail, and the findings remain visible. This is maintenance/build-tool debt, not a claim that the upstream library is fixed.

macOS ARM64 hosted jobs could not acquire a runner after repeated attempts. CI uses the documented standard Intel macOS runner for platform and privileged route tests; the Apple Silicon app and both actual ARM64 core startup matrices are built and checked locally. These scopes are recorded separately.

## Windows REALITY + XHTTP

An authenticated loopback Xray 26.11.9 sidecar transports XHTTP while sing-box retains routing, application/torrent policy and the local browser entry. Imported standard VLESS XHTTP links preserve mode/path/host/SNI/public-key/short-ID fields. Supported XHTTP modes are auto, packet-up, stream-up and stream-one. Non-empty Vision flow on XHTTP and advanced `extra` JSON are rejected explicitly, never reinterpreted as TCP. Windows jobs own both child processes; failed child readiness makes the connection unhealthy and normal stop reaps both children. The installer includes the pinned source-built audited Xray resource, metadata and MPL license.

Local public loopback fixtures passed five real transfer cases (plain XHTTP packet-up plus REALITY in all four modes) through the routing engine with an explicit VPN route and server-side access evidence. A separate native sidecar test proved unauthenticated SOCKS requests are refused. Windows installed-binary transport and forced-parent-death checks remain pending CI. Protocol fixtures use no user profile, external VPS or certificate-validation bypass.

This XHTTP integration targets Windows. The macOS system VPN keeps the existing sing-box transports; importing an XHTTP node does not silently send it as TCP, and macOS production connection/export explicitly requires the Windows XHTTP module. A dedicated test-support build runs local Mac transport fixtures without modifying system networking.
