# foxVPN 0.1.37 — prevention and diagnostic scope

## Changes

- The macOS helper observes the application ownership channel, including peer closure while a lookup is pending. An internal channel fault becomes unready and is recovered under the existing restore/backoff policy without rotating the selected server. Unknown owners still fail closed.
- A bounded owner-scoped root-owned history records typed lifecycle/failure events. Stop does not erase the prior failure. No server identities, URLs, credentials or raw traffic are persisted in this history. Storage failures do not stop the VPN and are visible in diagnostics.
- System VPN readiness requires the OS IPv4 route through utun99 as well as HTTPS and DNS. Startup errors distinguish local-proxy HTTPS from system-tunnel HTTPS and ownership-channel failure.
- Explicit checks inspect both small HTTPS endpoints. A partial endpoint failure is shown separately and does not automatically restart a working connection. A critical route/DNS/core failure takes precedence over the partial-site notice.
- Local-proxy checks identify their scope and do not require a macOS system helper or claim whole-device protection. The reported core version is read from the packaged manifest.

## Physical laptop evidence, 2 November 2026

The installed app/helper are still 0.1.36 during this check. An earlier attempt failed the generic HTTPS startup check and was stopped; the old implementation did not retain sufficient evidence to identify its failing stage. A later start on the same current network succeeded. Without an explicit proxy, gstatic, Cloudflare and YouTube returned 204; external egress matched the user's VPS; helper reported utun99, active DNS and Kill Switch. Redundant Hiddify system proxy flags were disabled only after this confirmation. These observations do not establish the cause of the earlier failed attempt, nor validate 0.1.37 on the physical laptop.

## Release acceptance

Local checks passed: 232 Rust tests (231 workspace tests plus the additional startup-channel regression), 127 UI tests, TypeScript/Vite build, Clippy with warnings denied, 11 dependency-policy and 19 Go-policy regressions. Both freshly built macOS cores passed the Go advisory gate, including the mandatory process broker race tests. Native macOS privileged app/torrent routing and runtime matrix CI passed (41412441205); Windows installer, installed core, local AI and proxy tests passed (41412441151); reciprocal backups passed (41412441158); Windows service IPC fixture passed (41412601016). Final source: ca135d25213c70867ad306c78a6e407fa1afacbb. UI CI 41411947143 and advisory CI 41411947104 passed on 2baf650; later commits only correct helper startup classification and the macOS-only module boundary, with no dependency/UI changes.

Each packaged Mac core passed 72 runtime scenarios. Packaged Mac local AI passed six cases and rejection/cleanup checks. Sealed Mac update installation/tamper, signed component preparation and Windows signed-cache/version-tamper checks passed. Release v0.1.37 is published with 15 assets; every remote asset size and SHA256 matched local files before and after publication. Both feeds are updated only after publication.

Physical acceptance of 0.1.37 remains pending. The laptop keeps the verified working 0.1.36 connection; no new build or helper was installed during this release. This distinction avoids claiming CI results as physical acceptance.

Windows remains a local HTTP/SOCKS proxy. System TUN/WFP and complete application isolation on Windows are not provided. The added route check verifies a fixed generic IPv4 route; it is not a comprehensive IPv6/leak certification.
