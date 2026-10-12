# Windows service boundary, protocol 1

This change is a **non-networking experimental service transport**. It does not
close readiness tasks 4.2, 4.3 or 4.4 and is not bundled/enabled by the NSIS
installer. Windows still provides the existing local/system proxy scope.

The LocalSystem service is installed only by an explicit administrator deployment
into `C:\Program Files\foxVPN Network`; the bound desktop caller must reside in
`C:\Program Files\foxVPN\smart-vpn-desktop.exe`. Other installation roots are
rejected. The slot/binding/executables reject reparse points, untrusted ownership
and unprivileged writable ACLs. Open verified files forbid write/delete sharing.
The administrator pins a SHA256 for the service and client and one normal user
SID. Upgrade preserves that owner and restores the previous files if startup
fails. Removal touches only the fixed service and its two fixed files.

Named pipe `\\.\pipe\foxVPN.Network.v1` uses an explicit DACL, rejects remote
clients, reserves the first instance, and denies the owner create-instance
permission. Frames have a four-byte little-endian length, a 512 KiB limit and a
three-second server deadline. A one-byte client acknowledgement prevents
disconnection from discarding a response that has not yet been read. Every received frame authenticates the impersonated
owner token, client process token, a held live process handle, exact protected
client executable and pinned SHA256. The client authenticates the LocalSystem
server process and protected pinned image before sending data. The protocol has
only Status, Stop and typed Start; it has no shell, binary/config/file path,
installer/update, DNS command, arbitrary route or log command.

Status reports both TUN and Kill Switch unsupported. Start validates the existing
server/settings/rules, bounds reserves/rules and prepares a service-only TUN
configuration with no local proxy or controller, but **always returns an explicit
unaccepted error without launching a privileged core or changing networking**.
Stop is idempotent because this transport cannot own any network state yet.
Do not interpret successful IPC tests as TUN/DNS/WFP acceptance.

Remaining release gates:

- Pin the protected Windows TUN core and lock its verified image during launch.
  The pinned sing-tun source already embeds Wintun 0.14.1 and memory-loads that
  byte array; no external DLL search/download is used by this module. Its amd64
  DLL is byte-identical to the official archive checked against the SHA256 on
  wintun.net. See [driver provenance](../vendor/windows-network-dependencies.json).
  This verifies source dependency provenance, not driver execution/acceptance.
- Add a service-owned process job, fixed private atomic session journal and
  interface identity. Upstream can reopen a same-name adapter, so a pre-existing
  foreign adapter must be rejected rather than reconfigured. Prove ordinary core stop and forced death restore only
  owned adapter/routes/DNS, preserving concurrent host configuration changes.
- Implement WFP provider/sublayer with transactional IPv4/IPv6 filters, narrow
  core/TUN/loopback exceptions and explicit stop recovery. Dynamic WFP sessions
  alone drop filters on service crash and cannot satisfy a persistent Kill Switch.
  Persistent/boot filters need an accepted crash/reboot/remove protocol.
- Native disposable Windows runner: accepted GUI and rejected same-owner process,
  alternate SID/session, remote client, pipe squatting, oversized/slow frames,
  service crash, upgrade rollback, removal, and network leak/failure matrix.
- Actual Windows 10/11 PC installation/network/reboot acceptance remains deferred
  by the user; a native runner cannot substitute for it.

The threat boundary excludes an administrator, kernel attacker and injection into
the already-authorized desktop process. SID/hash authentication alone cannot
protect an ordinary desktop process from malicious code already running with the
same account. No privileged Start action is enabled while that boundary is being
accepted. Authenticode is a separate owner-certificate dependency.

References: [Microsoft named-pipe ACLs](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights),
[pipe impersonation](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient),
[ALE layers](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-layers).

Local evidence (11.10.2026): four engine policy tests passed on macOS; the actual
native transport module and ignored security test compiled and passed clippy
with warnings denied for the Windows GNU target in an isolated type-check
harness. The complete engine Windows target check cannot run here because
MinGW's C compiler is absent. PowerShell/SCM/IPC fixture execution has not yet
been performed; neither local checks nor a future IPC fixture test prove native
TUN/WFP or physical-PC acceptance.
