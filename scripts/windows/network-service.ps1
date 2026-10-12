# Experimental service transport deployment. Administrator approval is provided
# by invoking this script. It does not enable TUN or claim a WFP Kill Switch.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('Install','Upgrade','Remove')][string]$Mode,
    [string]$ServiceBinary,
    [string]$ExpectedServiceSha256,
    [string]$ExpectedClientSha256,
    [string]$OwnerSid
)
$ErrorActionPreference = 'Stop'
$slot = 'C:\Program Files\foxVPN Network'
$client = 'C:\Program Files\foxVPN\smart-vpn-desktop.exe'
$name = 'foxVPNNetwork'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator deployment is required' }
if ($env:ProgramFiles -ne 'C:\Program Files') { throw 'Unsupported Program Files location; no alternate privileged path is accepted' }
function Check-PlainPath([string]$Path) {
    $item = Get-Item -LiteralPath $Path
    while ($item) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse points are not permitted' }
        if ($item -is [IO.FileInfo]) { $item = $item.Directory } else { $item = $item.Parent }
        if (!$item) { break }
    }
}
function Run-Sc([string[]]$Arguments) {
    & "$env:SystemRoot\System32\sc.exe" @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Service manager operation failed' }
}
function Verify-OwnService {
    $serviceInfo = Get-CimInstance Win32_Service -Filter "Name='$name'"
    if ($serviceInfo -and ($serviceInfo.PathName -cne '"C:\Program Files\foxVPN Network\foxvpn-windows-service.exe"' -or $serviceInfo.StartName -ne 'LocalSystem')) { throw 'Refusing to manage a different service identity' }
}
function Stop-OwnService {
    $service = Get-Service -Name $name -ErrorAction SilentlyContinue
    $serviceInfo = Get-CimInstance Win32_Service -Filter "Name='$name'"
    # Retain the exact owned service process; never terminate or search by name.
    $process = $null
    if ($serviceInfo -and $serviceInfo.ProcessId -ne 0) {
        try {
            $process = [Diagnostics.Process]::GetProcessById([int]$serviceInfo.ProcessId)
            $null = $process.Handle # Hold process identity before SCM stop/PID reuse.
        } catch [ArgumentException] { $process = $null }
    }
    if ($service -and $service.Status -ne 'Stopped') { Stop-Service -Name $name; $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(15)) }
    if ($process) {
        try { if (!$process.WaitForExit(5000)) { throw 'Owned service process has not exited; replacement is aborted' } } finally { $process.Dispose() }
    }
}
function Protect([string]$Path, [string]$Sid) {
    # Protected owner, inherited ACL disabled, no user write/replace permissions.
    & "$env:SystemRoot\System32\icacls.exe" $Path /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' "*$($Sid):(OI)(CI)RX" /setowner '*S-1-5-32-544' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot protect the service directory' }
}
if ($Mode -eq 'Remove') {
    if (Test-Path -LiteralPath $slot) { Check-PlainPath $slot }
    Verify-OwnService
    Stop-OwnService
    if (Get-Service -Name $name -ErrorAction SilentlyContinue) { Run-Sc -Arguments @('delete', $name) }
    # Only fixed owned filenames are removed; no recursive deletion or user profile.
    foreach ($file in @('foxvpn-windows-service.exe', 'binding.json')) {
        $path = Join-Path $slot $file
        if (Test-Path -LiteralPath $path) { Check-PlainPath $path; Remove-Item -LiteralPath $path -Force }
    }
    if ((Test-Path $slot) -and @(Get-ChildItem -LiteralPath $slot -Force).Count -eq 0) { Remove-Item -LiteralPath $slot }
    return
}
if ($OwnerSid -notmatch '^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$' -or [uint32]($OwnerSid.Split('-')[-1]) -lt 1000) { throw 'A nonprivileged local/domain owner SID is required' }
foreach ($digest in @($ExpectedServiceSha256, $ExpectedClientSha256)) { if ($digest -cnotmatch '^[0-9a-f]{64}$') { throw 'Explicit lowercase SHA256 pins are required' } }
Check-PlainPath $ServiceBinary; Check-PlainPath $client
# Freeze the verified source against write/delete sharing, bound the snapshot,
# then hash the exact bytes written to the privileged slot.
$sourceStream = [IO.File]::Open($ServiceBinary, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
try {
    if ($sourceStream.Length -le 0 -or $sourceStream.Length -gt 200000000) { throw 'Invalid service binary size' }
    $serviceBytes = [byte[]]::new([int]$sourceStream.Length)
    $offset = 0
    while ($offset -lt $serviceBytes.Length) {
        $read = $sourceStream.Read($serviceBytes, $offset, $serviceBytes.Length - $offset)
        if ($read -le 0) { throw 'Incomplete service binary snapshot' }
        $offset += $read
    }
} finally { $sourceStream.Dispose() }
$hasher = [Security.Cryptography.SHA256]::Create()
try { $sourceHash = ([BitConverter]::ToString($hasher.ComputeHash($serviceBytes))).Replace('-', '').ToLowerInvariant() } finally { $hasher.Dispose() }
if ($sourceHash -cne $ExpectedServiceSha256) { throw 'Service digest differs' }
if ((Get-FileHash -LiteralPath $client -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ExpectedClientSha256) { throw 'Installed client digest differs' }
$existing = Get-Service -Name $name -ErrorAction SilentlyContinue
if ($Mode -eq 'Install' -and ($existing -or (Test-Path $slot))) { throw 'Existing component requires Upgrade' }
if ($Mode -eq 'Upgrade' -and (!$existing -or !(Test-Path "$slot\binding.json"))) { throw 'No component to upgrade' }
if ($existing) {
    Verify-OwnService
    Check-PlainPath "$slot\binding.json"
    $previous = Get-Content -LiteralPath "$slot\binding.json" -Raw | ConvertFrom-Json
    if ($previous.owner_sid -cne $OwnerSid) { throw 'An upgrade cannot change the component owner' }
    $serviceInfo = Get-CimInstance Win32_Service -Filter "Name='$name'"
    if ($serviceInfo.PathName -cne '"C:\Program Files\foxVPN Network\foxvpn-windows-service.exe"' -or $serviceInfo.StartName -ne 'LocalSystem') { throw 'Service identity differs' }
}
$created = !$existing
$beforeBinary = $null; $beforeBinding = $null
if ($existing) { Check-PlainPath "$slot\foxvpn-windows-service.exe"; $beforeBinary = [IO.File]::ReadAllBytes("$slot\foxvpn-windows-service.exe"); $beforeBinding = [IO.File]::ReadAllBytes("$slot\binding.json") }
try {
    Stop-OwnService
    if (!(Test-Path $slot)) { New-Item -ItemType Directory -Path $slot | Out-Null }
    Check-PlainPath $slot; Protect $slot $OwnerSid
    [IO.File]::WriteAllBytes("$slot\foxvpn-windows-service.exe", $serviceBytes)
    # The GUI directory must be administrative; runtime rejects writable ACLs.
    $binding = @{ protocol = 1; owner_sid = $OwnerSid; client_sha256 = $ExpectedClientSha256; service_sha256 = $ExpectedServiceSha256 } | ConvertTo-Json
    [IO.File]::WriteAllText("$slot\binding.json", $binding, [Text.UTF8Encoding]::new($false))
    foreach ($file in @('foxvpn-windows-service.exe', 'binding.json')) {
        & "$env:SystemRoot\System32\icacls.exe" "$slot\$file" /reset /setowner '*S-1-5-32-544' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Cannot protect a service file' }
    }
    if ($created) { Run-Sc -Arguments @('create', $name, 'binPath=', '"C:\Program Files\foxVPN Network\foxvpn-windows-service.exe"', 'start=', 'demand', 'obj=', 'LocalSystem', 'DisplayName=', 'foxVPN Network (experimental transport)') }
    # Only administrators/SYSTEM may reconfigure/start/stop/delete the service.
    Run-Sc -Arguments @('sdset', $name, 'D:P(A;;GA;;;SY)(A;;GA;;;BA)')
    Start-Service -Name $name
    (Get-Service -Name $name).WaitForStatus('Running', [TimeSpan]::FromSeconds(10))
    Start-Sleep -Milliseconds 500
    if ((Get-Service -Name $name).Status -ne 'Running') { throw 'Service did not stay ready' }
} catch {
    Stop-OwnService
    if ($created) {
        if (Get-Service -Name $name -ErrorAction SilentlyContinue) { Run-Sc -Arguments @('delete', $name) }
        foreach ($file in @('foxvpn-windows-service.exe', 'binding.json')) { if (Test-Path "$slot\$file") { Remove-Item -LiteralPath "$slot\$file" -Force } }
        if ((Test-Path $slot) -and @(Get-ChildItem -LiteralPath $slot -Force).Count -eq 0) { Remove-Item -LiteralPath $slot }
    } else {
        [IO.File]::WriteAllBytes("$slot\foxvpn-windows-service.exe", $beforeBinary)
        [IO.File]::WriteAllBytes("$slot\binding.json", $beforeBinding)
        Start-Service -Name $name
    }
    throw
}
