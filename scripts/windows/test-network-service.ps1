# Native disposable runner test. Never run against a user's installed component.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$ServiceBinary, [Parameter(Mandatory=$true)][string]$ProbeBinary)
$ErrorActionPreference = 'Stop'
if ($env:FOXVPN_TEST_ALLOW_SERVICE -ne '1' -or $env:CI -ne 'true') { throw 'Only an explicitly enabled disposable CI runner is supported' }
$clientDir = 'C:\Program Files\foxVPN'
$slot = 'C:\Program Files\foxVPN Network'
$client = "$clientDir\smart-vpn-desktop.exe"
if ((Test-Path $clientDir) -or (Test-Path $slot) -or (Get-Service foxVPNNetwork -ErrorAction SilentlyContinue)) { throw 'Refusing to replace an existing installation' }
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$serviceHash = (Get-FileHash $ServiceBinary -Algorithm SHA256).Hash.ToLowerInvariant()
$clientHash = (Get-FileHash $ProbeBinary -Algorithm SHA256).Hash.ToLowerInvariant()
$installed = $false
try {
    New-Item -ItemType Directory -Path $clientDir | Out-Null
    & "$env:SystemRoot\System32\icacls.exe" $clientDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' "*$($sid):(OI)(CI)RX" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot apply protected file permissions' }
    & "$env:SystemRoot\System32\icacls.exe" $clientDir /setowner '*S-1-5-32-544' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot protect the test client' }
    Copy-Item -LiteralPath $ProbeBinary -Destination $client
    & "$env:SystemRoot\System32\icacls.exe" $client /reset | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot apply protected file permissions' }
    & "$env:SystemRoot\System32\icacls.exe" $client /setowner '*S-1-5-32-544' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot protect the test executable' }
    & "$PSScriptRoot\network-service.ps1" -Mode Install -ServiceBinary $ServiceBinary -ExpectedServiceSha256 $serviceHash -ExpectedClientSha256 $clientHash -OwnerSid $sid
    $installed = $true
    & $client
    if ($LASTEXITCODE -ne 0) { throw 'Pinned fixture client was rejected' }
    & $ProbeBinary
    if ($LASTEXITCODE -eq 0) { throw 'Identical image at an untrusted path was accepted' }
    cargo test --locked -p smart-vpn-engine same_owner_untrusted_process_and_pipe_instance_are_denied -- --ignored --test-threads=1
    if ($LASTEXITCODE -ne 0) { throw 'Native pipe authentication test failed' }
    & "$PSScriptRoot\network-service.ps1" -Mode Upgrade -ServiceBinary $ServiceBinary -ExpectedServiceSha256 $serviceHash -ExpectedClientSha256 $clientHash -OwnerSid $sid
    & $client
    if ($LASTEXITCODE -ne 0) { throw 'Accepted caller failed after service upgrade' }
    Stop-Service foxVPNNetwork
    & $client
    if ($LASTEXITCODE -eq 0) { throw 'Stopped component answered a request' }
    Start-Service foxVPNNetwork
    & $client
    if ($LASTEXITCODE -ne 0) { throw 'Service restart failed' }
} finally {
    if ($installed -or (Get-Service foxVPNNetwork -ErrorAction SilentlyContinue)) { & "$PSScriptRoot\network-service.ps1" -Mode Remove }
    if (Test-Path $client) { Remove-Item -LiteralPath $client -Force }
    if ((Test-Path $clientDir) -and @(Get-ChildItem -LiteralPath $clientDir -Force).Count -eq 0) { Remove-Item -LiteralPath $clientDir }
}
if (Test-Path $slot) { throw 'Component slot remained after removal' }
Write-Host 'Native service IPC fixture passed; TUN, DNS, WFP and device acceptance are not tested.'
