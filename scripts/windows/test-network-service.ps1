# Native disposable runner test. Never run against a user's installed component.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$ServiceBinary, [Parameter(Mandatory=$true)][string]$ProbeBinary)
$ErrorActionPreference = 'Stop'
if ($env:FOXVPN_TEST_ALLOW_SERVICE -ne '1' -or $env:CI -ne 'true') { throw 'Only an explicitly enabled disposable CI runner is supported' }
$clientDir = 'C:\Program Files\foxVPN'
$slot = 'C:\Program Files\foxVPN Network'
$client = "$clientDir\smart-vpn-desktop.exe"
if ((Test-Path $clientDir) -or (Test-Path $slot) -or (Get-Service foxVPNNetwork -ErrorAction SilentlyContinue)) { throw 'Refusing to replace an existing installation' }
# The runner can use built-in Administrator (RID 500). Test as a newly created
# ordinary owner instead of relaxing production SID or pipe policy.
$fixtureName = 'foxvpn_' + [Guid]::NewGuid().ToString('N').Substring(0,12)
$password = ConvertTo-SecureString (([Guid]::NewGuid().ToString('N')) + '!aA9') -AsPlainText -Force
$user = New-LocalUser -Name $fixtureName -Password $password -AccountNeverExpires -PasswordNeverExpires
$sid = $user.SID.Value
$credential = [PSCredential]::new("$env:COMPUTERNAME\$fixtureName", $password)
$fixtureDir = Join-Path $env:PUBLIC $fixtureName
New-Item -ItemType Directory -Path $fixtureDir | Out-Null
& "$env:SystemRoot\System32\icacls.exe" $fixtureDir /grant:r "*$($sid):(OI)(CI)M" | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot prepare disposable owner fixture' }
$untrusted = Join-Path $fixtureDir 'untrusted-probe.exe'
Copy-Item -LiteralPath $ProbeBinary -Destination $untrusted
function Run-Probe([string]$Image,[string]$Argument='') {
    $out = Join-Path $fixtureDir 'out.txt'
    $err = Join-Path $fixtureDir 'err.txt'
    $args = @{ FilePath=$Image;Credential=$credential;LoadUserProfile=$true;WorkingDirectory=$fixtureDir;RedirectStandardOutput=$out;RedirectStandardError=$err;PassThru=$true }
    if ($Argument) { $args.ArgumentList=$Argument }
    $process=Start-Process @args
    if (!$process.WaitForExit(15000)) { throw 'Disposable probe exceeded deadline' }
    $process.Refresh()
    $code=$process.ExitCode
    if (Test-Path $err) { Get-Content -LiteralPath $err | Write-Host }
    $process.Dispose()
    return $code
}
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
    if ((Run-Probe $client) -ne 0) { throw 'Pinned fixture client was rejected' }
    if ((Run-Probe $untrusted) -eq 0) { throw 'Identical image at an untrusted path was accepted' }
    if ((Run-Probe $untrusted '--security-boundary') -ne 0) { throw 'Native pipe authentication test failed' }
    & "$PSScriptRoot\network-service.ps1" -Mode Upgrade -ServiceBinary $ServiceBinary -ExpectedServiceSha256 $serviceHash -ExpectedClientSha256 $clientHash -OwnerSid $sid
    if ((Run-Probe $client) -ne 0) { throw 'Accepted caller failed after service upgrade' }
    Stop-Service foxVPNNetwork
    if ((Run-Probe $client) -eq 0) { throw 'Stopped component answered a request' }
    Start-Service foxVPNNetwork
    if ((Run-Probe $client) -ne 0) { throw 'Service restart failed' }
} finally {
    if ($installed -or (Get-Service foxVPNNetwork -ErrorAction SilentlyContinue)) { & "$PSScriptRoot\network-service.ps1" -Mode Remove }
    if (Test-Path $client) { Remove-Item -LiteralPath $client -Force }
    if ((Test-Path $clientDir) -and @(Get-ChildItem -LiteralPath $clientDir -Force).Count -eq 0) { Remove-Item -LiteralPath $clientDir }
    foreach ($name in @('out.txt','err.txt','untrusted-probe.exe')) { $path=Join-Path $fixtureDir $name;if(Test-Path $path){Remove-Item -LiteralPath $path -Force} }
    if ((Test-Path $fixtureDir) -and @(Get-ChildItem -LiteralPath $fixtureDir -Force).Count -eq 0) { Remove-Item -LiteralPath $fixtureDir }
    Remove-LocalUser -Name $fixtureName
}
if (Test-Path $slot) { throw 'Component slot remained after removal' }
Write-Host 'Native service IPC fixture passed; TUN, DNS, WFP and device acceptance are not tested.'
