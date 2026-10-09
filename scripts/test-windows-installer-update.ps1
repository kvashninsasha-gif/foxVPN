# Disposable runner only: install the previous release, then use NSIS /UPDATE /P.
param([Parameter(Mandatory=$true)][string]$Installer,
      [Parameter(Mandatory=$true)][string]$ExpectedVersion)
$ErrorActionPreference = 'Stop'
if ($env:FOXVPN_TEST_ALLOW_INSTALLER -ne '1') { throw 'Explicit disposable-runner opt-in required' }
$taskRoot = Join-Path $env:TEMP ("foxvpn-install-test-" + [guid]::NewGuid())
$installRoot = Join-Path $taskRoot 'app'
$savedAppData = $env:APPDATA
New-Item -ItemType Directory -Path $taskRoot -Force | Out-Null
try {
    $env:APPDATA = Join-Path $taskRoot 'data'
    $profileRoot = Join-Path $env:APPDATA 'ru.smartvpn.router'
    New-Item -ItemType Directory -Path $profileRoot -Force | Out-Null
    $profile = Join-Path $profileRoot 'profile.enc'
    [IO.File]::WriteAllBytes($profile, [Text.Encoding]::UTF8.GetBytes('preserved-test-profile'))
    $profileHash = (Get-FileHash $profile -Algorithm SHA256).Hash
    $release = Invoke-RestMethod -Uri 'https://api.github.com/repos/kvashninsasha-gif/foxVPN/releases/tags/v0.1.19'
    $asset = $release.assets | Where-Object name -eq 'foxVPN_0.1.19_x64-setup.exe'
    if (-not $asset -or -not $asset.digest.StartsWith('sha256:')) { throw 'Pinned old release missing' }
    $oldInstaller = Join-Path $taskRoot 'old.exe'
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $oldInstaller
    if (('sha256:' + (Get-FileHash $oldInstaller -Algorithm SHA256).Hash.ToLowerInvariant()) -ne $asset.digest) {
        throw 'Old installer SHA256 mismatch'
    }
    $first = Start-Process $oldInstaller -ArgumentList @('/S', "/D=$installRoot") -PassThru
    if (-not $first.WaitForExit(120000)) { $first.Kill(); throw 'Old installer timed out' }
    if ($first.ExitCode -notin @(0,3010)) { throw 'Old installation failed' }
    $exe = Join-Path $installRoot 'smart-vpn-desktop.exe'
    if (-not (Test-Path $exe)) { throw 'Initial app missing' }
    $next = Start-Process (Resolve-Path $Installer).Path -ArgumentList @('/UPDATE','/P',"/D=$installRoot") -PassThru
    if (-not $next.WaitForExit(120000)) { $next.Kill(); throw 'Update installer timed out' }
    if ($next.ExitCode -notin @(0,3010)) { throw 'Update installation failed' }
    if ([Diagnostics.FileVersionInfo]::GetVersionInfo($exe).ProductVersion -ne $ExpectedVersion) {
        throw 'Installed application version mismatch'
    }
    if ((Get-FileHash $profile -Algorithm SHA256).Hash -ne $profileHash) { throw 'Profile changed by update' }
    Write-Output 'NSIS update mode and profile preservation verified'
} finally {
    $uninstaller = Join-Path $installRoot 'uninstall.exe'
    if (Test-Path $uninstaller) {
        $cleanup = Start-Process $uninstaller -ArgumentList '/S' -PassThru
        if (-not $cleanup.WaitForExit(60000)) { $cleanup.Kill() }
    }
    $env:APPDATA = $savedAppData
    Remove-Item -LiteralPath $taskRoot -Recurse -Force -ErrorAction SilentlyContinue
}
