#Requires -Version 5.1
#Requires -RunAsAdministrator
<##
.SYNOPSIS
Install the Windows x64 release, optionally creating a native Windows service.
.EXAMPLE
.\install.ps1 -InstallService -Config C:\secure\oixc-proxy.conf
.EXAMPLE
.\install.ps1 -BinaryPath .\target\release\oixc-proxy.exe
##>
[CmdletBinding()]
param(
    [string]$Version = 'latest',
    [string]$Repository = 'we11adam/oixc-proxy',
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'oixc-proxy'),
    [string]$BinaryPath,
    [switch]$InstallService,
    [string]$Config
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Protect-Directory([string]$Path) {
    # Reject junctions in any existing ancestor before creating/repermissioning.
    $ancestor = [IO.Path]::GetFullPath($Path)
    while ($ancestor) {
        if (Test-Path -LiteralPath $ancestor) {
            $item = Get-Item -LiteralPath $ancestor -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Installation/config paths must not contain reparse points.' }
        }
        $ancestor = [IO.Path]::GetDirectoryName($ancestor)
    }
    $directory = New-Item -ItemType Directory -Force -Path $Path
    if (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Installation/config directories must not be reparse points.'
    }
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $identity = New-Object Security.Principal.SecurityIdentifier($sid)
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Protect-File([string]$Path) {
    $acl = New-Object Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $identity = New-Object Security.Principal.SecurityIdentifier($sid)
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'Allow')))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

if ($env:OS -ne 'Windows_NT') { throw 'This installer supports Windows only.' }
$architecture = $env:PROCESSOR_ARCHITEW6432
if (-not $architecture) { $architecture = $env:PROCESSOR_ARCHITECTURE }
if ($architecture -ne 'AMD64') { throw 'This release installer currently supports Windows x64 only.' }
if ($Repository -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') { throw 'Repository must be owner/repository.' }
if ($Version -ne 'latest' -and $Version -notmatch '^v?\d+\.\d+\.\d+([+-][A-Za-z0-9.-]+)?$') { throw 'Invalid version.' }
$InstallDir = [IO.Path]::GetFullPath($InstallDir)
$programFiles = [IO.Path]::GetFullPath($env:ProgramFiles).TrimEnd('\') + '\'
if (-not $InstallDir.StartsWith($programFiles, [StringComparison]::OrdinalIgnoreCase) -or $InstallDir.TrimEnd('\') -eq $programFiles.TrimEnd('\')) {
    throw 'InstallDir must be a dedicated directory under ProgramFiles.'
}
$existing = Get-Service -Name oixc-proxy -ErrorAction SilentlyContinue
if ($InstallService -and $existing) { throw 'Service already exists; its registration and config will not be overwritten. Omit -InstallService for a binary-only update.' }
if ($existing -and $existing.Status -ne 'Stopped') { throw 'Stop-Service oixc-proxy and wait for Stopped before updating.' }

$destination = Join-Path $InstallDir 'oixc-proxy.exe'
$stateDir = Join-Path $env:ProgramData 'oixc-proxy'
$serviceConfig = Join-Path $stateDir 'oixc-proxy.conf'
if ($InstallService) {
    if ($Config) { $Config = (Resolve-Path -LiteralPath $Config).Path }
    elseif (-not (Test-Path -LiteralPath $serviceConfig -PathType Leaf)) { throw '-InstallService requires -Config or an existing ProgramData config.' }
    if ($Config -and (Test-Path -LiteralPath $serviceConfig) -and -not [String]::Equals($Config, $serviceConfig, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'ProgramData config already exists; it will not be overwritten.'
    }
}

$temporaryDirectory = Join-Path ([IO.Path]::GetTempPath()) ('oixc-proxy-install-' + [Guid]::NewGuid().ToString('N'))
Protect-Directory $temporaryDirectory
try {
    if ($BinaryPath) { $binary = (Resolve-Path -LiteralPath $BinaryPath).Path }
    else {
        $asset = 'oixc-proxy-x86_64-pc-windows-msvc.zip'
        $tag = $Version
        if ($tag -ne 'latest' -and -not $tag.StartsWith('v')) { $tag = 'v' + $tag }
        $useGh = $false
        if (Get-Command gh -ErrorAction SilentlyContinue) {
            & gh auth status --hostname github.com *> $null
            $useGh = $LASTEXITCODE -eq 0
        }
        if ($useGh) {
            $downloadArgs = @('release', 'download')
            if ($tag -ne 'latest') { $downloadArgs += $tag }
            & gh @downloadArgs --repo $Repository --pattern $asset --pattern SHA256SUMS --dir $temporaryDirectory
            if ($LASTEXITCODE -ne 0) { throw 'GitHub asset download failed.' }
        } else {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $base = if ($tag -eq 'latest') { "https://github.com/$Repository/releases/latest/download" } else { "https://github.com/$Repository/releases/download/$tag" }
            foreach ($name in @($asset, 'SHA256SUMS')) { Invoke-WebRequest -UseBasicParsing -Uri "$base/$name" -OutFile (Join-Path $temporaryDirectory $name) }
        }
        $archive = Join-Path $temporaryDirectory $asset
        $checksumLines = @(Get-Content -LiteralPath (Join-Path $temporaryDirectory 'SHA256SUMS') | Where-Object { $_ -match ('^[a-fA-F0-9]{64}\s+\*?' + [Regex]::Escape($asset) + '$') })
        if ($checksumLines.Count -ne 1) { throw 'Archive is missing or duplicated in SHA256SUMS.' }
        $expected = ($checksumLines[0] -split '\s+')[0]
        if ((Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash -ne $expected) { throw 'Archive checksum mismatch.' }
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [IO.Compression.ZipFile]::OpenRead($archive)
        try {
            if ($zip.Entries.Count -ne 1 -or $zip.Entries[0].FullName -cne 'oixc-proxy.exe' -or $zip.Entries[0].Length -gt 100MB) { throw 'Unexpected release archive contents.' }
        } finally { $zip.Dispose() }
        $extracted = Join-Path $temporaryDirectory 'extracted'
        [IO.Compression.ZipFile]::ExtractToDirectory($archive, $extracted)
        $binary = Join-Path $extracted 'oixc-proxy.exe'
    }
    $reported = & $binary version
    $versionMatch = [Regex]::Match([string]$reported, '^oixc-proxy ([^ ]+) \(commit ')
    if ($LASTEXITCODE -ne 0 -or -not $versionMatch.Success) { throw 'Binary version check failed.' }
    if (-not $BinaryPath -and $Version -ne 'latest' -and $versionMatch.Groups[1].Value -ne $Version.TrimStart('v')) { throw 'Binary does not match requested version.' }
    Protect-Directory $InstallDir
    $staged = Join-Path $InstallDir ('oixc-proxy-' + [Guid]::NewGuid().ToString('N') + '.new')
    Copy-Item -LiteralPath $binary -Destination $staged
    Protect-File $staged
    if (Test-Path -LiteralPath $destination) {
        [IO.File]::Replace($staged, $destination, (Join-Path $InstallDir 'oixc-proxy.previous.exe'))
    } else { [IO.File]::Move($staged, $destination) }
    Protect-File $destination
    if ($InstallService) {
        Protect-Directory $stateDir
        if ($Config -and -not (Test-Path -LiteralPath $serviceConfig)) {
            Copy-Item -LiteralPath $Config -Destination $serviceConfig
            Protect-File $serviceConfig
        }
        # Existing state files are not overwritten or recursively repermissioned.
        & $destination install-windows-service --config $serviceConfig
        if ($LASTEXITCODE -ne 0) { throw 'Service installation/start failed; files retained for diagnosis.' }
    }
    Write-Output "Installed $reported at $destination"
    if (-not $InstallService) { Write-Output 'No configuration or service was created or restarted.' }
} finally {
    # This exact GUID directory was created by this invocation only.
    Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force
}
