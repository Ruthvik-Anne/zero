#Requires -Version 5.1
<#
.SYNOPSIS
    Installs Zero (https://github.com/Ruthvik-Anne/zero) globally via npm.

.DESCRIPTION
    Windows counterpart to install.sh: resolves the latest (or requested)
    GitHub release, downloads and checksum-verifies the release tarballs,
    then runs `npm install -g` against the main package tarball. Mirrors
    install.sh's environment variables so docs/config apply to both:

      ZERO_GITHUB_REPO               owner/repo to install from
      ZERO_RELEASE_CHANNEL           "stable" (default) or "beta"
      ZERO_VERSION                   an explicit version to install
      ZERO_PACKAGE                   main npm package name (default: zero)
      ZERO_CMD                       installed command name (default: zero)
      ZERO_BOOTSTRAP_KERNEL_ON_INSTALL   "1"/"0" to skip the prompt
      ZERO_INSTALLER_NONINTERACTIVE  "1" to never prompt (assume yes)

.PARAMETER Version
    An explicit version, git tag, or release channel ("stable"/"beta") to
    install. Overrides ZERO_RELEASE_CHANNEL/ZERO_VERSION.
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Version
)

$ErrorActionPreference = 'Stop'
# GitHub's API and release CDN require TLS 1.2; Windows PowerShell 5.1's
# default SecurityProtocol on older Windows can still be TLS 1.0, which
# fails the handshake outright rather than retrying.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$ZeroRepo = if ($env:ZERO_GITHUB_REPO) { $env:ZERO_GITHUB_REPO } else { 'Ruthvik-Anne/zero' }
$ZeroReleaseChannel = if ($env:ZERO_RELEASE_CHANNEL) { $env:ZERO_RELEASE_CHANNEL } else { 'stable' }
$ZeroPackage = if ($env:ZERO_PACKAGE) { $env:ZERO_PACKAGE } else { 'zero' }
$ZeroCmd = if ($env:ZERO_CMD) { $env:ZERO_CMD } else { 'zero' }
$MinNodeMajor = 20
$MinNodeMinor = 6
$MinNodePatch = 0

function Write-ZeroInfo([string]$Message) {
    Write-Host $Message -ForegroundColor Cyan
}

function Write-ZeroWarn([string]$Message) {
    Write-Host $Message -ForegroundColor Yellow
}

function Write-ZeroError([string]$Message) {
    Write-Host "error: $Message" -ForegroundColor Red
}

# `irm URL | iex` fully evaluates the piped script before running it, so
# stdin is free by the time this runs — but treat a redirected/non-TTY
# console (CI, a non-interactive pipeline) the same way install.sh treats
# "no terminal detected": proceed without prompting instead of hanging.
function Confirm-ZeroAction([string]$Question, [string]$Detail) {
    if ($env:ZERO_INSTALLER_NONINTERACTIVE -eq '1') {
        Write-ZeroInfo "$Question .. continuing without confirmation (ZERO_INSTALLER_NONINTERACTIVE=1)."
        return $true
    }
    if ([Console]::IsInputRedirected -or -not [Environment]::UserInteractive) {
        Write-ZeroInfo "$Question .. no terminal detected; continuing without confirmation."
        return $true
    }
    if ($Detail) { Write-Host $Detail -ForegroundColor DarkGray }
    $answer = Read-Host "$Question [Y/n]"
    return -not ($answer -match '^(n|no)$')
}

function Invoke-ZeroWithRetry {
    param(
        [Parameter(Mandatory)][scriptblock]$Action,
        [int]$MaxAttempts = 5,
        [int]$DelaySeconds = 1
    )
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            return & $Action
        } catch {
            if ($attempt -eq $MaxAttempts) { throw }
            Start-Sleep -Seconds $DelaySeconds
        }
    }
}

function Get-InstalledNodeVersion {
    $nodeCmd = Get-Command node -ErrorAction SilentlyContinue
    if (-not $nodeCmd) { return $null }
    try {
        $raw = (& node --version).Trim().TrimStart('v')
        $parts = $raw.Split('.')
        return [PSCustomObject]@{
            Major = [int]$parts[0]
            Minor = [int]$parts[1]
            Patch = [int]$parts[2]
            Raw   = $raw
        }
    } catch {
        return $null
    }
}

function Test-NodeVersionIsNewEnough($Version) {
    if (-not $Version) { return $false }
    if ($Version.Major -gt $MinNodeMajor) { return $true }
    if ($Version.Major -eq $MinNodeMajor -and $Version.Minor -gt $MinNodeMinor) { return $true }
    if ($Version.Major -eq $MinNodeMajor -and $Version.Minor -eq $MinNodeMinor -and $Version.Patch -ge $MinNodePatch) { return $true }
    return $false
}

function Install-NodeWithWinget {
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if (-not $winget) { return $false }
    if (-not (Confirm-ZeroAction 'Install Node.js and npm with winget?' 'Required before Zero can be installed.')) {
        return $false
    }
    Write-ZeroInfo 'Installing Node.js (LTS) with winget...'
    & winget install --id OpenJS.NodeJS.LTS -e --accept-source-agreements --accept-package-agreements
    if ($LASTEXITCODE -ne 0) { return $false }
    # winget updates machine PATH via the registry, not this process's env —
    # refresh so a freshly-installed `node`/`npm` resolve without a new shell.
    $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User')
    return $true
}

function Assert-NodeAndNpmAvailable {
    $nodeVersion = Get-InstalledNodeVersion
    $npmCmd = Get-Command npm -ErrorAction SilentlyContinue

    if ((Test-NodeVersionIsNewEnough $nodeVersion) -and $npmCmd) {
        return
    }

    if (-not $nodeVersion) {
        Write-ZeroError "Node.js $MinNodeMajor.$MinNodeMinor.$MinNodePatch or newer is required to install Zero."
    } else {
        Write-ZeroError "Zero requires Node.js $MinNodeMajor.$MinNodeMinor.$MinNodePatch or newer. Found $($nodeVersion.Raw)."
    }

    if (Install-NodeWithWinget) {
        $nodeVersion = Get-InstalledNodeVersion
        $npmCmd = Get-Command npm -ErrorAction SilentlyContinue
        if ((Test-NodeVersionIsNewEnough $nodeVersion) -and $npmCmd) {
            Write-ZeroInfo 'Node.js and npm are installed.'
            return
        }
    }

    Write-Host ''
    Write-Host "Install Node.js $MinNodeMajor.$MinNodeMinor.$MinNodePatch or newer and npm, then run this installer again."
    Write-Host 'https://nodejs.org/en/download'
    exit 1
}

function ConvertTo-ZeroVersion([string]$Raw) {
    $version = $Raw.TrimStart('v')
    if (-not $version) {
        Write-ZeroError 'empty Zero version.'
        exit 1
    }
    if ($version -notmatch '^[0-9A-Za-z.-]+$') {
        Write-ZeroError "invalid Zero version: $Raw"
        exit 1
    }
    return $version
}

function Resolve-ZeroStableTag {
    Invoke-ZeroWithRetry -Action {
        $response = Invoke-RestMethod -Uri "https://api.github.com/repos/$ZeroRepo/releases/latest" `
            -Headers @{ Accept = 'application/vnd.github+json' } -UseBasicParsing
        return $response.tag_name
    }
}

function Resolve-ZeroBetaVersion {
    $release = Invoke-ZeroWithRetry -Action {
        Invoke-RestMethod -Uri "https://api.github.com/repos/$ZeroRepo/releases/tags/beta" `
            -Headers @{ Accept = 'application/vnd.github+json' } -UseBasicParsing
    }
    # The beta release's own git tag is always the floating literal "beta";
    # the real version only shows up in the main package's asset filename,
    # which starts with a digit (unlike its zero-ai/zero-core/zero-tui
    # companions, which are prefixed with those fixed names instead).
    $asset = $release.assets | Where-Object { $_.name -match "^$([regex]::Escape($ZeroPackage))-[0-9][^""]*\.tgz$" } | Select-Object -First 1
    if (-not $asset) { return $null }
    return $asset.name.Substring("$ZeroPackage-".Length) -replace '\.tgz$', ''
}

function Resolve-ZeroVersion([string]$RequestedVersion) {
    $channel = $ZeroReleaseChannel
    if ($RequestedVersion) {
        if ($RequestedVersion -eq 'stable' -or $RequestedVersion -eq 'beta') {
            $channel = $RequestedVersion
        } else {
            $version = ConvertTo-ZeroVersion $RequestedVersion
            return [PSCustomObject]@{ Version = $version; Tag = "v$version" }
        }
    } elseif ($env:ZERO_VERSION) {
        $version = ConvertTo-ZeroVersion $env:ZERO_VERSION
        return [PSCustomObject]@{ Version = $version; Tag = "v$version" }
    }

    if ($channel -ne 'stable' -and $channel -ne 'beta') {
        Write-ZeroError "invalid Zero release channel: $channel"
        exit 1
    }

    Write-ZeroInfo "Resolving the $channel release..."
    if ($channel -eq 'beta') {
        $resolvedVersion = Resolve-ZeroBetaVersion
        $resolvedTag = 'beta'
    } else {
        $resolvedTag = Resolve-ZeroStableTag
        $resolvedVersion = if ($resolvedTag) { $resolvedTag.TrimStart('v') } else { $null }
    }

    if (-not $resolvedVersion -or -not $resolvedTag) {
        Write-ZeroError "could not resolve the latest Zero release from $ZeroRepo"
        exit 1
    }

    return [PSCustomObject]@{ Version = (ConvertTo-ZeroVersion $resolvedVersion); Tag = $resolvedTag }
}

function Get-ZeroReleaseAssets([string]$Version, [string]$Tag, [string]$DownloadDir) {
    $assetNames = @(
        "$ZeroPackage-$Version.tgz",
        "zero-ai-$Version.tgz",
        "zero-core-$Version.tgz",
        "zero-tui-$Version.tgz",
        'SHA256SUMS'
    )
    foreach ($assetName in $assetNames) {
        $destination = Join-Path $DownloadDir $assetName
        $url = "https://github.com/$ZeroRepo/releases/download/$Tag/$assetName"
        Write-ZeroInfo "Downloading $assetName..."
        try {
            Invoke-ZeroWithRetry -Action { Invoke-WebRequest -Uri $url -OutFile $destination -UseBasicParsing }
        } catch {
            Write-ZeroError "could not download $assetName from the $Tag release. $($_.Exception.Message)"
            exit 1
        }
    }
}

# SHA256SUMS uses the standard `sha256sum` output format: "<hex digest>  <filename>".
function Test-ZeroPackageChecksums([string]$DownloadDir) {
    Write-ZeroInfo 'Verifying download checksums...'
    $sumsPath = Join-Path $DownloadDir 'SHA256SUMS'
    $expected = @{}
    foreach ($line in Get-Content $sumsPath) {
        if ($line -match '^([0-9a-fA-F]{64})\s+\*?(.+)$') {
            $expected[$Matches[2].Trim()] = $Matches[1].ToLowerInvariant()
        }
    }

    $tarballs = @("$ZeroPackage-$Version.tgz", "zero-ai-$Version.tgz", "zero-core-$Version.tgz", "zero-tui-$Version.tgz")
    foreach ($name in $tarballs) {
        $expectedHash = $expected[$name]
        if (-not $expectedHash) {
            Write-ZeroError "SHA256SUMS has no entry for $name"
            exit 1
        }
        $actualHash = (Get-FileHash -Algorithm SHA256 -Path (Join-Path $DownloadDir $name)).Hash.ToLowerInvariant()
        if ($actualHash -ne $expectedHash) {
            Write-ZeroError "checksum mismatch for $name (expected $expectedHash, got $actualHash)"
            exit 1
        }
    }
}

function Install-ZeroPackage([string]$TarballPath, [bool]$BootstrapKernel) {
    Write-ZeroInfo 'Installing Zero with npm...'
    $previousBootstrapTools = $env:ZERO_BOOTSTRAP_TOOLS_ON_INSTALL
    $previousBootstrapKernel = $env:ZERO_BOOTSTRAP_KERNEL_ON_INSTALL
    $previousInstallUv = $env:ZERO_INSTALL_UV
    try {
        $env:ZERO_BOOTSTRAP_TOOLS_ON_INSTALL = '1'
        if ($BootstrapKernel) {
            $env:ZERO_BOOTSTRAP_KERNEL_ON_INSTALL = '1'
            $env:ZERO_INSTALL_UV = '1'
        }
        & npm install -g --no-fund --no-audit --loglevel=error --progress=false $TarballPath
        if ($LASTEXITCODE -ne 0) {
            throw "npm install -g exited with code $LASTEXITCODE"
        }
    } finally {
        $env:ZERO_BOOTSTRAP_TOOLS_ON_INSTALL = $previousBootstrapTools
        $env:ZERO_BOOTSTRAP_KERNEL_ON_INSTALL = $previousBootstrapKernel
        $env:ZERO_INSTALL_UV = $previousInstallUv
    }
}

function Main {
    Write-Host ''
    Write-Host 'Installing Zero' -ForegroundColor Magenta
    Write-Host 'npm global install' -ForegroundColor DarkGray
    Write-Host ''

    Assert-NodeAndNpmAvailable

    $existingZero = Get-Command $ZeroCmd -ErrorAction SilentlyContinue
    if ($existingZero) {
        Write-ZeroWarn "Existing $ZeroCmd found at: $($existingZero.Source)"
    }

    $resolved = Resolve-ZeroVersion $Version
    $version = $resolved.Version
    $tag = $resolved.Tag

    if (-not (Confirm-ZeroAction "Install Zero v$version globally with npm?" 'Downloads the verified release and runs npm install -g.')) {
        Write-Host 'Installation cancelled.'
        exit 0
    }

    $bootstrapKernel = $false
    switch ($env:ZERO_BOOTSTRAP_KERNEL_ON_INSTALL) {
        '1' { $bootstrapKernel = $true }
        '0' { $bootstrapKernel = $false }
        default {
            $bootstrapKernel = Confirm-ZeroAction 'Prepare IPython runtime now?' 'Installs uv, Python 3.11, ipykernel, and the Zero runtime.'
        }
    }

    $downloadDir = Join-Path ([System.IO.Path]::GetTempPath()) "zero-install-$([guid]::NewGuid().ToString('N').Substring(0, 8))"
    New-Item -ItemType Directory -Path $downloadDir -Force | Out-Null
    try {
        Get-ZeroReleaseAssets -Version $version -Tag $tag -DownloadDir $downloadDir
        Test-ZeroPackageChecksums -DownloadDir $downloadDir
        $tarballPath = Join-Path $downloadDir "$ZeroPackage-$version.tgz"
        Install-ZeroPackage -TarballPath $tarballPath -BootstrapKernel $bootstrapKernel
    } finally {
        Remove-Item -Recurse -Force $downloadDir -ErrorAction SilentlyContinue
    }

    $installedZero = Get-Command $ZeroCmd -ErrorAction SilentlyContinue
    Write-Host ''
    if ($installedZero) {
        Write-Host 'Zero was installed successfully.' -ForegroundColor Green
        Write-Host "Run it with: $ZeroCmd"
    } else {
        Write-Host 'Zero was installed successfully.' -ForegroundColor Green
        Write-Host "The $ZeroCmd command was installed, but it is not on your PATH yet."
        Write-Host "Check npm's global bin directory with:"
        Write-Host ''
        Write-Host '  npm prefix -g'
        Write-Host ''
        Write-Host 'Then add that directory to your PATH, or restart your shell.'
    }
}

Main
