#requires -Version 5.1
<#
.SYNOPSIS
    Zero Windows installer (T-INST-02; INST-02, INST-04, INST-05, INST-06).

.DESCRIPTION
    Installs one already-downloaded executable after verifying its SHA-256.
    The installer is non-interactive and non-admin: it never elevates, never
    prompts, and never reads stdin. It writes one file under a user prefix
    (by default %LOCALAPPDATA%\Zero), stages it beside the target, re-hashes the
    staged copy, and renames it into place.

    Downloading, archive decoding, and Ed25519 manifest verification stay in
    the release tooling; this script trusts the bytes only because the caller
    passes the artifact's SHA-256.

.EXAMPLE
    powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass `
        -File installer/windows.ps1 -File .\zero.exe `
        -Sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass `
        -File installer/windows.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    [string]$Prefix = '',
    [string]$File,
    [string]$Name = 'zero',
    [string]$Sha256,
    [switch]$Force,
    [switch]$Uninstall,
    [switch]$NoPath,
    [switch]$UpdatePath,
    [switch]$WhatIf,
    [switch]$Help
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$ProgName = 'zero-windows-install'
$script:StopCode = $null
$script:StopMessage = ''
$script:LockStream = $null
$script:LockPath = $null
$script:LockHeld = $false
$script:TempPath = $null

# The user PATH value is bounded so an update can never produce an
# environment block a process cannot load.
$MaxUserPathChars = 8192

function Write-Say {
    param([string]$Message)
    [Console]::Out.WriteLine($Message)
}

function Write-Warn {
    param([string]$Message)
    [Console]::Error.WriteLine("$ProgName`: $Message")
}

# Stop the script with one of the documented exit codes. The outer catch turns
# this into a message and an exit status; the outer finally always cleans up
# the lock and the staged file.
function Stop-Installer {
    param([int]$Code, [string]$Message)
    $script:StopCode = $Code
    $script:StopMessage = $Message
    throw 'zero-installer-stop'
}

function Show-Usage {
    Write-Say @'
usage: powershell -NoProfile -ExecutionPolicy Bypass -File installer/windows.ps1 [options]

Install or remove one Zero executable without administrator rights.

options:
  -Prefix DIR     install root; the executable goes directly in DIR
                  (default: %LOCALAPPDATA%\Zero). Must be an absolute path
                  this user can write.
  -File PATH      artifact to install (required unless -Uninstall)
  -Name NAME      installed executable name (default: zero; .exe is added when
                  NAME has no extension)
  -Sha256 HEX     expected SHA-256 of -File, 64 hex characters (required)
  -Force          replace an existing binary that has different content
  -Uninstall      remove the installed binary and the lock; keep user data
  -NoPath         do not print PATH guidance and never change the user PATH
  -UpdatePath     append the install directory to the user PATH, once
  -WhatIf         print what would happen and change nothing
  -Help           print this help

safety:
  the checksum is verified before anything is written, the install is staged
  beside the target and renamed atomically, an exclusive lock file refuses
  concurrent installs, and a finally block removes the staged file and the
  lock. Nothing is ever prompted and stdin is never read. The script never
  elevates: Program Files, System32, the Windows directory, and a drive root
  are refused with user-prefix guidance.

exit codes: 0 ok, 2 usage, 3 refused (lock, checksum, conflict, permissions)
'@
}

function Test-SameOrUnder {
    param([string]$Path, [string]$Root)
    if ([string]::IsNullOrWhiteSpace($Root)) {
        return $false
    }
    $rootText = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    $pathText = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    if ([string]::Equals($pathText, $rootText, [StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }
    return $pathText.StartsWith($rootText + '\', [StringComparison]::OrdinalIgnoreCase)
}

function Normalize-Prefix {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
            Stop-Installer 2 'LOCALAPPDATA is not set; pass -Prefix explicitly'
        }
        $Value = Join-Path $env:LOCALAPPDATA 'Zero'
    }

    $expanded = [Environment]::ExpandEnvironmentVariables($Value.Trim())
    if ($expanded -eq '~') {
        $expanded = $HOME
    } elseif ($expanded.StartsWith('~\') -or $expanded.StartsWith('~/')) {
        $expanded = Join-Path $HOME $expanded.Substring(2)
    }

    if ($expanded -notmatch '^(?:[A-Za-z]:[\\/]|\\\\)') {
        Stop-Installer 2 "-Prefix must be an absolute path; choose '$env:LOCALAPPDATA\Zero'"
    }
    if (($expanded -split '[\\/]') -contains '..') {
        Stop-Installer 2 "-Prefix must not contain a '..' component"
    }

    $full = [IO.Path]::GetFullPath($expanded).TrimEnd('\')
    if ($full -match '^[A-Za-z]:$') {
        Stop-Installer 3 "refusing to install into the drive root $full; choose a user prefix such as '$env:LOCALAPPDATA\Zero'"
    }

    $protected = @()
    foreach ($candidate in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:SystemRoot, $env:CommonProgramFiles, ${env:CommonProgramFiles(x86)})) {
        if (-not [string]::IsNullOrWhiteSpace($candidate)) {
            $protected += $candidate
        }
    }
    $windowsRoot = $env:SystemRoot
    if ([string]::IsNullOrWhiteSpace($windowsRoot)) {
        $windowsRoot = 'C:\Windows'
    }
    $protected += (Join-Path $windowsRoot 'System32')

    foreach ($root in $protected) {
        if (Test-SameOrUnder -Path $full -Root $root) {
            Stop-Installer 3 "refusing to install into ${full}: that location needs administrator rights; choose a user prefix such as '$env:LOCALAPPDATA\Zero'"
        }
    }

    return $full
}

function Assert-PlainName {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) {
        Stop-Installer 2 '-Name must not be empty'
    }
    if ($Value -eq '.' -or $Value -eq '..') {
        Stop-Installer 2 "-Name must be a plain file name"
    }
    if ($Value.IndexOfAny([char[]]@('\', '/', ':', '*', '?', '"', '<', '>', '|')) -ge 0) {
        Stop-Installer 2 '-Name must be a plain file name without a path separator or reserved character'
    }
    if ($Value -match '[\x00-\x1f]') {
        Stop-Installer 2 '-Name must not contain a control character'
    }
    if ($Value.EndsWith('.') -or $Value.EndsWith(' ')) {
        Stop-Installer 2 '-Name must not end with a dot or a space'
    }
    $stem = ($Value -split '\.')[0].ToUpperInvariant()
    if ($stem -match '^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$') {
        Stop-Installer 2 "-Name must not use the reserved Windows device name $stem"
    }
}

function Assert-UserWritable {
    param([string]$Path)

    $probeRoot = $Path
    while ($probeRoot -and -not (Test-Path -LiteralPath $probeRoot)) {
        $parent = Split-Path -Parent $probeRoot
        if ([string]::IsNullOrEmpty($parent) -or $parent -eq $probeRoot) {
            break
        }
        $probeRoot = $parent
    }
    if ([string]::IsNullOrEmpty($probeRoot) -or -not (Test-Path -LiteralPath $probeRoot -PathType Container)) {
        Stop-Installer 3 "cannot find a writable parent for $Path; choose a user prefix such as '$env:LOCALAPPDATA\Zero'"
    }

    $probeFile = Join-Path $probeRoot ('.zero-write-probe-' + $PID)
    try {
        [IO.File]::WriteAllText($probeFile, 'probe')
    } catch {
        Stop-Installer 3 "refusing to install into ${Path}: that location needs administrator rights; choose a user prefix such as '$env:LOCALAPPDATA\Zero'"
    } finally {
        if (Test-Path -LiteralPath $probeFile) {
            Remove-Item -LiteralPath $probeFile -Force -ErrorAction SilentlyContinue
        }
    }
}

# Take an exclusive lock file. CreateNew plus FileShare.None means two
# installers cannot both hold it. A lock whose PID is dead is stale and is
# removed; a lock that cannot be read is held by a live installer.
function Enter-InstallLock {
    param([string]$Path)

    $script:LockPath = $Path
    $stream = $null

    try {
        $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    } catch {
        if (-not (Test-Path -LiteralPath $Path)) {
            Stop-Installer 3 "could not create the install lock at $Path`: $($_.Exception.Message)"
        }

        $existing = $null
        try {
            $existing = [IO.File]::ReadAllText($Path)
        } catch {
            $existing = $null
        }
        if ($null -eq $existing) {
            Stop-Installer 3 "another install is already running for $Prefix; wait for it, or remove $Path"
        }

        $owner = 0
        $hasOwner = [int]::TryParse($existing.Trim(), [ref]$owner)
        $alive = $false
        if ($hasOwner -and $owner -gt 0) {
            try {
                $process = Get-Process -Id $owner -ErrorAction SilentlyContinue
                $alive = ($null -ne $process)
            } catch {
                # A process we cannot inspect is treated as live rather than
                # stealing its lock.
                $alive = $true
            }
        }
        if ($alive) {
            Stop-Installer 3 "another install is already running for $Prefix (pid $owner); wait for it, or remove $Path"
        }

        Write-Say "removing a stale install lock at $Path"
        try {
            Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
        } catch {
            Stop-Installer 3 "could not clear the stale install lock at $Path"
        }
        try {
            $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        } catch {
            Stop-Installer 3 "another install took the lock for $Prefix"
        }
    }

    try {
        $bytes = [Text.Encoding]::ASCII.GetBytes("$PID`n")
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush()
    } catch {
        try { $stream.Dispose() } catch { }
        try { Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue } catch { }
        Stop-Installer 3 "could not write the install lock at $Path"
    }

    $script:LockStream = $stream
    $script:LockHeld = $true
}

function Exit-InstallLock {
    if ($null -ne $script:LockStream) {
        try { $script:LockStream.Dispose() } catch { }
        $script:LockStream = $null
    }
    if ($script:LockHeld -and -not [string]::IsNullOrEmpty($script:LockPath)) {
        Remove-Item -LiteralPath $script:LockPath -Force -ErrorAction SilentlyContinue
    }
    $script:LockHeld = $false
}

function Get-UserPath {
    $value = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($null -eq $value) {
        return ''
    }
    return [string]$value
}

function Test-PathEntry {
    param([string]$Value, [string]$Entry)
    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $false
    }
    $wanted = $Entry.TrimEnd('\')
    foreach ($part in $Value.Split(';')) {
        $trimmed = $part.Trim()
        if ($trimmed.Length -eq 0) {
            continue
        }
        if ([string]::Equals($trimmed.TrimEnd('\'), $wanted, [StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

# Append the install directory to the *user* PATH only. The machine PATH is
# never read with write intent and never changed. A value that would exceed the
# bound prints manual guidance instead of being written.
function Add-UserPath {
    param([string]$Entry)

    $current = Get-UserPath
    if (Test-PathEntry -Value $current -Entry $Entry) {
        Write-Say "the user PATH already contains $Entry"
        return
    }

    $base = $current.TrimEnd(';')
    if ($base.Length -gt 0) {
        $combined = $base + ';' + $Entry
    } else {
        $combined = $Entry
    }
    if ($combined.Length -gt $MaxUserPathChars) {
        Write-Warn "the user PATH would be $($combined.Length) characters, above the $MaxUserPathChars character limit; add this directory manually: $Entry"
        return
    }

    try {
        [Environment]::SetEnvironmentVariable('Path', $combined, 'User')
    } catch {
        Write-Warn "the user PATH could not be updated: $($_.Exception.Message)"
        Write-Warn "add this directory manually: $Entry"
        return
    }

    if (-not (Test-PathEntry -Value (Get-UserPath) -Entry $Entry)) {
        Write-Warn "the user PATH update could not be verified; add this directory manually: $Entry"
        return
    }
    Write-Say "appended $Entry to the user PATH"
    Write-Say "sign out and back in (or open a new terminal) to use it"
}

function Show-PathGuidance {
    if ($NoPath) {
        return
    }
    Write-Say ''
    if (Test-PathEntry -Value (Get-UserPath) -Entry $Prefix) {
        Write-Say "PATH: $Prefix is already in the user PATH"
    } else {
        Write-Say 'PATH: add this directory to your user PATH:'
        Write-Say "  $Prefix"
    }

    if ($UpdatePath) {
        Add-UserPath -Entry $Prefix
    } else {
        Write-Say 'the user PATH was not changed; pass -UpdatePath to add it'
        Write-Say "manual step: [Environment]::SetEnvironmentVariable('Path', [Environment]::GetEnvironmentVariable('Path','User') + ';$Prefix', 'User')"
    }
}

function Invoke-Main {
    if ($Help) {
        Show-Usage
        return 0
    }
    if ($NoPath -and $UpdatePath) {
        Stop-Installer 2 '-NoPath and -UpdatePath cannot be combined'
    }

    $installPrefix = Normalize-Prefix -Value $Prefix
    Assert-PlainName -Value $Name
    $installedName = $Name
    if ([string]::IsNullOrEmpty([IO.Path]::GetExtension($installedName))) {
        $installedName = $Name + '.exe'
    }

    $target = Join-Path $installPrefix $installedName
    $lockPath = Join-Path $installPrefix '.zero-install.lock'

    if ($Uninstall) {
        if (-not (Test-Path -LiteralPath $installPrefix)) {
            Write-Say "nothing to uninstall: $installPrefix does not exist"
            return 0
        }
        if (-not (Test-Path -LiteralPath $installPrefix -PathType Container)) {
            Stop-Installer 3 "the prefix $installPrefix is not a directory"
        }
        if ($WhatIf) {
            Write-Say "would remove $target and $lockPath; user data and configuration are kept"
            return 0
        }

        Enter-InstallLock -Path $lockPath
        if (Test-Path -LiteralPath $target) {
            try {
                Remove-Item -LiteralPath $target -Force -ErrorAction Stop
            } catch {
                Stop-Installer 3 "could not remove $target`: $($_.Exception.Message)"
            }
            Write-Say "removed $target"
        } else {
            Write-Say "not installed: $target"
        }
        Exit-InstallLock
        Write-Say ''
        Write-Say 'Kept: user data and configuration. Nothing under the Zero data directories was touched.'
        Write-Say 'Reinstall with -File and -Sha256 when needed.'
        return 0
    }

    if ([string]::IsNullOrWhiteSpace($File)) {
        Stop-Installer 2 '-File is required to install'
    }
    if ([string]::IsNullOrWhiteSpace($Sha256)) {
        Stop-Installer 2 '-Sha256 is required to install'
    }
    if ($Sha256 -notmatch '^[0-9A-Fa-f]{64}$') {
        Stop-Installer 2 '-Sha256 must be exactly 64 hexadecimal characters'
    }
    $expected = $Sha256.ToLowerInvariant()

    if (-not (Test-Path -LiteralPath $File -PathType Leaf)) {
        Stop-Installer 2 "artifact not found: $File"
    }

    try {
        $actual = (Get-FileHash -LiteralPath $File -Algorithm SHA256).Hash.ToLowerInvariant()
    } catch {
        Stop-Installer 3 "could not hash the artifact $File`: $($_.Exception.Message)"
    }
    if ($actual -ne $expected) {
        Write-Warn "checksum mismatch for $File"
        Write-Warn "  expected $expected"
        Write-Warn "  actual   $actual"
        Stop-Installer 3 'refusing to install an artifact that does not match -Sha256'
    }

    if ($WhatIf) {
        Write-Say "would install $File to $target (sha256 $expected)"
        if ($UpdatePath) {
            Write-Say "would add $installPrefix to the user PATH"
        }
        return 0
    }

    Assert-UserWritable -Path $installPrefix

    try {
        New-Item -ItemType Directory -Path $installPrefix -Force | Out-Null
    } catch {
        Stop-Installer 3 "cannot create $installPrefix without administrator rights; choose a user prefix such as '$env:LOCALAPPDATA\Zero'"
    }
    if (-not (Test-Path -LiteralPath $installPrefix -PathType Container)) {
        Stop-Installer 3 "cannot write to $installPrefix; choose a user prefix such as '$env:LOCALAPPDATA\Zero'"
    }

    Enter-InstallLock -Path $lockPath

    if (Test-Path -LiteralPath $target) {
        if (-not (Test-Path -LiteralPath $target -PathType Leaf)) {
            Stop-Installer 3 "$target exists and is not a file; remove it before installing"
        }
        $existing = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($existing -eq $expected) {
            Write-Say "already installed: $target (identical sha256)"
            Show-PathGuidance
            Write-Say ''
            Write-Say 'mode: non-interactive (no prompts were shown)'
            return 0
        }
        if (-not $Force) {
            Stop-Installer 3 "$target already exists with different content; pass -Force to replace it"
        }
        Write-Say "replacing $target (-Force)"
    }

    $temp = Join-Path $installPrefix ('.{0}.tmp.{1}' -f $installedName, $PID)
    $script:TempPath = $temp
    try {
        Copy-Item -LiteralPath $File -Destination $temp -Force
        $copied = (Get-FileHash -LiteralPath $temp -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($copied -ne $expected) {
            Stop-Installer 3 'the staged copy does not match -Sha256'
        }
        Move-Item -LiteralPath $temp -Destination $target -Force
        $script:TempPath = $null
    } catch {
        if ($null -ne $script:StopCode) {
            throw
        }
        Stop-Installer 3 "could not stage the binary into $installPrefix`: $($_.Exception.Message)"
    } finally {
        if (-not [string]::IsNullOrEmpty($script:TempPath) -and (Test-Path -LiteralPath $script:TempPath)) {
            Remove-Item -LiteralPath $script:TempPath -Force -ErrorAction SilentlyContinue
        }
    }

    Write-Say "installed $target"
    Show-PathGuidance
    Write-Say ''
    Write-Say 'mode: non-interactive (no prompts were shown)'
    Write-Say "verify: $target --version"
    return 0
}

$finalCode = 0
try {
    $finalCode = Invoke-Main
} catch {
    if ($null -ne $script:StopCode) {
        Write-Warn $script:StopMessage
        $finalCode = [int]$script:StopCode
    } else {
        Write-Warn $_.Exception.Message
        $finalCode = 3
    }
} finally {
    Exit-InstallLock
}

exit $finalCode
