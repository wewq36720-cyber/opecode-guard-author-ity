[CmdletBinding()]
param(
    [string]$Python = "python",
    [string]$ConfigRoot = "",
    [switch]$DryRun,
    [switch]$RemovePythonPackage
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repo = Split-Path -Parent $PSScriptRoot
if (-not $ConfigRoot) {
    $base = if ($env:XDG_CONFIG_HOME) { $env:XDG_CONFIG_HOME } else { Join-Path $HOME ".config" }
    $ConfigRoot = Join-Path $base "opencode"
}
$ConfigRoot = [IO.Path]::GetFullPath($ConfigRoot)
$pluginDir = Join-Path $ConfigRoot "plugins"
$target = Join-Path $pluginDir "opencode-guard-authority.js"
$bundle = Join-Path $pluginDir "opencode-guard-authority"
$manifest = Join-Path $pluginDir "opencode-guard-authority.install.json"
$backup = Join-Path $pluginDir "opencode-guard-authority.js.before-guard"
$ownedRelative = @(
    "opencode-guard-authority.js",
    "opencode-guard-authority/client.js",
    "opencode-guard-authority/hooks.js",
    "opencode-guard-authority/index.js",
    "opencode-guard-authority/schemas.js",
    "opencode-guard-authority/tools.js"
)

function Assert-PluginChild([string]$Path) {
    $root = [IO.Path]::GetFullPath($pluginDir).TrimEnd("\")
    $candidate = [IO.Path]::GetFullPath($Path)
    if (-not $candidate.StartsWith($root + "\", [StringComparison]::OrdinalIgnoreCase)) {
        throw "Plugin path escaped its directory: $candidate"
    }
}

function Read-Ownership {
    if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) {
        if ((Test-Path -LiteralPath $target -PathType Leaf) -or
            (Test-Path -LiteralPath $bundle) -or
            (Test-Path -LiteralPath $backup -PathType Leaf)) {
            throw "Guard installation exists without an ownership manifest: $pluginDir"
        }
        return $null
    }
    try { $ownership = Get-Content -Raw -LiteralPath $manifest | ConvertFrom-Json }
    catch { throw "Guard ownership manifest is invalid: $manifest" }
    if ($ownership.owner -ne "opencode-guard-authority" -or $null -eq $ownership.files) {
        throw "Guard ownership manifest is not the minimal bundle format: $manifest"
    }
    $actualNames = @($ownership.files.PSObject.Properties.Name | Sort-Object)
    $expectedNames = @($ownedRelative | Sort-Object)
    if (Compare-Object $actualNames $expectedNames) {
        throw "Guard ownership manifest has an unexpected file set: $manifest"
    }
    foreach ($relative in $ownedRelative) {
        $path = Join-Path $pluginDir ($relative -replace "/", "\")
        Assert-PluginChild $path
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Owned Guard file is missing: $path"
        }
        $expected = ([string]$ownership.files.$relative).ToLowerInvariant()
        $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant()
        if ($actual -ne $expected) { throw "Owned Guard file changed after installation: $path" }
    }
    if ([bool]$ownership.had_previous -and -not (Test-Path -LiteralPath $backup -PathType Leaf)) {
        throw "Guard backup declared by the manifest is missing: $backup"
    }
    return $ownership
}

$ownership = Read-Ownership
if ($DryRun) {
    [pscustomobject]@{
        installed = $null -ne $ownership
        plugin = $target
        bundle = $bundle
        manifest = $manifest
        restores_previous_plugin = if ($null -ne $ownership) { [bool]$ownership.had_previous } else { $false }
        removes_python_package = [bool]$RemovePythonPackage
    } | ConvertTo-Json
    exit 0
}

if ($null -ne $ownership) {
    Assert-PluginChild $bundle
    Assert-PluginChild $target
    Assert-PluginChild $manifest
    Remove-Item -LiteralPath $bundle -Recurse -Force
    Remove-Item -LiteralPath $target -Force
    Remove-Item -LiteralPath $manifest -Force
    if ([bool]$ownership.had_previous) {
        Move-Item -LiteralPath $backup -Destination $target -Force
    }
}

if ($RemovePythonPackage) {
    & $Python -m pip uninstall -y opencode-guard-authority
    if ($LASTEXITCODE -ne 0) { throw "Python package removal failed." }
}

[pscustomobject]@{
    removed = $null -ne $ownership
    plugin = $target
    bundle = $bundle
    manifest = $manifest
    restored_previous_plugin = if ($null -ne $ownership) { [bool]$ownership.had_previous } else { $false }
    python_package_removed = [bool]$RemovePythonPackage
} | ConvertTo-Json
