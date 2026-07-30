[CmdletBinding()]
param(
    [string]$Python = "python",
    [string]$Npm = "npm",
    [string]$ConfigRoot = "",
    [switch]$DryRun,
    [switch]$SkipPythonInstall,
    [switch]$SkipNodeInstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$utf8 = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = $utf8
$OutputEncoding = $utf8

$repo = Split-Path -Parent $PSScriptRoot
if (-not $ConfigRoot) {
    $base = if ($env:XDG_CONFIG_HOME) { $env:XDG_CONFIG_HOME } else { Join-Path $HOME ".config" }
    $ConfigRoot = Join-Path $base "opencode"
}
$ConfigRoot = [IO.Path]::GetFullPath($ConfigRoot)
$sourceDir = Join-Path $repo "opencode-plugin"
$pluginDir = Join-Path $ConfigRoot "plugins"
$target = Join-Path $pluginDir "opencode-guard-authority.js"
$bundle = Join-Path $pluginDir "opencode-guard-authority"
$manifest = Join-Path $pluginDir "opencode-guard-authority.install.json"
$backup = Join-Path $pluginDir "opencode-guard-authority.js.before-guard"
$sourceNames = @("index.js", "client.js", "hooks.js", "tools.js", "schemas.js")
$ownedRelative = @(
    "opencode-guard-authority.js",
    "opencode-guard-authority/client.js",
    "opencode-guard-authority/hooks.js",
    "opencode-guard-authority/index.js",
    "opencode-guard-authority/schemas.js",
    "opencode-guard-authority/tools.js"
)
$loaderContent = 'export { OpenCodeGuardAuthority } from "./opencode-guard-authority/index.js";' + "`n"

function Assert-PluginChild([string]$Path) {
    $root = [IO.Path]::GetFullPath($pluginDir).TrimEnd("\")
    $candidate = [IO.Path]::GetFullPath($Path)
    if (-not $candidate.StartsWith($root + "\", [StringComparison]::OrdinalIgnoreCase)) {
        throw "Plugin path escaped its directory: $candidate"
    }
}

function Get-GuardOwnership {
    if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) {
        if (Test-Path -LiteralPath $bundle) { throw "Unowned Guard bundle exists: $bundle" }
        if (Test-Path -LiteralPath $backup) { throw "Unowned Guard backup exists: $backup" }
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
        $expected = [string]$ownership.files.$relative
        $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant()
        if ($actual -ne $expected) { throw "Owned Guard file changed after installation: $path" }
    }
    if ([bool]$ownership.had_previous -and -not (Test-Path -LiteralPath $backup -PathType Leaf)) {
        throw "Guard backup declared by the manifest is missing: $backup"
    }
    return $ownership
}

function Assert-PythonInstall {
    $sourcePackage = [IO.Path]::GetFullPath((Join-Path $repo "src\opencode_guardian"))
    $moduleOutput = @(& $Python -I -c "import opencode_guardian.contracts as c; print(c.__file__)" 2>&1)
    if ($LASTEXITCODE -ne 0 -or $moduleOutput.Count -eq 0) {
        throw "Installed Guard Python module could not be imported in isolated mode."
    }
    $installedContracts = [IO.Path]::GetFullPath([string]$moduleOutput[-1])
    if (-not (Test-Path -LiteralPath $installedContracts -PathType Leaf)) {
        throw "Installed Guard contracts module was not a file: $installedContracts"
    }
    $installedPackage = Split-Path -Parent $installedContracts
    $sourceFiles = @(Get-ChildItem -LiteralPath $sourcePackage -Recurse -File -Filter "*.py")
    $installedFiles = @(Get-ChildItem -LiteralPath $installedPackage -Recurse -File -Filter "*.py")
    $sourceRelative = @($sourceFiles | ForEach-Object {
        $_.FullName.Substring($sourcePackage.Length + 1).Replace("\", "/")
    } | Sort-Object)
    $installedRelative = @($installedFiles | ForEach-Object {
        $_.FullName.Substring($installedPackage.Length + 1).Replace("\", "/")
    } | Sort-Object)
    if (Compare-Object $sourceRelative $installedRelative) {
        throw "Installed Guard Python package does not match repository source."
    }
    foreach ($relative in $sourceRelative) {
        $sourceDigest = (Get-FileHash -Algorithm SHA256 -LiteralPath (
            Join-Path $sourcePackage ($relative -replace "/", "\")
        )).Hash
        $installedDigest = (Get-FileHash -Algorithm SHA256 -LiteralPath (
            Join-Path $installedPackage ($relative -replace "/", "\")
        )).Hash
        if ($sourceDigest -ne $installedDigest) {
            throw "Installed Guard Python package does not match repository source."
        }
    }
}

foreach ($name in $sourceNames) {
    $source = Join-Path $sourceDir $name
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw "Plugin source not found: $source"
    }
}

if ($DryRun) {
    [pscustomobject]@{
        repository = $repo
        python_package = $repo + "[mcp]"
        plugin_sources = @($sourceNames | ForEach-Object { Join-Path $sourceDir $_ })
        plugin_target = $target
        plugin_bundle = $bundle
        modifies_jsonc = $false
    } | ConvertTo-Json -Depth 4
    exit 0
}

$preflightOwnership = Get-GuardOwnership
if (-not $SkipPythonInstall) {
    & $Python -m pip install ($repo + "[mcp]")
    if ($LASTEXITCODE -ne 0) { throw "Python package installation failed." }
}
Assert-PythonInstall
if (-not $SkipNodeInstall) {
    New-Item -ItemType Directory -Force -Path $ConfigRoot | Out-Null
    Push-Location $ConfigRoot
    try {
        & $Npm install --ignore-scripts --save-exact "@opencode-ai/plugin@1.18.3"
        if ($LASTEXITCODE -ne 0) { throw "OpenCode plugin dependency installation failed." }
    }
    finally { Pop-Location }
}

New-Item -ItemType Directory -Force -Path $pluginDir | Out-Null
$ownership = Get-GuardOwnership
if (($null -eq $preflightOwnership) -ne ($null -eq $ownership)) {
    throw "Guard ownership changed during dependency installation."
}
$hadPrevious = if ($null -ne $ownership) { [bool]$ownership.had_previous } else { $false }
if ($null -eq $ownership -and (Test-Path -LiteralPath $target -PathType Leaf)) {
    Copy-Item -LiteralPath $target -Destination $backup
    $hadPrevious = $true
}

$temporaryBundle = "$bundle.installing.$PID"
$rollbackBundle = "$bundle.rollback.$PID"
$temporaryLoader = "$target.installing.$PID"
$rollbackLoader = "$target.rollback.$PID"
$temporaryManifest = "$manifest.installing.$PID"
foreach ($path in @($temporaryBundle, $rollbackBundle)) { Assert-PluginChild $path }

try {
    if (Test-Path -LiteralPath $bundle) { Copy-Item -LiteralPath $bundle -Destination $rollbackBundle -Recurse }
    if (Test-Path -LiteralPath $target -PathType Leaf) {
        Copy-Item -LiteralPath $target -Destination $rollbackLoader -Force
    }
    New-Item -ItemType Directory -Path $temporaryBundle -Force | Out-Null
    foreach ($name in $sourceNames) {
        Copy-Item -LiteralPath (Join-Path $sourceDir $name) -Destination $temporaryBundle -Force
    }
    [IO.File]::WriteAllText(
        $temporaryLoader,
        $loaderContent,
        [Text.UTF8Encoding]::new($false)
    )
    if (Test-Path -LiteralPath $bundle) {
        Assert-PluginChild $bundle
        Remove-Item -LiteralPath $bundle -Recurse -Force
    }
    Move-Item -LiteralPath $temporaryBundle -Destination $bundle
    Move-Item -LiteralPath $temporaryLoader -Destination $target -Force

    $files = [ordered]@{}
    foreach ($relative in $ownedRelative) {
        $path = Join-Path $pluginDir ($relative -replace "/", "\")
        $files[$relative] = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant()
    }
    [pscustomobject]@{
        owner = "opencode-guard-authority"
        package_version = "2.0.0-alpha.1"
        files = $files
        had_previous = $hadPrevious
        backup_file = if ($hadPrevious) { Split-Path -Leaf $backup } else { "" }
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $temporaryManifest -Encoding UTF8
    Move-Item -LiteralPath $temporaryManifest -Destination $manifest -Force
}
catch {
    if (Test-Path -LiteralPath $bundle) {
        Assert-PluginChild $bundle
        Remove-Item -LiteralPath $bundle -Recurse -Force
    }
    if (Test-Path -LiteralPath $rollbackBundle) {
        Move-Item -LiteralPath $rollbackBundle -Destination $bundle
    }
    if (Test-Path -LiteralPath $rollbackLoader -PathType Leaf) {
        Move-Item -LiteralPath $rollbackLoader -Destination $target -Force
    }
    elseif (Test-Path -LiteralPath $target -PathType Leaf) {
        Remove-Item -LiteralPath $target -Force
    }
    throw
}
finally {
    foreach ($path in @($temporaryBundle, $rollbackBundle)) {
        if (Test-Path -LiteralPath $path) {
            Assert-PluginChild $path
            Remove-Item -LiteralPath $path -Recurse -Force
        }
    }
    foreach ($path in @($temporaryLoader, $rollbackLoader, $temporaryManifest)) {
        if (Test-Path -LiteralPath $path -PathType Leaf) { Remove-Item -LiteralPath $path -Force }
    }
}

[pscustomobject]@{
    installed = $true
    plugin = $target
    bundle = $bundle
    manifest = $manifest
    files = $ownedRelative.Count
    previous_plugin_backed_up = $hadPrevious
    modifies_jsonc = $false
} | ConvertTo-Json
