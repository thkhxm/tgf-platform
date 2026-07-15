[CmdletBinding()]
param(
    [ValidatePattern('^v[0-9]+\.[0-9]+\.[0-9]+$')]
    [string]$ExpectedCoreVersion = 'v0.1.1'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$coreModulePath = 'github.com/thkhxm/tgf-platform/core'
$platformNames = @(
    'alipay',
    'apple',
    'douyin',
    'facebook',
    'google',
    'huawei',
    'line',
    'steam',
    'taptap',
    'telegram',
    'tiktok',
    'wechat',
    'xiaomi'
)
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$goCommand = (Get-Command go -ErrorAction Stop).Source

function Invoke-GoCommand {
    param(
        [Parameter(Mandatory)]
        [string]$WorkingDirectory,
        [Parameter(Mandatory)]
        [string[]]$Arguments
    )

    $previousGoWork = $env:GOWORK
    $previousErrorActionPreference = $ErrorActionPreference
    Push-Location -LiteralPath $WorkingDirectory
    try {
        $env:GOWORK = 'off'
        # Windows PowerShell 5 wraps native stderr as ErrorRecord and honors Stop before
        # LASTEXITCODE can be inspected. Capture it normally and decide from the exit code.
        $ErrorActionPreference = 'Continue'
        $output = @(& $goCommand @Arguments 2>&1)
        if ($LASTEXITCODE -ne 0) {
            $rendered = ($output | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine
            throw "go $($Arguments -join ' ') failed in ${WorkingDirectory}:`n$rendered"
        }
        return @($output | ForEach-Object { $_.ToString() })
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
        Pop-Location
        if ($null -eq $previousGoWork) {
            Remove-Item Env:GOWORK -ErrorAction SilentlyContinue
        }
        else {
            $env:GOWORK = $previousGoWork
        }
    }
}

$actualModuleNames = @(
    Get-ChildItem -LiteralPath $repositoryRoot -Directory |
        Where-Object { $_.Name -ne 'core' -and (Test-Path -LiteralPath (Join-Path $_.FullName 'go.mod')) } |
        ForEach-Object { $_.Name } |
        Sort-Object
)
$expectedModuleNames = @($platformNames | Sort-Object)
$moduleNameDiff = @(Compare-Object -ReferenceObject $expectedModuleNames -DifferenceObject $actualModuleNames)
if ($moduleNameDiff.Count -ne 0) {
    throw "expected exactly the 13 platform modules [$($expectedModuleNames -join ', ')], found [$($actualModuleNames -join ', ')]"
}

foreach ($platformName in $platformNames) {
    $platformDirectory = Join-Path $repositoryRoot $platformName
    $metadataText = (Invoke-GoCommand -WorkingDirectory $platformDirectory -Arguments @('mod', 'edit', '-json')) -join "`n"
    $metadata = $metadataText | ConvertFrom-Json

    $coreRequirements = @($metadata.Require | Where-Object { $_.Path -eq $coreModulePath })
    if ($coreRequirements.Count -ne 1 -or $coreRequirements[0].Version -ne $ExpectedCoreVersion) {
        $found = @($coreRequirements | ForEach-Object { $_.Version }) -join ', '
        throw "${platformName}/go.mod must require ${coreModulePath} ${ExpectedCoreVersion}; found [$found]"
    }

    $coreReplacements = @($metadata.Replace | Where-Object { $_.Old.Path -eq $coreModulePath })
    if ($coreReplacements.Count -ne 1 -or $coreReplacements[0].New.Path -ne '../core') {
        throw "${platformName}/go.mod must retain the module-local replace ${coreModulePath} => ../core"
    }
}
Write-Host "Verified all 13 platform require declarations at ${coreModulePath} ${ExpectedCoreVersion}."

$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('tgf-platform-module-graph-' + [Guid]::NewGuid().ToString('N'))
$sourceRoot = Join-Path $tempRoot 'source'
$consumerRoot = Join-Path $tempRoot 'consumer'

try {
    New-Item -ItemType Directory -Path $sourceRoot, $consumerRoot -Force | Out-Null

    foreach ($moduleName in @('core') + $platformNames) {
        $sourceModule = Join-Path $repositoryRoot $moduleName
        $copiedModule = Join-Path $sourceRoot $moduleName
        New-Item -ItemType Directory -Path $copiedModule -Force | Out-Null
        Get-ChildItem -LiteralPath $sourceModule -Force |
            Copy-Item -Destination $copiedModule -Recurse -Force
    }

    foreach ($platformName in $platformNames) {
        $copiedPlatform = Join-Path $sourceRoot $platformName
        Invoke-GoCommand -WorkingDirectory $copiedPlatform -Arguments @('list', '-mod=readonly', '-deps', './...') | Out-Null
    }
    Write-Host 'Verified every platform source graph from a temporary copy with GOWORK=off.'

    $goModLines = @(
        'module example.com/tgf-platform-source-consumer',
        '',
        'go 1.26.0',
        '',
        'require ('
    )
    foreach ($platformName in $platformNames) {
        $goModLines += "`tgithub.com/thkhxm/tgf-platform/${platformName} v0.0.0"
    }
    $goModLines += @(
        ')',
        '',
        'replace ('
    )
    foreach ($platformName in $platformNames) {
        $goModLines += "`tgithub.com/thkhxm/tgf-platform/${platformName} => ../source/${platformName}"
    }
    # Dependency-module replace directives are intentionally ignored by Go. This explicit
    # consumer-side core replace validates unreleased source only; it does not simulate a tag.
    $goModLines += "`t${coreModulePath} => ../source/core"
    $goModLines += ')'

    $consumerLines = @(
        'package consumer',
        '',
        'import ('
    )
    foreach ($platformName in $platformNames) {
        $consumerLines += "`t_ `"github.com/thkhxm/tgf-platform/${platformName}`""
    }
    $consumerLines += ')'

    $utf8NoBom = [Text.UTF8Encoding]::new($false)
    [IO.File]::WriteAllText((Join-Path $consumerRoot 'go.mod'), ($goModLines -join "`n") + "`n", $utf8NoBom)
    [IO.File]::WriteAllText((Join-Path $consumerRoot 'consumer.go'), ($consumerLines -join "`n") + "`n", $utf8NoBom)

    Invoke-GoCommand -WorkingDirectory $consumerRoot -Arguments @('mod', 'tidy') | Out-Null
    Invoke-GoCommand -WorkingDirectory $consumerRoot -Arguments @('test', '-count=1', './...') | Out-Null

    $goWork = (Invoke-GoCommand -WorkingDirectory $consumerRoot -Arguments @('env', 'GOWORK')) -join ''
    if ($goWork.Trim() -ne 'off') {
        throw "temporary consumer unexpectedly used a workspace: $goWork"
    }

    $coreGraphText = (Invoke-GoCommand -WorkingDirectory $consumerRoot -Arguments @('list', '-m', '-json', $coreModulePath)) -join "`n"
    $coreGraph = $coreGraphText | ConvertFrom-Json
    if ($coreGraph.Version -ne $ExpectedCoreVersion) {
        throw "temporary consumer selected core $($coreGraph.Version), expected ${ExpectedCoreVersion}"
    }
    if ($null -eq $coreGraph.Replace -or $coreGraph.Replace.Path -ne '../source/core') {
        throw 'temporary consumer did not use its explicit source-only core replacement'
    }

    Write-Host "Verified consumer-shaped source graph selects core ${ExpectedCoreVersion} with GOWORK=off."
    Write-Host 'This source-only check does not claim that any remote tag exists or is publicly resolvable.'
}
finally {
    if (Test-Path -LiteralPath $tempRoot) {
        $resolvedTempRoot = [IO.Path]::GetFullPath($tempRoot)
        $resolvedTempBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
        $isExpectedTemp = $resolvedTempRoot.StartsWith($resolvedTempBase, [StringComparison]::OrdinalIgnoreCase) -and
            ([IO.Path]::GetFileName($resolvedTempRoot)).StartsWith('tgf-platform-module-graph-', [StringComparison]::Ordinal)
        if (-not $isExpectedTemp) {
            throw "refusing to remove unexpected temporary path: $resolvedTempRoot"
        }
        Remove-Item -LiteralPath $resolvedTempRoot -Recurse -Force
    }
}
