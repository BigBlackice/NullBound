[CmdletBinding()]
param(
    [switch]$CheckOnly,
    [switch]$Force,
    [switch]$SkipNmap,
    [switch]$NoPersistPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'This bootstrapper installs Windows executables and can only run on Windows.'
}
if (-not [Environment]::Is64BitOperatingSystem) {
    throw 'Blackwall tool bootstrap currently supports 64-bit Windows only.'
}

$ProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$DefinitionsPath = Join-Path $ProjectRoot 'recon_modules\definitions.json'
$ToolsRoot = Join-Path $ProjectRoot '.blackwall-tools'
$BinPath = Join-Path $ToolsRoot 'bin'
$PackagesPath = Join-Path $ToolsRoot 'packages'
$DownloadsPath = Join-Path $ToolsRoot 'downloads'
$NmapPath = Join-Path $ToolsRoot 'nmap'

$GitHubTools = [ordered]@{
    amass = @{ Repository = 'owasp-amass/amass'; VersionArguments = @('-version'); VersionPattern = '(?i)amass' }
    dnsx  = @{ Repository = 'projectdiscovery/dnsx'; VersionArguments = @('-version'); VersionPattern = '(?i)dnsx' }
    httpx = @{ Repository = 'projectdiscovery/httpx'; VersionArguments = @('-version'); VersionPattern = '(?i)httpx' }
    gau   = @{ Repository = 'lc/gau'; VersionArguments = @('--version'); VersionPattern = '(?i)(gau|v\d+\.)' }
    tlsx  = @{ Repository = 'projectdiscovery/tlsx'; VersionArguments = @('-version'); VersionPattern = '(?i)tlsx' }
}

$VersionChecks = @{
    amass = @{ Arguments = @('-version'); Pattern = '(?i)amass' }
    dnsx  = @{ Arguments = @('-version'); Pattern = '(?i)dnsx' }
    nmap  = @{ Arguments = @('--version'); Pattern = '(?i)nmap version' }
    httpx = @{ Arguments = @('-version'); Pattern = '(?i)httpx' }
    gau   = @{ Arguments = @('--version'); Pattern = '(?i)(gau|v\d+\.)' }
    tlsx  = @{ Arguments = @('-version'); Pattern = '(?i)tlsx' }
}

function Write-Step {
    param([string]$Message)
    Write-Host "`n==> $Message" -ForegroundColor Cyan
}

function Test-PathInsideToolsRoot {
    param([Parameter(Mandatory = $true)][string]$Path)
    $resolvedRoot = [System.IO.Path]::GetFullPath($ToolsRoot).TrimEnd('\') + '\'
    $resolvedPath = [System.IO.Path]::GetFullPath($Path)
    if (-not $resolvedPath.StartsWith($resolvedRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to modify a path outside $ToolsRoot`: $resolvedPath"
    }
}

function Remove-LocalItem {
    param([Parameter(Mandatory = $true)][string]$Path)
    Test-PathInsideToolsRoot -Path $Path
    if (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path -Recurse -Force
    }
}

function Test-ToolExecutable {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Path
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $false
    }
    $check = $VersionChecks[$Name]
    $previousErrorPreference = $ErrorActionPreference
    try {
        # ProjectDiscovery writes version banners to stderr. Windows PowerShell
        # wraps native stderr as an error record when the global preference is
        # Stop, so relax it only for this non-mutating health check.
        $ErrorActionPreference = 'Continue'
        $output = (& $Path @($check.Arguments) 2>&1 | Out-String)
        return $output -match $check.Pattern
    }
    catch {
        return $false
    }
    finally {
        $ErrorActionPreference = $previousErrorPreference
    }
}

function Find-ToolExecutable {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [string]$ConfiguredPath
    )

    $localCandidates = @(
        (Join-Path $BinPath "$Name.exe"),
        (Join-Path $NmapPath "$Name.exe")
    )
    foreach ($candidate in $localCandidates) {
        if (Test-ToolExecutable -Name $Name -Path $candidate) {
            return [System.IO.Path]::GetFullPath($candidate)
        }
    }

    if ($ConfiguredPath) {
        $candidate = $ConfiguredPath
        if (-not [System.IO.Path]::IsPathRooted($candidate)) {
            $projectCandidates = @((Join-Path $ProjectRoot $candidate))
            if (-not [System.IO.Path]::HasExtension($candidate)) {
                $projectCandidates += Join-Path $ProjectRoot "$candidate.exe"
            }
            foreach ($projectCandidate in $projectCandidates) {
                if (Test-ToolExecutable -Name $Name -Path $projectCandidate) {
                    return [System.IO.Path]::GetFullPath($projectCandidate)
                }
            }
        }
        elseif (Test-ToolExecutable -Name $Name -Path $candidate) {
            return [System.IO.Path]::GetFullPath($candidate)
        }
    }

    $command = Get-Command "$Name.exe" -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($command -and (Test-ToolExecutable -Name $Name -Path $command.Source)) {
        return $command.Source
    }
    return $null
}

function Get-WindowsAssetRegex {
    if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') {
        return '(?i)(^|[_.-])(windows|win)([_.-])[^/]*arm64[^/]*\.(zip|tar\.gz)$'
    }
    return '(?i)(^|[_.-])(windows|win)([_.-])[^/]*(amd64|x86_64|64-bit)[^/]*\.(zip|tar\.gz)$'
}

function Confirm-GitHubChecksum {
    param(
        [Parameter(Mandatory = $true)]$Release,
        [Parameter(Mandatory = $true)]$Asset,
        [Parameter(Mandatory = $true)][string]$ArchivePath
    )

    $checksumAsset = $Release.assets |
        Where-Object { $_.name -match '(?i)(checksums?|sha256sums?)(\.txt)?$' } |
        Select-Object -First 1
    if (-not $checksumAsset) {
        Write-Warning "No published checksum asset found for $($Asset.name); relying on HTTPS and GitHub release integrity."
        return
    }

    $checksumPath = Join-Path $DownloadsPath $checksumAsset.name
    Invoke-WebRequest -UseBasicParsing -Uri $checksumAsset.browser_download_url -OutFile $checksumPath
    $checksumText = Get-Content -LiteralPath $checksumPath -Raw
    $escapedName = [regex]::Escape($Asset.name)
    $match = [regex]::Match(
        $checksumText,
        "(?im)^\s*([a-f0-9]{64})\s+\*?$escapedName\s*$"
    )
    if (-not $match.Success) {
        $match = [regex]::Match(
            $checksumText,
            "(?im)^\s*$escapedName\s*[:=]\s*([a-f0-9]{64})\s*$"
        )
    }
    if (-not $match.Success) {
        throw "Published checksum file did not contain $($Asset.name)."
    }
    $expected = $match.Groups[1].Value.ToUpperInvariant()
    $actual = (Get-FileHash -LiteralPath $ArchivePath -Algorithm SHA256).Hash
    if ($actual -ne $expected) {
        throw "SHA256 mismatch for $($Asset.name)."
    }
}

function Install-GitHubTool {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Repository
    )

    Write-Step "Installing $Name from $Repository"
    $headers = @{ Accept = 'application/vnd.github+json'; 'User-Agent' = 'Blackwall-tool-bootstrap' }
    $release = Invoke-RestMethod -Headers $headers -Uri "https://api.github.com/repos/$Repository/releases/latest"
    $assetPattern = Get-WindowsAssetRegex
    $asset = $release.assets |
        Where-Object { $_.name -match $assetPattern -and $_.name -notmatch '(?i)(checksum|sha256)' } |
        Select-Object -First 1
    if (-not $asset) {
        throw "No Windows 64-bit archive was published in the latest $Repository release."
    }
    if ($asset.name -match '(?i)(^|[_.-])(darwin|linux|freebsd)([_.-])') {
        throw "Refusing non-Windows release asset selected for $Name`: $($asset.name)"
    }

    $archivePath = Join-Path $DownloadsPath $asset.name
    Invoke-WebRequest -UseBasicParsing -Uri $asset.browser_download_url -OutFile $archivePath
    Confirm-GitHubChecksum -Release $release -Asset $asset -ArchivePath $archivePath

    $packagePath = Join-Path $PackagesPath $Name
    $stagingPath = Join-Path $PackagesPath "$Name.staging"
    Remove-LocalItem -Path $stagingPath
    New-Item -ItemType Directory -Path $stagingPath -Force | Out-Null
    if ($archivePath.EndsWith('.zip', [System.StringComparison]::OrdinalIgnoreCase)) {
        Expand-Archive -LiteralPath $archivePath -DestinationPath $stagingPath -Force
    }
    elseif ($archivePath.EndsWith('.tar.gz', [System.StringComparison]::OrdinalIgnoreCase)) {
        $tar = Get-Command 'tar.exe' -CommandType Application -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if (-not $tar) {
            throw "$($asset.name) requires tar.exe, which is included with current Windows releases."
        }
        & $tar.Source -xzf $archivePath -C $stagingPath
        if ($LASTEXITCODE -ne 0) {
            throw "tar.exe could not extract $($asset.name)."
        }
    }
    else {
        throw "Unsupported release archive: $($asset.name)"
    }
    $executable = Get-ChildItem -LiteralPath $stagingPath -Filter "$Name.exe" -File -Recurse |
        Select-Object -First 1
    if (-not $executable) {
        throw "$($asset.name) did not contain $Name.exe."
    }

    Remove-LocalItem -Path $packagePath
    Move-Item -LiteralPath $stagingPath -Destination $packagePath
    $installedExecutable = Get-ChildItem -LiteralPath $packagePath -Filter "$Name.exe" -File -Recurse |
        Select-Object -First 1
    Copy-Item -LiteralPath $installedExecutable.FullName -Destination (Join-Path $BinPath "$Name.exe") -Force
    Remove-LocalItem -Path $archivePath

    $installedPath = Join-Path $BinPath "$Name.exe"
    if (-not (Test-ToolExecutable -Name $Name -Path $installedPath)) {
        throw "$Name was downloaded but failed its version health check."
    }
    return $installedPath
}

function Install-Nmap {
    Write-Step 'Installing Nmap from nmap.org (administrator prompt expected)'
    $downloadPage = Invoke-WebRequest -UseBasicParsing -Uri 'https://nmap.org/download.html'
    $match = [regex]::Match(
        $downloadPage.Content,
        'href="(?<url>[^" ]*nmap-(?<version>[0-9.]+)-setup\.exe)"',
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )
    if (-not $match.Success) {
        throw 'Could not identify the current official Nmap Windows installer.'
    }
    $installerUri = [Uri]::new([Uri]'https://nmap.org/download.html', $match.Groups['url'].Value)
    $installerName = [System.IO.Path]::GetFileName($installerUri.LocalPath)
    $installerPath = Join-Path $DownloadsPath $installerName
    Invoke-WebRequest -UseBasicParsing -Uri $installerUri.AbsoluteUri -OutFile $installerPath

    $digestUri = "https://nmap.org/dist/sigs/$installerName.digest.txt"
    $digest = (Invoke-WebRequest -UseBasicParsing -Uri $digestUri).Content -replace '\s', ''
    $digestMatch = [regex]::Match($digest, 'SHA256=([A-Fa-f0-9]{64})')
    if (-not $digestMatch.Success) {
        throw 'The official Nmap digest did not contain a SHA256 value.'
    }
    $actual = (Get-FileHash -LiteralPath $installerPath -Algorithm SHA256).Hash
    if ($actual -ne $digestMatch.Groups[1].Value.ToUpperInvariant()) {
        throw "SHA256 mismatch for $installerName."
    }

    New-Item -ItemType Directory -Path $NmapPath -Force | Out-Null
    $npcap = Get-Service -Name 'npcap' -ErrorAction SilentlyContinue
    if ($npcap) {
        Write-Host 'Npcap is already installed; using the supported silent Nmap path.' -ForegroundColor Green
        $arguments = @(
            '/S', '/ZENMAP=NO', '/NDIFF=NO', '/REGISTERPATH=NO', "/D=$NmapPath"
        )
    }
    else {
        Write-Host 'Npcap is not installed. The Nmap installer will open interactively.' -ForegroundColor Yellow
        Write-Host 'Keep Npcap selected in the installer; free Npcap cannot be installed silently.' -ForegroundColor Yellow
        $arguments = @('/ZENMAP=NO', '/NDIFF=NO', '/REGISTERPATH=NO', "/D=$NmapPath")
    }
    $process = Start-Process -FilePath $installerPath -ArgumentList $arguments -Verb RunAs -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        throw "Nmap installer exited with code $($process.ExitCode)."
    }
    Remove-LocalItem -Path $installerPath
    $installedPath = Join-Path $NmapPath 'nmap.exe'
    if (-not (Test-ToolExecutable -Name 'nmap' -Path $installedPath)) {
        throw 'Nmap installation completed but nmap.exe failed its version health check.'
    }
    return $installedPath
}

function Show-DependencyStatus {
    $nmap = Find-ToolExecutable -Name 'nmap' -ConfiguredPath 'nmap'
    if ($nmap) {
        $npcap = Get-Service -Name 'npcap' -ErrorAction SilentlyContinue
        if ($npcap) {
            Write-Host ("[REQUIRED] Npcap available for Nmap: service {0}" -f $npcap.Status) -ForegroundColor Green
        }
        else {
            Write-Warning (
                'Npcap was not detected. Nmap TCP-connect scans can use -sT -Pn, but ' +
                'normal host discovery and raw-packet scans require Npcap.'
            )
        }
    }

    $tlsx = Find-ToolExecutable -Name 'tlsx' -ConfiguredPath 'tlsx'
    if (-not $tlsx) {
        return
    }
    $openssl = Get-Command 'openssl.exe' -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($openssl) {
        Write-Host ("[OPTIONAL] OpenSSL available for tlsx: {0}" -f $openssl.Source) -ForegroundColor Green
    }
    else {
        Write-Warning (
            'OpenSSL was not found. Blackwall tlsx profiles still use the built-in ctls/ztls modes; ' +
            'only explicit OpenSSL mode and its extra fallback coverage are unavailable.'
        )
    }
}

function Add-ToolDirectoriesToPath {
    param([string[]]$Directories)
    $directoriesToAdd = @($Directories | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique)
    if (-not $directoriesToAdd) {
        return
    }

    $processEntries = @($env:Path -split ';' | Where-Object { $_ })
    foreach ($directory in $directoriesToAdd) {
        if ($processEntries -notcontains $directory) {
            $processEntries = @($directory) + $processEntries
        }
    }
    $env:Path = $processEntries -join ';'

    if ($NoPersistPath) {
        return
    }
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $userEntries = @($userPath -split ';' | Where-Object { $_ })
    foreach ($directory in $directoriesToAdd) {
        if ($userEntries -notcontains $directory) {
            $userEntries += $directory
        }
    }
    [Environment]::SetEnvironmentVariable('Path', ($userEntries -join ';'), 'User')
}

if (-not (Test-Path -LiteralPath $DefinitionsPath -PathType Leaf)) {
    throw "Cannot find Blackwall module definitions at $DefinitionsPath"
}
$catalog = Get-Content -LiteralPath $DefinitionsPath -Raw | ConvertFrom-Json
$requiredModules = @($catalog.modules)
$status = [ordered]@{}

Write-Step 'Checking Blackwall module executables'
foreach ($module in $requiredModules) {
    $name = [string]$module.bin
    $found = Find-ToolExecutable -Name $name -ConfiguredPath ([string]$module.path)
    $status[$name] = $found
    if ($found) {
        Write-Host ("[FOUND]   {0,-8} {1}" -f $name, $found) -ForegroundColor Green
    }
    else {
        Write-Host ("[MISSING] {0}" -f $name) -ForegroundColor Yellow
    }
}

if ($CheckOnly) {
    Show-DependencyStatus
    $missing = @($status.Keys | Where-Object { -not $status[$_] })
    if ($missing) {
        Write-Host "`nMissing: $($missing -join ', ')" -ForegroundColor Yellow
        exit 1
    }
    Write-Host "`nAll Blackwall module executables are available." -ForegroundColor Green
    exit 0
}

New-Item -ItemType Directory -Path $BinPath, $PackagesPath, $DownloadsPath -Force | Out-Null
$installErrors = [ordered]@{}
# Install portable tools first so the privileged/interactive Nmap step cannot
# prevent gau or tlsx from being prepared if Nmap is cancelled.
$installModules = @($requiredModules | Where-Object { $_.bin -ne 'nmap' })
$installModules += @($requiredModules | Where-Object { $_.bin -eq 'nmap' })
foreach ($module in $installModules) {
    $name = [string]$module.bin
    if ($status[$name] -and -not $Force) {
        continue
    }
    try {
        if ($name -eq 'nmap') {
            if ($SkipNmap) {
                Write-Warning 'Nmap is missing but was skipped.'
                continue
            }
            $status[$name] = Install-Nmap
            continue
        }
        if (-not $GitHubTools.Contains($name)) {
            Write-Warning "No bootstrap source is configured for $name; leaving it unchanged."
            continue
        }
        $status[$name] = Install-GitHubTool -Name $name -Repository $GitHubTools[$name].Repository
    }
    catch {
        $installErrors[$name] = $_.Exception.Message
        Write-Warning "$name installation failed: $($_.Exception.Message)"
        Write-Warning 'Continuing with the remaining Blackwall tools.'
    }
}

$pathDirectories = @($BinPath)
if (Test-Path -LiteralPath (Join-Path $NmapPath 'nmap.exe')) {
    $pathDirectories += $NmapPath
}
Add-ToolDirectoriesToPath -Directories $pathDirectories
Show-DependencyStatus

Write-Step 'Final tool status'
$failed = @()
foreach ($module in $requiredModules) {
    $name = [string]$module.bin
    $found = Find-ToolExecutable -Name $name -ConfiguredPath ([string]$module.path)
    if ($found) {
        Write-Host ("[READY]   {0,-8} {1}" -f $name, $found) -ForegroundColor Green
    }
    else {
        $failed += $name
        Write-Host ("[MISSING] {0}" -f $name) -ForegroundColor Red
    }
}

if (-not $NoPersistPath) {
    Write-Host "`nThe project tool directories were added to your user PATH." -ForegroundColor Cyan
    Write-Host 'Open a new terminal before starting Blackwall, or dot-source this script to update the current shell.'
}
if ($failed) {
    foreach ($name in $installErrors.Keys) {
        Write-Warning ("{0}: {1}" -f $name, $installErrors[$name])
    }
    throw "Some required executables are still missing: $($failed -join ', ')"
}
