<#
.SYNOPSIS
Temporarily permits a broad public DNS resolver pool through Mullvad.

.NOTES
Standalone operator helper; NullBound never invokes it or changes VPN settings.

.EXAMPLE
.\scripts\amass-mullvad-dns.ps1 Enable

.EXAMPLE
.\scripts\amass-mullvad-dns.ps1 Restore

.EXAMPLE
.\scripts\amass-mullvad-dns.ps1 Run { subfinder -d example.com }
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('Enable', 'Restore', 'Run')]
    [string] $Action,

    [Parameter(Position = 1)]
    [scriptblock] $Command
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Broad resolver pool originally collected while testing Amass v5.1.1.
# It can also be used temporarily while testing other DNS discovery tools.
$DiscoveryResolvers = @(
    '8.8.8.8',
    '8.8.4.4',
    '95.85.95.85',
    '2.56.220.2',
    '76.76.2.0',
    '76.76.10.0',
    '9.9.9.9',
    '149.112.112.112',
    '208.67.222.222',
    '208.67.220.220',
    '1.1.1.1',
    '1.0.0.1',
    '185.228.168.9',
    '185.228.169.9',
    '76.76.19.19',
    '76.223.122.150',
    '94.140.14.14',
    '94.140.15.15',
    '176.103.130.130',
    '176.103.130.131',
    '8.26.56.26',
    '8.20.247.20',
    '205.171.3.65',
    '205.171.2.65',
    '64.6.64.6',
    '64.6.65.6',
    '209.244.0.3',
    '209.244.0.4',
    '149.112.121.10',
    '149.112.122.10',
    '138.197.140.189',
    '162.243.19.47',
    '216.87.84.211',
    '23.90.4.6',
    '216.146.35.35',
    '216.146.36.36',
    '91.239.100.100',
    '89.233.43.71',
    '77.88.8.8',
    '77.88.8.1',
    '74.82.42.42',
    '94.130.180.225',
    '78.47.64.161',
    '80.80.80.80',
    '80.80.81.81',
    '84.200.69.80',
    '84.200.70.40',
    '156.154.70.5',
    '156.157.71.5',
    '81.218.119.11',
    '209.88.198.133',
    '37.235.1.177',
    '38.132.106.139'
)

function Find-MullvadCli {
    $installed = Get-Command 'mullvad.exe' -ErrorAction SilentlyContinue
    if ($null -ne $installed) {
        return $installed.Source
    }

    $candidates = @(
        (Join-Path $env:ProgramFiles 'Mullvad VPN\resources\mullvad.exe')
    )
    if (${env:ProgramFiles(x86)}) {
        $candidates += Join-Path ${env:ProgramFiles(x86)} 'Mullvad VPN\resources\mullvad.exe'
    }

    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return $candidate
        }
    }

    throw 'Mullvad CLI was not found in PATH or the standard Windows installation folders.'
}

function Invoke-Mullvad {
    param([Parameter(Mandatory = $true)][string[]] $Arguments)

    & $script:MullvadCli @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Mullvad CLI exited with code $LASTEXITCODE."
    }
}

function Enable-DiscoveryResolvers {
    Write-Host "Allowing $($DiscoveryResolvers.Count) public discovery resolvers through Mullvad..."
    Invoke-Mullvad -Arguments (@('dns', 'set', 'custom') + $DiscoveryResolvers)
    Invoke-Mullvad -Arguments @('dns', 'get')
}

function Restore-OriginalDns {
    Write-Host 'Restoring default Mullvad DNS with ad blocking enabled...'
    Invoke-Mullvad -Arguments @('dns', 'set', 'default', '--block-ads')
    Invoke-Mullvad -Arguments @('dns', 'get')
}

$MullvadCli = Find-MullvadCli

switch ($Action) {
    'Enable' {
        Enable-DiscoveryResolvers
    }
    'Restore' {
        Restore-OriginalDns
    }
    'Run' {
        if ($null -eq $Command) {
            throw 'Run requires a script block, for example: Run { subfinder -d example.com }'
        }

        $commandExitCode = 0
        $commandError = $null
        $restoreError = $null

        try {
            Enable-DiscoveryResolvers
            $global:LASTEXITCODE = 0
            & $Command
            $commandExitCode = $LASTEXITCODE
        }
        catch {
            $commandError = $_
            $commandExitCode = 1
        }
        finally {
            try {
                Restore-OriginalDns
            }
            catch {
                $restoreError = $_
                Write-Warning "Automatic Mullvad DNS restoration failed: $($_.Exception.Message)"
            }
        }

        if ($null -ne $commandError) {
            throw $commandError
        }
        if ($null -ne $restoreError) {
            exit 1
        }
        exit $commandExitCode
    }
}

