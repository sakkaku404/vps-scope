[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateCount(2, 16)]
    [string[]] $Hosts,

    [string] $Output = "vps-scope-lab-connectivity.json",

    [ValidateRange(10, 120)]
    [int] $ScenarioSeconds = 30
)

$ErrorActionPreference = "Stop"
$networks = @(
    @{ Name = "tcp4"; Port = 39081 },
    @{ Name = "udp4"; Port = 39082 }
)

foreach ($name in $Hosts) {
    if ($name -notmatch '^[A-Za-z0-9._-]+$') {
        throw "Unsafe SSH host alias: $name"
    }
}
if (Test-Path -LiteralPath $Output) {
    throw "Output already exists: $Output"
}

function Resolve-SshHost([string] $Alias) {
    $line = ssh -G $Alias 2>$null | Select-String '^hostname ' | Select-Object -First 1
    if (-not $line) { throw "Cannot resolve SSH host alias: $Alias" }
    $value = ($line.Line -split '\s+')[1]
    if ($value -notmatch '^[A-Za-z0-9.:-]+$') { throw "Unsafe resolved host value for $Alias" }
    return $value
}

$addresses = @{}
foreach ($name in $Hosts) { $addresses[$name] = Resolve-SshHost $name }
$results = [System.Collections.Generic.List[object]]::new()

foreach ($network in $networks) {
    foreach ($target in $Hosts) {
        $remote = "nohup env VPS_SCOPE_LAB_NETWORK=$($network.Name) VPS_SCOPE_LAB_PORT=$($network.Port) VPS_SCOPE_LAB_DURATION=$ScenarioSeconds VPS_SCOPE_LAB_OPEN_FIREWALL=1 VPS_SCOPE_LAB_HELPER=/opt/vps-scope-lab/net-helper /opt/vps-scope-lab/scenario.sh </dev/null >/run/vps-scope-lab/$($network.Name).out 2>&1 &"
        ssh $target $remote | Out-Null
        Start-Sleep -Seconds 2

        $jobs = @()
        foreach ($peer in $Hosts) {
            if ($peer -eq $target) { continue }
            $jobs += Start-Job -ScriptBlock {
                param($From, $To, $Network, $Address, $Port)
                ssh $From "/opt/vps-scope-lab/net-helper --mode probe --network $Network --address ${Address}:$Port --timeout 5s" 2>$null | Out-Null
                [pscustomobject]@{ Network = $Network; From = $From; To = $To; Passed = ($LASTEXITCODE -eq 0) }
            } -ArgumentList $peer, $target, $network.Name, $addresses[$target], $network.Port
        }
        $jobs | Wait-Job -Timeout 12 | Out-Null
        foreach ($job in $jobs) {
            if ($job.State -eq 'Completed') {
                $results.Add((Receive-Job $job))
            } else {
                Stop-Job $job -ErrorAction SilentlyContinue
                $results.Add([pscustomobject]@{ Network = $network.Name; From = "unknown"; To = $target; Passed = $false })
            }
            Remove-Job $job -Force
        }
    }
}

Start-Sleep -Seconds ($ScenarioSeconds + 2)
$cleanup = @()
foreach ($target in $Hosts) {
    $remaining = ssh $target "ufw status | grep -E '39081|39082' | wc -l"
    $cleanup += [pscustomobject]@{ Host = $target; RemainingLabRules = [int]$remaining }
}

$document = [ordered]@{
    schema = "vps-scope-lab-connectivity/v1"
    created_at = [DateTime]::UtcNow.ToString("o")
    results = $results
    cleanup = $cleanup
}
$document | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $Output -Encoding UTF8
if (@($cleanup | Where-Object { $_.RemainingLabRules -ne 0 }).Count -ne 0) { throw "At least one lab firewall rule was not removed" }
$passed = @($results | Where-Object Passed).Count
Write-Output "matrix complete: $passed/$($results.Count) probes passed; cleanup verified on $($Hosts.Count) hosts"
