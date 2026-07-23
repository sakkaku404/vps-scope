[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateCount(2, 16)]
    [string[]] $Hosts,

    [string] $Output = "vps-scope-lab-connectivity.json",

    [string] $IdentityFile,

    [ValidatePattern('^[A-Za-z_][A-Za-z0-9_-]*$')]
    [string] $SshUser,

    # Start-Job plus a fresh SSH handshake can consume more than ten seconds
    # on a Windows development host. Keep the advertised lower bound long
    # enough that every parallel probe starts while the scenario is alive.
    [ValidateRange(30, 120)]
    [int] $ScenarioSeconds = 30
)

$ErrorActionPreference = "Stop"
$script:SshArgs = @("-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes")
if ($IdentityFile) {
    if (-not (Test-Path -LiteralPath $IdentityFile -PathType Leaf)) {
        throw "SSH identity file does not exist: $IdentityFile"
    }
    $script:SshArgs += @("-i", (Resolve-Path -LiteralPath $IdentityFile).Path)
}
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
    $line = & ssh @script:SshArgs -G (Get-SshTarget $Alias) 2>$null | Select-String '^hostname ' | Select-Object -First 1
    if (-not $line) { throw "Cannot resolve SSH host alias: $Alias" }
    $value = ($line.Line -split '\s+')[1]
    if ($value -notmatch '^[A-Za-z0-9.:-]+$') { throw "Unsafe resolved host value for $Alias" }
    return $value
}

function Get-SshTarget([string] $Alias) {
    if ($SshUser) { return "$SshUser@$Alias" }
    return $Alias
}

$addresses = @{}
foreach ($name in $Hosts) { $addresses[$name] = Resolve-SshHost $name }
$results = [System.Collections.Generic.List[object]]::new()

function Wait-RemoteScenarioReady([string] $Target, [string] $Network, [int] $Port) {
    $expected = "$Network $Port"
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        $actual = & ssh @script:SshArgs (Get-SshTarget $Target) "cat /run/vps-scope-lab/ready 2>/dev/null || true"
        if (($actual | Out-String).Trim() -eq $expected) { return $true }
        Start-Sleep -Milliseconds 200
    }
    return $false
}

function Wait-RemoteScenarioFinished([string] $Target, [int] $MaxSeconds) {
    $deadline = [DateTime]::UtcNow.AddSeconds($MaxSeconds + 10)
    while ([DateTime]::UtcNow -lt $deadline) {
        $actual = & ssh @script:SshArgs (Get-SshTarget $Target) "cat /run/vps-scope-lab/ready 2>/dev/null || true"
        if ([string]::IsNullOrWhiteSpace(($actual | Out-String).Trim())) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

$lifecycleFailed = $false

foreach ($network in $networks) {
    foreach ($target in $Hosts) {
        $remote = "nohup env VPS_SCOPE_LAB_NETWORK=$($network.Name) VPS_SCOPE_LAB_PORT=$($network.Port) VPS_SCOPE_LAB_DURATION=$ScenarioSeconds VPS_SCOPE_LAB_OPEN_FIREWALL=1 VPS_SCOPE_LAB_HELPER=/opt/vps-scope-lab/net-helper /opt/vps-scope-lab/scenario.sh </dev/null >/run/vps-scope-lab/$($network.Name).out 2>&1 &"
        & ssh @script:SshArgs (Get-SshTarget $target) $remote | Out-Null
        if (-not (Wait-RemoteScenarioReady $target $network.Name $network.Port)) {
            $diagnostic = & ssh @script:SshArgs (Get-SshTarget $target) "tail -n 5 /run/vps-scope-lab/$($network.Name).out 2>/dev/null || true"
            Write-Warning "Scenario did not become ready on $target ($($network.Name)): $diagnostic"
            foreach ($peer in $Hosts) {
                if ($peer -eq $target) { continue }
                $results.Add([pscustomobject]@{ Network = $network.Name; From = $peer; To = $target; Passed = $false })
            }
            continue
        }

        $jobs = @()
        foreach ($peer in $Hosts) {
            if ($peer -eq $target) { continue }
            $jobs += Start-Job -ScriptBlock {
                param($From, $To, $Network, $Address, $Port, $SshArgs, $SshUser)
                $sshTarget = if ($SshUser) { "$SshUser@$From" } else { $From }
                & ssh @SshArgs $sshTarget "/opt/vps-scope-lab/net-helper --mode probe --network $Network --address ${Address}:$Port --timeout 5s" 2>$null | Out-Null
                [pscustomobject]@{ Network = $Network; From = $From; To = $To; Passed = ($LASTEXITCODE -eq 0) }
            } -ArgumentList $peer, $target, $network.Name, $addresses[$target], $network.Port, $script:SshArgs, $SshUser
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
        if (-not (Wait-RemoteScenarioFinished $target $ScenarioSeconds)) {
            Write-Warning "Scenario did not finish cleanly on $target ($($network.Name))"
            $lifecycleFailed = $true
        }
    }
}

$cleanup = @()
foreach ($target in $Hosts) {
    & ssh @script:SshArgs (Get-SshTarget $target) "rm -f -- /run/vps-scope-lab/tcp4.out /run/vps-scope-lab/udp4.out" | Out-Null
    $remaining = & ssh @script:SshArgs (Get-SshTarget $target) "ufw status | grep -E '39081|39082' | wc -l"
    $helpers = & ssh @script:SshArgs (Get-SshTarget $target) "pgrep -fc '[n]et-helper --mode serve' || true"
    $stateFiles = & ssh @script:SshArgs (Get-SshTarget $target) "find /run/vps-scope-lab -maxdepth 1 -type f \( -name ready -o -name helper.log -o -name helper.pid -o -name tcp4.out -o -name udp4.out \) 2>/dev/null | wc -l"
    $cleanup += [pscustomobject]@{
        Host = $target
        RemainingLabRules = [int]$remaining
        RemainingHelpers = [int]$helpers
        RemainingStateFiles = [int]$stateFiles
    }
}

$document = [ordered]@{
    schema = "vps-scope-lab-connectivity/v1"
    created_at = [DateTime]::UtcNow.ToString("o")
    results = $results
    cleanup = $cleanup
}
$document | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $Output -Encoding UTF8
if (@($cleanup | Where-Object { $_.RemainingLabRules -ne 0 -or $_.RemainingHelpers -ne 0 -or $_.RemainingStateFiles -ne 0 }).Count -ne 0) {
    throw "At least one lab host retained a firewall rule, helper process, or runtime state file"
}
$passed = @($results | Where-Object Passed).Count
Write-Output "matrix complete: $passed/$($results.Count) probes passed; cleanup verified on $($Hosts.Count) hosts"
if ($passed -ne $results.Count -or $lifecycleFailed) {
    throw "At least one connectivity probe or scenario lifecycle check failed"
}
