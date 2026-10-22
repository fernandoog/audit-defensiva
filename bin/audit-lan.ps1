#Requires -Version 5.1
<#
.SYNOPSIS
  Auditoría defensiva de red local en Windows (sin escanear otros hosts).
#>
[CmdletBinding()]
param(
    [switch]$Json,
    [string]$OutDir = ""
)

$ErrorActionPreference = "Continue"
$VERSION = "1.1.0"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir
if ([string]::IsNullOrWhiteSpace($OutDir)) { $OutDir = Join-Path $RootDir "reports" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$Stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$HostName = $env:COMPUTERNAME
$Report = Join-Path $OutDir "audit-lan-$HostName-$Stamp.txt"
$JsonOut = Join-Path $OutDir "audit-lan-$HostName-$Stamp.json"
$Pass = 0; $Warn = 0; $Fail = 0; $Info = 0
$Results = New-Object System.Collections.Generic.List[object]
$Lines = New-Object System.Collections.Generic.List[string]

function Add-Line([string]$t) { $Lines.Add($t); Write-Host $t }
function Record($s, $c, $m) {
    $Results.Add([pscustomobject]@{ status = $s; code = $c; message = $m })
    switch ($s) { "PASS" { $script:Pass++ } "WARN" { $script:Warn++ } "FAIL" { $script:Fail++ } "INFO" { $script:Info++ } }
    Add-Line "[$s] $c — $m"
}
function Section($t) { Add-Line ""; Add-Line "== $t ==" }

Add-Line "audit-lan.ps1 v$VERSION"
Add-Line "Generado: $Stamp (UTC)  Host: $HostName"
Add-Line "Alcance: red de ESTE equipo (defensivo)"

Section "Interfaces"
try {
    Get-NetIPConfiguration -ErrorAction Stop | ForEach-Object {
        Add-Line ("  {0}  IPv4={1}  Gw={2}" -f $_.InterfaceAlias, ($_.IPv4Address.IPAddress -join ','), ($_.IPv4DefaultGateway.NextHop -join ','))
    }
    Record "INFO" "ifaces" "interfaces listadas"
} catch { Record "WARN" "ifaces" $_.Exception.Message }

Section "Perfil de red / firewall"
try {
    Get-NetConnectionProfile | ForEach-Object {
        Record "INFO" "net-profile" "$($_.Name) → $($_.NetworkCategory)"
        if ($_.NetworkCategory -eq "Public") {
            Record "PASS" "net-category" "perfil Público (más restrictivo)"
        } else {
            Record "WARN" "net-category" "perfil $($_.NetworkCategory) — revisa confianza de la red"
        }
    }
} catch { Record "INFO" "net-profile" "no disponible" }

try {
    Get-NetFirewallProfile | ForEach-Object {
        if ($_.Enabled) { Record "PASS" "fw-$($_.Name)" "firewall $($_.Name) ON" }
        else { Record "FAIL" "fw-$($_.Name)" "firewall $($_.Name) OFF" }
    }
} catch { Record "INFO" "firewall" "no legible" }

Section "Vecinos ARP (pasivo)"
try {
    $n = Get-NetNeighbor -ErrorAction Stop | Where-Object { $_.State -ne "Unreachable" }
    Record "INFO" "neigh" "$($n.Count) vecinos en caché local (sin scan)"
    $n | Select-Object -First 30 | ForEach-Object { Add-Line ("  {0}  {1}  {2}" -f $_.IPAddress, $_.LinkLayerAddress, $_.State) }
} catch { Record "INFO" "neigh" "no disponible" }

Section "Comparticiones de ESTE host"
try {
    $shares = Get-SmbShare -ErrorAction Stop | Where-Object { $_.Name -notmatch '^(ADMIN\$|C\$|IPC\$)$' }
    if ($shares) {
        Record "WARN" "smb-shares" "comparticiones no administrativas: $(($shares.Name) -join ', ')"
    } else {
        Record "PASS" "smb-shares" "sin comparticiones de usuario obvias"
    }
} catch { Record "INFO" "smb-shares" "SMB no consultable" }

Section "Resumen"
Add-Line "PASS=$Pass WARN=$Warn FAIL=$Fail INFO=$Info"
$Lines | Set-Content -Path $Report -Encoding UTF8
Write-Host "Informe: $Report"
if ($Json) {
    [pscustomobject]@{ version = $VERSION; host = $HostName; generated_at = $Stamp; summary = @{ pass = $Pass; warn = $Warn; fail = $Fail; info = $Info }; results = $Results } |
        ConvertTo-Json -Depth 5 | Set-Content $JsonOut -Encoding UTF8
    Write-Host "JSON: $JsonOut"
}
if ($Fail -gt 0) { exit 2 }; if ($Warn -gt 0) { exit 1 }; exit 0
