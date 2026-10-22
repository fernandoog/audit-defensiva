#Requires -Version 5.1
<#
.SYNOPSIS
  Auditoría defensiva de Bluetooth en Windows (adaptador local).
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
$Report = Join-Path $OutDir "audit-bt-$HostName-$Stamp.txt"
$JsonOut = Join-Path $OutDir "audit-bt-$HostName-$Stamp.json"
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

Add-Line "audit-bluetooth.ps1 v$VERSION"
Add-Line "Generado: $Stamp (UTC)  Host: $HostName"

Section "Radio Bluetooth"
try {
    $radios = Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue
    if (-not $radios) {
        Record "INFO" "bt-radio" "no hay dispositivos PnP Bluetooth"
    } else {
        foreach ($r in $radios) {
            Record "INFO" "bt-radio" "$($r.FriendlyName) status=$($r.Status)"
            if ($r.Status -eq "OK") { Record "INFO" "bt-power" "adaptador presente y OK" }
        }
    }
} catch { Record "INFO" "bt-radio" $_.Exception.Message }

Section "Servicio Bluetooth"
try {
    $svc = Get-Service bthserv -ErrorAction SilentlyContinue
    if ($null -eq $svc) {
        Record "INFO" "bthserv" "servicio bthserv no encontrado"
    } elseif ($svc.Status -eq "Running") {
        Record "INFO" "bthserv" "bthserv en ejecución"
    } else {
        Record "PASS" "bthserv" "bthserv $($svc.Status) (menor superficie si no usas BT)"
    }
} catch { Record "INFO" "bthserv" "no consultable" }

Section "Dispositivos emparejados (PnP)"
try {
    $devs = Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue |
        Where-Object { $_.FriendlyName -and $_.FriendlyName -notmatch 'Generic|Microsoft Bluetooth|Radio|Enumerator|Adapter' }
    if (-not $devs) {
        Record "INFO" "paired" "sin periféricos Bluetooth obvios"
    } else {
        Record "INFO" "paired" "$($devs.Count) dispositivo(s)"
        $devs | ForEach-Object { Add-Line ("  {0} [{1}]" -f $_.FriendlyName, $_.Status) }
    }
} catch { Record "INFO" "paired" "no disponible" }

Section "Resumen"
Add-Line "PASS=$Pass WARN=$Warn FAIL=$Fail INFO=$Info"
Add-Line "Nota: en Windows el estado Discoverable/Pairable exacto depende del panel de Configuración."
$Lines | Set-Content -Path $Report -Encoding UTF8
Write-Host "Informe: $Report"
if ($Json) {
    [pscustomobject]@{ version = $VERSION; host = $HostName; generated_at = $Stamp; summary = @{ pass = $Pass; warn = $Warn; fail = $Fail; info = $Info }; results = $Results } |
        ConvertTo-Json -Depth 5 | Set-Content $JsonOut -Encoding UTF8
    Write-Host "JSON: $JsonOut"
}
if ($Fail -gt 0) { exit 2 }; if ($Warn -gt 0) { exit 1 }; exit 0
