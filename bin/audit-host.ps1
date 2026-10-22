#Requires -Version 5.1
<#
.SYNOPSIS
  Auditoría defensiva del host Windows local (sin explotación).

.DESCRIPTION
  Revisa firewall, actualizaciones, puertos en escucha, RDP, BitLocker,
  UAC, antivirus y usuarios. Solo inspecciona ESTE equipo.

.EXAMPLE
  .\bin\audit-host.ps1
  .\bin\audit-host.ps1 -Json
  .\bin\audit-host.ps1 -OutDir C:\Temp\informes
#>
[CmdletBinding()]
param(
    [switch]$Json,
    [string]$OutDir = "",
    [switch]$Help
)

$ErrorActionPreference = "Continue"
$VERSION = "1.0.0"

if ($Help) {
    Write-Host @"
audit-host.ps1 v$VERSION
Auditoría defensiva del host Windows local.

Uso:
  .\bin\audit-host.ps1 [-Json] [-OutDir DIR]

Solo inspecciona este equipo. No lanza exploits ni escanea otros hosts.
"@
    exit 0
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir
if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $OutDir = Join-Path $RootDir "reports"
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$Stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$HostName = $env:COMPUTERNAME
$Report = Join-Path $OutDir "audit-$HostName-$Stamp.txt"
$JsonOut = Join-Path $OutDir "audit-$HostName-$Stamp.json"

$script:Pass = 0
$script:Warn = 0
$script:Fail = 0
$script:Info = 0
$script:Results = New-Object System.Collections.Generic.List[object]
$script:Lines = New-Object System.Collections.Generic.List[string]

function Add-Line([string]$Text) {
    $script:Lines.Add($Text)
    Write-Host $Text
}

function Record([string]$Status, [string]$Code, [string]$Msg) {
    $script:Results.Add([pscustomobject]@{ status = $Status; code = $Code; message = $Msg })
    switch ($Status) {
        "PASS" { $script:Pass++ }
        "WARN" { $script:Warn++ }
        "FAIL" { $script:Fail++ }
        "INFO" { $script:Info++ }
    }
    Add-Line "[$Status] $Code — $Msg"
}

function Section([string]$Title) {
    Add-Line ""
    Add-Line "== $Title =="
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# --- checks ---

function Check-Identity {
    Section "Identidad del host"
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $caption = if ($os) { $os.Caption } else { "Windows" }
    $ver = if ($os) { $os.Version } else { "?" }
    Record "INFO" "identity" "host=$HostName os=$caption version=$ver user=$env:USERNAME"
    if (Test-Admin) {
        Record "WARN" "privileges" "ejecutando como Administrador; preferible usuario normal + elevación puntual"
    } else {
        Record "PASS" "privileges" "ejecutando como usuario estándar"
    }
}

function Check-Updates {
    Section "Actualizaciones"
    try {
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $result = $searcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
        $count = $result.Updates.Count
        if ($count -eq 0) {
            Record "PASS" "updates" "sin actualizaciones pendientes visibles"
        } elseif ($count -gt 10) {
            Record "FAIL" "updates" "$count actualizaciones pendientes"
        } else {
            Record "WARN" "updates" "$count actualizaciones pendientes"
        }
    } catch {
        Record "INFO" "updates" "no se pudo consultar Windows Update ($($_.Exception.Message))"
    }
}

function Check-Firewall {
    Section "Firewall de Windows"
    try {
        $profiles = Get-NetFirewallProfile -ErrorAction Stop
        foreach ($p in $profiles) {
            if ($p.Enabled) {
                Record "PASS" "fw-$($p.Name)" "perfil $($p.Name) activo"
            } else {
                Record "FAIL" "fw-$($p.Name)" "perfil $($p.Name) desactivado"
            }
        }
    } catch {
        Record "INFO" "firewall" "no se pudo leer el firewall ($($_.Exception.Message))"
    }
}

function Check-Listening {
    Section "Puertos en escucha (local)"
    try {
        $listeners = Get-NetTCPConnection -State Listen -ErrorAction Stop |
            Select-Object -Property LocalAddress, LocalPort, OwningProcess |
            Sort-Object LocalPort -Unique
        $count = ($listeners | Measure-Object).Count
        Record "INFO" "ports" "$count sockets TCP en escucha (detalle abajo)"
        $risky = 0
        $sensitive = @(21, 23, 135, 139, 445, 3389, 5900, 5985, 5986)
        foreach ($l in $listeners) {
            $addr = $l.LocalAddress
            $port = $l.LocalPort
            Add-Line ("  {0}:{1}  pid={2}" -f $addr, $port, $l.OwningProcess)
            $exposed = ($addr -eq "0.0.0.0" -or $addr -eq "::" -or $addr -eq "*")
            if ($exposed -and ($sensitive -contains [int]$port)) {
                $risky++
                Record "WARN" "ports-bind" "servicio sensible escuchando en todas las interfaces: ${addr}:${port}"
            }
        }
        if ($risky -eq 0) {
            Record "PASS" "ports-bind" "sin servicios sensibles obvios en 0.0.0.0/::"
        }
    } catch {
        Record "WARN" "ports" "no se pudieron listar puertos ($($_.Exception.Message))"
    }
}

function Check-Rdp {
    Section "Escritorio remoto (RDP)"
    try {
        $rdp = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction Stop).fDenyTSConnections
        if ($rdp -eq 1) {
            Record "PASS" "rdp" "RDP deshabilitado"
        } else {
            Record "WARN" "rdp" "RDP habilitado; asegúrate de red segura, NLA y contraseñas fuertes"
            try {
                $nla = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -ErrorAction Stop).UserAuthentication
                if ($nla -eq 1) {
                    Record "PASS" "rdp-nla" "Network Level Authentication activo"
                } else {
                    Record "FAIL" "rdp-nla" "NLA desactivado con RDP activo"
                }
            } catch {
                Record "INFO" "rdp-nla" "no se pudo leer NLA"
            }
        }
    } catch {
        Record "INFO" "rdp" "no se pudo leer la clave RDP"
    }
}

function Check-Uac {
    Section "UAC"
    try {
        $uac = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction Stop).EnableLUA
        if ($uac -eq 1) {
            Record "PASS" "uac" "UAC habilitado"
        } else {
            Record "FAIL" "uac" "UAC deshabilitado"
        }
    } catch {
        Record "INFO" "uac" "no se pudo leer UAC"
    }
}

function Check-BitLocker {
    Section "BitLocker"
    try {
        $vols = Get-BitLockerVolume -ErrorAction Stop
        $any = $false
        foreach ($v in $vols) {
            if ($v.VolumeType -eq "OperatingSystem") {
                $any = $true
                if ($v.ProtectionStatus -eq "On") {
                    Record "PASS" "bitlocker" "volumen OS protegido ($($v.MountPoint))"
                } else {
                    Record "WARN" "bitlocker" "volumen OS sin protección BitLocker ($($v.MountPoint))"
                }
            }
        }
        if (-not $any) {
            Record "INFO" "bitlocker" "no se detectó volumen OS con BitLocker (¿permisos?)"
        }
    } catch {
        Record "INFO" "bitlocker" "BitLocker no consultable sin privilegios o no disponible"
    }
}

function Check-Defender {
    Section "Antivirus (Defender)"
    try {
        $s = Get-MpComputerStatus -ErrorAction Stop
        if ($s.RealTimeProtectionEnabled) {
            Record "PASS" "defender-rtp" "protección en tiempo real activa"
        } else {
            Record "FAIL" "defender-rtp" "protección en tiempo real desactivada"
        }
        if ($s.AntivirusEnabled) {
            Record "PASS" "defender-av" "AntivirusEnabled=True"
        } else {
            Record "WARN" "defender-av" "AntivirusEnabled=False"
        }
        if ($s.AntivirusSignatureAge -le 7) {
            Record "PASS" "defender-sig" "firmas con $($s.AntivirusSignatureAge) día(s) de antigüedad"
        } else {
            Record "WARN" "defender-sig" "firmas antiguas ($($s.AntivirusSignatureAge) días)"
        }
    } catch {
        Record "INFO" "defender" "no se pudo consultar Defender ($($_.Exception.Message))"
    }
}

function Check-Users {
    Section "Usuarios locales"
    try {
        $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
        $names = ($admins | ForEach-Object { $_.Name }) -join ", "
        Record "INFO" "admins" "miembros de Administrators: $names"
        $enabledAdmins = @($admins | Where-Object {
            try {
                $u = Get-LocalUser -Name ($_.Name.Split('\')[-1]) -ErrorAction Stop
                $u.Enabled
            } catch { $true }
        })
        if ($enabledAdmins.Count -gt 3) {
            Record "WARN" "admins-count" "muchos administradores habilitados ($($enabledAdmins.Count))"
        } else {
            Record "PASS" "admins-count" "número de administradores razonable ($($enabledAdmins.Count))"
        }
    } catch {
        Record "INFO" "admins" "no se pudo listar Administrators"
    }

    try {
        $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
        if ($null -eq $guest) {
            Record "INFO" "guest" "cuenta Guest no presente"
        } elseif ($guest.Enabled) {
            Record "FAIL" "guest" "cuenta Guest habilitada"
        } else {
            Record "PASS" "guest" "cuenta Guest deshabilitada"
        }
    } catch {
        Record "INFO" "guest" "no se pudo comprobar Guest"
    }
}

function Check-Smb {
    Section "SMB / compartir"
    try {
        $smbv1 = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction SilentlyContinue
        if ($null -ne $smbv1) {
            if ($smbv1.State -eq "Enabled") {
                Record "FAIL" "smb1" "SMBv1 habilitado (protocolo inseguro)"
            } else {
                Record "PASS" "smb1" "SMBv1 no habilitado"
            }
        } else {
            Record "INFO" "smb1" "no se pudo consultar la característica SMBv1 (¿hace falta admin?)"
        }
    } catch {
        Record "INFO" "smb1" "consulta SMBv1 no disponible"
    }
}

# --- run ---

Add-Line "audit-host.ps1 v$VERSION"
Add-Line "Generado: $Stamp (UTC)"
Add-Line "Host: $HostName"
Add-Line "Alcance: solo este equipo (defensivo)"

Check-Identity
Check-Updates
Check-Firewall
Check-Listening
Check-Rdp
Check-Uac
Check-BitLocker
Check-Defender
Check-Users
Check-Smb

Section "Resumen"
Add-Line "PASS=$script:Pass WARN=$script:Warn FAIL=$script:Fail INFO=$script:Info"
if ($script:Fail -gt 0) {
    Add-Line "Veredicto: hay hallazgos críticos (FAIL). Prioriza corregirlos."
} elseif ($script:Warn -gt 0) {
    Add-Line "Veredicto: sin FAIL, pero hay advertencias a revisar."
} else {
    Add-Line "Veredicto: sin FAIL/WARN en las comprobaciones automatizadas."
}

$script:Lines | Set-Content -Path $Report -Encoding UTF8
Write-Host "Informe: $Report"

if ($Json) {
    $payload = [pscustomobject]@{
        version      = $VERSION
        host         = $HostName
        generated_at = $Stamp
        summary      = @{ pass = $script:Pass; warn = $script:Warn; fail = $script:Fail; info = $script:Info }
        results      = $script:Results
    }
    $payload | ConvertTo-Json -Depth 5 | Set-Content -Path $JsonOut -Encoding UTF8
    Write-Host "JSON: $JsonOut"
}

if ($script:Fail -gt 0) { exit 2 }
if ($script:Warn -gt 0) { exit 1 }
exit 0
