# Manual — audit-defensiva

Auditoría defensiva del **propio** equipo: host, LAN/Wi‑Fi y Bluetooth.  
No escanea ni ataca otros dispositivos de la red.

## Linux: instalar como aplicación

Desde el clon del repo:

```bash
git clone https://github.com/fernandoog/audit-defensiva.git
cd audit-defensiva
./install.sh
```

Esto copia el proyecto a `~/.local/share/audit-defensiva`, pone `audit-defensiva` en `~/.local/bin` y registra «Audit Defensiva» en el menú de aplicaciones.

### Abrir la app

- Launcher / menú → **Audit Defensiva**
- O en terminal:

```bash
audit-defensiva
```

Menú: `1` Host · `2` LAN · `3` Bluetooth · `4` Todo · `0` Salir.

Sin menú:

```bash
audit-defensiva host --json
audit-defensiva lan --json
audit-defensiva bluetooth --json
audit-defensiva all
```

Informes en `~/.local/share/audit-defensiva/reports/` (si instalaste) o `./reports/` (si lanzas desde el repo).

### Actualizar

```bash
cd ~/Dv/audit-defensiva   # repo
git pull
./install.sh
```

---

## Módulo Host

Sistema, actualizaciones, firewall, puertos locales, SSH, usuarios, sysctl.

```bash
./bin/audit-host.sh --json
```

---

## Módulo LAN (defensivo)

- Interfaces y direcciones
- Wi‑Fi (SSID, tipo de cifrado WPA2/WPA3)
- IP forwarding
- Vecinos en tabla ARP/NDP (**solo caché local**, sin port-scan)
- Comparticiones NFS/Samba de **este** host
- Firewall

```bash
./bin/audit-lan.sh --json
# o
audit-defensiva lan
```

---

## Módulo Bluetooth (defensivo)

- Powered / Discoverable / Pairable
- Dispositivos conocidos
- rfkill

```bash
./bin/audit-bluetooth.sh --json
# o
audit-defensiva bluetooth
```

Consejo: si no usas BT, apágalo. Si lo usas, `Discoverable=no` y `Pairable=no` salvo al emparejar.

---

## Windows

Clona o descarga el ZIP **en el PC Windows** y en PowerShell (admin recomendado):

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\bin\audit-host.ps1 -Json
.\bin\audit-lan.ps1 -Json
.\bin\audit-bluetooth.ps1 -Json
```

No lances estos scripts «contra» el Windows desde otro PC por Wi‑Fi: ejecútalos **en** el Windows.

---

## Cómo leer resultados

| Etiqueta | Significado |
|----------|-------------|
| PASS | Correcto |
| WARN | Revisar |
| FAIL | Prioritario |
| INFO | Contexto |

Salida: `0` ok · `1` solo WARN · `2` hay FAIL.

---

## Qué no hace

- Metasploit / exploits
- Escaneo de puertos de otros hosts
- Ataques Bluetooth a terceros
