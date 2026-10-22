# audit-defensiva

Auditoría **defensiva** del host local en **Linux** y **Windows**.

Revisa superficie de ataque de **tu propio equipo**: firewall, actualizaciones, puertos en escucha, RDP/SSH, antivirus, usuarios y endurecimiento básico. **No** explota vulnerabilidades ni escanea otros hosts de la red.

## Manual completo

Instrucciones paso a paso (clonar, PowerShell, informes): **[MANUAL.md](MANUAL.md)**.

## Uso rápido

### Linux

```bash
chmod +x bin/audit-host.sh
./bin/audit-host.sh --json
```

### Windows (en el propio PC Windows)

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\bin\audit-host.ps1 -Json
```

Informes en `reports/`.

| Código de salida | Significado      |
|------------------|------------------|
| 0                | Sin FAIL ni WARN |
| 1                | Solo WARN        |
| 2                | Hay FAIL         |

## Scripts

| Archivo              | Plataforma |
|----------------------|------------|
| `bin/audit-host.sh`  | Linux      |
| `bin/audit-host.ps1` | Windows    |

## Alcance y ética

Ejecuta el script **en la máquina que administras**. No sirve (ni está pensado) para atacar o escanear otros equipos por Wi‑Fi.

## Licencia

MIT — ver [LICENSE](LICENSE).
