# audit-defensiva

Aplicación de auditoría **defensiva** local: **host**, **LAN/Wi‑Fi** y **Bluetooth** (Linux y Windows).

No explota vulnerabilidades ni escanea puertos de otros equipos.

## Instalación en Linux (Omarchy)

```bash
cd ~/Dv/audit-defensiva   # o donde clones el repo
./install.sh
```

Queda en:

| Qué | Dónde |
|-----|--------|
| App / datos | `~/.local/share/audit-defensiva` |
| Comando | `~/.local/bin/audit-defensiva` |
| Menú | «Audit Defensiva» |

```bash
audit-defensiva          # menú
audit-defensiva all      # host + lan + bluetooth
audit-defensiva lan
audit-defensiva bluetooth
```

## Manual

Paso a paso: **[MANUAL.md](MANUAL.md)**.

## Scripts

| Archivo | Qué hace |
|---------|----------|
| `bin/audit-defensiva` | App / menú |
| `bin/audit-host.sh` / `.ps1` | Sistema |
| `bin/audit-lan.sh` / `.ps1` | LAN / Wi‑Fi (pasivo) |
| `bin/audit-bluetooth.sh` / `.ps1` | Bluetooth local |

## Ética

Ejecuta solo en máquinas que administras. LAN/Bluetooth aquí = **tu** adaptador y vista pasiva de vecinos, no ataques a la red.

## Licencia

MIT — [LICENSE](LICENSE).
