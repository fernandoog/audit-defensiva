# audit-defensiva

Auditoría **defensiva** del host local en Linux (Omarchy/Arch y similares).

Revisa superficie de ataque de **tu propio equipo**: actualizaciones, firewall, puertos en escucha, SSH, usuarios, permisos del home y sysctl. **No** explota vulnerabilidades ni escanea otros hosts.

## Requisitos

- Bash 4+
- Herramientas habituales: `ss`, `sysctl`, `systemctl`
- Opcionales: `ufw`, `nft`, `checkupdates` (Arch), `lynis`, `nmap`

## Uso

```bash
chmod +x bin/audit-host.sh
./bin/audit-host.sh
```

Informe en `reports/audit-<host>-<timestamp>.txt`.

```bash
./bin/audit-host.sh --json
./bin/audit-host.sh --out /tmp/mis-informes
```

Códigos de salida:

| Código | Significado        |
|--------|--------------------|
| 0      | Sin FAIL ni WARN   |
| 1      | Solo WARN          |
| 2      | Hay FAIL           |

## Qué comprueba

- Identidad del host y privilegios del proceso
- Paquetes pendientes (`checkupdates` en Arch)
- Estado de UFW / reglas nftables
- Sockets TCP/UDP en escucha (`ss`) y binds sensibles en `0.0.0.0`
- `PermitRootLogin` / `PasswordAuthentication` en SSH
- Cuentas UID 0 y (si hay permiso) contraseñas vacías
- Permisos de `$HOME`, `.ssh` y `.gnupg`
- Sysctl de endurecimiento habitual

## Ampliación opcional

Si instalas [Lynis](https://cisofy.com/lynis/):

```bash
sudo pacman -S lynis
sudo lynis audit system
```

## Alcance y ética

Este proyecto es para **auditar y endurecer máquinas que administras**. No uses estas ideas para atacar sistemas ajenos.

## Licencia

MIT — ver [LICENSE](LICENSE).
