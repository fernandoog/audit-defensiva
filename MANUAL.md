# Manual de uso — audit-defensiva

Guía para lanzar la auditoría **en el propio equipo** que quieres revisar (Linux o Windows).  
No se audita un PC remoto por Wi‑Fi: clona o copia el proyecto **en esa máquina** y ejecuta el script allí.

## 1. Obtener el proyecto

En el equipo a auditar:

```bash
git clone https://github.com/fernandoog/audit-defensiva.git
cd audit-defensiva
```

Sin git: descarga el ZIP desde GitHub → **Code → Download ZIP**, descomprime y entra en la carpeta.

---

## 2. Linux (Omarchy / Arch / similares)

```bash
chmod +x bin/audit-host.sh
./bin/audit-host.sh
```

Con JSON:

```bash
./bin/audit-host.sh --json
```

Informe en `reports/audit-<nombre>-<fecha>.txt`.

Algunas comprobaciones (firewall completo, `/etc/shadow`) mejoran con:

```bash
sudo ./bin/audit-host.sh --json
```

---

## 3. Windows (tu portátil)

Hazlo **sentado en el Windows**, no desde otro PC de la red.

### 3.1 Abrir PowerShell

1. Tecla Windows → escribe `PowerShell`.
2. Clic derecho → **Ejecutar como administrador** (recomendado para BitLocker, SMBv1 y Defender completos).
3. Ve a la carpeta del proyecto:

```powershell
cd $HOME\Downloads\audit-defensiva
# o la ruta donde clonaste / descomprimiste
```

### 3.2 Política de ejecución (solo si Windows bloquea el script)

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Eso solo afecta a **esa** ventana de PowerShell.

### 3.3 Lanzar la auditoría

```powershell
.\bin\audit-host.ps1
```

Con JSON:

```powershell
.\bin\audit-host.ps1 -Json
```

Otro directorio de informes:

```powershell
.\bin\audit-host.ps1 -Json -OutDir $env:USERPROFILE\Desktop\informes-audit
```

### 3.4 Dónde está el informe

Carpeta `reports\` dentro del proyecto (o la de `-OutDir`):

- `audit-<NOMBRE-PC>-<timestamp>.txt`
- `audit-<NOMBRE-PC>-<timestamp>.json` (si usaste `-Json`)

---

## 4. Cómo leer el resultado

| Etiqueta | Significado |
|----------|-------------|
| PASS | Bien según la comprobación |
| WARN | Revisar / endurecer |
| FAIL | Prioritario corregir |
| INFO | Contexto, no es un fallo |

Códigos de salida del proceso:

| Código | Significado |
|--------|-------------|
| 0 | Sin FAIL ni WARN |
| 1 | Solo WARN |
| 2 | Hay FAIL |

---

## 5. Qué mirar primero en Windows

1. Perfiles de **Firewall** desactivados → actívalos.
2. **Actualizaciones** pendientes → Windows Update.
3. **RDP** abierto sin necesidad → desactívalo o exige NLA.
4. **Defender** con RTP off o firmas viejas → corrige antes de seguir.
5. **SMBv1** habilitado → desinstala la característica.
6. Cuenta **Guest** habilitada → deshabilítala.
7. Puertos sensibles en `0.0.0.0` (445, 3389, …) → reduce exposición.

En Linux: UFW/nft, actualizaciones, SSH (`PermitRootLogin`, contraseñas) y binds en `0.0.0.0`.

---

## 6. Qué no hace este proyecto

- No usa Metasploit ni exploits.
- No escanea otros equipos de la Wi‑Fi.
- No sustituye un pentest profesional ni antivirus completo.

Solo ayuda a **ver y endurecer la superficie** del host donde lo ejecutas.

---

## 7. Problemas frecuentes

**Windows: “no se puede cargar porque la ejecución de scripts está deshabilitada”**  
→ `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` y vuelve a lanzar.

**Windows: poco detalle en BitLocker / SMBv1**  
→ abre PowerShell **como administrador**.

**Linux: UFW “sin salida”**  
→ prueba con `sudo ./bin/audit-host.sh`.

**¿Auditar el Windows estando en el Linux de la misma Wi‑Fi?**  
→ no con este tool. Copia el repo al Windows (USB, git clone, ZIP) y ejecuta `audit-host.ps1` allí.
