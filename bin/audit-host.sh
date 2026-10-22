#!/usr/bin/env bash
# audit-host.sh — auditoría defensiva local (sin explotación)
# Uso: ./bin/audit-host.sh [--json] [--out DIR]
set -euo pipefail

VERSION="1.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="${ROOT_DIR}/reports"
JSON_MODE=0
PASS=0
WARN=0
FAIL=0
INFO=0
RESULTS=()

usage() {
  cat <<EOF
audit-host.sh v${VERSION}
Auditoría defensiva del host local (puertos, firewall, SSH, actualizaciones, usuarios).

Uso:
  $(basename "$0") [--json] [--out DIR]

Opciones:
  --json     Resumen final en JSON además del informe texto
  --out DIR  Directorio de informes (default: ./reports)
  -h, --help Ayuda

Solo inspecciona este equipo. No lanza exploits ni escanea otros hosts.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --json) JSON_MODE=1; shift ;;
    --out)
      OUT_DIR="${2:?--out requiere un directorio}"
      shift 2
      ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Opción desconocida: $1" >&2; usage >&2; exit 1 ;;
  esac
done

mkdir -p "$OUT_DIR"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
HOST="$(hostname -s 2>/dev/null || hostname)"
REPORT="${OUT_DIR}/audit-${HOST}-${STAMP}.txt"
JSON_OUT="${OUT_DIR}/audit-${HOST}-${STAMP}.json"

record() {
  local status="$1" code="$2" msg="$3"
  RESULTS+=("${status}|${code}|${msg}")
  case "$status" in
    PASS) PASS=$((PASS + 1)) ;;
    WARN) WARN=$((WARN + 1)) ;;
    FAIL) FAIL=$((FAIL + 1)) ;;
    INFO) INFO=$((INFO + 1)) ;;
  esac
  printf '[%s] %s — %s\n' "$status" "$code" "$msg"
}

section() {
  printf '\n== %s ==\n' "$1"
}

have() { command -v "$1" >/dev/null 2>&1; }

# --- checks ---

check_identity() {
  section "Identidad del host"
  record INFO identity "host=${HOST} kernel=$(uname -r) arch=$(uname -m) user=$(id -un)"
  if [[ "$(id -u)" -eq 0 ]]; then
    record WARN privileges "ejecutando como root; preferible usuario normal + sudo puntual"
  else
    record PASS privileges "ejecutando como usuario no root"
  fi
}

check_updates() {
  section "Actualizaciones pendientes"
  if have checkupdates; then
    local pending
    pending="$(checkupdates 2>/dev/null | wc -l | tr -d ' ')" || pending="?"
    if [[ "$pending" == "0" ]]; then
      record PASS updates "sin paquetes pendientes (checkupdates)"
    elif [[ "$pending" =~ ^[0-9]+$ ]]; then
      if [[ "$pending" -gt 20 ]]; then
        record FAIL updates "${pending} paquetes pendientes de actualizar"
      else
        record WARN updates "${pending} paquetes pendientes de actualizar"
      fi
    else
      record INFO updates "no se pudo consultar checkupdates (¿mirror/db?)"
    fi
  elif have apt-get; then
    record INFO updates "sistema no Arch; revisa 'apt update && apt list --upgradable' manualmente"
  else
    record INFO updates "no hay gestor de actualizaciones detectable"
  fi
}

check_firewall() {
  section "Firewall"
  if have ufw; then
    local status
    status="$(ufw status 2>/dev/null | head -1 | tr -d '\r' || true)"
    status="${status:-sin salida (¿hace falta sudo?)}"
    if echo "$status" | grep -qi 'active'; then
      record PASS ufw "UFW activo"
    else
      record WARN ufw "UFW instalado pero no activo: ${status}"
    fi
  else
    record INFO ufw "UFW no instalado"
  fi

  if have nft; then
    local rules=0
    rules="$(nft list ruleset 2>/dev/null | wc -l | tr -d '[:space:]')" || true
    rules="${rules:-0}"
    if [[ "$rules" =~ ^[0-9]+$ ]] && [[ "$rules" -gt 5 ]]; then
      record PASS nftables "hay reglas nftables (${rules} líneas)"
    else
      record WARN nftables "pocas o ninguna regla nftables visible (¿permisos?)"
    fi
  fi
}

check_listening() {
  section "Puertos en escucha (local)"
  if ! have ss; then
    record WARN ports "ss no disponible"
    return
  fi

  local listen
  listen="$(ss -tulnH 2>/dev/null || true)"
  if [[ -z "$listen" ]]; then
    record PASS ports "ningún socket TCP/UDP en escucha detectado"
    return
  fi

  local count risky=0
  count="$(echo "$listen" | wc -l | tr -d ' ')"
  record INFO ports "${count} sockets en escucha (detalle abajo)"

  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    echo "  $line"
    # Riesgos habituales si escuchan en 0.0.0.0 / *
    if echo "$line" | grep -Eq '0\.0\.0\.0:|\[::\]:|\*:'; then
      if echo "$line" | grep -Eq ':(22|23|21|445|3389|5900|6379|27017|5432|3306|9200)\s'; then
        risky=$((risky + 1))
        record WARN ports-bind "servicio sensible escuchando en todas las interfaces: ${line}"
      fi
    fi
  done <<< "$listen"

  if [[ "$risky" -eq 0 ]]; then
    record PASS ports-bind "sin servicios sensibles obvios en 0.0.0.0/*"
  fi
}

check_ssh() {
  section "Configuración SSH"
  local cfg="/etc/ssh/sshd_config"
  if [[ ! -r "$cfg" ]]; then
    if [[ -e "$cfg" ]]; then
      record INFO ssh "sshd_config existe pero no es legible sin privilegios elevados"
    else
      record INFO ssh "no hay sshd_config (¿SSH no instalado?)"
    fi
    return
  fi

  get_ssh() {
    local key="$1" default="$2"
    local val
    val="$(grep -E "^[[:space:]]*${key}[[:space:]]+" "$cfg" 2>/dev/null | awk '{print $2}' | tail -1 || true)"
    echo "${val:-$default}"
  }

  local permit_root password_auth
  permit_root="$(get_ssh PermitRootLogin prohibit-password)"
  password_auth="$(get_ssh PasswordAuthentication yes)"

  case "${permit_root,,}" in
    no) record PASS ssh-root "PermitRootLogin no" ;;
    prohibit-password|without-password)
      record WARN ssh-root "PermitRootLogin=${permit_root} (mejor: no)" ;;
    yes) record FAIL ssh-root "PermitRootLogin yes" ;;
    *) record INFO ssh-root "PermitRootLogin=${permit_root}" ;;
  esac

  case "${password_auth,,}" in
    no) record PASS ssh-password "PasswordAuthentication no" ;;
    yes) record WARN ssh-password "PasswordAuthentication yes (preferible claves)" ;;
    *) record INFO ssh-password "PasswordAuthentication=${password_auth}" ;;
  esac

  if systemctl is-active --quiet sshd 2>/dev/null || systemctl is-active --quiet ssh 2>/dev/null; then
    record INFO ssh-service "servicio SSH activo"
  else
    record PASS ssh-service "servicio SSH no activo (superficie menor)"
  fi
}

check_users() {
  section "Usuarios y privilegios"
  local uid0
  uid0="$(awk -F: '$3==0 {print $1}' /etc/passwd 2>/dev/null | tr '\n' ' ')"
  if [[ "$(echo "$uid0" | wc -w)" -eq 1 ]] && echo "$uid0" | grep -qw root; then
    record PASS uid0 "solo root con UID 0"
  else
    record WARN uid0 "cuentas con UID 0: ${uid0}"
  fi

  if [[ -r /etc/sudoers ]] || [[ -d /etc/sudoers.d ]]; then
    if groups | grep -Eq '\b(wheel|sudo)\b'; then
      record INFO sudo "usuario actual en grupo sudo/wheel"
    else
      record INFO sudo "usuario actual fuera de sudo/wheel"
    fi
  fi

  local empty_pass=0
  if [[ -r /etc/shadow ]]; then
    empty_pass="$(awk -F: '($2=="" || $2=="!" || $2=="!!" || $2=="*") {next} $2 ~ /^!/ {next} length($2)==0 {c++} END{print c+0}' /etc/shadow 2>/dev/null || echo 0)"
    # empty password field for login-capable users is rare; better check for accounts without locked password that have empty
    empty_pass="$(awk -F: '$2=="" {print $1}' /etc/shadow 2>/dev/null | wc -l | tr -d ' ')"
    if [[ "$empty_pass" -gt 0 ]]; then
      record FAIL shadow "cuentas con contraseña vacía en /etc/shadow: ${empty_pass}"
    else
      record PASS shadow "sin contraseñas vacías en /etc/shadow"
    fi
  else
    record INFO shadow "/etc/shadow no legible (normal sin root)"
  fi
}

check_home_perms() {
  section "Permisos del home"
  local home="${HOME:-}"
  if [[ -z "$home" || ! -d "$home" ]]; then
    record INFO home "HOME no definido"
    return
  fi
  local mode
  mode="$(stat -c '%a' "$home" 2>/dev/null || echo '?')"
  if [[ "$mode" =~ ^7[0-7][0-7]$ ]]; then
    # world/group writable is bad; 755 ok-ish, 750/700 better
    if [[ "${mode: -1}" != "0" ]] || [[ "${mode: -2:1}" != "0" && "${mode: -2:1}" != "5" ]]; then
      :
    fi
  fi
  if [[ "$mode" == "700" || "$mode" == "750" ]]; then
    record PASS home-mode "permisos de ${home}: ${mode}"
  elif [[ "$mode" == "755" ]]; then
    record WARN home-mode "permisos de ${home}: 755 (recomendado 750 o 700)"
  else
    record WARN home-mode "permisos de ${home}: ${mode}"
  fi

  for f in .ssh .gnupg; do
    if [[ -d "$home/$f" ]]; then
      local pm
      pm="$(stat -c '%a' "$home/$f")"
      if [[ "$pm" == "700" ]]; then
        record PASS "home-${f}" "${home}/${f} modo 700"
      else
        record FAIL "home-${f}" "${home}/${f} modo ${pm} (debe ser 700)"
      fi
    fi
  done
}

check_kernel_hardening() {
  section "Endurecimiento del kernel (sysctl)"
  local keys=(
    "kernel.randomize_va_space=2"
    "net.ipv4.conf.all.rp_filter=1"
    "net.ipv4.conf.default.rp_filter=1"
    "net.ipv4.tcp_syncookies=1"
    "net.ipv4.conf.all.accept_redirects=0"
    "net.ipv6.conf.all.accept_redirects=0"
  )
  for pair in "${keys[@]}"; do
    local key="${pair%%=*}" want="${pair#*=}" got
    got="$(sysctl -n "$key" 2>/dev/null || echo missing)"
    if [[ "$got" == "$want" ]]; then
      record PASS "sysctl-${key}" "${key}=${got}"
    elif [[ "$got" == "missing" ]]; then
      record INFO "sysctl-${key}" "${key} no disponible"
    else
      record WARN "sysctl-${key}" "${key}=${got} (esperado ${want})"
    fi
  done
}

check_lynis_hint() {
  section "Herramientas opcionales"
  if have lynis; then
    record INFO lynis "Lynis instalado: puedes ampliar con 'sudo lynis audit system'"
  else
    record INFO lynis "Lynis no instalado (opcional: pacman -S lynis)"
  fi
  if have nmap; then
    record INFO nmap "Nmap disponible; este script solo usa inspección local (ss)"
  fi
}

write_summary() {
  section "Resumen"
  printf 'PASS=%s WARN=%s FAIL=%s INFO=%s\n' "$PASS" "$WARN" "$FAIL" "$INFO"
  if [[ "$FAIL" -gt 0 ]]; then
    echo "Veredicto: hay hallazgos críticos (FAIL). Prioriza corregirlos."
  elif [[ "$WARN" -gt 0 ]]; then
    echo "Veredicto: sin FAIL, pero hay advertencias a revisar."
  else
    echo "Veredicto: sin FAIL/WARN en las comprobaciones automatizadas."
  fi
}

write_json() {
  {
    echo '{'
    echo "  \"version\": \"${VERSION}\","
    echo "  \"host\": \"${HOST}\","
    echo "  \"generated_at\": \"${STAMP}\","
    echo "  \"summary\": {\"pass\": ${PASS}, \"warn\": ${WARN}, \"fail\": ${FAIL}, \"info\": ${INFO}},"
    echo '  "results": ['
    local i=0
    local total=${#RESULTS[@]}
    for item in "${RESULTS[@]}"; do
      local st code msg
      st="${item%%|*}"
      rest="${item#*|}"
      code="${rest%%|*}"
      msg="${rest#*|}"
      msg="${msg//\\/\\\\}"
      msg="${msg//\"/\\\"}"
      printf '    {"status":"%s","code":"%s","message":"%s"}' "$st" "$code" "$msg"
      i=$((i + 1))
      if [[ $i -lt $total ]]; then echo ','; else echo; fi
    done
    echo '  ]'
    echo '}'
  } > "$JSON_OUT"
}

main() {
  local tmp
  tmp="$(mktemp)"
  {
    echo "audit-host.sh v${VERSION}"
    echo "Generado: ${STAMP} (UTC)"
    echo "Host: ${HOST}"
    echo "Alcance: solo este equipo (defensivo)"
    check_identity
    check_updates
    check_firewall
    check_listening
    check_ssh
    check_users
    check_home_perms
    check_kernel_hardening
    check_lynis_hint
    write_summary
  } > "$tmp"

  cat "$tmp"
  cp "$tmp" "$REPORT"
  rm -f "$tmp"

  if [[ "$JSON_MODE" -eq 1 ]]; then
    write_json
    echo "JSON: ${JSON_OUT}"
  fi
  echo "Informe: ${REPORT}"

  if [[ "$FAIL" -gt 0 ]]; then
    exit 2
  fi
  if [[ "$WARN" -gt 0 ]]; then
    exit 1
  fi
  exit 0
}

main
