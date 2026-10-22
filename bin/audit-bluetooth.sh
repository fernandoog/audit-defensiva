#!/usr/bin/env bash
# audit-bluetooth.sh — auditoría defensiva del adaptador Bluetooth local
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/audit-common.sh
source "$SCRIPT_DIR/lib/audit-common.sh"

ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="${ROOT_DIR}/reports"
JSON_MODE=0

usage() {
  cat <<EOF
audit-bluetooth.sh v${AUDIT_VERSION}
Auditoría defensiva de Bluetooth de ESTE equipo.

Uso: $(basename "$0") [--json] [--out DIR]
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --json) JSON_MODE=1; shift ;;
    --out) OUT_DIR="${2:?}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Opción desconocida: $1" >&2; exit 1 ;;
  esac
done

mkdir -p "$OUT_DIR"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
HOST="$(hostname -s 2>/dev/null || hostname)"
REPORT="${OUT_DIR}/audit-bt-${HOST}-${STAMP}.txt"
JSON_OUT="${OUT_DIR}/audit-bt-${HOST}-${STAMP}.json"

check_adapter() {
  section "Adaptador Bluetooth"
  if ! have bluetoothctl; then
    record WARN bluetoothctl "bluetoothctl no instalado"
    return 1
  fi
  if ! have bluetoothd && ! systemctl is-active --quiet bluetooth 2>/dev/null; then
    if ! systemctl is-active --quiet bluetooth 2>/dev/null; then
      record INFO bluetooth-svc "servicio bluetooth no activo"
    fi
  fi

  local show
  show="$(bluetoothctl show 2>/dev/null || true)"
  if [[ -z "$show" ]]; then
    record WARN adapter "no hay controlador Bluetooth visible"
    return 1
  fi

  local powered discoverable pairable discovering name
  powered="$(echo "$show" | awk -F': ' '/^\tPowered:/{print $2; exit}')"
  discoverable="$(echo "$show" | awk -F': ' '/^\tDiscoverable:/{print $2; exit}')"
  pairable="$(echo "$show" | awk -F': ' '/^\tPairable:/{print $2; exit}')"
  discovering="$(echo "$show" | awk -F': ' '/^\tDiscovering:/{print $2; exit}')"
  name="$(echo "$show" | awk -F': ' '/^\tName:/{print $2; exit}')"

  record INFO adapter "nombre=${name:-?} powered=${powered:-?} discoverable=${discoverable:-?} pairable=${pairable:-?}"

  case "${powered,,}" in
    yes)
      record INFO power "Bluetooth encendido"
      ;;
    no)
      record PASS power "Bluetooth apagado (menor superficie)"
      return 0
      ;;
    *)
      record INFO power "Powered=${powered}"
      ;;
  esac

  case "${discoverable,,}" in
    yes)
      record FAIL discoverable "Discoverable=yes — el equipo es visible para emparejar"
      ;;
    no)
      record PASS discoverable "Discoverable=no"
      ;;
    *)
      record INFO discoverable "Discoverable=${discoverable}"
      ;;
  esac

  case "${pairable,,}" in
    yes)
      record WARN pairable "Pairable=yes — desactívalo si no estás emparejando ahora"
      ;;
    no)
      record PASS pairable "Pairable=no"
      ;;
    *)
      record INFO pairable "Pairable=${pairable}"
      ;;
  esac

  case "${discovering,,}" in
    yes)
      record WARN discovering "Discovering=yes (escaneo activo en curso)"
      ;;
    no)
      record PASS discovering "sin descubrimiento activo"
      ;;
  esac
}

check_paired() {
  section "Dispositivos emparejados / conocidos"
  if ! have bluetoothctl; then
    return
  fi
  local devices
  devices="$(bluetoothctl devices 2>/dev/null || true)"
  if [[ -z "$devices" ]]; then
    record INFO paired "ningún dispositivo conocido"
    return
  fi
  local count
  count="$(echo "$devices" | grep -c . || true)"
  record INFO paired "${count} dispositivo(s) conocido(s)"
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    echo "  $line"
    local mac
    mac="$(echo "$line" | awk '{print $2}')"
    local info connected trusted blocked
    info="$(bluetoothctl info "$mac" 2>/dev/null || true)"
    connected="$(echo "$info" | awk -F': ' '/^\tConnected:/{print $2; exit}')"
    trusted="$(echo "$info" | awk -F': ' '/^\tTrusted:/{print $2; exit}')"
    blocked="$(echo "$info" | awk -F': ' '/^\tBlocked:/{print $2; exit}')"
    if [[ "${blocked,,}" == "yes" ]]; then
      record INFO "bt-${mac}" "bloqueado"
    elif [[ "${connected,,}" == "yes" ]]; then
      record INFO "bt-${mac}" "conectado (trusted=${trusted:-?})"
    else
      record INFO "bt-${mac}" "conocido, no conectado (trusted=${trusted:-?})"
    fi
  done <<< "$devices"
}

check_rfkill() {
  section "rfkill"
  if have rfkill; then
    local bt
    bt="$(rfkill list bluetooth 2>/dev/null || true)"
    if echo "$bt" | grep -qi 'Soft blocked: yes\|Hard blocked: yes'; then
      record PASS rfkill "Bluetooth bloqueado por rfkill"
      echo "$bt" | while IFS= read -r line; do echo "  $line"; done
    elif [[ -n "$bt" ]]; then
      record INFO rfkill "estado rfkill:"
      echo "$bt" | while IFS= read -r line; do echo "  $line"; done
    else
      record INFO rfkill "sin entradas bluetooth en rfkill"
    fi
  else
    record INFO rfkill "rfkill no disponible"
  fi
}

main() {
  local tmp
  tmp="$(mktemp)"
  {
    echo "audit-bluetooth.sh v${AUDIT_VERSION}"
    echo "Generado: ${STAMP} (UTC)"
    echo "Host: ${HOST}"
    echo "Alcance: adaptador Bluetooth de ESTE equipo (defensivo)"
    check_adapter || true
    check_paired
    check_rfkill
    audit_summary
  } > "$tmp"
  cat "$tmp"
  cp "$tmp" "$REPORT"
  rm -f "$tmp"
  if [[ "$JSON_MODE" -eq 1 ]]; then
    audit_write_json "$JSON_OUT" "$HOST" "$STAMP"
    echo "JSON: ${JSON_OUT}"
  fi
  echo "Informe: ${REPORT}"
  audit_exit_code
}

main
