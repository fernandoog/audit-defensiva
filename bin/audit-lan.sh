#!/usr/bin/env bash
# audit-lan.sh — auditoría defensiva de red local (interfaces/Wi‑Fi/vecinos ARP)
# No escanea puertos de otros hosts ni lanza ataques.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/audit-common.sh
source "$SCRIPT_DIR/lib/audit-common.sh"

ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="${ROOT_DIR}/reports"
JSON_MODE=0

usage() {
  cat <<EOF
audit-lan.sh v${AUDIT_VERSION}
Auditoría defensiva de LAN/Wi‑Fi de ESTE equipo.

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
REPORT="${OUT_DIR}/audit-lan-${HOST}-${STAMP}.txt"
JSON_OUT="${OUT_DIR}/audit-lan-${HOST}-${STAMP}.json"

check_interfaces() {
  section "Interfaces y direcciones"
  if ! have ip; then
    record WARN ip "comando ip no disponible"
    return
  fi
  local up=0
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    echo "  $line"
    if echo "$line" | grep -q ' UP '; then
      up=$((up + 1))
    fi
  done < <(ip -br addr 2>/dev/null || true)
  record INFO ifaces "${up} interfaz(es) UP"
}

check_wifi() {
  section "Wi‑Fi / NetworkManager"
  if ! have nmcli; then
    record INFO nmcli "nmcli no disponible"
    return
  fi

  local status
  status="$(nmcli -t -f DEVICE,TYPE,STATE,CONNECTION device status 2>/dev/null || true)"
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    echo "  $line"
  done <<< "$status"

  local wifi_conn
  wifi_conn="$(nmcli -t -f DEVICE,TYPE,STATE,CONNECTION device status 2>/dev/null \
    | awk -F: '$2=="wifi" && $3=="connected" {print $4; exit}')"
  if [[ -z "$wifi_conn" ]]; then
    record INFO wifi "sin Wi‑Fi conectado ahora"
    return
  fi
  record INFO wifi "conectado a «${wifi_conn}»"

  local keymgmt
  keymgmt="$(nmcli -g 802-11-wireless-security.key-mgmt connection show "$wifi_conn" 2>/dev/null || true)"
  case "${keymgmt}" in
    wpa-psk|wpa-eap)
      record WARN wifi-sec "key-mgmt=${keymgmt} (WPA2). Si el AP soporta WPA3, mejorálo."
      ;;
    sae|wpa3*|owe)
      record PASS wifi-sec "key-mgmt=${keymgmt} (WPA3/moderno)"
      ;;
    "" )
      record INFO wifi-sec "no se pudo leer key-mgmt de «${wifi_conn}»"
      ;;
    none|wep)
      record FAIL wifi-sec "key-mgmt=${keymgmt} (inseguro)"
      ;;
    *)
      record INFO wifi-sec "key-mgmt=${keymgmt}"
      ;;
  esac

  # Wi‑Fi hotspot / AP mode on this machine increases exposure
  if nmcli -t -f NAME,TYPE connection show --active 2>/dev/null | grep -qi 'wifi-ap\|802-11-wireless.mode:ap'; then
    record WARN wifi-ap "parece haber un AP/hotspot activo en este equipo"
  else
    record PASS wifi-ap "sin hotspot/AP activo detectado"
  fi
}

check_forwarding() {
  section "Reenvío IP / exposición"
  local v4 v6
  v4="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo missing)"
  v6="$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null || echo missing)"
  if [[ "$v4" == "0" ]]; then
    record PASS ip-forward "net.ipv4.ip_forward=0"
  elif [[ "$v4" == "1" ]]; then
    record WARN ip-forward "net.ipv4.ip_forward=1 (este PC enruta tráfico)"
  else
    record INFO ip-forward "net.ipv4.ip_forward=${v4}"
  fi
  if [[ "$v6" == "0" ]]; then
    record PASS ip6-forward "net.ipv6.conf.all.forwarding=0"
  elif [[ "$v6" == "1" ]]; then
    record WARN ip6-forward "IPv6 forwarding activo"
  else
    record INFO ip6-forward "forwarding IPv6=${v6}"
  fi
}

check_neighbors() {
  section "Vecinos conocidos (tabla ARP/NDP local)"
  if ! have ip; then
    record INFO neigh "sin ip"
    return
  fi
  # Solo lista lo que el kernel ya conoce — no hace discovery activo agresivo
  local neigh count
  neigh="$(ip neigh show 2>/dev/null | grep -v 'FAILED' || true)"
  count="$(echo "$neigh" | grep -c . || true)"
  count="${count:-0}"
  record INFO neigh "${count} entrada(s) en la tabla de vecinos (vista pasiva)"
  if [[ "$count" -gt 0 ]]; then
    echo "$neigh" | head -40 | while IFS= read -r line; do
      echo "  $line"
    done
    if [[ "$count" -gt 40 ]]; then
      echo "  … ($((count - 40)) más)"
    fi
  fi
  record INFO neigh-scope "no se escanean puertos de otros hosts; solo inventario local"
}

check_shares() {
  section "Comparticiones exportadas por ESTE host"
  local exported=0
  if have exportfs; then
    local nfs
    nfs="$(exportfs -v 2>/dev/null || true)"
    if [[ -n "$nfs" ]]; then
      exported=1
      record WARN nfs "hay exportaciones NFS activas"
      echo "$nfs" | head -20 | while IFS= read -r line; do echo "  $line"; done
    else
      record PASS nfs "sin exportaciones NFS visibles"
    fi
  else
    record INFO nfs "exportfs no disponible"
  fi

  if have smbstatus || [[ -r /etc/samba/smb.conf ]]; then
    if systemctl is-active --quiet smb 2>/dev/null || systemctl is-active --quiet smbd 2>/dev/null; then
      exported=1
      record WARN samba "servicio Samba/SMB activo en este host"
    else
      record PASS samba "Samba/SMB no activo"
    fi
  else
    record INFO samba "Samba no detectado"
  fi

  if have avahi-daemon || systemctl is-active --quiet avahi-daemon 2>/dev/null; then
    if systemctl is-active --quiet avahi-daemon 2>/dev/null; then
      record INFO avahi "avahi-daemon activo (descubrimiento mDNS en LAN)"
    fi
  fi

  if [[ "$exported" -eq 0 ]]; then
    record PASS shares "sin comparticiones obvias exportadas"
  fi
}

check_firewall_lan() {
  section "Firewall frente a LAN"
  if have ufw; then
    local st
    st="$(ufw status 2>/dev/null | head -1 || true)"
    if echo "$st" | grep -qi active; then
      record PASS ufw-lan "UFW activo"
    else
      record WARN ufw-lan "UFW no activo o no legible sin sudo"
    fi
  elif have firewall-cmd; then
    if firewall-cmd --state 2>/dev/null | grep -qi running; then
      record PASS firewalld "firewalld en ejecución"
    else
      record WARN firewalld "firewalld no en ejecución"
    fi
  else
    record INFO fw "sin UFW/firewalld detectado; revisa nftables/iptables"
  fi
}

main() {
  local tmp
  tmp="$(mktemp)"
  {
    echo "audit-lan.sh v${AUDIT_VERSION}"
    echo "Generado: ${STAMP} (UTC)"
    echo "Host: ${HOST}"
    echo "Alcance: red de ESTE equipo (defensivo; sin scan de terceros)"
    check_interfaces
    check_wifi
    check_forwarding
    check_neighbors
    check_shares
    check_firewall_lan
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
