#!/usr/bin/env bash
# Instala audit-defensiva como aplicación de usuario en Omarchy/Linux.
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHARE="${XDG_DATA_HOME:-$HOME/.local/share}/audit-defensiva"
BIN_DIR="${XDG_BIN_HOME:-$HOME/.local/bin}"
APPS="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
ICON_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor/scalable/apps"

echo "Origen:  $SRC"
echo "Destino: $SHARE"

mkdir -p "$SHARE" "$BIN_DIR" "$APPS" "$ICON_DIR" "$SHARE/reports"

# Copia del proyecto (sin .git ni informes locales)
rsync -a --delete \
  --exclude '.git/' \
  --exclude 'reports/*' \
  --exclude '*.txt' \
  --exclude '*.json' \
  "$SRC/" "$SHARE/"

# Mantener reports/.gitkeep
mkdir -p "$SHARE/reports"
[[ -f "$SRC/reports/.gitkeep" ]] && cp "$SRC/reports/.gitkeep" "$SHARE/reports/"

chmod +x "$SHARE/bin/"*.sh "$SHARE/bin/audit-defensiva" "$SHARE/install.sh" 2>/dev/null || true
chmod +x "$SHARE/bin/audit-host.sh" "$SHARE/bin/audit-lan.sh" "$SHARE/bin/audit-bluetooth.sh"

# Launcher en PATH
ln -sfn "$SHARE/bin/audit-defensiva" "$BIN_DIR/audit-defensiva"

# Icono simple (SVG escudo)
cat > "$ICON_DIR/audit-defensiva.svg" <<'SVG'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" fill="none">
  <path d="M32 4 L54 14 V34 C54 48 42 58 32 60 C22 58 10 48 10 34 V14 Z"
        fill="#1a5f4a" stroke="#0d3d30" stroke-width="2"/>
  <path d="M22 32 L29 39 L44 22" stroke="#e8f5f0" stroke-width="4"
        stroke-linecap="round" stroke-linejoin="round"/>
</svg>
SVG

# Entrada de aplicación (menú / launcher Omarchy)
cp "$SHARE/share/applications/audit-defensiva.desktop" "$APPS/audit-defensiva.desktop"
# Asegurar rutas absolutas al binario instalado
sed -i "s|^Exec=.*|Exec=xdg-terminal-exec --app-id=audit.defensiva -e ${BIN_DIR}/audit-defensiva|" \
  "$APPS/audit-defensiva.desktop"
sed -i "s|^Icon=.*|Icon=audit-defensiva|" "$APPS/audit-defensiva.desktop"

if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database "$APPS" 2>/dev/null || true
fi

echo
echo "Instalado."
echo "  Comando:  audit-defensiva"
echo "  Menú:     Audit Defensiva"
echo "  Datos:    $SHARE"
echo
echo "Prueba: audit-defensiva lan"
