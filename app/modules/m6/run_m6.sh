#!/bin/bash
# run_m6.sh — Lanzador de M6 Traductor para el Controller VM
# Grupo 2 TEL354 — SDN PUCP
#
# Uso desde /opt/ (donde copias m6_traductor.py):
#   bash run_m6.sh             # auto: gunicorn si disponible, si no Flask
#   bash run_m6.sh gunicorn    # fuerza gunicorn
#   bash run_m6.sh flask       # fuerza Flask built-in (modo desarrollo)
#
# Para instalar dependencias en el Controller VM:
#   pip3 install flask requests mysql-connector-python gunicorn

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

M6_MODULE="m6_traductor"        # nombre del .py sin extensión
M6_APP="app"                    # nombre del objeto Flask dentro del .py
M6_PORT=8080
M6_HOST="0.0.0.0"
MODE="${1:-auto}"

echo ""
echo "═══════════════════════════════════════════════"
echo "  M6 — Módulo Traductor SDN PUCP"
echo "  Grupo 2 TEL354 | Mark Valencia (20221747)"
echo "═══════════════════════════════════════════════"
echo "  Directorio : $SCRIPT_DIR"
echo "  Módulo     : $M6_MODULE.py"
echo "  Puerto     : $M6_HOST:$M6_PORT"
echo "  Modo       : $MODE"
echo "═══════════════════════════════════════════════"
echo ""

# Verificar que el archivo existe
if [ ! -f "${M6_MODULE}.py" ]; then
    echo "✗  No se encontró ${M6_MODULE}.py en $SCRIPT_DIR"
    exit 1
fi

# Verificar dependencias mínimas
python3 -c "import flask, requests" 2>/dev/null || {
    echo "Instalando dependencias..."
    pip3 install flask requests 2>/dev/null || pip install flask requests
}

launch_gunicorn() {
    # 1 worker + 4 threads: mínimo RAM (1 proceso Python ~50MB)
    # con capacidad de atender 4 peticiones simultáneas (M1+M4+M5+ping)
    echo "[M6] Iniciando con Gunicorn (1 worker, 4 threads)..."
    exec gunicorn \
        --workers 1 \
        --threads 4 \
        --timeout 30 \
        --bind "${M6_HOST}:${M6_PORT}" \
        --access-logfile - \
        --error-logfile - \
        "${M6_MODULE}:${M6_APP}"
}

launch_flask() {
    echo "[M6] Iniciando con Flask built-in (threaded=True)..."
    exec python3 "${M6_MODULE}.py"
}

case "$MODE" in
    gunicorn)
        command -v gunicorn &>/dev/null || {
            echo "⚠  gunicorn no instalado. Instala con: pip3 install gunicorn"
            echo "   Usando Flask como fallback..."
            launch_flask
        }
        launch_gunicorn
        ;;
    flask)
        launch_flask
        ;;
    auto|*)
        if command -v gunicorn &>/dev/null; then
            launch_gunicorn
        else
            echo "ℹ  gunicorn no disponible, usando Flask (instala con pip3 install gunicorn)"
            launch_flask
        fi
        ;;
esac
