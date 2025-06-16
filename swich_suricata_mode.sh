#!/bin/bash

# -------------------------------------------------------------
# Script de gestión personal de Suricata IDS/IPS para TFG
# Hecho para facilitar la gestión entre modo IDS y IPS, gestionar logs,
# y automatizar tareas.
#
# ¡Cuidado! Ejecutar siempre como root o con sudo, si no no funciona.
# -------------------------------------------------------------

# ----- Configuración personal -----
CONFIG_FILE="/etc/suricata/suricata.yaml"
IFACE_ATACANTE="enp0s9"    # Interfaz hacia el atacante (ajusta según tu laboratorio)
IFACE_VICTIMA="enp0s10"    # Interfaz hacia la víctima
NFQUEUE_NUM=0
LOG_EVE="/var/log/suricata/eve.json"
LOG_FAST="/var/log/suricata/fast.log"
LINEAS_LOG=30
SERVICIO="suricata"
DIR_EXPORT="$HOME/Descargas"

# -------- Funciones básicas --------

# Añade regla NFQUEUE para modo IPS
add_nfqueue_rule() {
    echo "[INFO] Intentando añadir la regla NFQUEUE a iptables (cola $NFQUEUE_NUM)..."
    if ! sudo iptables -C FORWARD -j NFQUEUE --queue-num $NFQUEUE_NUM &>/dev/null; then
        sudo iptables -A FORWARD -j NFQUEUE --queue-num $NFQUEUE_NUM
        echo "[OK] Regla añadida."
    else
        echo "[INFO] La regla NFQUEUE ya está añadida. No hago nada."
    fi
}

# Elimina regla NFQUEUE (me pasó una vez dejarla puesta sin querer)
del_nfqueue_rule() {
    echo "[INFO] Eliminando la regla NFQUEUE de iptables (cola $NFQUEUE_NUM)..."
    while sudo iptables -C FORWARD -j NFQUEUE --queue-num $NFQUEUE_NUM &>/dev/null; do
        sudo iptables -D FORWARD -j NFQUEUE --queue-num $NFQUEUE_NUM
    done
    echo "[OK] Regla eliminada (si estaba puesta)."
}

# Arranca Suricata (systemd)
start_suricata() {
    echo "[INFO] Arrancando Suricata..."
    sudo systemctl start $SERVICIO
    sleep 1
    sudo systemctl status $SERVICIO --no-pager
}

# Para Suricata y limpia reglas por si acaso
stop_suricata() {
    echo "[INFO] Parando Suricata..."
    sudo systemctl stop $SERVICIO
    del_nfqueue_rule
    echo "[OK] Suricata parada y reglas limpias."
}

# Estado del servicio Suricata (truco: --no-pager para que no se quede colgado)
status_suricata() {
    sudo systemctl status $SERVICIO --no-pager
}

# Recarga reglas sin reiniciar Suricata (no siempre funciona según config)
reload_rules() {
    echo "[INFO] Intentando recargar reglas..."
    if systemctl is-active --quiet $SERVICIO; then
        sudo suricatasc -c reload-rules && echo "[OK] Reglas recargadas." || echo "[ERROR] Fallo al recargar."
    else
        echo "[ERROR] Suricata no está activo."
    fi
}

# -------- Logs y exportaciones --------

# Comprueba si existe el log (truco para evitar errores tontos)
check_log_file_exists() {
    local fichero="$1"
    if [ ! -f "$fichero" ]; then
        echo "[ERROR] El archivo $fichero no existe aún."
        return 1
    fi
    return 0
}

# Últimas N alertas EVE (formato fácil de leer si tienes jq)
ver_ultimas_alertas_eve() {
    echo; echo "[INFO] Mostrando las últimas $LINEAS_LOG alertas (eve.json)..."
    if ! check_log_file_exists "$LOG_EVE"; then read -p "Pulsa enter para seguir..."; return; fi
    if ! command -v jq &>/dev/null; then
        echo "[AVISO] No tienes jq instalado. Instálalo para ver alertas formateadas."
        echo "sudo apt install jq"; read -p "Pulsa enter para seguir..."; return
    fi
    sudo grep '"event_type":"alert"' "$LOG_EVE" | tail -n $LINEAS_LOG | jq -r '
        "\(.timestamp) | \(.alert.signature) | \(.src_ip):\(.src_port) -> \(.dest_ip):\(.dest_port) | Acción: \(.alert.action // "allowed")"
    ' | less -S
    read -p "Pulsa enter para volver..."
}

# Muestra alertas DROP (acción dropped)
ver_alertas_drop_eve() {
    echo; echo "[INFO] Mostrando $LINEAS_LOG alertas DROP (eve.json)..."
    if ! check_log_file_exists "$LOG_EVE"; then read -p "Pulsa enter para seguir..."; return; fi
    if ! command -v jq &>/dev/null; then
        echo "[AVISO] No tienes jq instalado. Instálalo para ver alertas formateadas."
        echo "sudo apt install jq"; read -p "Pulsa enter para seguir..."; return
    fi
    sudo grep '"event_type":"alert"' "$LOG_EVE" | grep '"action":"dropped"' | tail -n $LINEAS_LOG | jq -r '
        "\(.timestamp) | \(.alert.signature) | \(.src_ip):\(.src_port) -> \(.dest_ip):\(.dest_port)"
    ' | less -S
    read -p "Pulsa enter para volver..."
}

# Log fast en tiempo real (para debugging en laboratorio)
tail_fastlog() {
    echo "[INFO] Mostrando $LOG_FAST en tiempo real. Ctrl+C para salir."
    if ! check_log_file_exists "$LOG_FAST"; then sleep 2; return; fi
    sudo tail -f "$LOG_FAST"
}

# Exporta alertas a un JSON
exportar_alertas_eve() {
    echo "[INFO] Exportando todas las alertas a $DIR_EXPORT"
    if ! check_log_file_exists "$LOG_EVE"; then read -p "Pulsa enter..."; return; fi
    mkdir -p "$DIR_EXPORT"
    local salida="$DIR_EXPORT/suricata_alerts_$(date +%Y%m%d_%H%M%S).json"
    sudo grep '"event_type":"alert"' "$LOG_EVE" | sudo tee "$salida" >/dev/null
    sudo chown "$(logname):$(logname)" "$salida"
    echo "[OK] Exportado en $salida"
    read -p "Pulsa enter para volver..."
}

exportar_alertas_drop() {
    echo "[INFO] Exportando alertas DROP a $DIR_EXPORT"
    if ! check_log_file_exists "$LOG_EVE"; then read -p "Pulsa enter..."; return; fi
    mkdir -p "$DIR_EXPORT"
    local salida="$DIR_EXPORT/suricata_drop_$(date +%Y%m%d_%H%M%S).json"
    sudo grep '"event_type":"alert"' "$LOG_EVE" | grep '"action":"dropped"' | sudo tee "$salida" >/dev/null
    sudo chown "$(logname):$(logname)" "$salida"
    echo "[OK] Exportado en $salida"
    read -p "Pulsa enter para volver..."
}

# Vacía logs (mucho ojo, pide confirmación)
vaciar_logs() {
    echo "[AVISO] Esto borra TODOS los logs. ¿Seguro? (s/N)"
    read resp
    [[ "$resp" =~ ^[sS] ]] || { echo "Cancelado."; return; }
    stop_suricata
    sudo truncate -s 0 "$LOG_EVE" 2>/dev/null || echo "No se pudo vaciar $LOG_EVE"
    sudo truncate -s 0 "$LOG_FAST" 2>/dev/null || echo "No se pudo vaciar $LOG_FAST"
    echo "[OK] Logs vaciados."
    start_suricata
    read -p "Pulsa enter para volver..."
}

# ---------- Menú de logs ----------
menu_logs() {
    while true; do
        clear
        echo "========================================"
        echo "      Análisis y Exportación de Logs"
        echo "========================================"
        echo "  1. Ver últimas $LINEAS_LOG alertas (Formateado EVE)"
        echo "  2. Ver últimas $LINEAS_LOG alertas DROP (Formateado EVE)"
        echo "  3. Ver alertas en TIEMPO REAL (fast.log)"
        echo "  --------------------------------------"
        echo "  4. Exportar TODAS las alertas a archivo (EVE JSON)"
        echo "  5. Exportar alertas DROP a archivo (EVE JSON)"
        echo "  --------------------------------------"
        echo "  6. Vaciar archivos de logs (eve.json, fast.log)"
        echo "  --------------------------------------"
        echo "  7. Volver al menú principal"
        echo "========================================"
        read -p "Elige una opción: " op
        case $op in
            1) ver_ultimas_alertas_eve ;;
            2) ver_alertas_drop_eve ;;
            3) tail_fastlog ;;
            4) exportar_alertas_eve ;;
            5) exportar_alertas_drop ;;
            6) vaciar_logs ;;
            7) break ;;
            *) echo "Opción inválida." ;;
        esac
    done
}

# ---------- Menú principal ----------
while true; do
    clear
    echo "========================================"
    echo "       Gestión de Suricata IDS/IPS"
    echo "========================================"
    echo "  Modo Actual (Reglas iptables):"
    if sudo iptables -C FORWARD -j NFQUEUE --queue-num $NFQUEUE_NUM &> /dev/null; then
        echo "    >> MODO IPS (NFQUEUE) CONFIGURADO <<"
    else
        echo "    >> MODO IDS (AF-PACKET) CONFIGURADO <<"
    fi
    echo "----------------------------------------"
    echo "  Acciones Principales:"
    echo "  1. Configurar para Modo IDS (af-packet)"
    echo "  2. Configurar para Modo IPS (NFQUEUE)"
    echo "  3. Iniciar Servicio Suricata"
    echo "  4. Detener Servicio Suricata"
    echo "  5. Ver Estado del Servicio"
    echo "  6. Recargar Reglas (Servicio Activo)"
    echo "  --------------------------------------"
    echo "  7. Análisis/Exportación de Logs..."
    echo "  --------------------------------------"
    echo "  8. Salir"
    echo "========================================"
    read -p "Elige una opción [1-8]: " op

    case $op in
        1) stop_suricata; del_nfqueue_rule; echo "Modo IDS listo. Ahora arranca el servicio (3)."; read -p "Pulsa enter..." ;;
        2) stop_suricata; add_nfqueue_rule; echo "Modo IPS listo. Arranca el servicio (3)."; read -p "Pulsa enter..." ;;
        3) start_suricata; read -p "Pulsa enter..." ;;
        4) stop_suricata; read -p "Pulsa enter..." ;;
        5) status_suricata; read -p "Pulsa enter..." ;;
        6) reload_rules; read -p "Pulsa enter..." ;;
        7) menu_logs ;;
        8) echo "Saliendo..."; exit 0 ;;
        *) echo "Opción no válida."; read -p "Pulsa enter..." ;;
    esac
done
