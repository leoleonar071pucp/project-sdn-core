#!/bin/bash
# run_services.sh — Arranca OPA, sync.py y M6 en VM-Auth
# Ejecutar como root: bash setup/run_services.sh

LOG=/tmp

echo "=== Deteniendo procesos previos ==="
pkill -f "opa run"         2>/dev/null && echo "  OPA detenido"   || true
pkill -f "sync\.py"        2>/dev/null && echo "  sync.py detenido" || true
pkill -f "m6_traductor\.py" 2>/dev/null && echo "  M6 detenido"   || true
sleep 1

echo ""
echo "=== [1/3] OPA (M2) en puerto 8182 ==="
nohup opa run --server --addr=0.0.0.0:8182 /root/m2/policy.rego \
    > $LOG/opa.log 2>&1 &
echo "  PID $! — $LOG/opa.log"
sleep 2

echo ""
echo "=== [2/3] sync.py (MySQL → OPA) ==="
nohup python3 -u /root/m2/sync.py > $LOG/sync.log 2>&1 &
echo "  PID $! — $LOG/sync.log"
sleep 1

echo ""
echo "=== [3/3] M6 (traductor SDN) en puerto 8080 ==="
nohup python3 -u /root/m6_traductor.py > $LOG/m6.log 2>&1 &
echo "  PID $! — $LOG/m6.log"

echo ""
echo "=== Esperando arranque M6 ==="
for i in $(seq 1 10); do
    sleep 2
    STATUS=$(curl -s http://localhost:8080/m6/status 2>/dev/null)
    if echo "$STATUS" | grep -q "ok\|running\|status"; then
        echo "  M6 respondió: $STATUS"
        break
    fi
    echo "  intento $i/10..."
done

echo ""
echo "=== Estado final ==="
ps aux | grep -E "opa|sync\.py|m6_traductor" | grep -v grep | \
    awk '{print "  PID " $2 " " $11}' || true

echo ""
echo "Logs en vivo:"
echo "  tail -f $LOG/m6.log"
echo "  tail -f $LOG/sync.log"
echo "  tail -f $LOG/opa.log"
echo ""
echo "Portal cautivo (manual, en nueva terminal SSH):"
echo "  python3 /root/portal_cautivo.py"
