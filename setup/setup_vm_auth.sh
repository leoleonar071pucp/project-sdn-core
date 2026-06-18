#!/bin/bash
# setup_vm_auth.sh — Setup VM-Auth (AAA-Policies) para SDN Zero Trust PUCP
# Ejecutar como root desde la raíz del repo:
#   bash setup/setup_vm_auth.sh

set -e

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SQL_FILE="$REPO_DIR/sql/radius_db_pucp_sdn (2).sql"

echo "=== [1/6] Paquetes ==="
apt-get update -q
apt-get install -y -q mysql-server freeradius freeradius-mysql python3-pip curl wget
echo "  OK"

echo ""
echo "=== [2/6] MySQL — radius_db ==="
systemctl start mysql && systemctl enable mysql

# Crear usuario y base de datos (el SQL tiene CREATE USER comentado)
mysql -e "CREATE DATABASE IF NOT EXISTS radius_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
mysql -e "CREATE USER IF NOT EXISTS 'radius'@'localhost' IDENTIFIED BY 'radius_pass';"
mysql -e "FLUSH PRIVILEGES;"

mysql radius_db < "$SQL_FILE"

RADCHECK_N=$(mysql -uradius -pradius_pass radius_db -sNe "SELECT COUNT(*) FROM radcheck;" 2>/dev/null)
echo "  OK — radcheck: $RADCHECK_N entradas"

echo ""
echo "=== [3/6] FreeRADIUS — módulo SQL ==="

# Escribir config SQL directamente (sin archivos externos)
cat > /etc/freeradius/3.0/mods-available/sql <<'FRSQL'
sql {
    dialect   = "mysql"
    driver    = "rlm_sql_${dialect}"

    mysql {
        warnings = auto
    }

    server    = "localhost"
    port      = 3306
    login     = "radius"
    password  = "radius_pass"
    radius_db = "radius_db"

    acct_table1      = "radacct"
    acct_table2      = "radacct"
    postauth_table   = "radpostauth"
    authcheck_table  = "radcheck"
    groupcheck_table = "radgroupcheck"
    authreply_table  = "radreply"
    groupreply_table = "radgroupreply"
    usergroup_table  = "radusergroup"

    read_groups           = yes
    delete_stale_sessions = yes

    pool {
        start        = 2
        min          = 1
        max          = 10
        spare        = 3
        uses         = 0
        retry_delay  = 30
        lifetime     = 0
        idle_timeout = 60
    }

    logfile = ${logdir}/sqllog.sql
}
FRSQL

# Habilitar módulo
ln -sf /etc/freeradius/3.0/mods-available/sql \
       /etc/freeradius/3.0/mods-enabled/sql

# Sitio default mínimo — PAP + SQL (pyrad usa PAP, no EAP)
cat > /etc/freeradius/3.0/sites-available/default <<'FRSITE'
server default {
    listen {
        type  = auth
        ipaddr = *
        port  = 1812
    }
    listen {
        type  = acct
        ipaddr = *
        port  = 1813
    }

    authorize {
        preprocess
        chap
        mschap
        suffix
        sql
        pap
    }

    authenticate {
        Auth-Type PAP {
            pap
        }
        Auth-Type CHAP {
            chap
        }
    }

    session {
        sql
    }

    post-auth {
        sql
        Post-Auth-Type REJECT {
            attr_filter.access_reject
        }
    }

    accounting {
        detail
        sql
    }
}
FRSITE

# Deshabilitar inner-tunnel (no se usa, evita errores de EAP)
rm -f /etc/freeradius/3.0/sites-enabled/inner-tunnel

systemctl restart freeradius
systemctl enable freeradius

sleep 1
if radtest 20192434 pass_teleco123 127.0.0.1 0 testing123 2>&1 | grep -q "Access-Accept"; then
    echo "  OK — Access-Accept para 20192434 (Estudiante_Telecom)"
else
    echo "  [!] Test RADIUS falló — revisar: freeradius -X"
fi

echo ""
echo "=== [4/6] OPA (M2) — puerto 8182 ==="
if ! command -v opa &>/dev/null; then
    curl -sL -o /usr/local/bin/opa \
        https://github.com/open-policy-agent/opa/releases/download/v0.65.0/opa_linux_amd64_static
    chmod +x /usr/local/bin/opa
fi
echo "  $(opa version | head -1)"

mkdir -p /root/m2
cp "$REPO_DIR/app/modules/m2_policies/opa/policy.rego" /root/m2/policy.rego
echo "  policy.rego → /root/m2/"

echo ""
echo "=== [5/6] Python deps ==="
pip3 install -q flask requests mysql-connector-python pyrad pymysql
echo "  OK — flask requests mysql-connector-python pyrad pymysql"

echo ""
echo "=== [6/6] Archivos de producción → /root/ ==="
cp "$REPO_DIR/app/modules/m6/m6_traductor.py"             /root/m6_traductor.py
cp "$REPO_DIR/portal_cautivo.py"                           /root/portal_cautivo.py
cp "$REPO_DIR/app/modules/m2_policies/sync/sync.py"       /root/m2/sync.py
echo "  /root/m6_traductor.py"
echo "  /root/portal_cautivo.py"
echo "  /root/m2/sync.py"

echo ""
echo "========================================"
echo " SETUP COMPLETO"
echo ""
echo " Siguiente: bash setup/run_services.sh"
echo " Debug FreeRADIUS: freeradius -X"
echo "========================================"
