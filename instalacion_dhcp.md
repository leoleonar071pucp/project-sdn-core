# 1. Instalar dnsmasq en la VM
sudo apt update
sudo apt install dnsmasq -y

# 2. Desactivar systemd-resolved si está corriendo (conflicto puerto 53)
sudo systemctl disable --now systemd-resolved
sudo systemctl stop systemd-resolved

# 3. Copiar la configuración de pools
sudo cp sdn-pools.conf /etc/dnsmasq.d/sdn-pools.conf

# 4. Crear el archivo de reservas vacío con permisos correctos
sudo touch /etc/dnsmasq.d/reservations.conf
sudo chmod 666 /etc/dnsmasq.d/reservations.conf

# 5. Iniciar dnsmasq
sudo systemctl enable dnsmasq
sudo systemctl start dnsmasq
sudo systemctl status dnsmasq

# 6. Instalar dependencias Python del dhcp_manager
pip install flask mysql-connector-python

# 7. Levantar el dhcp_manager (en background o pantalla separada)
sudo python3 dhcp_manager.py
# sudo porque necesita leer el PID de dnsmasq y enviar señales

# 8. Probar la asignación manualmente antes de conectarlo con el portal
curl -X POST http://localhost:5001/dhcp/assign \
  -H "Content-Type: application/json" \
  -d '{
    "mac": "aa:bb:cc:dd:ee:ff",
    "rol": "Estudiante_Telecom",
    "codigo_pucp": "20192434",
    "switch_dpid": "of:0000000000000001",
    "in_port": 3
  }'

# Respuesta esperada:
# {"cidr_rol":"10.2.1.0/24","exito":true,"ip_asignada":"10.2.1.100",
#  "mensaje":"IP 10.2.1.100 asignada a aa:bb:cc:dd:ee:ff para rol Estudiante_Telecom",
#  "tag":"telecom"}

# 9. Verificar que dnsmasq tiene la reserva
cat /etc/dnsmasq.d/reservations.conf

# 10. Ver reservas activas
curl http://localhost:5001/dhcp/status

# 11. Probar el flujo completo con el portal cautivo
# (coordinar con tu compañera para añadir la llamada en portal_cautivo.py)
python3 portal_cautivo.py