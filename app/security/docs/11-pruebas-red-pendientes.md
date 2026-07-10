# Pruebas de red pendientes

Estas pruebas se encuentran expresamente diferidas porque los switches están
en modo standalone o presentan problemas de integración.

No deben ejecutarse durante la implementación local:

1. Recepción real de `Packet-In` desde ONOS.
2. Escritura o eliminación de flows en los switches.
3. Bloqueos T0 contra hosts reales.
4. Consultas de topología que dependan de ONOS.
5. Configuración OVSDB.
6. Activación de Port Mirroring, GRE o ERSPAN.
7. Ingesta de sFlow/NetFlow desde switches reales.
8. Suricata conectado al tráfico del laboratorio.
9. Simulaciones ofensivas de port scan, spoofing, DDoS o exfiltración.

Antes de habilitarlas se debe confirmar:

- ONOS controla correctamente cada switch.
- Los DPIDs y puertos coinciden con la topología.
- Existe una ventana de mantenimiento.
- Se dispone de un procedimiento de rollback.
- Los flags de red se habilitan de forma deliberada y uno por uno.
