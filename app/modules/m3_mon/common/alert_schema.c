#include <stdio.h>
#include <string.h>
#include "alert_schema.h"

void alert_to_json(const alert_t *alert, char *buf, size_t len)
{
    snprintf(buf, len,
        "{\"event_id\":\"%s\",\"timestamp\":%llu,\"anomaly_type\":%d,\"attacker_ip\":%u,\"attacker_vlan\":%u,\"target_ip\":%u,\"target_port\":%u,\"protocol\":%u,\"measured_pps\":%.2f,\"measured_bps\":%.2f,\"confidence\":%.2f,\"severity\":%d,\"message\":\"%s\"}",
        alert->event_id,
        (unsigned long long)alert->timestamp,
        alert->anomaly_type,
        alert->attacker_ip,
        alert->attacker_vlan,
        alert->target_ip,
        alert->target_port,
        alert->protocol,
        alert->measured_pps,
        alert->measured_bps,
        alert->confidence,
        alert->severity,
        alert->message);
}
