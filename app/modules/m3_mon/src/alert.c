#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <rte_ring.h>
#include <rte_malloc.h>
#include "alert.h"
#include "alert_schema.h"
#include "rest_helper.h"
#include "config.h"

extern m3_config_t config;

static struct rte_ring *alert_ring = NULL;

int alert_init(uint32_t ring_size)
{
    alert_ring = rte_ring_create("alert_ring", ring_size, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    return alert_ring ? 0 : -1;
}

int alert_enqueue(const alert_t *alert)
{
    if (!alert_ring || !alert) {
        return -1;
    }

    alert_t *copy = rte_malloc(NULL, sizeof(alert_t), 0);
    if (!copy) {
        return -1;
    }
    memcpy(copy, alert, sizeof(alert_t));

    if (rte_ring_sp_enqueue(alert_ring, copy) != 0) {
        rte_free(copy);
        return -1;
    }
    return 0;
}

static void serialize_alert(const alert_t *alert, char *buf, size_t len)
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

void *alert_publisher_loop(void *arg)
{
    (void)arg;
    alert_t *alert;
    char buffer[1024];

    while (1) {
        if (rte_ring_sc_dequeue(alert_ring, (void **)&alert) == 0) {
            serialize_alert(alert, buffer, sizeof(buffer));
            send_alert(buffer, config.alert_endpoint);
            rte_free(alert);
        } else {
            usleep(100000);
        }
    }

    return NULL;
}
