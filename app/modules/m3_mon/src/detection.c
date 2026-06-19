#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "detection.h"
#include "alert.h"
#include "host_table.h"
#include "config.h"

extern m3_config_t config;
extern volatile bool keep_running;

int detection_init(void)
{
    return 0;
}

void *detection_loop(void *arg)
{
    (void)arg;
    time_t last_scan = time(NULL);

    while (!keep_running) {
        usleep(100000);
    }

    while (keep_running) {
        time_t now = time(NULL);
        detection_volumetric();
        host_table_evaluate((uint64_t)now);

        if ((uint32_t)(now - last_scan) >= 300) {
            detection_scan();
            last_scan = now;
        }
        sleep(1);
    }
    return NULL;
}

void detection_volumetric(void)
{
    alert_t alert = {0};
    strncpy(alert.event_id, "dummy-volumetric-alert-0000", sizeof(alert.event_id) - 1);
    alert.timestamp = (uint64_t)time(NULL);
    alert.anomaly_type = ALERT_TYPE_FLOOD;
    alert.attacker_ip = 0;
    alert.attacker_vlan = 0;
    alert.target_ip = 0;
    alert.target_port = 0;
    alert.protocol = 0;
    alert.measured_pps = 0;
    alert.measured_bps = 0;
    alert.confidence = 0.0;
    alert.severity = 1;
    strncpy(alert.message, "dummy volumetric alert", sizeof(alert.message) - 1);
    detection_enqueue_alert(&alert);
}

void detection_scan(void)
{
    alert_t alert = {0};
    strncpy(alert.event_id, "dummy-scan-alert-00000000", sizeof(alert.event_id) - 1);
    alert.timestamp = (uint64_t)time(NULL);
    alert.anomaly_type = ALERT_TYPE_VERTICAL_SCAN;
    alert.attacker_ip = 0;
    alert.attacker_vlan = 0;
    alert.target_ip = 0;
    alert.target_port = 0;
    alert.protocol = 0;
    alert.measured_pps = 0;
    alert.measured_bps = 0;
    alert.confidence = 0.0;
    alert.severity = 1;
    strncpy(alert.message, "dummy scan alert", sizeof(alert.message) - 1);
    detection_enqueue_alert(&alert);
}

int detection_enqueue_alert(const alert_t *alert)
{
    return alert_enqueue(alert);
}
