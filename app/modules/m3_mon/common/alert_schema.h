#ifndef ALERT_SCHEMA_H
#define ALERT_SCHEMA_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    ALERT_TYPE_UNKNOWN = 0,
    ALERT_TYPE_FLOOD,
    ALERT_TYPE_FAST_SCAN,
    ALERT_TYPE_UNIDIR_RATIO,
    ALERT_TYPE_VERTICAL_SCAN,
    ALERT_TYPE_GLOBAL_SCAN,
} anomaly_type_t;

typedef struct {
    char event_id[37];
    uint64_t timestamp;
    anomaly_type_t anomaly_type;
    uint32_t attacker_ip;
    uint16_t attacker_vlan;
    uint32_t target_ip;
    uint16_t target_port;
    uint8_t protocol;
    double measured_pps;
    double measured_bps;
    double confidence;
    int severity;
    char message[128];
} alert_t;

void alert_to_json(const alert_t *alert, char *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif // ALERT_SCHEMA_H
