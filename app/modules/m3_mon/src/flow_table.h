#ifndef FLOW_TABLE_H
#define FLOW_TABLE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct __attribute__((packed)) {
    uint16_t vlan;
    uint32_t ip_src;
    uint32_t ip_dst;
    uint16_t port_src;
    uint16_t port_dst;
    uint8_t protocol;
} flow_key_t;

int flow_table_init(uint32_t max_flows);
int flow_table_update(const flow_key_t *key, uint16_t len);

#ifdef __cplusplus
}
#endif

#endif // FLOW_TABLE_H
