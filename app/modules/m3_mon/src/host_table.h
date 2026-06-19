#ifndef HOST_TABLE_H
#define HOST_TABLE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct __attribute__((packed)) {
    uint16_t vlan;
    uint32_t ip_src;
} host_key_t;

int host_table_init(uint32_t max_hosts);
int host_table_update(const host_key_t *key, uint32_t dst_ip, uint16_t dst_port, uint64_t now);
int host_table_evaluate(uint64_t now);

#ifdef __cplusplus
}
#endif

#endif // HOST_TABLE_H
