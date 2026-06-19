#ifndef M3_CONFIG_H
#define M3_CONFIG_H

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    char pci_address[32];
    uint32_t mbuf_pool_size;
    uint32_t flood_dst_flows;
    uint32_t fast_scan_src_flows;
    double unidir_ratio;
    uint32_t vertical_scan_dst_ports;
    uint32_t global_scan_ports;
    uint32_t idle_timeout_s;
    uint32_t host_idle_timeout_s;
    uint32_t max_flows;
    uint32_t max_hosts;
    char alert_endpoint[256];
} m3_config_t;

extern m3_config_t config;

int load_config(const char *path);

#endif // M3_CONFIG_H
