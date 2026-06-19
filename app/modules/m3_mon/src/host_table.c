#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_malloc.h>
#include <rte_cycles.h>

#include "host_table.h"
#include "bloom.h"
#include "detection.h"
#include "config.h"

extern m3_config_t config;

struct per_dst_entry {
    uint32_t dst_ip;
    uint16_t dst_port;
    bloom_filter_t filter;
    uint64_t last_seen;
};

struct host_entry {
    bloom_filter_t global_filter;
    struct per_dst_entry destinations[5];
    uint64_t last_seen;
};

static struct rte_hash *host_hash = NULL;
static struct host_entry *host_entries = NULL;
static uint32_t host_capacity = 0;

int host_table_init(uint32_t max_hosts)
{
    struct rte_hash_parameters hash_params = {
        .name = "host_table_hash",
        .entries = max_hosts,
        .key_len = sizeof(host_key_t),
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id(),
    };

    host_hash = rte_hash_create(&hash_params);
    if (!host_hash) {
        fprintf(stderr, "Failed to create host hash table\n");
        return -1;
    }

    host_entries = rte_zmalloc(NULL, sizeof(struct host_entry) * max_hosts, 0);
    if (!host_entries) {
        fprintf(stderr, "Failed to allocate host entries\n");
        return -1;
    }

    host_capacity = max_hosts;
    return 0;
}

static struct host_entry *create_host_entry(int32_t idx)
{
    struct host_entry *entry = &host_entries[idx];
    bloom_init(&entry->global_filter);
    for (int i = 0; i < 5; i++) {
        entry->destinations[i].dst_ip = 0;
        entry->destinations[i].dst_port = 0;
        bloom_init(&entry->destinations[i].filter);
        entry->destinations[i].last_seen = 0;
    }
    entry->last_seen = rte_get_timer_cycles();
    return entry;
}

int host_table_update(const host_key_t *key, uint32_t dst_ip, uint16_t dst_port, uint64_t now)
{
    int32_t idx = rte_hash_lookup(host_hash, key);
    struct host_entry *entry;
    if (idx >= 0) {
        entry = &host_entries[idx];
    } else {
        idx = rte_hash_add_key(host_hash, key);
        if (idx < 0 || (uint32_t)idx >= host_capacity) {
            return -1;
        }
        entry = create_host_entry(idx);
    }

    entry->last_seen = now;
    bloom_insert(&entry->global_filter, dst_port);

    int lru_index = 0;
    uint64_t oldest = entry->destinations[0].last_seen;
    for (int i = 0; i < 5; i++) {
        if (entry->destinations[i].dst_ip == dst_ip && entry->destinations[i].dst_port == dst_port) {
            bloom_insert(&entry->destinations[i].filter, dst_port);
            entry->destinations[i].last_seen = now;
            return 0;
        }
        if (entry->destinations[i].last_seen < oldest) {
            oldest = entry->destinations[i].last_seen;
            lru_index = i;
        }
    }

    entry->destinations[lru_index].dst_ip = dst_ip;
    entry->destinations[lru_index].dst_port = dst_port;
    bloom_init(&entry->destinations[lru_index].filter);
    bloom_insert(&entry->destinations[lru_index].filter, dst_port);
    entry->destinations[lru_index].last_seen = now;
    return 0;
}

int host_table_evaluate(uint64_t now)
{
    const void *key = NULL;
    uint32_t iter = 0;
    int32_t idx;

    while ((idx = rte_hash_iterate(host_hash, &key, &iter)) >= 0) {
        const host_key_t *host_key = key;
        struct host_entry *entry = &host_entries[idx];
        uint64_t age = now - entry->last_seen;

        if (age > config.host_idle_timeout_s) {
            rte_hash_del_key(host_hash, host_key);
            continue;
        }

        int global_bits = bloom_count_bits(&entry->global_filter);
        if ((uint32_t)global_bits > config.global_scan_ports) {
            alert_t alert = {0};
            strncpy(alert.event_id, "host-global-scan", sizeof(alert.event_id) - 1);
            alert.timestamp = now;
            alert.anomaly_type = ALERT_TYPE_GLOBAL_SCAN;
            alert.attacker_ip = host_key->ip_src;
            alert.attacker_vlan = host_key->vlan;
            alert.target_ip = 0;
            alert.target_port = 0;
            alert.confidence = 1.0;
            alert.severity = 2;
            strncpy(alert.message, "global port scan estimate exceeded", sizeof(alert.message) - 1);
            detection_enqueue_alert(&alert);
        }

        for (int i = 0; i < 5; i++) {
            int bits = bloom_count_bits(&entry->destinations[i].filter);
            if (entry->destinations[i].dst_ip != 0 && (uint32_t)bits > config.vertical_scan_dst_ports) {
                alert_t alert = {0};
                strncpy(alert.event_id, "host-vertical-scan", sizeof(alert.event_id) - 1);
                alert.timestamp = now;
                alert.anomaly_type = ALERT_TYPE_VERTICAL_SCAN;
                alert.attacker_ip = host_key->ip_src;
                alert.attacker_vlan = host_key->vlan;
                alert.target_ip = entry->destinations[i].dst_ip;
                alert.target_port = entry->destinations[i].dst_port;
                alert.confidence = 1.0;
                alert.severity = 2;
                strncpy(alert.message, "vertical scan estimate exceeded", sizeof(alert.message) - 1);
                detection_enqueue_alert(&alert);
            }
        }
    }
    return 0;
}
