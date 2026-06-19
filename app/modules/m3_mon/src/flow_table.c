#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_malloc.h>
#include <rte_atomic.h>
#include <rte_cycles.h>

#include "flow_table.h"

struct flow_entry {
    rte_atomic64_t packet_count;
    rte_atomic64_t byte_count;
    uint64_t last_seen;
};

static struct rte_hash *flow_hash = NULL;
static struct flow_entry *flow_entries = NULL;
static uint32_t flow_capacity = 0;
static uint64_t flow_drops = 0;

int flow_table_init(uint32_t max_flows)
{
    struct rte_hash_parameters hash_params = {
        .name = "flow_table_hash",
        .entries = max_flows,
        .key_len = sizeof(flow_key_t),
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id(),
    };

    flow_hash = rte_hash_create(&hash_params);
    if (!flow_hash) {
        fprintf(stderr, "Failed to create flow hash table\n");
        return -1;
    }

    flow_entries = rte_zmalloc(NULL, sizeof(struct flow_entry) * max_flows, 0);
    if (!flow_entries) {
        fprintf(stderr, "Failed to allocate flow entries\n");
        return -1;
    }

    flow_capacity = max_flows;
    return 0;
}

int flow_table_update(const flow_key_t *key, uint16_t len)
{
    int32_t idx = rte_hash_lookup(flow_hash, key);
    if (idx >= 0) {
        rte_atomic64_inc(&flow_entries[idx].packet_count);
        rte_atomic64_add(&flow_entries[idx].byte_count, len);
        flow_entries[idx].last_seen = rte_get_timer_cycles();
        return 0;
    }

    int32_t new_idx = rte_hash_add_key(flow_hash, key);
    if (new_idx >= 0 && (uint32_t)new_idx < flow_capacity) {
        rte_atomic64_set(&flow_entries[new_idx].packet_count, 1);
        rte_atomic64_set(&flow_entries[new_idx].byte_count, len);
        flow_entries[new_idx].last_seen = rte_get_timer_cycles();
        return 0;
    }

    flow_drops++;
    return -1;
}
