#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>

#include "config.h"
#include "capture.h"
#include "flow_table.h"
#include "host_table.h"
#include "detection.h"
#include "alert.h"

m3_config_t config;
volatile bool keep_running = true;
static struct rte_mempool *mbuf_pool = NULL;

static void signal_handler(int signo)
{
    (void)signo;
    keep_running = false;
}

static void trim(char *s)
{
    char *end;
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') {
        s++;
    }
    if (*s == 0) {
        return;
    }
    end = s + strlen(s) - 1;
    while (end > s && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')) {
        *end = '\0';
        end--;
    }
}

int load_config(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        return -1;
    }

    strncpy(config.pci_address, "0000:00:08.0", sizeof(config.pci_address));
    config.mbuf_pool_size = 8192;
    config.flood_dst_flows = 100;
    config.fast_scan_src_flows = 10;
    config.unidir_ratio = 0.8;
    config.vertical_scan_dst_ports = 15;
    config.global_scan_ports = 50;
    config.idle_timeout_s = 5;
    config.host_idle_timeout_s = 300;
    config.max_flows = 100000;
    config.max_hosts = 5000;
    strncpy(config.alert_endpoint, "http://localhost:8080/alerts", sizeof(config.alert_endpoint));

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char *pos = strchr(line, ':');
        if (!pos) {
            continue;
        }
        *pos = '\0';
        char key[128];
        char value[128];
        strncpy(key, line, sizeof(key));
        strncpy(value, pos + 1, sizeof(value));
        trim(key);
        trim(value);
        if (strcmp(key, "pci_address") == 0) {
            strncpy(config.pci_address, value, sizeof(config.pci_address));
        } else if (strcmp(key, "mbuf_pool_size") == 0) {
            config.mbuf_pool_size = (uint32_t)atoi(value);
        } else if (strcmp(key, "flood_dst_flows") == 0) {
            config.flood_dst_flows = (uint32_t)atoi(value);
        } else if (strcmp(key, "fast_scan_src_flows") == 0) {
            config.fast_scan_src_flows = (uint32_t)atoi(value);
        } else if (strcmp(key, "unidir_ratio") == 0) {
            config.unidir_ratio = atof(value);
        } else if (strcmp(key, "vertical_scan_dst_ports") == 0) {
            config.vertical_scan_dst_ports = (uint32_t)atoi(value);
        } else if (strcmp(key, "global_scan_ports") == 0) {
            config.global_scan_ports = (uint32_t)atoi(value);
        } else if (strcmp(key, "idle_timeout_s") == 0) {
            config.idle_timeout_s = (uint32_t)atoi(value);
        } else if (strcmp(key, "host_idle_timeout_s") == 0) {
            config.host_idle_timeout_s = (uint32_t)atoi(value);
        } else if (strcmp(key, "max_flows") == 0) {
            config.max_flows = (uint32_t)atoi(value);
        } else if (strcmp(key, "max_hosts") == 0) {
            config.max_hosts = (uint32_t)atoi(value);
        } else if (strcmp(key, "alert_endpoint") == 0) {
            if (value[0] == '"') {
                size_t len = strlen(value);
                if (value[len - 1] == '"') {
                    value[len - 1] = '\0';
                    memmove(value, value + 1, len - 1);
                }
            }
            strncpy(config.alert_endpoint, value, sizeof(config.alert_endpoint));
        }
    }
    fclose(f);
    return 0;
}

int init_dpdk(int argc, char **argv)
{
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        fprintf(stderr, "Failed to initialize EAL\n");
        return -1;
    }

    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", config.mbuf_pool_size,
        256, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!mbuf_pool) {
        fprintf(stderr, "Failed to create mbuf pool\n");
        return -1;
    }

    uint16_t port_id = 0;
    struct rte_eth_conf port_conf = {0};
    port_conf.rxmode.max_rx_pkt_len = RTE_ETHER_MAX_LEN;

    if (rte_eth_dev_configure(port_id, 1, 1, &port_conf) != 0) {
        fprintf(stderr, "Failed to configure port %u\n", port_id);
        return -1;
    }

    if (rte_eth_rx_queue_setup(port_id, 0, 1024, rte_eth_dev_socket_id(port_id), NULL, mbuf_pool) < 0) {
        fprintf(stderr, "Failed to setup RX queue\n");
        return -1;
    }

    if (rte_eth_dev_start(port_id) < 0) {
        fprintf(stderr, "Failed to start port %u\n", port_id);
        return -1;
    }

    printf("DPDK initialized on port %u with PCI %s\n", port_id, config.pci_address);
    return 0;
}

int main(int argc, char **argv)
{
    if (load_config("../config.yaml") != 0) {
        fprintf(stderr, "Warning: failed to load config.yaml, using defaults\n");
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    if (init_dpdk(argc, argv) != 0) {
        return EXIT_FAILURE;
    }

    if (flow_table_init(config.max_flows) != 0) {
        return EXIT_FAILURE;
    }

    if (host_table_init(config.max_hosts) != 0) {
        return EXIT_FAILURE;
    }

    if (alert_init(1024) != 0) {
        return EXIT_FAILURE;
    }

    if (detection_init() != 0) {
        return EXIT_FAILURE;
    }

    pthread_t capture_thread;
    pthread_t detection_thread;
    pthread_t publisher_thread;

    pthread_create(&capture_thread, NULL, capture_loop, NULL);
    pthread_create(&detection_thread, NULL, detection_loop, NULL);
    pthread_create(&publisher_thread, NULL, alert_publisher_loop, NULL);

    while (keep_running) {
        sleep(1);
    }

    printf("Stopping M3 module...\n");

    pthread_join(capture_thread, NULL);
    pthread_join(detection_thread, NULL);
    pthread_join(publisher_thread, NULL);

    return EXIT_SUCCESS;
}
