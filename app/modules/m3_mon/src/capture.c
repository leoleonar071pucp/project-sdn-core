#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_icmp.h>
#include <rte_byteorder.h>
#include <rte_cycles.h>

#include "capture.h"
#include "flow_table.h"
#include "host_table.h"
#include "config.h"

extern m3_config_t config;
extern volatile bool keep_running;

static uint16_t port_id = 0;

static int parse_packet(struct rte_mbuf *mbuf, flow_key_t *flow_key, uint32_t *dst_ip, uint16_t *dst_port)
{
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    uint16_t eth_type = rte_be_to_cpu_16(eth->ether_type);
    uint16_t vlan = 0;
    uint8_t *payload = (uint8_t *)(eth + 1);

    if (eth_type == RTE_ETHER_TYPE_VLAN) {
        struct rte_vlan_hdr *vhdr = (struct rte_vlan_hdr *)payload;
        vlan = rte_be_to_cpu_16(vhdr->vlan_tci) & 0x0fff;
        eth_type = rte_be_to_cpu_16(vhdr->eth_proto);
        payload += sizeof(struct rte_vlan_hdr);
    }

    if (eth_type != RTE_ETHER_TYPE_IPV4) {
        return -1;
    }

    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)payload;
    uint8_t protocol = ip->next_proto_id;
    uint16_t l4_offset = (ip->ihl * 4);
    uint8_t *l4 = payload + l4_offset;

    flow_key->vlan = vlan;
    flow_key->ip_src = ip->src_addr;
    flow_key->ip_dst = ip->dst_addr;
    flow_key->protocol = protocol;
    flow_key->port_src = 0;
    flow_key->port_dst = 0;

    if (protocol == IPPROTO_TCP) {
        struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)l4;
        flow_key->port_src = tcp->src_port;
        flow_key->port_dst = tcp->dst_port;
    } else if (protocol == IPPROTO_UDP) {
        struct rte_udp_hdr *udp = (struct rte_udp_hdr *)l4;
        flow_key->port_src = udp->src_port;
        flow_key->port_dst = udp->dst_port;
    } else if (protocol == IPPROTO_ICMP) {
        *dst_port = 0;
    }

    *dst_ip = ip->dst_addr;
    *dst_port = flow_key->port_dst;
    return 0;
}

void *capture_loop(void *arg)
{
    (void)arg;
    struct rte_mbuf *bufs[32];
    uint64_t total_packets = 0;
    time_t last_time = time(NULL);

    while (keep_running) {
        uint16_t nb_rx = rte_eth_rx_burst(port_id, 0, bufs, RTE_DIM(bufs));
        for (uint16_t i = 0; i < nb_rx; i++) {
            flow_key_t key;
            host_key_t host_key;
            uint32_t dst_ip = 0;
            uint16_t dst_port = 0;
            if (parse_packet(bufs[i], &key, &dst_ip, &dst_port) == 0) {
                flow_table_update(&key, rte_pktmbuf_pkt_len(bufs[i]));
                host_key.vlan = key.vlan;
                host_key.ip_src = key.ip_src;
                host_table_update(&host_key, dst_ip, dst_port, time(NULL));
            }
            rte_pktmbuf_free(bufs[i]);
            total_packets++;
        }

        time_t now = time(NULL);
        if (now != last_time) {
            printf("capture: %llu packets, pps=%llu\n", (unsigned long long)total_packets, (unsigned long long)total_packets);
            total_packets = 0;
            last_time = now;
        }
    }

    return NULL;
}
