// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2023 Ayush Singh <ayushdevel1325@gmail.com>
 */

#include "tcp_discovery.h"
#include "node.h"
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#define MAX_GREYBUS_NODES CONFIG_BEAGLEPLAY_GREYBUS_MAX_NODES

LOG_MODULE_DECLARE(cc1352_greybus, CONFIG_BEAGLEPLAY_GREYBUS_LOG_LEVEL);

struct tcp_discovery_data {
	int sock;
};

static struct tcp_discovery_data tcp_discovery_data = {.sock = -1};

#ifndef CONFIG_BEAGLEPLAY_GREYBUS_MDNS_DISCOVERY

static void handler(void *p1, void *p2, void *p3)
{
	static const char addr[] = CONFIG_BEAGLEPLAY_GREYBUS_NODE1;
	struct sockaddr_in6 addr6;

	net_ipaddr_parse(addr, sizeof(addr), (struct sockaddr *)&addr6);

	while (1) {
		k_msleep(NODE_DISCOVERY_INTERVAL);
		node_filter(&addr6.sin6_addr, 1);
	}
}

#else

static void handler(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	int ret;
	struct in6_addr node_array[MAX_GREYBUS_NODES];
	char query[] = "_greybus._tcp.local\0";

	while (1) {
		k_msleep(NODE_DISCOVERY_INTERVAL);

		if (tcp_discovery_data.sock < 0) {
			continue;
		}

		ret = mdns_query_send(tcp_discovery_data.sock, query, strlen(query));
		if (ret < 0) {
			LOG_WRN("Failed to get greybus nodes");
			continue;
		}

		ret = mdns_query_recv(tcp_discovery_data.sock, node_array, MAX_GREYBUS_NODES, query,
				      strlen(query), 2000);
		if (ret < 0) {
			LOG_WRN("Failed to get greybus nodes");
			continue;
		}

		node_filter(node_array, ret);
	}
}

#endif // CONFIG_BEAGLEPLAY_GREYBUS_MDNS_DISCOVERY

K_THREAD_DEFINE(tcp_discovery, 2048, handler, NULL, NULL, NULL, 6, 0, 0);

void tcp_discovery_start(void)
{
#ifdef CONFIG_BEAGLEPLAY_GREYBUS_MDNS_DISCOVERY
	tcp_discovery_data.sock = mdns_socket_open_ipv6(&mdns_addr);
#endif
	k_thread_resume(tcp_discovery);
}

void tcp_discovery_stop(void)
{
	k_thread_suspend(tcp_discovery);
#ifdef CONFIG_BEAGLEPLAY_GREYBUS_MDNS_DISCOVERY
	if (tcp_discovery_data.sock >= 0) {
		mdns_socket_close(tcp_discovery_data.sock);
		tcp_discovery_data.sock = -1;
	}
#endif
}
