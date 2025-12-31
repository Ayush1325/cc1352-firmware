// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2023 Ayush Singh <ayushdevel1325@gmail.com>
 */

#include "tcp_discovery.h"
#include "node.h"
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/dns_resolve.h>

#define MAX_GREYBUS_NODES CONFIG_GREYBUS_APBRIDGE_CPORTS

LOG_MODULE_DECLARE(cc1352_greybus, CONFIG_BEAGLEPLAY_GREYBUS_LOG_LEVEL);

#ifdef CONFIG_BEAGLEPLAY_GREYBUS_MDNS_DISCOVERY

static void handler(struct k_work *work);

static K_WORK_DEFINE(node_discovery, handler);

static void cb(enum dns_resolve_status status, struct dns_addrinfo *info, void *user_data)
{
	switch (status) {
	case DNS_EAI_CANCELED:
		LOG_DBG("Service request timeout");
		k_work_submit(&node_discovery);
		break;
	case DNS_EAI_INPROGRESS:
		if (info) {
			// Ignore all other responses
			if (info->ai_family == NET_AF_INET6) {
				LOG_DBG("Got node address");
				node_filter(&net_sin6(&info->ai_addr)->sin6_addr, 1);
			}
		}
		break;
	case DNS_EAI_ALLDONE:
		LOG_DBG("All results received");
		k_work_submit(&node_discovery);
		break;
	case DNS_EAI_FAIL:
		LOG_DBG("No such name found.");
		break;
	default:
		LOG_WRN("Unhandled status %d received (errno %d)", status, errno);
		k_work_submit(&node_discovery);
	}
}

static void handler(struct k_work *work)
{
	int ret;
	const char *query = "_greybus._tcp.local";

	ret = dns_resolve_service(dns_resolve_get_default(), query, NULL, cb, NULL,
				  NODE_DISCOVERY_INTERVAL);
	if (ret < 0) {
		LOG_ERR("Cannot resolve DNS service (%d)", ret);
	}
}
#endif // CONFIG_BEAGLEPLAY_GREYBUS_MDNS_DISCOVERY

void tcp_discovery_start(void)
{
#if CONFIG_BEAGLEPLAY_GREYBUS_STATIC_NODES_ENABLE
	const char addr[] = CONFIG_BEAGLEPLAY_GREYBUS_STATIC_NODES;
	struct sockaddr_in6 addr6;
	int i, start;

	for (i = 0, start = 0; i < ARRAY_SIZE(addr); i++) {
		if (addr[i] == ',') {
			net_ipaddr_parse(&addr[start], i - start, (struct sockaddr *)&addr6);
			node_filter(&addr6.sin6_addr, 1);
			start = i + 1;
		}
	}

	if (i > start) {
		net_ipaddr_parse(&addr[start], i - start, (struct sockaddr *)&addr6);
		node_filter(&addr6.sin6_addr, 1);
	}
#endif // CONFIG_BEAGLEPLAY_GREYBUS_STATIC_NODES_ENABLE

#ifdef CONFIG_BEAGLEPLAY_GREYBUS_MDNS_DISCOVERY
	k_work_submit(&node_discovery);
#endif // CONFIG_BEAGLEPLAY_GREYBUS_MDNS_DISCOVERY
}

void tcp_discovery_stop(void)
{
#ifdef CONFIG_BEAGLEPLAY_GREYBUS_MDNS_DISCOVERY
	k_work_cancel(&node_discovery);
#endif // CONFIG_BEAGLEPLAY_GREYBUS_MDNS_DISCOVERY
}
