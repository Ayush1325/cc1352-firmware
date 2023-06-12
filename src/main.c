/*
 * Copyright (c) 2012-2014 Wind River Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "mdns/mdns.h"
#include <stdbool.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/init.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/dns_resolve.h>
#include <zephyr/net/net_config.h>
#include <zephyr/net/net_if.h>

LOG_MODULE_REGISTER(cc1352_greybus, CONFIG_BEAGLEPLAY_GREYBUS_LOG_LEVEL);

#define UART_DEVICE_NODE DT_CHOSEN(zephyr_shell_uart)

#define MSG_SIZE 32
#define DNS_TIMEOUT (10 * MSEC_PER_SEC)

static const struct device *const uart_dev = DEVICE_DT_GET(UART_DEVICE_NODE);
static const struct device *const ieee802154_dev =
    DEVICE_DT_GET(DT_CHOSEN(zephyr_ieee802154));
static struct ieee802154_radio_api *radio_api;

static const char *query = "zephyr.local";

K_MSGQ_DEFINE(uart_msgq, sizeof(char), 10, 4);

void serial_callback(const struct device *dev, void *user_data) {
  char c;

  if (!uart_irq_update(uart_dev)) {
    return;
  }

  if (!uart_irq_rx_ready(uart_dev)) {
    return;
  }

  while (uart_fifo_read(uart_dev, &c, 1) == 1) {
    if (c == '1' || c == '2' || c == '3') {
      k_msgq_put(&uart_msgq, &c, K_NO_WAIT);
    } else {
      LOG_DBG("Invalid Input: %c", c);
    }
  }
}

void print_uart(char *buf) {
  int msg_len = strlen(buf);

  for (int i = 0; i < msg_len; i++) {
    uart_poll_out(uart_dev, buf[i]);
  }
}

void mdns_result_cb(enum dns_resolve_status status, struct dns_addrinfo *info,
                    void *user_data) {
  char hr_addr[NET_IPV6_ADDR_LEN];
  char *hr_family;
  void *addr;

  switch (status) {
  case DNS_EAI_CANCELED:
    LOG_INF("mDNS query was canceled");
    return;
  case DNS_EAI_FAIL:
    LOG_INF("mDNS resolve failed");
    return;
  case DNS_EAI_NODATA:
    LOG_INF("Cannot resolve address using mDNS");
    return;
  case DNS_EAI_ALLDONE:
    LOG_INF("mDNS resolving finished");
    return;
  case DNS_EAI_INPROGRESS:
    break;
  default:
    LOG_INF("mDNS resolving error (%d)", status);
    return;
  }

  if (!info) {
    return;
  }

  if (info->ai_family == AF_INET) {
    hr_family = "IPv4";
    addr = &net_sin(&info->ai_addr)->sin_addr;
  } else if (info->ai_family == AF_INET6) {
    hr_family = "IPv6";
    addr = &net_sin6(&info->ai_addr)->sin6_addr;
  } else {
    LOG_ERR("Invalid IP address family %d", info->ai_family);
    return;
  }

  LOG_INF("%s %s address: %s", user_data ? (char *)user_data : "<null>",
          hr_family,
          net_addr_ntop(info->ai_family, addr, hr_addr, sizeof(hr_addr)));
}

static void do_mdns_ipv4_lookup() {
  int ret;

  LOG_DBG("Doing mDNS v4 query for %s", query);

  ret = dns_get_addr_info(query, DNS_QUERY_TYPE_A, NULL, mdns_result_cb,
                          (void *)query, DNS_TIMEOUT);
  if (ret < 0) {
    LOG_ERR("Cannot resolve mDNS IPv4 address (%d)", ret);
    return;
  }

  LOG_DBG("mDNS v4 query sent");
}

static void do_mdns_ipv6_lookup() {
  int ret;

  LOG_DBG("Doing mDNS v6 query for %s", query);

  ret = dns_get_addr_info(query, DNS_QUERY_TYPE_AAAA, NULL, mdns_result_cb,
                          (void *)query, DNS_TIMEOUT);
  if (ret < 0) {
    LOG_ERR("Cannot resolve mDNS IPv6 address (%d)", ret);
    return;
  }

  LOG_DBG("mDNS v6 query sent");
}

void main(void) {
  LOG_INF("Starting BeaglePlay Greybus");
  int ret;

  char tx;

  if (!device_is_ready(uart_dev)) {
    LOG_ERR("UART device not found!");
    return;
  }

  if (!device_is_ready(ieee802154_dev)) {
    LOG_ERR("IEEE802.15.4 device not ready");
    return;
  }
  LOG_INF("IEEE802.15.4 device is ready");

  ret = net_config_init_app(ieee802154_dev, "cc1352_greybus");
  if (ret != 0) {
    LOG_ERR("Failed to init netoworking: %d", ret);
    return;
  }

  radio_api = (struct ieee802154_radio_api *)ieee802154_dev->api;

  dns_init_resolver();

  ret = uart_irq_callback_user_data_set(uart_dev, serial_callback, NULL);
  if (ret < 0) {
    if (ret == -ENOTSUP) {
      LOG_ERR("Interrupt-driven UART API support not enabled\n");
    } else if (ret == -ENOSYS) {
      LOG_ERR("UART device does not support interrupt-driven API\n");
    } else {
      LOG_ERR("Error setting UART callback: %d\n", ret);
    }
    return;
  }

  uart_irq_rx_enable(uart_dev);

  while (k_msgq_get(&uart_msgq, &tx, K_FOREVER) == 0) {
    switch (tx) {
    case '1':
      do_mdns_ipv4_lookup();
      break;
    case '2':
      do_mdns_ipv6_lookup();
      break;
    case '3':
      send_query("_zephyr._tcp");
      break;
    }
  }
}
