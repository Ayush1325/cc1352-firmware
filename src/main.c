// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2023 Ayush Singh <ayushdevel1325@gmail.com>
 */

#include "ap.h"
#include "apbridge.h"
#include "mdns.h"
#include "hdlc.h"
#include "mcumgr.h"
#include "node.h"
#include "operations.h"
#include "svc.h"
#include <stdbool.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/init.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/net_config.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/socket.h>
#include <zephyr/sys/dlist.h>

#define UART_DEVICE_NODE        DT_CHOSEN(zephyr_shell_uart)
#define NODE_DISCOVERY_INTERVAL 5000
#define MAX_GREYBUS_NODES       CONFIG_BEAGLEPLAY_GREYBUS_MAX_NODES
#define CONTROL_SVC_START       0x01
#define CONTROL_SVC_STOP        0x02

LOG_MODULE_REGISTER(cc1352_greybus, CONFIG_BEAGLEPLAY_GREYBUS_LOG_LEVEL);

static void serial_callback(const struct device *dev, void *user_data)
{
	ARG_UNUSED(user_data);

	uint8_t *buf;
	int ret;

	if (!uart_irq_update(dev) && !uart_irq_rx_ready(dev)) {
		return;
	}

	ret = hdlc_rx_start(&buf);
	if (ret == 0) {
		/* No space */
		LOG_ERR("No more space for HDLC receive");
		return;
	}

	ret = uart_fifo_read(dev, buf, ret);
	if (ret < 0) {
		/* Something went wrong */
		LOG_ERR("Failed to read UART");
		return;
	}

	ret = hdlc_rx_finish(ret);
	if (ret < 0) {
		/* Some error */
		LOG_ERR("Filed to write data to hdlc buffer");
		return;
	}
}

static int hdlc_process_greybus_frame(const char *buffer, size_t buffer_len)
{
	struct gb_operation_msg_hdr hdr;
	struct gb_message *msg;
	size_t payload_size;

	memcpy(&hdr, buffer, sizeof(struct gb_operation_msg_hdr));

	if (hdr.size > buffer_len) {
		LOG_ERR("Greybus Message size is greater than received buffer.");
		return -1;
	}

	payload_size = hdr.size - sizeof(struct gb_operation_msg_hdr);
	msg = k_malloc(sizeof(struct gb_message) + payload_size);
	if (msg == NULL) {
		LOG_ERR("Failed to allocate greybus message");
		return -1;
	}
	msg->payload_size = payload_size;
	memcpy(&msg->header, &hdr, sizeof(struct gb_operation_msg_hdr));
	memcpy(msg->payload, &buffer[sizeof(struct gb_operation_msg_hdr)], msg->payload_size);
	ap_rx_submit(msg);

	return 0;
}

static int control_process_frame(const char *buffer, size_t buffer_len)
{
	uint8_t command;
	struct gb_connection *conn;
	struct gb_interface *ap, *svc;

	if (buffer_len != 1) {
		LOG_ERR("Invalid Buffer");
		return -1;
	}

	command = buffer[0];

	switch (command) {
	case CONTROL_SVC_START:
		LOG_INF("Starting SVC");
		ap = ap_init();
		svc = svc_init();
		conn = gb_create_connection(ap, svc, 0, 0);
		svc_send_version();
		apbridge_start();
		return 0;
	case CONTROL_SVC_STOP:
		LOG_INF("Stopping SVC");
		gb_connection_destroy_all();
		node_destroy_all();
		svc_deinit();
		ap_deinit();
		apbridge_stop();
		return 0;
	}

	return -1;
}

static int hdlc_process_complete_frame(const void *buffer, size_t len, uint8_t address)
{
	switch (address) {
	case ADDRESS_GREYBUS:
		return hdlc_process_greybus_frame(buffer, len);
	case ADDRESS_MCUMGR:
		return mcumgr_process_frame(buffer, len);
	case ADDRESS_CONTROL:
		return control_process_frame(buffer, len);
	case ADDRESS_DBG:
		LOG_WRN("Ignore DBG Frame");
		return 0;
	}

	return -1;
}

void main(void)
{
	int ret, sock;
	struct in6_addr node_array[MAX_GREYBUS_NODES];
	char query[] = "_greybus._tcp.local\0";

	LOG_INF("Starting BeaglePlay Greybus");
	apbridge_stop();

	if (!device_is_ready(uart_dev)) {
		LOG_ERR("UART device not found!");
		return;
	}

	mcumgr_init();
	hdlc_init(hdlc_process_complete_frame);

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

	sock = mdns_socket_open_ipv6(&mdns_addr, 2000);

	while (1) {
		k_msleep(NODE_DISCOVERY_INTERVAL);

		if (!svc_is_ready()) {
			LOG_WRN("SVC Not Ready");
			continue;
		}

		ret = mdns_query_send(sock, query, strlen(query));
		if (ret < 0) {
			LOG_WRN("Failed to get greybus nodes");
			continue;
		}

		ret = mdns_query_recv(sock, node_array, MAX_GREYBUS_NODES, query, strlen(query));
		if (ret < 0) {
			LOG_WRN("Failed to get greybus nodes");
			continue;
		}

		node_filter(node_array, ret);
	}
}
