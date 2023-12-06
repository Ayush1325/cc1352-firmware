// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2023 Ayush Singh <ayushdevel1325@gmail.com>
 */

#include "ap.h"
#include "apbridge.h"
#include "greybus_protocol.h"
#include "mdns.h"
#include "hdlc.h"
#include "node.h"
#include "svc.h"
#include "greybus_connections.h"
#include "tcp_discovery.h"
#include <zephyr/drivers/uart.h>
#include <zephyr/init.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/net_ip.h>

#define UART_DEVICE_NODE        DT_CHOSEN(zephyr_shell_uart)
#define CONTROL_SVC_START       0x01
#define CONTROL_SVC_STOP        0x02

LOG_MODULE_REGISTER(cc1352_greybus, CONFIG_BEAGLEPLAY_GREYBUS_LOG_LEVEL);

static const struct device *const uart_dev = DEVICE_DT_GET(UART_DEVICE_NODE);

static int hdlc_send_callback(const uint8_t *buffer, size_t buffer_len) {
	size_t i;

	for (i = 0; i < buffer_len; ++i) {
		uart_poll_out(uart_dev, buffer[i]);
	}

	return i;
}

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
	struct gb_message *msg;
	int ret;
	struct gb_operation_msg_hdr *hdr = (struct gb_operation_msg_hdr *)buffer;

	if (hdr->size > buffer_len) {
		LOG_ERR("Greybus Message size is greater than received buffer.");
		return -1;
	}

	msg = gb_message_alloc(gb_hdr_payload_len(hdr), hdr->type, hdr->id,
			       hdr->status);
	if (!msg) {
		LOG_ERR("Failed to allocate greybus message");
		return -1;
	}
	memcpy(msg->payload, &buffer[sizeof(struct gb_operation_msg_hdr)], gb_message_payload_len(msg));
	ret = ap_rx_submit(msg, sys_get_le16(hdr->pad));
	if (ret < 0) {
		LOG_ERR("Failed add message to AP Queue");
	}

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
		conn = gb_connection_create(ap, svc, 0, 0);
		svc_send_version();
		apbridge_start();
		tcp_discovery_start();
		return 0;
	case CONTROL_SVC_STOP:
		LOG_INF("Stopping SVC");
		tcp_discovery_stop();
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
	int ret;

	LOG_INF("Starting BeaglePlay Greybus");
	tcp_discovery_stop();
	apbridge_stop();

	if (!device_is_ready(uart_dev)) {
		LOG_ERR("UART device not found!");
		return;
	}

	hdlc_init(hdlc_process_complete_frame, hdlc_send_callback);

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

	k_sleep(K_FOREVER);
}
