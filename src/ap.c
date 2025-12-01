// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2023 Ayush Singh <ayushdevel1325@gmail.com>
 */

#include "ap.h"
#include "hdlc.h"
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

LOG_MODULE_DECLARE(cc1352_greybus, CONFIG_BEAGLEPLAY_GREYBUS_LOG_LEVEL);

static int ap_send(struct gb_interface *intf, struct gb_message *msg, uint16_t cport) {

	int ret = gb_message_hdlc_send(msg, cport);
	gb_message_dealloc(msg);

	return ret;
}

static struct gb_interface intf = {
	.id = AP_INF_ID,
	.write = ap_send,
};

void ap_init(void)
{
	gb_interface_add(&intf);
}

void ap_deinit(void)
{
	gb_interface_remove(intf.id);
}
