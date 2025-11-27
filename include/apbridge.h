/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2023 Ayush Singh <ayushdevel1325@gmail.com>
 */

#ifndef _APBRIDGE_H_
#define _APBRIDGE_H_

#include <stdint.h>
#include <greybus/greybus_messages.h>

void apbridge_init(void);

void apbridge_deinit(void);

int connection_create(uint8_t intf1_id, uint16_t intf1_cport, uint8_t intf2_id,
		      uint16_t intf2_cport);

int connection_destroy(uint8_t intf1_id, uint16_t intf1_cport, uint8_t intf2_id,
		       uint16_t intf2_cport);

int connection_send(uint8_t intf_id, uint16_t intf_cport, struct gb_message *msg);

/*
 * Send a message to the node
 *
 * @msg: The message to send
 * @cport: The cport of ap
 *
 * Returns 0 on success, negative errno on failure
 */
// int node_to_ap(struct gb_message *msg, uint16_t cport);

/*
 * Send a message to the AP
 *
 * @msg: The message to send
 * @cport: The cport of ap
 *
 * Returns 0 on success, negative errno on failure
 */
// int ap_to_node(struct gb_message *msg, uint16_t cport);

// int ap_register_node(uint16_t cport, node_send_fn fn, void *priv);

// int ap_derigster_node(uint16_t cport);

#endif
