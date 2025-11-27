/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2023 Ayush Singh <ayushdevel1325@gmail.com>
 */

#ifndef _OPERATIONS_H_
#define _OPERATIONS_H_

#include <zephyr/sys/dlist.h>
#include <zephyr/types.h>
#include <greybus/greybus_messages.h>

struct gb_interface;

/*
 * Callback for writing to an interface
 *
 * @param controller
 * @param greybus message to send
 * @param Cport to write to
 *
 * @return 0 if successful. Negative in case of error
 */
typedef int (*gb_controller_write_callback_t)(struct gb_interface *, struct gb_message *, uint16_t);

/*
 * Callback to create new connection with a Cport in the interface
 *
 * @param controller
 * @param cport
 *
 * @return 0 if successful. Negative in case of error
 */
typedef int (*gb_controller_create_connection_t)(struct gb_interface *, uint16_t);

/*
 * Callback to destroy connection with a Cport in the interface
 *
 * @param controller
 * @param cport
 */
typedef void (*gb_controller_destroy_connection_t)(struct gb_interface *, uint16_t);

/*
 * A greybus interface. Can have multiple Cports
 *
 * @param id: Interface ID
 * @param write: a non-blocking write function. The ownership of message is
 * transferred.
 * @param ctrl_data: private controller data
 */
struct gb_interface {
	uint8_t id;
	gb_controller_write_callback_t write;
	gb_controller_create_connection_t create_connection;
	gb_controller_destroy_connection_t destroy_connection;
	void *ctrl_data;
};

/*
 * Allocate a greybus interface
 *
 * @param read callback
 * @param write callback
 * @param create connection callback
 * @param destroy connection callback
 * @param controller data
 *
 * @return allocated greybus interface. NULL in case of error
 */
struct gb_interface *gb_interface_alloc(gb_controller_write_callback_t write_cb,
					gb_controller_create_connection_t create_connection_cb,
					gb_controller_destroy_connection_t destroy_connection_cb,
					void *ctrl_data);

/*
 * Deallocate a greybus interface
 *
 * @param greybus interface
 */
void gb_interface_dealloc(struct gb_interface *intf);

/*
 * Get interface associated with interface id.
 *
 * @param interface id
 *
 * @param greybus interface
 */
struct gb_interface *gb_interface_find_by_id(uint8_t intf_id);

#endif
