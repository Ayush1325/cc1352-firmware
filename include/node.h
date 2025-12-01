/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2023 Ayush Singh <ayushdevel1325@gmail.com>
 */

#ifndef _NODE_H_
#define _NODE_H_

#include <zephyr/net/net_ip.h>
#include <greybus/apbridge.h>

#define GB_TRANSPORT_TCPIP_BASE_PORT 4242

/*
 * Destroy a tcp greybus interface
 *
 * @return greybus interface
 */
void node_destroy_interface(struct gb_interface *intf);

/*
 * Find greybus node by interface ID
 *
 * @param interface id
 *
 * @return greybus interface
 */
struct gb_interface *node_find_by_id(uint8_t intf_id);

/*
 * Checks if any new nodes have been added or any previous nodes removed.
 *
 * @param list of nodes discovered
 * @param lenght of nodes list
 */
void node_filter(struct in6_addr *active_addr, size_t active_len);

/*
 * Destroy all current node interfaces.
 *
 * Note: This does not destroy the connections
 */
void node_destroy_all(void);

#endif
