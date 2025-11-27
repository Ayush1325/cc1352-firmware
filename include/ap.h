/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2023 Ayush Singh <ayushdevel1325@gmail.com>
 */

#ifndef _AP_H_
#define _AP_H_

#include "apbridge.h"
#include "greybus_interfaces.h"

#define AP_MAX_NODES CONFIG_BEAGLEPLAY_GREYBUS_MAX_NODES

#define AP_INF_ID       1
#define AP_SVC_CPORT_ID 0

/*
 * Initialize AP interface
 *
 * @return AP Interface
 */
void ap_init(void);

/*
 * De-Initialize AP Interface
 *
 * Note: This should be called only after all connections have been closed. This does not take care
 * of closing connections or flushing pending data.
 */
void ap_deinit(void);

/*
 * Submit message received by AP from transport
 *
 * @param greybus message
 * @param cport_id
 *
 * @return 0 if successful, negative in case of error
 */
static inline int ap_rx_submit(struct gb_message *msg, uint16_t cport_id)
{
	return connection_send(AP_INF_ID, cport_id, msg);
}

int ap_send(struct gb_message *msg, uint16_t cport);

#endif
