/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2023 Ayush Singh <ayushdevel1325@gmail.com>
 */

#ifndef _SVC_H_
#define _SVC_H_

#include <stdbool.h>
#include <zephyr/types.h>
#include <greybus/apbridge.h>

#define SVC_INF_ID 0

/*
 * Initialize SVC Interface. Should be called before sending any greybus
 * request.
 */
void svc_init(void);

/*
 * Create SVC_TYPE_VERSION greybus message and queue it for sending.
 *
 * @return 0 if successful, else error.
 */
int svc_send_version(void);

/*
 * Send the SVC module inserted request.
 *
 * @param interface id of the new module
 *
 * @return 0 if successfully, negative in case of error
 */
int svc_send_module_inserted(uint8_t intf_id);

/*
 * Send the SVC module removed request.
 *
 * @param interface id of the module removed
 *
 * @return 0 if successfully, negative in case of error
 */
int svc_send_module_removed(struct gb_interface *intf);

/*
 * Get the SVC interface
 *
 * @return pointer to svc interface
 */
struct gb_interface *svc_interface(void);

/*
 * De-Initialize SVC
 */
void svc_deinit(void);

bool svc_is_ready(void);

#endif
