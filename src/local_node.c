// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2016 Alexandre Bailon
 *
 * Modifications Copyright (c) 2023 Ayush Singh <ayushdevel1325@gmail.com>
 */

#include "greybus_messages.h"
#include "greybus_interfaces.h"
#include "greybus_protocol.h"
#include "local_node.h"
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include "apbridge.h"

#define CPORTS_NUM 1

#define CONTROL_PROTOCOL_CPORT 0

LOG_MODULE_DECLARE(cc1352_greybus, CONFIG_BEAGLEPLAY_GREYBUS_LOG_LEVEL);

struct gb_control_version_response {
	uint8_t major;
	uint8_t minor;
} __packed;

struct gb_control_get_manifest_size_response {
	uint16_t manifest_size;
} __packed;

/* Control protocol manifest get request has no payload */
struct gb_control_get_manifest_response {
	uint8_t data[0];
} __packed;

/* Control protocol [dis]connected request */
struct gb_control_connected_request {
	uint16_t cport_id;
} __packed;

struct gb_control_disconnecting_request {
	uint16_t cport_id;
} __packed;
/* disconnecting response has no payload */

struct gb_control_disconnected_request {
	uint16_t cport_id;
} __packed;

static const uint8_t manifest[] = {
	0x3c, 0x00, 0x00, 0x01, 0x08, 0x00, 0x01, 0x00, 0x01, 0x02, 0x00, 0x00, 0x18, 0x00, 0x02,
	0x00, 0x11, 0x01, 0x42, 0x65, 0x61, 0x67, 0x6c, 0x65, 0x50, 0x6c, 0x61, 0x79, 0x20, 0x43,
	0x43, 0x31, 0x33, 0x35, 0x32, 0x00, 0x18, 0x00, 0x02, 0x00, 0x11, 0x02, 0x42, 0x65, 0x61,
	0x67, 0x6c, 0x65, 0x50, 0x6c, 0x61, 0x79, 0x20, 0x43, 0x43, 0x31, 0x33, 0x35, 0x32, 0x00};

static void response_helper(struct gb_interface *ctrl, struct gb_message *msg, const void *payload,
			    size_t payload_len, uint8_t status, uint16_t cport_id)
{
	int ret;
	struct gb_message *resp = gb_message_response_alloc(payload, payload_len, msg->header.type,
							    msg->header.id, status);

	if (resp == NULL) {
		LOG_ERR("Failed to allocate response for %X", msg->header.type);
		return;
	}
	ret = connection_send(LOCAL_NODE_ID, cport_id, resp);
	if (ret < 0) {
		LOG_ERR("Failed to send response for %X", msg->header.type);
	}
}

static void control_protocol_cport_shutdown_handler(struct gb_interface *ctrl,
						    struct gb_message *msg)
{
	response_helper(ctrl, msg, NULL, 0, GB_OP_SUCCESS, CONTROL_PROTOCOL_CPORT);
}

static void control_protocol_version_handler(struct gb_interface *ctrl, struct gb_message *msg)
{
	struct gb_control_version_response response = {
		.major = 0,
		.minor = 1,
	};

	response_helper(ctrl, msg, &response, sizeof(response), GB_OP_SUCCESS,
			CONTROL_PROTOCOL_CPORT);
}

static void control_protocol_get_manifest_size_handler(struct gb_interface *ctrl,
						       struct gb_message *msg)
{
	struct gb_control_get_manifest_size_response response = {
		.manifest_size = sys_cpu_to_le16(sizeof(manifest)),
	};

	response_helper(ctrl, msg, &response, sizeof(response), GB_OP_SUCCESS,
			CONTROL_PROTOCOL_CPORT);
}

static void control_protocol_get_manifest_handler(struct gb_interface *ctrl,
						  struct gb_message *msg)
{
	response_helper(ctrl, msg, manifest, sizeof(manifest), GB_OP_SUCCESS,
			CONTROL_PROTOCOL_CPORT);
}

static void control_protocol_empty_handler(struct gb_interface *ctrl, struct gb_message *msg)
{
	response_helper(ctrl, msg, NULL, 0, GB_OP_SUCCESS, CONTROL_PROTOCOL_CPORT);
}

static void control_protocol_handle(struct gb_interface *ctrl, struct gb_message *msg)
{

	switch (gb_message_type(msg)) {
	case GB_COMMON_TYPE_CPORT_SHUTDOWN_REQUEST:
		control_protocol_cport_shutdown_handler(ctrl, msg);
		break;
	case GB_CONTROL_TYPE_VERSION_REQUEST:
		control_protocol_version_handler(ctrl, msg);
		break;
	case GB_CONTROL_TYPE_GET_MANIFEST_SIZE_REQUEST:
		control_protocol_get_manifest_size_handler(ctrl, msg);
		break;
	case GB_CONTROL_TYPE_GET_MANIFEST_REQUEST:
		control_protocol_get_manifest_handler(ctrl, msg);
		break;
	case GB_CONTROL_TYPE_CONNECTED_REQUEST:
	case GB_CONTROL_TYPE_DISCONNECTING_REQUEST:
	case GB_CONTROL_TYPE_DISCONNECTED_REQUEST:
	case GB_CONTROL_TYPE_TIMESYNC_ENABLE_REQUEST:
	case GB_CONTROL_TYPE_TIMESYNC_DISABLE_REQUEST:
	case GB_CONTROL_TYPE_TIMESYNC_AUTHORITATIVE_REQUEST:
	case GB_CONTROL_TYPE_INTF_HIBERNATE_ABORT_REQUEST:
		control_protocol_empty_handler(ctrl, msg);
		break;
	default:
		LOG_ERR("Unimplemented control protocol request %X", gb_message_type(msg));
	}
}

static int intf_write(struct gb_interface *ctrl, struct gb_message *msg, uint16_t cport_id)
{
	LOG_DBG("Local node received %u of type %X on cport %u", msg->header.id,
		gb_message_type(msg), cport_id);

	switch (cport_id) {
	case CONTROL_PROTOCOL_CPORT:
		control_protocol_handle(ctrl, msg);
		break;
	}

	gb_message_dealloc(msg);

	return 0;
}

static int intf_create_connection(struct gb_interface *ctrl, uint16_t cport_id)
{
	return 0;
}

static void intf_destroy_connection(struct gb_interface *ctrl, uint16_t cport_id)
{
}

static struct gb_interface intf = {.id = LOCAL_NODE_ID,
				   .write = intf_write,
				   .create_connection = intf_create_connection,
				   .destroy_connection = intf_destroy_connection,
				   .ctrl_data = NULL};

struct gb_interface *local_node_interface(void)
{
	return &intf;
}
