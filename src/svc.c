// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2016 Alexandre Bailon
 *
 * Modifications Copyright (c) 2023 Ayush Singh <ayushdevel1325@gmail.com>
 */

#include "local_node.h"
#include "svc.h"
#include "ap.h"
#include <greybus/greybus_messages.h>
#include "node.h"
#include <zephyr/sys/dlist.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/atomic.h>

#define ENDO_ID           0x4755
#define MAX_GREYBUS_NODES CONFIG_BEAGLEPLAY_GREYBUS_MAX_NODES

LOG_MODULE_DECLARE(cc1352_greybus, CONFIG_BEAGLEPLAY_GREYBUS_LOG_LEVEL);

ATOMIC_DEFINE(svc_is_read_flag, 1);

static int svc_inf_write(struct gb_interface *, struct gb_message *, uint16_t);

static int svc_inf_create_connection(struct gb_interface *ctrl, uint16_t cport_id)
{
	ARG_UNUSED(ctrl);

	return cport_id == 0 && !svc_is_ready();
}

static void svc_inf_destroy_connection(struct gb_interface *ctrl, uint16_t cport_id)
{
	ARG_UNUSED(ctrl);

	if (cport_id != 0) {
		LOG_ERR("Unknown SVC Cport");
		return;
	}

	/* Set svc to uninitialized */
	atomic_set_bit_to(svc_is_read_flag, 0, false);
}

static struct gb_interface intf = {.id = SVC_INF_ID,
				   .write = svc_inf_write,
				   .create_connection = svc_inf_create_connection,
				   .destroy_connection = svc_inf_destroy_connection,
				   .ctrl_data = NULL};

static int control_send_request(void *payload, size_t payload_len, uint8_t request_type)
{
	int ret;
	struct gb_message *msg;

	msg = gb_message_request_alloc(payload_len, request_type, false);
	if (msg == NULL) {
		return -ENOMEM;
	}

	memcpy(msg->payload, payload, payload_len);

	ret = connection_send(SVC_INF_ID, 0, msg);
	if (ret < 0) {
		LOG_ERR("Failed to send SVC message");
		return ret;
	}

	return msg->header.operation_id;
}

static int svc_send_hello(void)
{
	struct gb_svc_hello_request req = {.endo_id = ENDO_ID, .interface_id = AP_INF_ID};

	return control_send_request(&req, sizeof(struct gb_svc_hello_request),
				    GB_SVC_TYPE_SVC_HELLO);
}

static void svc_response_helper(struct gb_message *msg, const void *payload, size_t payload_len,
				uint8_t status)
{
	int ret;
	struct gb_message *resp = gb_message_response_alloc(payload, payload_len, msg->header.type,
							    msg->header.operation_id, status);
	if (resp == NULL) {
		LOG_ERR("Failed to allocate response for %X", msg->header.type);
		return;
	}
	ret = connection_send(SVC_INF_ID, 0, resp);
	if (ret < 0) {
		LOG_ERR("Failed to send SVC message");
	}
}

static void svc_version_response_handler(struct gb_message *msg)
{
	struct gb_svc_version_request *response = (struct gb_svc_version_request *)msg->payload;

	LOG_DBG("SVC Protocol Version %u.%u", response->major, response->minor);
	svc_send_hello();
}

static void svc_hello_response_handler(struct gb_message *msg)
{
	ARG_UNUSED(msg);

	LOG_DBG("Hello Response Success");

	/* Add local Module */
	// svc_send_module_inserted(LOCAL_NODE_ID);
}

static void svc_empty_request_handler(struct gb_message *msg)
{
	svc_response_helper(msg, NULL, 0, GB_SVC_OP_SUCCESS);
}

static void svc_pwrm_get_rail_count_handler(struct gb_message *msg)
{
	struct gb_svc_pwrmon_rail_count_get_response req = {.rail_count = 0};

	svc_response_helper(msg, &req, sizeof(struct gb_svc_pwrmon_rail_count_get_response),
			    GB_SVC_OP_SUCCESS);
}

static void svc_intf_set_pwrm_handler(struct gb_message *msg)
{
	uint8_t tx_mode, rx_mode;
	struct gb_svc_intf_set_pwrm_response resp = {.result_code = GB_SVC_SETPWRM_PWR_LOCAL};
	struct gb_svc_intf_set_pwrm_request *req =
		(struct gb_svc_intf_set_pwrm_request *)msg->payload;
	tx_mode = req->tx_mode;
	rx_mode = req->rx_mode;

	if (tx_mode == GB_SVC_UNIPRO_HIBERNATE_MODE && rx_mode == GB_SVC_UNIPRO_HIBERNATE_MODE) {
		resp.result_code = GB_SVC_SETPWRM_PWR_OK;
	}

	svc_response_helper(msg, &resp, sizeof(struct gb_svc_intf_set_pwrm_response),
			    GB_SVC_OP_SUCCESS);
}

static void svc_intf_vsys_enable_disable_handler(struct gb_message *msg)
{
	struct gb_svc_intf_vsys_response resp = {.result_code = GB_SVC_INTF_VSYS_OK};

	svc_response_helper(msg, &resp, sizeof(struct gb_svc_intf_vsys_response),
			    GB_SVC_OP_SUCCESS);
}

static void svc_interface_refclk_enable_disable_handler(struct gb_message *msg)
{
	struct gb_svc_intf_refclk_response resp = {.result_code = GB_SVC_INTF_REFCLK_OK};

	svc_response_helper(msg, &resp, sizeof(struct gb_svc_intf_refclk_response),
			    GB_SVC_OP_SUCCESS);
}

static void svc_interface_unipro_enable_disable_handler(struct gb_message *msg)
{
	struct gb_svc_intf_unipro_response resp = {.result_code = GB_SVC_INTF_UNIPRO_OK};

	svc_response_helper(msg, &resp, sizeof(struct gb_svc_intf_unipro_response),
			    GB_SVC_OP_SUCCESS);
}

static void svc_interface_activate_handler(struct gb_message *msg)
{
	struct gb_svc_intf_activate_response resp = {.status = GB_SVC_OP_SUCCESS,
						     .intf_type = GB_SVC_INTF_TYPE_GREYBUS};
	svc_response_helper(msg, &resp, sizeof(struct gb_svc_intf_activate_response),
			    GB_SVC_OP_SUCCESS);
}

static void svc_dme_peer_get_handler(struct gb_message *msg)
{
	struct gb_svc_dme_peer_get_response resp = {.result_code = 0, .attr_value = 0x0126};

	svc_response_helper(msg, &resp, sizeof(struct gb_svc_dme_peer_get_response),
			    GB_SVC_OP_SUCCESS);
}

static void svc_dme_peer_set_handler(struct gb_message *msg)
{
	struct gb_svc_dme_peer_set_response resp = {.result_code = 0};

	svc_response_helper(msg, &resp, sizeof(struct gb_svc_dme_peer_set_response),
			    GB_SVC_OP_SUCCESS);
}

static void svc_connection_create_handler(struct gb_message *msg)
{
	int ret;
	struct gb_svc_conn_create_request *req = (struct gb_svc_conn_create_request *)msg->payload;

	if (req->intf1_id == req->intf2_id && req->cport1_id == req->cport2_id) {
		LOG_ERR("Cannot create loop connection");
		goto fail;
	}

	ret = connection_create(req->intf1_id, req->cport1_id, req->intf2_id, req->cport2_id);
	if (ret < 0) {
		LOG_ERR("Failed to create connection");
		goto fail;
	}

	LOG_DBG("Created connection between Intf %u, Cport %u and Intf %u, Cport %u", req->intf1_id,
		req->cport1_id, req->intf2_id, req->cport2_id);

	svc_response_helper(msg, NULL, 0, GB_SVC_OP_SUCCESS);
	return;

fail:
	svc_response_helper(msg, NULL, 0, GB_SVC_OP_UNKNOWN_ERROR);
}

static void svc_connection_destroy_handler(struct gb_message *msg)
{
	int ret;
	struct gb_svc_conn_destroy_request *req =
		(struct gb_svc_conn_destroy_request *)msg->payload;

	LOG_DBG("Destroy connection between Intf %u, Cport %u and Intf %u, Cport %u", req->intf1_id,
		req->cport1_id, req->intf2_id, req->cport2_id);
	ret = connection_destroy(req->intf1_id, req->cport1_id, req->intf2_id, req->cport2_id);
	if (ret < 0) {
		LOG_ERR("Failed to destroy connection %d between Cport 1: %u of Interface 1: %u "
			"and Cport 2: %u of Interface 2: %u",
			ret, req->cport1_id, req->intf1_id, req->cport2_id, req->intf2_id);
		goto fail;
	}

	svc_response_helper(msg, NULL, 0, GB_SVC_OP_SUCCESS);
	return;

fail:
	svc_response_helper(msg, NULL, 0, GB_SVC_OP_UNKNOWN_ERROR);
}

static void svc_interface_resume_handler(struct gb_message *msg)
{
	struct gb_svc_intf_resume_response resp = {.status = GB_SVC_OP_SUCCESS};

	svc_response_helper(msg, &resp, sizeof(struct gb_svc_intf_resume_response),
			    GB_SVC_OP_SUCCESS);
}

static void svc_module_inserted_response_handler(struct gb_message *msg)
{
	if (!gb_message_is_success(msg)) {
		/* TODO: Add functionality to remove the interface in case of error */
		LOG_ERR("Module Inserted Event failed");
	}
}

static void svc_module_removed_response_handler(struct gb_message *msg)
{
	if (!gb_message_is_success(msg)) {
		LOG_DBG("Module Removal Failed");
	}
}

static void gb_handle_msg(struct gb_message *msg)
{
	switch (gb_message_type(msg)) {
	case GB_SVC_TYPE_INTF_DEVICE_ID:
	case GB_SVC_TYPE_ROUTE_CREATE:
	case GB_SVC_TYPE_ROUTE_DESTROY:
	case GB_SVC_TYPE_PING:
		svc_empty_request_handler(msg);
		break;
	case GB_SVC_TYPE_CONN_CREATE:
		svc_connection_create_handler(msg);
		break;
	case GB_SVC_TYPE_CONN_DESTROY:
		svc_connection_destroy_handler(msg);
		break;
	case GB_SVC_TYPE_DME_PEER_GET:
		svc_dme_peer_get_handler(msg);
		break;
	case GB_SVC_TYPE_DME_PEER_SET:
		svc_dme_peer_set_handler(msg);
		break;
	case GB_SVC_TYPE_INTF_SET_PWRM:
		svc_intf_set_pwrm_handler(msg);
		break;
	case GB_SVC_TYPE_PWRMON_RAIL_COUNT_GET:
		svc_pwrm_get_rail_count_handler(msg);
		break;
	case GB_SVC_TYPE_INTF_VSYS_ENABLE:
	case GB_SVC_TYPE_INTF_VSYS_DISABLE:
		svc_intf_vsys_enable_disable_handler(msg);
		break;
	case GB_SVC_TYPE_INTF_REFCLK_ENABLE:
	case GB_SVC_TYPE_INTF_REFCLK_DISABLE:
		svc_interface_refclk_enable_disable_handler(msg);
		break;
	case GB_SVC_TYPE_INTF_UNIPRO_ENABLE:
	case GB_SVC_TYPE_INTF_UNIPRO_DISABLE:
		svc_interface_unipro_enable_disable_handler(msg);
		break;
	case GB_SVC_TYPE_INTF_ACTIVATE:
		svc_interface_activate_handler(msg);
		break;
	case GB_SVC_TYPE_INTF_RESUME:
		svc_interface_resume_handler(msg);
		break;
	case GB_RESPONSE(GB_SVC_TYPE_PROTOCOL_VERSION):
		svc_version_response_handler(msg);
		break;
	case GB_RESPONSE(GB_SVC_TYPE_SVC_HELLO):
		svc_hello_response_handler(msg);
		break;
	case GB_RESPONSE(GB_SVC_TYPE_MODULE_INSERTED):
		svc_module_inserted_response_handler(msg);
		break;
	case GB_RESPONSE(GB_SVC_TYPE_MODULE_REMOVED):
		svc_module_removed_response_handler(msg);
		break;
	default:
		LOG_WRN("Handling SVC operation Type %X not supported yet", msg->header.type);
	}
}

static int svc_inf_write(struct gb_interface *ctrl, struct gb_message *msg, uint16_t cport_id)
{
	if (cport_id != 0) {
		LOG_ERR("Unknown SVC Cport");
		return -1;
	}

	gb_handle_msg(msg);
	gb_message_dealloc(msg);
	return 0;
}

int svc_send_module_inserted(uint8_t primary_intf_id)
{
	struct gb_svc_module_inserted_request req = {
		.primary_intf_id = primary_intf_id, .intf_count = 1, .flags = 0};
	return control_send_request(&req, sizeof(struct gb_svc_module_inserted_request),
				    GB_SVC_TYPE_MODULE_INSERTED);
}

int svc_send_module_removed(struct gb_interface *intf)
{
	int ret;
	struct gb_svc_module_removed_request req = {.primary_intf_id = sys_cpu_to_le16(intf->id)};

	ret = control_send_request(&req, sizeof(req), GB_SVC_TYPE_MODULE_REMOVED);
	if (ret < 0) {
		return ret;
	}

	node_destroy_interface(intf);

	return ret;
}

int svc_send_version(void)
{
	struct gb_svc_version_request req = {.major = GB_SVC_VERSION_MAJOR,
					     .minor = GB_SVC_VERSION_MINOR};
	return control_send_request(&req, sizeof(struct gb_svc_version_request),
				    GB_SVC_TYPE_PROTOCOL_VERSION);
}

void svc_init(void)
{
	atomic_set_bit(svc_is_read_flag, 0);
}

struct gb_interface *svc_interface(void)
{
	if (svc_is_ready()) {
		return &intf;
	}

	return NULL;
}

void svc_deinit(void)
{
	atomic_set_bit_to(svc_is_read_flag, 0, false);
}

bool svc_is_ready(void)
{
	return atomic_test_bit(svc_is_read_flag, 0);
}
