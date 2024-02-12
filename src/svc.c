// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2016 Alexandre Bailon
 *
 * Modifications Copyright (c) 2023 Ayush Singh <ayushdevel1325@gmail.com>
 */

#include "local_node.h"
#include "svc.h"
#include "ap.h"
#include "greybus_protocol.h"
#include "greybus_messages.h"
#include "node.h"
#include <zephyr/sys/dlist.h>
#include <errno.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/atomic.h>

#define ENDO_ID           0x4755
#define MAX_GREYBUS_NODES CONFIG_BEAGLEPLAY_GREYBUS_MAX_NODES

LOG_MODULE_DECLARE(cc1352_greybus, CONFIG_BEAGLEPLAY_GREYBUS_LOG_LEVEL);

ATOMIC_DEFINE(svc_is_read_flag, 1);

static sys_dlist_t operations_list = SYS_DLIST_STATIC_INIT(&operations_list);

struct svc_module_removed_map_item {
	uint16_t opr_id;
	uint8_t intf_id;
	sys_dnode_t node;
};

K_MEM_SLAB_DEFINE_STATIC(svc_module_removed_map, sizeof(struct svc_module_removed_map_item),
			 MAX_GREYBUS_NODES, 4);

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

struct gb_svc_intf_resume_response {
	uint8_t status;
} __packed;

struct gb_svc_conn_destroy_request {
	uint8_t intf1_id;
	uint16_t cport1_id;
	uint8_t intf2_id;
	uint16_t cport2_id;
} __packed;

struct gb_svc_conn_create_request {
	uint8_t intf1_id;
	uint16_t cport1_id;
	uint8_t intf2_id;
	uint16_t cport2_id;
	uint8_t tc;
	uint8_t flags;
} __packed;

struct gb_svc_dme_peer_set_response {
	uint16_t result_code;
} __packed;

struct gb_svc_dme_peer_get_response {
	uint16_t result_code;
	uint32_t attr_value;
} __packed;

struct gb_svc_intf_activate_response {
	uint8_t status;
	uint8_t intf_type;
} __packed;

struct gb_svc_intf_unipro_response {
	uint8_t result_code;
} __packed;

struct gb_svc_intf_refclk_response {
	uint8_t result_code;
} __packed;

struct gb_svc_intf_vsys_response {
	uint8_t result_code;
} __packed;

struct gb_svc_module_inserted_request {
	uint8_t primary_intf_id;
	uint8_t intf_count;
	uint16_t flags;
} __packed;

struct gb_svc_module_removed_request {
	uint8_t primary_intf_id;
} __packed;

struct gb_svc_version_request {
	uint8_t major;
	uint8_t minor;
} __packed;

/* SVC protocol hello request */
struct gb_svc_hello_request {
	uint16_t endo_id;
	uint8_t interface_id;
} __packed;

struct gb_svc_pwrmon_rail_count_get_response {
	uint8_t rail_count;
} __packed;

struct gb_svc_l2_timer_cfg {
	uint16_t tsb_fc0_protection_timeout;
	uint16_t tsb_tc0_replay_timeout;
	uint16_t tsb_afc0_req_timeout;
	uint16_t tsb_fc1_protection_timeout;
	uint16_t tsb_tc1_replay_timeout;
	uint16_t tsb_afc1_req_timeout;
	uint16_t reserved_for_tc2[3];
	uint16_t reserved_for_tc3[3];
} __packed;

struct gb_svc_intf_set_pwrm_request {
	uint8_t intf_id;
	uint8_t hs_series;
	uint8_t tx_mode;
	uint8_t tx_gear;
	uint8_t tx_nlanes;
	uint8_t tx_amplitude;
	uint8_t tx_hs_equalizer;
	uint8_t rx_mode;
	uint8_t rx_gear;
	uint8_t rx_nlanes;
	uint8_t flags;
	uint32_t quirks;
	struct gb_svc_l2_timer_cfg local_l2timerdata, remote_l2timerdata;
} __packed;

struct gb_svc_intf_set_pwrm_response {
	uint8_t result_code;
} __packed;

static int control_send_request(void *payload, size_t payload_len, uint8_t request_type)
{
	int ret;
	struct gb_message *msg;

	msg = gb_message_request_alloc(payload, payload_len, request_type, false);
	if (msg == NULL) {
		return -ENOMEM;
	}

	ret = connection_send(SVC_INF_ID, 0, msg);
	if (ret < 0) {
		LOG_ERR("Failed to send SVC message");
		return ret;
	}

	return msg->header.id;
}

static int svc_send_hello(void)
{
	struct gb_svc_hello_request req = {.endo_id = ENDO_ID, .interface_id = AP_INF_ID};

	return control_send_request(&req, sizeof(struct gb_svc_hello_request),
				    GB_SVC_TYPE_HELLO_REQUEST);
}

static void svc_response_helper(struct gb_message *msg, const void *payload, size_t payload_len,
				uint8_t status)
{
	int ret;
	struct gb_message *resp = gb_message_response_alloc(payload, payload_len, msg->header.type,
							    msg->header.id, status);
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
	struct svc_module_removed_map_item *item, *item_safe;
	struct gb_interface *intf;

	if (gb_message_is_success(msg)) {
		SYS_DLIST_FOR_EACH_CONTAINER_SAFE(&operations_list, item, item_safe, node) {
			if (msg->header.id == item->opr_id) {
				sys_dlist_remove(&item->node);
				intf = gb_interface_find_by_id(item->intf_id);
				if (!intf) {
					LOG_ERR("Failed to find the removed interface");
				}

				/*
				 * I think that AP should destroy any connections left but not sure
				 */
				node_destroy_interface(intf);
				k_mem_slab_free(&svc_module_removed_map, (void **)&item);
				break;
			}
		}
	}
}

static void gb_handle_msg(struct gb_message *msg)
{
	switch (gb_message_type(msg)) {
	case GB_SVC_TYPE_INTF_DEVICE_ID_REQUEST:
	case GB_SVC_TYPE_ROUTE_CREATE_REQUEST:
	case GB_SVC_TYPE_ROUTE_DESTROY_REQUEST:
	case GB_SVC_TYPE_PING_REQUEST:
		svc_empty_request_handler(msg);
		break;
	case GB_SVC_TYPE_CONN_CREATE_REQUEST:
		svc_connection_create_handler(msg);
		break;
	case GB_SVC_TYPE_CONN_DESTROY_REQUEST:
		svc_connection_destroy_handler(msg);
		break;
	case GB_SVC_TYPE_DME_PEER_GET_REQUEST:
		svc_dme_peer_get_handler(msg);
		break;
	case GB_SVC_TYPE_DME_PEER_SET_REQUEST:
		svc_dme_peer_set_handler(msg);
		break;
	case GB_SVC_TYPE_INTF_SET_PWRM_REQUEST:
		svc_intf_set_pwrm_handler(msg);
		break;
	case GB_SVC_TYPE_PWRMON_RAIL_COUNT_GET_REQUEST:
		svc_pwrm_get_rail_count_handler(msg);
		break;
	case GB_SVC_TYPE_INTF_VSYS_ENABLE_REQUEST:
	case GB_SVC_TYPE_INTF_VSYS_DISABLE_REQUEST:
		svc_intf_vsys_enable_disable_handler(msg);
		break;
	case GB_SVC_TYPE_INTF_REFCLK_ENABLE_REQUEST:
	case GB_SVC_TYPE_INTF_REFCLK_DISABLE_REQUEST:
		svc_interface_refclk_enable_disable_handler(msg);
		break;
	case GB_SVC_TYPE_INTF_UNIPRO_ENABLE_REQUEST:
	case GB_SVC_TYPE_INTF_UNIPRO_DISABLE_REQUEST:
		svc_interface_unipro_enable_disable_handler(msg);
		break;
	case GB_SVC_TYPE_INTF_ACTIVATE_REQUEST:
		svc_interface_activate_handler(msg);
		break;
	case GB_SVC_TYPE_INTF_RESUME_REQUEST:
		svc_interface_resume_handler(msg);
		break;
	case GB_SVC_TYPE_PROTOCOL_VERSION_RESPONSE:
		svc_version_response_handler(msg);
		break;
	case GB_SVC_TYPE_HELLO_RESPONSE:
		svc_hello_response_handler(msg);
		break;
	case GB_SVC_TYPE_MODULE_INSERTED_RESPONSE:
		svc_module_inserted_response_handler(msg);
		break;
	case GB_SVC_TYPE_MODULE_REMOVED_RESPONSE:
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
				    GB_SVC_TYPE_MODULE_INSERTED_REQUEST);
}

int svc_send_module_removed(uint8_t intf_id)
{
	int ret;
	struct svc_module_removed_map_item *item;

	struct gb_svc_module_removed_request req = {.primary_intf_id = intf_id};

	ret = control_send_request(&req, sizeof(req), GB_SVC_TYPE_MODULE_REMOVED_REQUEST);
	if (ret < 0) {
		return ret;
	}

	k_mem_slab_alloc(&svc_module_removed_map, (void **)&item, K_NO_WAIT);
	item->intf_id = intf_id;
	item->opr_id = ret;
	sys_dlist_append(&operations_list, &item->node);

	return ret;
}

int svc_send_version(void)
{
	struct gb_svc_version_request req = {.major = GB_SVC_VERSION_MAJOR,
					     .minor = GB_SVC_VERSION_MINOR};
	return control_send_request(&req, sizeof(struct gb_svc_version_request),
				    GB_SVC_TYPE_PROTOCOL_VERSION_REQUEST);
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
