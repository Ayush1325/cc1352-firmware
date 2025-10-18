// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2023 Ayush Singh <ayushdevel1325@gmail.com>
 */

#include "node.h"
#include "greybus_protocols.h"
#include "greybus_messages.h"
#include "svc.h"
#include <zephyr/net/net_ip.h>
#include <zephyr/sys/dlist.h>
#include <assert.h>
#include <errno.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/socket.h>
#include "ap.h"

#define MAX_GREYBUS_NODES         CONFIG_BEAGLEPLAY_GREYBUS_MAX_NODES
#define NODE_RX_THREAD_STACK_SIZE 2048
#define NODE_RX_THREAD_PRIORITY   6

LOG_MODULE_DECLARE(cc1352_greybus, CONFIG_BEAGLEPLAY_GREYBUS_LOG_LEVEL);

struct gb_message_in_transport {
	uint16_t cport_id;
	struct gb_message *msg;
};

struct node_control_data {
	int sock;
};

K_MEM_SLAB_DEFINE_STATIC(node_control_data_slab, sizeof(struct node_control_data),
			 MAX_GREYBUS_NODES, 4);

struct node_item {
	int sock;
	uint8_t id;
	struct in6_addr addr;
	struct gb_interface *inf;
	uint8_t fail_count;
};

/* Node Cache */
static struct node_item node_cache[MAX_GREYBUS_NODES];
static size_t node_cache_pos;

static void node_rx_thread_entry(void *p1, void *p2, void *p3);

K_THREAD_DEFINE(node_rx_thread, NODE_RX_THREAD_STACK_SIZE, node_rx_thread_entry, NULL, NULL, NULL,
		NODE_RX_THREAD_PRIORITY, 0, 0);

static int local_pipe_writer;

static void pipe_send()
{
	const uint8_t temp = 0;
	int ret = zsock_send(local_pipe_writer, &temp, sizeof(temp), 0);
	if (ret < 0) {
		LOG_ERR("Failed to write to pipe %d", errno);
	}
}

static int node_cache_find_by_addr(const struct in6_addr *addr)
{
	size_t i;
	int ret;

	for (i = 0; i < node_cache_pos; ++i) {
		ret = net_ipv6_addr_cmp(&node_cache[i].addr, addr);
		if (ret) {
			return i;
		}
	}

	return -1;
}

static int node_cache_find_by_sock(int sock)
{
	size_t i;

	for (i = 0; i < node_cache_pos; ++i) {
		if (node_cache[i].sock == sock) {
			return i;
		}
	}

	return -1;
}

static int node_cache_find_by_id(uint8_t id)
{
	size_t i;

	for (i = 0; i < node_cache_pos; ++i) {
		if (node_cache[i].id == id) {
			return i;
		}
	}

	return -1;
}

static int node_cache_add(int sock, uint8_t id, const struct in6_addr *addr,
			  struct gb_interface *intf)
{
	if (node_cache_pos >= MAX_GREYBUS_NODES) {
		return -ENOMEM;
	}

	node_cache[node_cache_pos].sock = sock;
	node_cache[node_cache_pos].id = id;
	net_ipaddr_copy(&node_cache[node_cache_pos].addr, addr);
	node_cache[node_cache_pos].inf = intf;
	node_cache[node_cache_pos].fail_count = 0;

	node_cache_pos++;

	return 0;
}

static void node_cache_remove_at(size_t pos)
{
	--node_cache_pos;
	if (pos != node_cache_pos) {
		memcpy(&node_cache[pos], &node_cache[node_cache_pos], sizeof(struct node_item));
	}
}

static int node_cache_remove_by_id(uint8_t id)
{
	int ret = node_cache_find_by_id(id);
	if (ret >= 0) {
		node_cache_remove_at(ret);
	}

	return ret;
}

static int write_data(int sock, const void *data, size_t len)
{
	int ret, transmitted = 0;

	while (transmitted < len) {
		ret = zsock_send(sock, transmitted + (char *)data, len - transmitted, 0);
		if (ret < 0) {
			LOG_ERR("Failed to transmit data");
			return ret;
		}
		transmitted += ret;
	}
	return transmitted;
}

static int read_data(int sock, void *data, size_t len)
{
	int ret, received = 0;

	while (received < len) {
		ret = zsock_recv(sock, received + (char *)data, len - received, 0);
		if (ret <= 0) {
			LOG_ERR("Failed to receive data");
			return ret;
		}
		received += ret;
	}
	return received;
}

static struct gb_message_in_transport gb_message_receive(int sock, bool *flag)
{
	int ret;
	struct gb_operation_msg_hdr hdr;
	struct gb_message_in_transport msg;

	ret = read_data(sock, &msg.cport_id, sizeof(uint16_t));
	if (ret != sizeof(uint16_t)) {
		*flag = ret == 0;
		goto early_exit;
	}
	msg.cport_id = sys_le16_to_cpu(msg.cport_id);

	ret = read_data(sock, &hdr, sizeof(hdr));
	if (ret != sizeof(hdr)) {
		*flag = ret == 0;
		goto early_exit;
	}

	msg.msg =
		gb_message_alloc(gb_hdr_payload_len(&hdr), hdr.type, hdr.operation_id, hdr.result);
	if (!msg.msg) {
		LOG_ERR("Failed to allocate node message");
		goto early_exit;
	}

	ret = read_data(sock, msg.msg->payload, gb_message_payload_len(msg.msg));
	if (ret != gb_message_payload_len(msg.msg)) {
		*flag = ret == 0;
		goto free_msg;
	}

	return msg;

free_msg:
	gb_message_dealloc(msg.msg);
early_exit:
	msg.cport_id = 0;
	msg.msg = NULL;
	return msg;
}

static void svc_send_module_removed_by_sock(int sock)
{
	int ret = node_cache_find_by_sock(sock);
	if (ret < 0) {
		LOG_ERR("Failed to find node");
		return;
	}

	svc_send_module_removed(node_cache[ret].inf);
}

static void node_rx_thread_entry(void *p1, void *p2, void *p3)
{
	struct zsock_pollfd fds[AP_MAX_NODES + 1];
	size_t i, fds_len = 1;
	int pipe[2], ret;
	uint8_t temp;
	bool flag = false;
	struct gb_message_in_transport msg;

	while (!svc_is_ready()) {
		k_sleep(K_MSEC(500));
	}

	ret = zsock_socketpair(AF_UNIX, SOCK_STREAM, 0, pipe);
	if (ret < 0) {
		LOG_ERR("Failed to create socketpair %d", errno);
		return;
	}

	local_pipe_writer = pipe[1];
	fds[0].fd = pipe[0];

	while (1) {
		/* Populate fds */
		fds[0].events = ZSOCK_POLLIN;
		for (i = 0; i < node_cache_pos; ++i) {
			fds[i + 1].fd = node_cache[i].sock;
			fds[i + 1].events = ZSOCK_POLLIN;
		}
		fds_len = node_cache_pos + 1;

		LOG_DBG("Polling for %zu sockets", fds_len - 1);
		ret = zsock_poll(fds, fds_len, -1);
		if (ret < 0) {
			LOG_ERR("Failed to poll");
			continue;
		}

		if (fds[0].revents & ZSOCK_POLLIN) {
			/* Drain the pipe */
			LOG_DBG("Wakeup by pipe");
			zsock_recv(fds[0].fd, &temp, sizeof(temp), 0);
		}

		for (i = 1; i < fds_len; ++i) {
			if (fds[i].revents & ZSOCK_POLLIN) {
				ret = node_cache_find_by_sock(fds[i].fd);
				if (ret < 0) {
					LOG_ERR("Failed to find node");
					continue;
				}

				msg = gb_message_receive(fds[i].fd, &flag);
				if (flag) {
					LOG_ERR("Socket closed by peer");
					svc_send_module_removed(node_cache[ret].inf);
					continue;
				}

				if (!msg.msg) {
					LOG_ERR("Failed to get full message");
					svc_send_module_removed(node_cache[ret].inf);
					continue;
				}

				ret = connection_send(node_cache[ret].id, msg.cport_id, msg.msg);
				if (ret < 0) {
					LOG_ERR("Failed to send message to AP");
					continue;
				}
			} else if (fds[i].revents & ZSOCK_POLLNVAL) {
				LOG_WRN("Socket invalid");
				svc_send_module_removed_by_sock(fds[i].fd);
			} else if (fds[i].revents & ZSOCK_POLLHUP) {
				LOG_WRN("Socket pollhup");
				svc_send_module_removed_by_sock(fds[i].fd);
			} else if (fds[i].revents & ZSOCK_POLLERR) {
				LOG_WRN("Socket error");
				svc_send_module_removed_by_sock(fds[i].fd);
			}
		}
	}
}

static int gb_message_send(int sock, const struct gb_message *msg, uint16_t cport)
{
	int ret;
	uint16_t cport_le = sys_cpu_to_le16(cport);

	ret = write_data(sock, &cport_le, sizeof(uint16_t));
	if (ret != sizeof(uint16_t)) {
		LOG_ERR("Failed to send CPort ID to node");
		goto early_exit;
	}

	ret = write_data(sock, &msg->header, sizeof(struct gb_operation_msg_hdr));
	if (ret != sizeof(struct gb_operation_msg_hdr)) {
		LOG_ERR("Failed to send Greybus Message Header to node");
		goto early_exit;
	}

	ret = write_data(sock, msg->payload, gb_message_payload_len(msg));
	if (ret != gb_message_payload_len(msg)) {
		LOG_ERR("Failed to send Greybus Message Payload to node");
		goto early_exit;
	}

	return 0;

early_exit:
	svc_send_module_removed_by_sock(sock);
	return ret;
}

static int connect_to_node(const struct sockaddr *addr)
{
	int ret, sock;
	size_t addr_size;

	if (addr->sa_family == AF_INET6) {
		sock = zsock_socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
		addr_size = sizeof(struct sockaddr_in6);
	} else {
		sock = zsock_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		addr_size = sizeof(struct sockaddr_in);
	}

	if (sock < 0) {
		LOG_ERR("Failed to create socket %d", errno);
		return sock;
	}

	ret = zsock_connect(sock, addr, addr_size);
	if (ret) {
		LOG_ERR("Failed to connect to node %d", errno);
		goto fail;
	}

	return sock;

fail:
	zsock_close(sock);
	return ret;
}

static int node_intf_create_connection(struct gb_interface *ctrl, uint16_t cport_id)
{
	struct sockaddr_in6 node_addr;
	struct node_control_data *ctrl_data = ctrl->ctrl_data;
	int ret, sock;

	/* Do not create socket for cports other than 0 */
	if (cport_id != 0) {
		return 0;
	}

	/* It is possible for cport 0 to be disconnected. Since we are not closing the tcp
	 * socket, do not recreate an existing socket */
	if (ctrl_data->sock >= 0) {
		return ctrl_data->sock;
	}

	ret = node_cache_find_by_id(ctrl->id);
	if (ret < 0) {
		LOG_ERR("Failed to find node %u in cache. This should not happen", ctrl->id);
		return -EINVAL;
	}

	memcpy(&node_addr.sin6_addr, &node_cache[ret].addr, sizeof(struct in6_addr));
	node_addr.sin6_family = AF_INET6;
	node_addr.sin6_scope_id = 0;
	node_addr.sin6_port = htons(GB_TRANSPORT_TCPIP_BASE_PORT);

	sock = connect_to_node((struct sockaddr *)&node_addr);
	if (sock < 0) {
		LOG_ERR("Failed to connect to node");
		return sock;
	}
	node_cache[ret].sock = sock;
	ctrl_data->sock = sock;

	pipe_send();

	return sock;
}

static void node_intf_destroy_connection(struct gb_interface *ctrl, uint16_t cport_id)
{
	/* Do Nothing */
}

static int node_inf_write(struct gb_interface *ctrl, struct gb_message *msg, uint16_t cport_id)
{
	int ret;
	struct node_control_data *ctrl_data = ctrl->ctrl_data;

	ret = gb_message_send(ctrl_data->sock, msg, cport_id);
	if (ret < 0) {
		LOG_ERR("Socket seems closed");
		svc_send_module_removed(ctrl);
	}
	gb_message_dealloc(msg);

	return ret;
}

static struct gb_interface *node_create_interface(struct in6_addr *addr)
{
	int ret;
	struct node_control_data *ctrl_data;
	struct gb_interface *inf;

	ret = k_mem_slab_alloc(&node_control_data_slab, (void **)&ctrl_data, K_NO_WAIT);
	if (ret) {
		LOG_ERR("Failed to allocate Greybus connection");
		goto early_exit;
	}

	ctrl_data->sock = -1;

	inf = gb_interface_alloc(node_inf_write, node_intf_create_connection,
				 node_intf_destroy_connection, ctrl_data);
	if (!inf) {
		LOG_ERR("Failed to allocate Greybus interface");
		goto free_ctrl_data;
	}

	LOG_DBG("Create new interface with ID %u", inf->id);
	ret = node_cache_add(-1, inf->id, addr, inf);
	if (ret < 0) {
		LOG_ERR("Failed to add node to cache");
		goto free_ctrl_data;
	}

	return inf;

free_ctrl_data:
	k_mem_slab_free(&node_control_data_slab, (void **)&ctrl_data);
early_exit:
	return NULL;
}

void node_destroy_interface(struct gb_interface *inf)
{
	struct node_control_data *ctrl_data;

	if (inf == NULL) {
		return;
	}

	ctrl_data = inf->ctrl_data;

	if (ctrl_data->sock >= 0) {
		zsock_close(ctrl_data->sock);
	}

	node_cache_remove_by_id(inf->id);
	k_mem_slab_free(&node_control_data_slab, (void **)&ctrl_data);
	gb_interface_dealloc(inf);
}

struct gb_interface *node_find_by_id(uint8_t id)
{
	int ret = node_cache_find_by_id(id);

	return (ret >= 0) ? node_cache[ret].inf : NULL;
}

void node_filter(struct in6_addr *active_addr, size_t active_len)
{
	size_t i;
	struct gb_interface *inf;
	int ret;

	for (i = 0; i < active_len; ++i) {
		ret = node_cache_find_by_addr(&active_addr[i]);

		/* Handle New Node */
		if (ret < 0) {
			LOG_DBG("New node discovered");
			inf = node_create_interface(&active_addr[i]);
			if (!inf) {
				LOG_ERR("Failed to create interface");
				continue;
			}
			svc_send_module_inserted(inf->id);
		}
	}
}

void node_destroy_all(void)
{
	size_t i;

	for (i = 0; i < node_cache_pos; ++i) {
		node_destroy_interface(node_cache[i].inf);
	}

	node_cache_pos = 0;

	assert(!k_mem_slab_num_used_get(&node_control_data_slab));
}
