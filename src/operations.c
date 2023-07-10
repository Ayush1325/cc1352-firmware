#include "operations.h"
#include "error_handling.h"
#include "greybus_protocol.h"
#include "hdlc.h"
#include "zephyr/kernel.h"
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/socket.h>
#include <zephyr/sys/dlist.h>

LOG_MODULE_DECLARE(cc1352_greybus, CONFIG_BEAGLEPLAY_GREYBUS_LOG_LEVEL);

K_MUTEX_DEFINE(gb_operations_mutex);
K_MUTEX_DEFINE(gb_operations_callback_mutex);

static void callback_work_handler(struct k_work *);

static atomic_t operation_id_counter = ATOMIC_INIT(1);
static sys_dlist_t greybus_operations_list =
    SYS_DLIST_STATIC_INIT(&greybus_operations_list);
static sys_dlist_t greybus_operations_callback_list =
    SYS_DLIST_STATIC_INIT(&greybus_operations_callback_list);

K_WORK_DEFINE(callback_work, callback_work_handler);

static void gb_operation_dealloc(struct gb_operation *op) {
  if (op == NULL) {
    return;
  }

  LOG_DBG("Dealloc Request");
  gb_message_dealloc(op->request);
  LOG_DBG("Dealloc Response");
  gb_message_dealloc(op->response);

  LOG_DBG("Free Operation");
  k_free(op);
}

static void callback_work_handler(struct k_work *work) {
  struct gb_operation *op;
  sys_dnode_t *head_node;

  while (1) {
    k_mutex_lock(&gb_operations_callback_mutex, K_FOREVER);
    head_node = sys_dlist_get(&greybus_operations_callback_list);
    k_mutex_unlock(&gb_operations_callback_mutex);

    if (head_node == NULL) {
      return;
    }

    op = SYS_DLIST_CONTAINER(head_node, op, node);

    if (op->callback != NULL) {
      op->callback(op);
    }

    LOG_DBG("Dealloc Operation %d", op->operation_id);
    gb_operation_dealloc(op);
    LOG_DBG("Finish Dealloc Operation %d", op->operation_id);
  }
}

static void gb_operation_finish(struct gb_operation *op) {
  sys_dlist_remove(&op->node);

  k_mutex_lock(&gb_operations_callback_mutex, K_FOREVER);
  sys_dlist_append(&greybus_operations_callback_list, &op->node);
  k_mutex_unlock(&gb_operations_callback_mutex);

  k_work_submit(&callback_work);
}

static struct gb_operation *gb_operation_find_by_id(uint16_t operation_id,
                                                    sys_dlist_t *list) {
  struct gb_operation *op;

  SYS_DLIST_FOR_EACH_CONTAINER(list, op, node) {
    if (op->operation_id == operation_id) {
      return op;
    }
  }
  return NULL;
}

struct gb_operation *gb_operation_alloc(bool is_oneshot) {
  struct gb_operation *op = k_malloc(sizeof(struct gb_operation));
  if (!op) {
    LOG_ERR("Failed to allocate Greybus Operation");
    return NULL;
  }
  op->response = NULL;
  op->request = NULL;
  op->request_sent = false;
  op->response_received = false;
  op->callback = NULL;

  if (is_oneshot) {
    op->operation_id = 0;
  } else {
    atomic_val_t temp = atomic_inc(&operation_id_counter);
    if (temp == UINT16_MAX) {
      atomic_set(&operation_id_counter, 1);
    }
    op->operation_id = temp;
  }

  return op;
}

void gb_operation_queue(struct gb_operation *op) {
  k_mutex_lock(&gb_operations_mutex, K_FOREVER);
  sys_dlist_append(&greybus_operations_list, &op->node);
  k_mutex_unlock(&gb_operations_mutex);
}

int gb_operation_request_alloc(struct gb_operation *op, const void *payload,
                               size_t payload_len, uint8_t request_type,
                               greybus_operation_callback_t callback) {
  int ret;

  op->request = k_malloc(sizeof(struct gb_message) + payload_len);
  if (op->request == NULL) {
    LOG_WRN("Failed to allocate Greybus request message");
    ret = -E_NO_HEAP_MEM;
    goto early_exit;
  }

  op->request->header.size = sizeof(struct gb_operation_msg_hdr) + payload_len;
  op->request->header.id = op->operation_id;
  op->request->header.type = request_type;
  op->request->header.status = 0;

  memcpy(op->request->payload, payload, payload_len);
  op->request->payload_size = payload_len;

  op->request->operation = op;
  op->callback = callback;

  ret = SUCCESS;

early_exit:
  return ret;
}

void gb_message_dealloc(struct gb_message *msg) {
  if (msg == NULL) {
    return;
  }

  LOG_DBG("Free Message");
  k_free(msg);
}

int gb_operation_set_response(struct gb_message *msg) {
  struct gb_operation *op;

  k_mutex_lock(&gb_operations_mutex, K_FOREVER);
  op = gb_operation_find_by_id(msg->header.id, &greybus_operations_list);
  if (op == NULL || op->response_received) {
    return -E_CLIENT_REQUEST;
  }

  msg->operation = op;
  op->response = msg;
  op->response_received = true;
  LOG_DBG("Operation with ID %u completed", msg->header.id);
  gb_operation_finish(op);
  k_mutex_unlock(&gb_operations_mutex);

  return SUCCESS;
}

int gb_message_hdlc_send(const struct gb_message *msg) {
  char buffer[50];

  memcpy(buffer, &msg->header, sizeof(struct gb_operation_msg_hdr));
  memcpy(&buffer[sizeof(struct gb_operation_msg_hdr)], msg->payload,
         msg->payload_size);

  hdlc_block_send_sync(buffer, msg->header.size, ADDRESS_GREYBUS, 0x03);

  return SUCCESS;
}

struct gb_connection *gb_create_connection(struct gb_interface *inf_ap,
                                        struct gb_interface *inf_peer,
                                        uint16_t ap_cport,
                                        uint16_t peer_cport) {
  struct gb_connection *conn = k_malloc(sizeof(struct gb_connection));
  if (conn == NULL) {
    LOG_ERR("Failed to create Greybus connection");
    return NULL;
  }

  conn->inf_ap = inf_ap;
  conn->inf_peer = inf_peer;
  conn->peer_cport_id = peer_cport;
  conn->ap_cport_id = ap_cport;

  return conn;
}
