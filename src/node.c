#include "greybus_protocol.h"
#include "operations.h"
#include "zephyr/sys/dlist.h"
#include <zephyr/logging/log.h>
#include <zephyr/net/socket.h>

LOG_MODULE_DECLARE(cc1352_greybus, CONFIG_BEAGLEPLAY_GREYBUS_LOG_LEVEL);

static sys_dlist_t node_interface_list =
    SYS_DLIST_STATIC_INIT(&node_interface_list);

static int write_data(int sock, const void *data, size_t len) {
  int ret;
  int transmitted = 0;
  while (transmitted < len) {
    ret = zsock_send(sock, transmitted + (char *)data, len - transmitted, 0);
    if (ret < 0) {
      LOG_ERR("Failed to transmit data");
      return -1;
    }
    transmitted += ret;
  }
  return transmitted;
}

static int read_data(int sock, void *data, size_t len) {
  int ret;
  int recieved = 0;
  while (recieved < len) {
    ret = zsock_recv(sock, recieved + (char *)data, len - recieved, 0);
    if (ret < 0) {
      LOG_ERR("Failed to recieve data");
      return -1;
    } else if (ret == 0) {
      // Socket was closed by peer
      return 0;
    }
    recieved += ret;
  }
  return recieved;
}

static struct gb_message *gb_message_receive(int sock, bool *flag) {
  int ret;
  struct gb_operation_msg_hdr hdr;
  struct gb_message *msg;
  size_t payload_size;

  ret = read_data(sock, &hdr, sizeof(struct gb_operation_msg_hdr));
  if (ret <= 0) {
    *flag = ret == 0;
    goto early_exit;
  }

  payload_size = hdr.size - sizeof(struct gb_operation_msg_hdr);
  msg = k_malloc(sizeof(struct gb_message) + payload_size);
  if (msg == NULL) {
    LOG_ERR("Failed to allocate node message");
    goto free_msg;
  }

  memcpy(&msg->header, &hdr, sizeof(struct gb_operation_msg_hdr));
  msg->payload_size = payload_size;
  ret = read_data(sock, msg->payload, msg->payload_size);
  if (ret <= 0) {
    *flag = ret == 0;
    goto free_msg;
  }

  return msg;

free_msg:
  k_free(msg);
early_exit:
  return NULL;
}

static int gb_message_send(int sock, const struct gb_message *msg) {
  int ret;

  ret = write_data(sock, &msg->header, sizeof(struct gb_operation_msg_hdr));
  if (ret < 0) {
    return -1;
  }

  ret = write_data(sock, msg->payload, msg->payload_size);
  if (ret < 0) {
    return -1;
  }

  return SUCCESS;
}

struct node_control_data {
  int *cports;
  uint16_t cports_len;
  struct in6_addr addr;
};

static struct gb_message *node_inf_read(struct gb_controller *ctrl,
                                        uint16_t cport_id) {
  struct zsock_pollfd fd[1];
  int ret;
  bool flag = false;
  struct gb_message *msg = NULL;
  struct node_control_data *ctrl_data = ctrl->ctrl_data;

  if (cport_id >= ctrl_data->cports_len) {
    goto early_exit;
  }

  fd[0].fd = ctrl_data->cports[cport_id];
  fd[0].events = ZSOCK_POLLIN;

  ret = zsock_poll(fd, 1, 0);
  if (ret <= 0) {
    goto early_exit;
  }

  if (fd[0].revents & ZSOCK_POLLIN) {
    msg = gb_message_receive(fd[0].fd, &flag);
    if (flag) {
      LOG_ERR("Socket closed by Peer Node");
    }
  }

early_exit:
  return NULL;
}

static int node_inf_write(struct gb_controller *ctrl, struct gb_message *msg,
                          uint16_t cport_id) {
  struct node_control_data *ctrl_data = ctrl->ctrl_data;
  if (cport_id >= ctrl_data->cports_len) {
    return -1;
  }

  return gb_message_send(ctrl_data->cports[cport_id], msg);
}

struct gb_interface *node_create_interface(struct in6_addr *addr) {
  struct node_control_data *ctrl_data =
      k_malloc(sizeof(struct node_control_data));
  if (ctrl_data == NULL) {
    return NULL;
  }
  ctrl_data->cports = NULL;
  ctrl_data->cports_len = 0;
  memcpy(&ctrl_data->addr, addr, sizeof(struct in6_addr));

  struct gb_interface *inf =
      gb_interface_alloc(node_inf_read, node_inf_write, ctrl_data);
  if (inf == NULL) {
    goto free_ctrl_data;
  }

  sys_dlist_append(&node_interface_list, &inf->node);

  return inf;

free_ctrl_data:
  k_free(ctrl_data);
  return NULL;
}

void node_destroy_interface(struct gb_interface *inf) {
  if (inf == NULL) {
    return;
  }

  sys_dlist_remove(&inf->node);
  k_free(inf->controller.ctrl_data);
  gb_interface_dealloc(inf);
}

struct gb_interface *node_find_by_id(uint8_t id) {
  struct gb_interface *inf;

  SYS_DLIST_FOR_EACH_CONTAINER(&node_interface_list, inf, node) {
    if (inf->id == id) {
      return inf;
    }
  }

  return NULL;
}

struct gb_interface *node_find_by_addr(struct in6_addr *addr) {
  struct gb_interface *inf;
  struct node_control_data *ctrl_data;

  SYS_DLIST_FOR_EACH_CONTAINER(&node_interface_list, inf, node) {
    ctrl_data = inf->controller.ctrl_data;
    if (memcmp(&ctrl_data->addr, addr, sizeof(struct in6_addr)) == 0) {
      return inf;
    }
  }

  return NULL;
}