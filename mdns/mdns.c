// Alias some things to simulate recieving data to fuzz library
#include "mdns.h"

#define NI_MAXSERV 32

LOG_MODULE_DECLARE(cc1352_greybus, CONFIG_BEAGLEPLAY_GREYBUS_LOG_LEVEL);

static char addrbuffer[64];
static char entrybuffer[256];
static char namebuffer[256];
static mdns_record_txt_t txtbuffer[128];

volatile atomic_t running = 1;

// Data for our service including the mDNS records
typedef struct {
  mdns_string_t service;
  mdns_string_t hostname;
  mdns_string_t service_instance;
  mdns_string_t hostname_qualified;
  struct sockaddr_in address_ipv4;
  struct sockaddr_in6 address_ipv6;
  int port;
  mdns_record_t record_ptr;
  mdns_record_t record_srv;
  mdns_record_t record_a;
  mdns_record_t record_aaaa;
  mdns_record_t txt_record[2];
} service_t;

static mdns_string_t ipv4_address_to_string(char *buffer, size_t capacity,
                                            const struct sockaddr_in *addr,
                                            size_t addrlen) {
  char host[NI_MAXHOST] = {0};
  char service[NI_MAXSERV] = {0};
  int ret = zsock_getnameinfo((const struct sockaddr *)addr, (socklen_t)addrlen,
                              host, NI_MAXHOST, service, NI_MAXSERV,
                              NI_NUMERICSERV | NI_NUMERICHOST);
  int len = 0;
  if (ret == 0) {
    if (addr->sin_port != 0)
      len = snprintk(buffer, capacity, "%s:%s", host, service);
    else
      len = snprintk(buffer, capacity, "%s", host);
  }
  if (len >= (int)capacity)
    len = (int)capacity - 1;
  mdns_string_t str;
  str.str = buffer;
  str.length = len;
  return str;
}

static mdns_string_t ipv6_address_to_string(char *buffer, size_t capacity,
                                            const struct sockaddr_in6 *addr,
                                            size_t addrlen) {
  char host[NI_MAXHOST] = {0};
  char service[NI_MAXSERV] = {0};
  int ret = zsock_getnameinfo((const struct sockaddr *)addr, (socklen_t)addrlen,
                              host, NI_MAXHOST, service, NI_MAXSERV,
                              NI_NUMERICSERV | NI_NUMERICHOST);
  int len = 0;
  if (ret == 0) {
    if (addr->sin6_port != 0)
      len = snprintk(buffer, capacity, "[%s]:%s", host, service);
    else
      len = snprintk(buffer, capacity, "%s", host);
  }
  if (len >= (int)capacity)
    len = (int)capacity - 1;
  mdns_string_t str;
  str.str = buffer;
  str.length = len;
  return str;
}

static mdns_string_t ip_address_to_string(char *buffer, size_t capacity,
                                          const struct sockaddr *addr,
                                          size_t addrlen) {
  if (addr->sa_family == AF_INET6)
    return ipv6_address_to_string(buffer, capacity,
                                  (const struct sockaddr_in6 *)addr, addrlen);
  return ipv4_address_to_string(buffer, capacity,
                                (const struct sockaddr_in *)addr, addrlen);
}

// Callback handling parsing answers to queries sent
static int query_callback(int sock, const struct sockaddr *from, size_t addrlen,
                          mdns_entry_type_t entry, uint16_t query_id,
                          uint16_t rtype, uint16_t rclass, uint32_t ttl,
                          const void *data, size_t size, size_t name_offset,
                          size_t name_length, size_t record_offset,
                          size_t record_length, void *user_data) {
  (void)sizeof(sock);
  (void)sizeof(query_id);
  (void)sizeof(name_length);
  (void)sizeof(user_data);
  mdns_string_t fromaddrstr =
      ip_address_to_string(addrbuffer, sizeof(addrbuffer), from, addrlen);
  const char *entrytype =
      (entry == MDNS_ENTRYTYPE_ANSWER)
          ? "answer"
          : ((entry == MDNS_ENTRYTYPE_AUTHORITY) ? "authority" : "additional");
  mdns_string_t entrystr = mdns_string_extract(
      data, size, &name_offset, entrybuffer, sizeof(entrybuffer));
  if (rtype == MDNS_RECORDTYPE_PTR) {
    mdns_string_t namestr =
        mdns_record_parse_ptr(data, size, record_offset, record_length,
                              namebuffer, sizeof(namebuffer));
    LOG_DBG("%.*s : %s %.*s PTR %.*s rclass 0x%x ttl %u length %d\n",
            MDNS_STRING_FORMAT(fromaddrstr), entrytype,
            MDNS_STRING_FORMAT(entrystr), MDNS_STRING_FORMAT(namestr), rclass,
            ttl, (int)record_length);
  } else if (rtype == MDNS_RECORDTYPE_SRV) {
    mdns_record_srv_t srv =
        mdns_record_parse_srv(data, size, record_offset, record_length,
                              namebuffer, sizeof(namebuffer));
    LOG_DBG("%.*s : %s %.*s SRV %.*s priority %d weight %d port %d\n",
            MDNS_STRING_FORMAT(fromaddrstr), entrytype,
            MDNS_STRING_FORMAT(entrystr), MDNS_STRING_FORMAT(srv.name),
            srv.priority, srv.weight, srv.port);
  } else if (rtype == MDNS_RECORDTYPE_A) {
    struct sockaddr_in addr;
    mdns_record_parse_a(data, size, record_offset, record_length, &addr);
    mdns_string_t addrstr = ipv4_address_to_string(
        namebuffer, sizeof(namebuffer), &addr, sizeof(addr));
    LOG_DBG("%.*s : %s %.*s A %.*s\n", MDNS_STRING_FORMAT(fromaddrstr),
            entrytype, MDNS_STRING_FORMAT(entrystr),
            MDNS_STRING_FORMAT(addrstr));
  } else if (rtype == MDNS_RECORDTYPE_AAAA) {
    struct sockaddr_in6 addr;
    mdns_record_parse_aaaa(data, size, record_offset, record_length, &addr);
    mdns_string_t addrstr = ipv6_address_to_string(
        namebuffer, sizeof(namebuffer), &addr, sizeof(addr));
    LOG_DBG("%.*s : %s %.*s AAAA %.*s\n", MDNS_STRING_FORMAT(fromaddrstr),
            entrytype, MDNS_STRING_FORMAT(entrystr),
            MDNS_STRING_FORMAT(addrstr));
  } else if (rtype == MDNS_RECORDTYPE_TXT) {
    size_t parsed = mdns_record_parse_txt(
        data, size, record_offset, record_length, txtbuffer,
        sizeof(txtbuffer) / sizeof(mdns_record_txt_t));
    for (size_t itxt = 0; itxt < parsed; ++itxt) {
      if (txtbuffer[itxt].value.length) {
        LOG_DBG("%.*s : %s %.*s TXT %.*s = %.*s\n",
                MDNS_STRING_FORMAT(fromaddrstr), entrytype,
                MDNS_STRING_FORMAT(entrystr),
                MDNS_STRING_FORMAT(txtbuffer[itxt].key),
                MDNS_STRING_FORMAT(txtbuffer[itxt].value));
      } else {
        LOG_DBG("%.*s : %s %.*s TXT %.*s\n", MDNS_STRING_FORMAT(fromaddrstr),
                entrytype, MDNS_STRING_FORMAT(entrystr),
                MDNS_STRING_FORMAT(txtbuffer[itxt].key));
      }
    }
  } else {
    LOG_DBG("%.*s : %s %.*s type %u rclass 0x%x ttl %u length %d\n",
            MDNS_STRING_FORMAT(fromaddrstr), entrytype,
            MDNS_STRING_FORMAT(entrystr), rtype, rclass, ttl,
            (int)record_length);
  }
  return 0;
}

static int socket_setup_ipv6(int sock, const struct sockaddr_in6 *saddr) {
  struct sockaddr_in6 sock_addr;
  if (!saddr) {
    memset(&sock_addr, 0, sizeof(struct sockaddr_in6));
    sock_addr.sin6_addr = in6addr_any;
    sock_addr.sin6_family = AF_INET6;
  } else {
    memcpy(&sock_addr, saddr, sizeof(struct sockaddr_in6));
  }

  if (zsock_bind(sock, (struct sockaddr *)&sock_addr,
                 sizeof(struct sockaddr_in6))) {
    LOG_WRN("Failed to bind socket");
    return -1;
  }

  const int flags = fcntl(sock, F_GETFL, 0);
  zsock_fcntl(sock, F_SETFL, flags | O_NONBLOCK);

  return 0;
}

static int open_client_sockets(int *sockets, int max_sockets, int port) {
  int sock;
  struct sockaddr_in6 saddr;
  memset((void *)&saddr, 0, sizeof(struct sockaddr_in6));
  static const unsigned char localhost[] = {0, 0, 0, 0, 0, 0, 0, 0,
                                            0, 0, 0, 0, 0, 0, 0, 1};
  static const unsigned char localhost_mapped[] = {
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0x7f, 0, 0, 1};
  if (memcmp(saddr.sin6_addr.s6_addr, localhost, 16) &&
      memcmp(saddr.sin6_addr.s6_addr, localhost_mapped, 16)) {
    saddr.sin6_port = htons(port);
    sock = mdns_socket_open_ipv6(&saddr);
    if (sock >= 0) {
      sockets[0] = sock;
      char buffer[128];
      mdns_string_t addr = ipv6_address_to_string(
          buffer, sizeof(buffer), &saddr, sizeof(struct sockaddr_in6));
      LOG_DBG("Local IPv6 address: %.*s\n", MDNS_STRING_FORMAT(addr));
    } else {
      LOG_ERR("Failed to open Socket");
      return -1;
    }

    if (socket_setup_ipv6(sock, NULL)) {
      zsock_close(sock);
      LOG_WRN("Failed to setup socket options");
      return -1;
    }

    return 1;
  } else {
    LOG_WRN("memcmp failed");
  }

  return -1;
}

// Send a mDNS query
int send_mdns_query(mdns_query_t *query, size_t count) {
  int sockets[32];
  int query_id[32];
  int num_sockets =
      open_client_sockets(sockets, sizeof(sockets) / sizeof(sockets[0]), 0);
  if (num_sockets <= 0) {
    LOG_DBG("Failed to open any client sockets\n");
    return -1;
  }
  LOG_DBG("Opened %d socket%s for mDNS query\n", num_sockets,
          num_sockets ? "s" : "");

  const size_t capacity = 2048;
  void *buffer = malloc(capacity);
  void *user_data = 0;

  LOG_DBG("Sending mDNS query");
  for (size_t iq = 0; iq < count; ++iq) {
    const char *record_name = "PTR";
    if (query[iq].type == MDNS_RECORDTYPE_SRV)
      record_name = "SRV";
    else if (query[iq].type == MDNS_RECORDTYPE_A)
      record_name = "A";
    else if (query[iq].type == MDNS_RECORDTYPE_AAAA)
      record_name = "AAAA";
    else
      query[iq].type = MDNS_RECORDTYPE_PTR;
    LOG_DBG(" : %s %s", query[iq].name, record_name);
  }
  for (int isock = 0; isock < num_sockets; ++isock) {
    query_id[isock] =
        mdns_multiquery_send(sockets[isock], query, count, buffer, capacity, 0);
    if (query_id[isock] < 0)
      LOG_DBG("Failed to send mDNS query: %s\n", strerror(errno));
  }

  // This is a simple implementation that loops for 5 seconds or as long as we
  // get replies
  int res;
  LOG_DBG("Reading mDNS query replies\n");
  int records = 0;
  do {
    struct timeval timeout;
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;

    int nfds = 0;
    zsock_fd_set readfs;
    ZSOCK_FD_ZERO(&readfs);
    for (int isock = 0; isock < num_sockets; ++isock) {
      if (sockets[isock] >= nfds)
        nfds = sockets[isock] + 1;
      ZSOCK_FD_SET(sockets[isock], &readfs);
    }

    res = zsock_select(nfds, &readfs, 0, 0, &timeout);
    if (res > 0) {
      for (int isock = 0; isock < num_sockets; ++isock) {
        if (ZSOCK_FD_ISSET(sockets[isock], &readfs)) {
          size_t rec =
              mdns_query_recv(sockets[isock], buffer, capacity, query_callback,
                              user_data, query_id[isock]);
          if (rec > 0)
            records += rec;
        }
        ZSOCK_FD_SET(sockets[isock], &readfs);
      }
    }
  } while (res > 0);

  LOG_DBG("Read %d records\n", records);

  free(buffer);

  for (int isock = 0; isock < num_sockets; ++isock)
    mdns_socket_close(sockets[isock]);
  LOG_DBG("Closed socket%s\n", num_sockets ? "s" : "");

  return 0;
}

void signal_handler(int signal) { running = 0; }
