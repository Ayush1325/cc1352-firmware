#ifndef SVC_H
#define SVC_H

#include <stdint.h>

struct gb_svc_version_request {
	uint8_t major;
	uint8_t minor;
} __packed;

int svc_send_protocol_version_request(int);

#endif