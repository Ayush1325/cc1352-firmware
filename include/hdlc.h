/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2023 Ayush Singh <ayushdevel1325@gmail.com>
 */

#ifndef _HDLC_H_
#define _HDLC_H_

#include "greybus_messages.h"
#include <stdint.h>
#include <zephyr/device.h>

#define HDLC_MAX_BLOCK_SIZE CONFIG_BEAGLEPLAY_HDLC_MAX_BLOCK_SIZE

#define ADDRESS_GREYBUS 0x01
#define ADDRESS_DBG     0x02
#define ADDRESS_CONTROL 0x03
#define ADDRESS_MCUMGR  0x04

/*
 * Calback to process a received HDLC frame
 *
 * @param payload
 * @param payload len
 * @param HDLC address
 *
 * @return Negative in case of error
 */
typedef int (*hdlc_process_frame_callback)(const void *, size_t, uint8_t);

/*
 * Callback to send HDLC data
 *
 * @param buffer
 * @param buffer length
 *
 * @return Number of bytes sent, negative in case of error
 */
typedef int (*hdlc_send_frame_callback)(const uint8_t *, size_t);

/*
 * Initialize internal HDLC stuff
 *
 * @return 0 if successful. Negative in case of error.
 */
int hdlc_init(hdlc_process_frame_callback process_cb, hdlc_send_frame_callback send_cb);

/*
 * Submit an HDLC Block synchronously
 *
 * @param buffer
 * @param buffer_length
 * @param address
 * @param control
 *
 * @return block size (>= 0) if successful. Negative in case of error
 */
int hdlc_block_send_sync(const uint8_t *buffer, size_t buffer_len, uint8_t address,
			 uint8_t control);

/*
 * Get a buffer to write HDLC message received for processing. Make HDLC transport agnostic.
 *
 * @param the pointer to underlying buffer which can be used to write.
 *
 * @return number of bytes that can be written
 */
uint32_t hdlc_rx_start(uint8_t **buffer);

/*
 * Finish writing to rx buffer. Also queues rx buffer for processing
 *
 * @param number of bytes written
 *
 * @return 0 if successful. Negative in case of error.
 */
int hdlc_rx_finish(uint32_t written);

/*
 * Send a greybus message over HDLC
 *
 * @param Greybus message
 */
static inline int gb_message_hdlc_send(struct gb_message *msg, uint16_t cport)
{
	char buffer[HDLC_MAX_BLOCK_SIZE];

	memcpy(msg->header.pad, &sys_cpu_to_le16(cport), sizeof(cport));
	memcpy(buffer, &msg->header, sizeof(struct gb_operation_msg_hdr));
	memcpy(&buffer[sizeof(struct gb_operation_msg_hdr)], msg->payload, gb_message_payload_len(msg));

	hdlc_block_send_sync(buffer, msg->header.size, ADDRESS_GREYBUS, 0x03);

	return 0;
}

#endif
