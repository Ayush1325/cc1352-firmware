#ifndef HDLC_H
#define HDLC_H

#include "operations.h"
#include <stddef.h>
#include <stdint.h>
#include <zephyr/device.h>

#define ADDRESS_GREYBUS 0x01
#define ADDRESS_DBG 0x02
#define ADDRESS_MCUMGR 0x03

#define UART_DEVICE_NODE DT_CHOSEN(zephyr_shell_uart)
static const struct device *const uart_dev = DEVICE_DT_GET(UART_DEVICE_NODE);

typedef void (*greybus_message_callback)(struct gb_message *);

struct hdlc_block {
  void *fifo_reserved;
  uint8_t address;
  uint8_t control;
  uint8_t length;
  uint8_t buffer[];
};

/*
 * Initialize internal HDLC stuff
 *
 * @return 0 if successful. Negative in case of error.
 */
int hdlc_init();

/*
 * Submit an HDLC block to be transmitted. This is async
 *
 * @param buffer
 * @param buffer_length
 * @param address
 * @param control
 *
 * @return block size (> 0) if successful. Negative in case of error
 */
int hdlc_block_submit(uint8_t *, size_t, uint8_t, uint8_t);

/*
 * Submit an HDLC Block syncronously
 *
 * @param buffer
 * @param buffer_length
 * @param address
 * @param control
 *
 * @return block size (> 0) if successful. Negative in case of error
 */
int hdlc_block_send_sync(const uint8_t *, size_t, uint8_t, uint8_t);

/*
 * Read from UART. Mostly called by RX interrupt
 *
 * @return number of bytes read. Negative in case of error
 */
int hdlc_rx_submit();

#endif
