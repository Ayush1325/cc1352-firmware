#include "apbridge.h"
#include "operations.h"
#include <zephyr/kernel.h>

static void apbridge_entry(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	while (1) {
		/* Go through all connections */
		gb_connection_process_all();
		k_yield();
	}
}

K_THREAD_DEFINE(apbridge, 2048, apbridge_entry, NULL, NULL, NULL, 6, 0, 0);

void apbridge_start() {
	k_thread_resume(apbridge);
}

void apbridge_stop() {
	k_thread_suspend(apbridge);
}
