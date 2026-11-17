/*
 * CAN link layer: csp_can_rx() reassembles CFP fragments (CFP1 for CSP v1,
 * CFP2 for CSP v2) into CSP packets, which the router delivers to the local
 * sockets and services.
 * Input: [opt] then records of [can id: 4 bytes LE][dlc][dlc data bytes].
 * Drivers hand csp_can_rx() the data field of a classic CAN frame
 * (struct can_frame.data in can_socketcan.c: always 8 bytes, dlc <= 8), so
 * dlc is taken modulo 9 and the frame is copied into an 8-byte heap buffer,
 * zero-padded after dlc. Reads past those 8 bytes are reported by ASan.
 */
#include "fuzz_common.h"
#include <csp/interfaces/csp_if_can.h>

static int can_tx(void * driver_data, uint32_t id, const uint8_t * data, uint8_t dlc, const csp_packet_t * packet) {
	(void)driver_data; (void)id; (void)data; (void)dlc; (void)packet;
	return CSP_ERR_NONE;
}

static csp_can_interface_data_t can_data = {.tx_func = can_tx};
static csp_iface_t can_iface = {
	.name = "CAN", .addr = 1, .netmask = 4, .is_default = 1,
	.interface_data = &can_data,
};

int LLVMFuzzerInitialize(int * argc, char *** argv) {
	(void)argc; (void)argv;
	fuzz_csp_init();
	csp_can_add_interface(&can_iface);
	return 0;
}

static void can_reset_pbufs(void) {
	csp_packet_t * p = can_data.pbufs;
	while (p) {
		csp_packet_t * next = p->next;
		csp_buffer_free(p);
		p = next;
	}
	can_data.pbufs = NULL;
}

int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
	if (size < 1) {
		return -1;
	}
	fuzz_select_conf(data[0]);
	data++; size--;
	while (size >= 5) {
		uint32_t id = (uint32_t)data[0] | ((uint32_t)data[1] << 8) | ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
		uint8_t dlc = data[4] % 9;
		data += 5; size -= 5;
		if (dlc > size) {
			dlc = (uint8_t)size;
		}
		uint8_t * frame = calloc(1, 8);
		memcpy(frame, data, dlc);
		csp_can_rx(&can_iface, id, frame, dlc, 0, NULL);
		free(frame);
		data += dlc; size -= dlc;
		fuzz_drain();
	}
	fuzz_drain();
	can_reset_pbufs();
	fuzz_reset_state();
	return 0;
}
