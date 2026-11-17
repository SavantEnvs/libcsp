/*
 * KISS (serial) link layer: csp_kiss_rx() deframes/unescapes the byte stream,
 * checks the optional CRC32, strips the CSP header and queues the packet; the
 * router then delivers it to the local sockets and services.
 * Input: [opt][serial bytes...] (opt: see fuzz_select_conf()). The serial
 * bytes are fed in 64-byte chunks, like a UART driver delivers them.
 */
#include "fuzz_common.h"
#include <csp/interfaces/csp_if_kiss.h>

void csp_usart_lock(void * driver_data) { (void)driver_data; }
void csp_usart_unlock(void * driver_data) { (void)driver_data; }

static int kiss_tx(void * driver_data, const uint8_t * data, size_t len) {
	(void)driver_data; (void)data; (void)len;
	return CSP_ERR_NONE;
}

static csp_kiss_interface_data_t kiss_data = {.tx_func = kiss_tx};
static csp_iface_t kiss_iface = {
	.name = "KISS", .addr = 1, .netmask = 4, .is_default = 1,
	.interface_data = &kiss_data,
};

int LLVMFuzzerInitialize(int * argc, char *** argv) {
	(void)argc; (void)argv;
	fuzz_csp_init();
	csp_kiss_add_interface(&kiss_iface);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
	if (size < 1) {
		return -1;
	}
	fuzz_select_conf(data[0]);
	data++; size--;
	/* every input starts on a fresh line */
	kiss_data.rx_mode = KISS_MODE_NOT_STARTED;
	kiss_data.rx_length = 0;
	kiss_data.rx_first = false;
	while (size > 0) {
		size_t n = size < 64 ? size : 64;
		uint8_t * chunk = malloc(n);
		memcpy(chunk, data, n);
		csp_kiss_rx(&kiss_iface, chunk, n, NULL);
		free(chunk);
		fuzz_drain();
		data += n; size -= n;
	}
	fuzz_drain();
	fuzz_reset_state();
	return 0;
}
