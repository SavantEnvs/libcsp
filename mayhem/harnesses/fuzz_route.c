/*
 * Raw CSP packets into the router: what csp_if_udp / csp_if_i2c / csp_if_tun
 * do after receiving a frame. csp_id_strip() parses the CSP v1/v2 header, then
 * csp_route_work() runs dedup, forwarding, the security checks (CRC32, HMAC),
 * the RDP state machine (SYN/ACK/EACK/RST) and delivery to sockets, bound
 * callbacks and the services.
 * Input: [opt] then records of [frame length][frame: CSP header + payload].
 * A frame longer than the packet buffer is cut where csp_if_udp's recvfrom()
 * would cut it (sizeof(packet->data) + header size).
 */
#include "fuzz_common.h"

static csp_iface_t fuzz_iface = {
	.name = "FUZZ", .addr = 1, .netmask = 4, .is_default = 1,
	.nexthop = fuzz_nexthop,
};

int LLVMFuzzerInitialize(int * argc, char *** argv) {
	(void)argc; (void)argv;
	fuzz_csp_init();
	csp_iflist_add(&fuzz_iface);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
	if (size < 1) {
		return -1;
	}
	fuzz_select_conf(data[0]);
	data++; size--;
	while (size >= 1) {
		size_t len = data[0];
		data++; size--;
		if (len > size) {
			len = size;
		}
		csp_packet_t * packet = csp_buffer_get(0);
		if (packet == NULL) {
			break;
		}
		int header_size = csp_id_setup_rx(packet);
		size_t max = sizeof(packet->data) + (size_t)header_size;
		size_t n = len < max ? len : max;
		memcpy(packet->frame_begin, data, n);
		packet->frame_length = (uint16_t)n;
		if (csp_id_strip(packet) != 0) {
			csp_buffer_free(packet);
		} else {
			csp_qfifo_write(packet, &fuzz_iface, NULL);
		}
		data += len; size -= len;
		fuzz_drain();
	}
	fuzz_drain();
	fuzz_reset_state();
	return 0;
}
