/*
 * Ethernet link layer: csp_eth_rx() unpacks the CSP ethernet header
 * (packet id, source, segment size, packet length), reassembles segments via
 * csp_if_eth_pbuf.c, learns the ARP entry, strips the CSP header, and the
 * router delivers the packet to the local sockets and services.
 * Input: [opt] then records of [frame length: 2 bytes LE][frame bytes]. Each
 * frame is copied to an exact-size heap buffer and passed with that length,
 * like eth_linux.c passes recvfrom()'s length. An AF_PACKET socket always
 * delivers at least the 14-byte Ethernet MAC header (csp_eth_rx() reads
 * ether_type before it checks the length), so the buffer is never smaller
 * than 14 bytes (zero-padded); the length passed is the real one.
 */
#include "fuzz_common.h"
#include <csp/interfaces/csp_if_eth.h>

static uint8_t eth_tx_buf[2048];

static int eth_tx(void * driver_data, csp_eth_header_t * eth_frame) {
	(void)driver_data; (void)eth_frame;
	return CSP_ERR_NONE;
}

static csp_eth_interface_data_t eth_data = {
	.tx_func = eth_tx,
	.tx_mtu = 1200,
	.tx_buf = (csp_eth_header_t *)eth_tx_buf,
	.if_mac = {0x02, 0, 0, 0, 0, 1},
};

int LLVMFuzzerInitialize(int * argc, char *** argv) {
	(void)argc; (void)argv;
	fuzz_csp_init();
	eth_data.iface.name = "ETH";
	eth_data.iface.addr = 1;
	eth_data.iface.netmask = 4;
	eth_data.iface.is_default = 1;
	eth_data.iface.nexthop = csp_eth_tx;
	eth_data.iface.interface_data = &eth_data;
	csp_iflist_add(&eth_data.iface);
	return 0;
}

/* csp_if_eth.c statics (ARP table, 10 slots), made global by build.sh. */
extern size_t arp_used;
extern void * arp_list;

static void eth_reset_pbufs(void) {
	csp_packet_t * p = eth_data.pbufs;
	while (p) {
		csp_packet_t * next = p->next;
		csp_buffer_free(p);
		p = next;
	}
	eth_data.pbufs = NULL;
	arp_used = 0;
	arp_list = NULL;
}

int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
	if (size < 1) {
		return -1;
	}
	fuzz_select_conf(data[0]);
	eth_data.promisc = (data[0] >> 3) & 1;
	data++; size--;
	while (size >= 2) {
		size_t len = (size_t)data[0] | ((size_t)data[1] << 8);
		data += 2; size -= 2;
		if (len > size) {
			len = size;
		}
		uint8_t * frame = calloc(1, len > 14 ? len : 14);
		memcpy(frame, data, len);
		csp_eth_rx(&eth_data.iface, (csp_eth_header_t *)frame, (uint32_t)len, NULL);
		free(frame);
		data += len; size -= len;
		fuzz_drain();
	}
	fuzz_drain();
	eth_reset_pbufs();
	fuzz_reset_state();
	return 0;
}
