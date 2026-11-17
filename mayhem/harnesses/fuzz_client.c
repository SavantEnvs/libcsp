/*
 * Client side: the reply parsers of csp_transaction_w_opts() /
 * csp_transaction_persistent() (reply length vs. caller buffer), csp_ping,
 * csp_ps, csp_get_memfree, csp_get_buf_free, csp_get_uptime and the CMP
 * client requests (ident, if_stats, clock, route_set, peek) with replies the
 * remote node controls.
 * Input: [opt][request selector] then reply records of [flags][len][payload].
 * The interface's transmit function consumes one record per packet the
 * client sends and answers with it (source/destination and ports swapped, as
 * the remote node would), routing the reply synchronously so the client's
 * csp_read() finds it without a router thread.
 */
#include "fuzz_common.h"
#include <csp/csp_cmp.h>

static const uint8_t * g_rest;
static size_t g_rest_size;
static int g_in_tx;

static int client_nexthop(csp_iface_t * iface, uint16_t via, csp_packet_t * packet, int from_me) {
	(void)via; (void)from_me;
	csp_id_t out = packet->id;
	csp_buffer_free(packet);
	if (g_in_tx || g_rest_size < 2) {
		return CSP_ERR_NONE;
	}
	uint8_t flags = g_rest[0];
	size_t len = g_rest[1];
	g_rest += 2; g_rest_size -= 2;
	if (len > g_rest_size) {
		len = g_rest_size;
	}
	csp_packet_t * reply = csp_buffer_get(0);
	if (reply != NULL) {
		size_t n = len < sizeof(reply->data) ? len : sizeof(reply->data);
		memcpy(reply->data, g_rest, n);
		reply->length = (uint16_t)n;
		reply->id.pri = out.pri;
		reply->id.src = out.dst;
		reply->id.dst = out.src;
		reply->id.sport = out.dport;
		reply->id.dport = out.sport;
		reply->id.flags = flags;
		csp_qfifo_write(reply, iface, NULL);
		g_in_tx = 1;
		csp_qfifo_wake_up();
		int guard = 0;
		while (csp_route_work() == CSP_ERR_NONE && guard++ < 16) {
		}
		g_in_tx = 0;
	}
	g_rest += len; g_rest_size -= len;
	return CSP_ERR_NONE;
}

static csp_iface_t client_iface = {
	.name = "FUZZ", .addr = 1, .netmask = 4, .is_default = 1,
	.nexthop = client_nexthop,
};

int LLVMFuzzerInitialize(int * argc, char *** argv) {
	(void)argc; (void)argv;
	fuzz_csp_init();
	csp_iflist_add(&client_iface);
	return 0;
}

#define NODE 9

int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
	if (size < 2) {
		return -1;
	}
	fuzz_select_conf(data[0]);
	uint8_t sel = data[1];
	g_rest = data + 2;
	g_rest_size = size - 2;

	uint8_t * in = malloc(CSP_BUFFER_SIZE);
	uint32_t value;
	switch (sel % 12) {
		case 0: { /* reply of unknown length: caller buffer must hold a full packet */
			static const uint8_t req[] = {1, 2, 3, 4};
			csp_transaction_w_opts(CSP_PRIO_NORM, NODE, 20, 0, req, sizeof(req), in, -1, CSP_O_NONE);
			break;
		}
		case 1: { /* reply of a fixed, small length */
			uint8_t * small = malloc(8);
			csp_transaction_w_opts(CSP_PRIO_NORM, NODE, 20, 0, "q", 1, small, 8, CSP_O_NONE);
			free(small);
			break;
		}
		case 2: { /* persistent connection, two transactions */
			csp_conn_t * conn = csp_connect(CSP_PRIO_NORM, NODE, 21, 0, CSP_O_NONE);
			if (conn) {
				csp_transaction_persistent(conn, 0, "a", 1, in, -1);
				uint8_t * small = malloc(4);
				csp_transaction_persistent(conn, 0, "b", 1, small, 4);
				free(small);
				csp_close(conn);
			}
			break;
		}
		case 3: csp_ping(NODE, 0, 16, CSP_O_NONE); break;
		case 4: csp_ps(NODE, 0); break;
		case 5: csp_get_memfree(NODE, 0, &value); break;
		case 6: csp_get_buf_free(NODE, 0, &value); break;
		case 7: csp_get_uptime(NODE, 0, &value); break;
		case 8: {
			struct csp_cmp_message msg;
			memset(&msg, 0, sizeof(msg));
			csp_cmp_ident(NODE, 0, &msg);
			break;
		}
		case 9: {
			struct csp_cmp_message msg;
			memset(&msg, 0, sizeof(msg));
			strcpy(msg.if_stats.interface, "LOOP");
			csp_cmp_if_stats(NODE, 0, &msg);
			break;
		}
		case 10: {
			struct csp_cmp_message msg;
			memset(&msg, 0, sizeof(msg));
			csp_cmp_clock(NODE, 0, &msg);
			break;
		}
		default: {
			struct csp_cmp_message msg;
			memset(&msg, 0, sizeof(msg));
			msg.peek.addr = 0;
			msg.peek.len = 16;
			csp_cmp_peek(NODE, 0, &msg);
			break;
		}
	}
	free(in);
	fuzz_drain();
	fuzz_reset_state();
	return 0;
}
