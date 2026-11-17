/*
 * ZeroMQ hub receive path: csp_zmqhub_rx() is what the interface's receive
 * thread calls in a loop. It receives one ZMQ message with zmq_msg_recv(),
 * rejects multipart messages (draining the remaining parts), checks the frame
 * length against the header size and the maximum raw frame length, strips the
 * CSPv1 destination-address byte, extracts the CSP id and copies the frame into
 * a packet that the router then delivers (csp_qfifo_write -> csp_route_work).
 * The library's own thread is not needed: csp_zmqhub_rx() is a synchronous
 * public entry point, so the harness calls it itself on a socket of its own.
 * The socket is one end of an in-process ZMQ_PAIR (the code only uses
 * zmq_msg_recv/zmq_msg_more, not the socket type; the real SUB socket would
 * need a proxy and a subscription handshake).
 * Input: [opt] then records of [ctl][length: 2 bytes LE][payload]; each record
 * is one ZMQ message part, ctl bit 0 = more parts follow (ZMQ_SNDMORE).
 */
#include "fuzz_common.h"
#include <zmq.h>
#include "interfaces/csp_if_zmqhub_internal.h"

static csp_iface_t fuzz_iface = {
	.name = "ZMQ", .addr = 1, .netmask = 4, .is_default = 1,
	.nexthop = fuzz_nexthop,
};

static void * g_ctx;
static void * g_tx;
static void * g_rx;

int LLVMFuzzerInitialize(int * argc, char *** argv) {
	(void)argc; (void)argv;
	fuzz_csp_init();
	csp_iflist_add(&fuzz_iface);

	g_ctx = zmq_ctx_new();
	/* inproc needs no I/O thread */
	zmq_ctx_set(g_ctx, ZMQ_IO_THREADS, 0);
	g_rx = zmq_socket(g_ctx, ZMQ_PAIR);
	g_tx = zmq_socket(g_ctx, ZMQ_PAIR);
	/* same cap csp_zmqhub_set_max_msg_size() puts on the library's subscriber */
	const int64_t max_msg_size = UINT16_MAX;
	zmq_setsockopt(g_rx, ZMQ_MAXMSGSIZE, &max_msg_size, sizeof(max_msg_size));
	/* unlimited queue: zmq_send() never blocks or drops */
	const int hwm = 0;
	zmq_setsockopt(g_rx, ZMQ_RCVHWM, &hwm, sizeof(hwm));
	zmq_setsockopt(g_tx, ZMQ_SNDHWM, &hwm, sizeof(hwm));
	if (zmq_bind(g_rx, "inproc://csp-fuzz") != 0 || zmq_connect(g_tx, "inproc://csp-fuzz") != 0) {
		abort();
	}
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
	if (size < 1) {
		return -1;
	}
	fuzz_select_conf(data[0]);
	data++; size--;
	while (size >= 3) {
		int more = data[0] & 1;
		size_t len = (size_t)data[1] | ((size_t)data[2] << 8);
		data += 3; size -= 3;
		if (len > size) {
			len = size;
		}
		/* ZMQ delivers a multipart message only when its last part is sent, so
		 * the last record of the input always ends the message. */
		if (size - len < 3) {
			more = 0;
		}
		if (zmq_send(g_tx, data, len, more ? ZMQ_SNDMORE : 0) < 0) {
			abort(); /* harness invariant: an inproc send with no HWM cannot fail */
		}
		data += len; size -= len;
	}
	/* Receive every complete message that was sent. ZMQ_EVENTS is a
	 * non-blocking readiness check, so csp_zmqhub_rx() never waits. */
	for (;;) {
		int events = 0;
		size_t events_size = sizeof(events);
		if (zmq_getsockopt(g_rx, ZMQ_EVENTS, &events, &events_size) != 0 || !(events & ZMQ_POLLIN)) {
			break;
		}
		csp_zmqhub_rx(g_rx, &fuzz_iface);
		fuzz_drain();
	}
	fuzz_reset_state();
	return 0;
}
