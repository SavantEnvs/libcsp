/*
 * Shared setup for the libcsp fuzz harnesses (mayhem/harnesses/fuzz_*.c).
 *
 * libcsp keeps all of its state in process globals (buffer pool, connection
 * table, port table, router FIFO), so csp_init() runs once per process. Every
 * input then:
 *   1. selects the wire format (CSP v1 / v2) and the dedup mode from its first
 *      byte (csp_conf is read on every packet, and is reset for every input);
 *   2. feeds the remaining bytes to one link-layer receive function;
 *   3. drains the router FIFO with csp_route_work() and serves whatever reached
 *      the local sockets: accepted connections are read, passed to
 *      csp_service_handler() (CMP, ping, ps, memfree, buf_free, uptime), and
 *      closed; connection-less packets are freed.
 *
 * Every input's result depends only on that input: fuzz_reset_state() runs at
 * the end of each input and closes every open connection (RDP ones included,
 * so none lingers until its 10 s timeout), clears the dedup history and resets
 * the connection allocator and empties the routing table (CMP route-set packets
 * add routes). Everything an input allocates is freed by the
 * library, by fuzz_serve() or by that reset. The library's static state is
 * reached through symbols that build.sh makes global in a copy of libcsp.a
 * (objcopy --globalize-symbol); no library code is replaced or edited.
 *
 * Hooks the library expects from the platform are defined here instead of
 * linking src/arch/posix/csp_system.c, whose csp_reboot_hook() calls reboot()
 * and is reachable with a magic word on port CSP_REBOOT.
 */
#ifndef CSP_FUZZ_COMMON_H
#define CSP_FUZZ_COMMON_H

#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <csp/csp.h>
#include <csp/csp_hooks.h>
#include <csp/csp_id.h>
#include <csp/csp_iflist.h>
#include <csp/csp_interface.h>
#include <csp/csp_rtable.h>
#include <csp/crypto/csp_hmac.h>
#include <csp/interfaces/csp_if_lo.h>
#include <csp/arch/csp_time.h>
#include "csp_conn.h"

/* src/csp_qfifo.h is internal; this one prototype is what the router uses to
 * be woken up without waiting for its FIFO timeout. */
void csp_qfifo_wake_up(void);

/* Library statics made global by build.sh: dedup ring (csp_dedup.c, 16 slots)
 * and the connection allocator's round-robin cursor (csp_conn.c). */
extern uint32_t csp_dedup_array[16];
extern uint32_t csp_dedup_timestamp[16];
extern unsigned int csp_dedup_in;
extern uint8_t csp_conn_last_given;

/* ---- platform hooks (instead of src/arch/posix/csp_system.c) ---- */
uint32_t csp_memfree_hook(void) { return 4096; }
unsigned int csp_ps_hook(csp_packet_t * packet) {
	static const char ps[] = "fuzz 1\n";
	memcpy(packet->data, ps, sizeof(ps));
	return sizeof(ps);
}
void csp_reboot_hook(void) {}
void csp_shutdown_hook(void) {}

/* CMP peek/poke is an intentional remote memory read/write primitive (the
 * default csp_cmp_memcpy is a bare memcpy to an attacker-chosen address). Make
 * it a no-op so the harness explores the CMP parser, not arbitrary pointers. */
int csp_cmp_memcpy(csp_memptr_t to, csp_const_memptr_t from, size_t size) {
	(void)to; (void)from; (void)size;
	return CSP_ERR_NONE;
}
/* CMP clock set would change the process clock used for RDP timeouts. */
int csp_clock_set_time(const csp_timestamp_t * time) {
	(void)time;
	return CSP_ERR_NONE;
}
/* Silence csp_print(). */
void csp_print_func(const char * fmt, ...) { (void)fmt; }

/* ---- a plain interface whose transmit just drops the packet ---- */
static int fuzz_nexthop(csp_iface_t * iface, uint16_t via, csp_packet_t * packet, int from_me) {
	(void)iface; (void)via; (void)from_me;
	csp_buffer_free(packet);
	return CSP_ERR_NONE;
}

static csp_socket_t g_sock_any;      /* connection-oriented, every unbound port */
static csp_socket_t g_sock_rdp;      /* RDP required */
static csp_socket_t g_sock_sec;      /* HMAC + CRC32 required */
static csp_socket_t g_sock_connless; /* connection-less */

#define FUZZ_PORT_RDP      10
#define FUZZ_PORT_SEC      11
#define FUZZ_PORT_CONNLESS 12
#define FUZZ_PORT_CALLBACK 13

/* Called by every harness from its own init, after csp_init() and before the
 * interface is added. */
static void fuzz_csp_init(void) {
	csp_conf.version = 2;
	csp_conf.dedup = CSP_DEDUP_OFF;
	csp_init();
	csp_hmac_set_key("fuzzkey", 7);

	g_sock_rdp.opts = CSP_SO_RDPREQ;
	csp_bind(&g_sock_rdp, FUZZ_PORT_RDP);
	csp_listen(&g_sock_rdp, 4);

	g_sock_sec.opts = CSP_SO_HMACREQ | CSP_SO_CRC32REQ;
	csp_bind(&g_sock_sec, FUZZ_PORT_SEC);
	csp_listen(&g_sock_sec, 4);

	g_sock_connless.opts = CSP_SO_CONN_LESS;
	csp_bind(&g_sock_connless, FUZZ_PORT_CONNLESS);

	csp_bind_callback(csp_service_handler, FUZZ_PORT_CALLBACK);

	csp_bind(&g_sock_any, CSP_ANY);
	csp_listen(&g_sock_any, 8);
}

/* First input byte: bit 0 = CSP version (1/2), bits 1-2 = dedup mode. */
static void fuzz_select_conf(uint8_t opt) {
	csp_conf.version = (opt & 1) ? 1 : 2;
	csp_conf.dedup = (opt >> 1) & 3;
	/* csp_init() sizes the loopback netmask for the version it started with */
	csp_if_lo.netmask = csp_id_get_host_bits();
}

/* Optional per-connection consumer (the SFP harness reassembles here). */
typedef void (*fuzz_conn_fn)(csp_conn_t * conn);
static fuzz_conn_fn g_conn_fn;

static void fuzz_serve_socket(csp_socket_t * sock) {
	csp_conn_t * conn;
	while ((conn = csp_accept(sock, 0)) != NULL) {
		if (g_conn_fn) {
			g_conn_fn(conn);
		}
		csp_packet_t * packet;
		while ((packet = csp_read(conn, 0)) != NULL) {
			csp_service_handler(packet);
		}
		csp_close(conn);
	}
}

static void fuzz_serve(void) {
	fuzz_serve_socket(&g_sock_any);
	fuzz_serve_socket(&g_sock_rdp);
	fuzz_serve_socket(&g_sock_sec);
	csp_packet_t * packet;
	while ((packet = csp_recvfrom(&g_sock_connless, 0)) != NULL) {
		csp_buffer_free(packet);
	}
}

/* Route everything queued so far. csp_qfifo_wake_up() enqueues a NULL marker
 * after the queued packets; csp_route_work() returns CSP_ERR_TIMEDOUT on it
 * without waiting. Replies the services send to a local address go through the
 * FIFO again, hence the second round. */
static void fuzz_drain(void) {
	for (int round = 0; round < 2; round++) {
		csp_qfifo_wake_up();
		int guard = 0;
		while (csp_route_work() == CSP_ERR_NONE && guard++ < 64) {
		}
		fuzz_serve();
	}
}

/* Close everything still open once the input has been routed and served: RDP
 * connections waiting for more segments or an ACK, and any other connection a
 * packet opened. Closing an RDP connection can send an RST, hence the rounds. */
static void fuzz_reset_state(void) {
	for (int round = 0; round < 4; round++) {
		size_t n;
		const csp_conn_t * pool = csp_conn_get_array(&n);
		int open = 0;
		for (size_t i = 0; i < n; i++) {
			if (pool[i].state == CONN_OPEN) {
				open++;
				csp_conn_close((csp_conn_t *)&pool[i], CSP_RDP_CLOSED_BY_ALL);
			}
		}
		if (open == 0) {
			break;
		}
		fuzz_drain();
	}
	memset(csp_dedup_array, 0, sizeof(csp_dedup_array));
	memset(csp_dedup_timestamp, 0, sizeof(csp_dedup_timestamp));
	csp_dedup_in = 0;
	csp_conn_last_given = 0;
	/* CMP route-set packets write the routing table; csp_init() leaves it empty. */
	csp_rtable_clear();
}

#endif
