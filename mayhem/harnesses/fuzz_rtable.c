/*
 * Routing-table text parser: csp_rtable_check() and csp_rtable_load() parse
 * "<addr>[/mask] <ifname> [via], ..." with strtok/sscanf and install routes
 * through csp_rtable_set(); csp_rtable_save() prints the table back and
 * csp_rtable_find_route() looks routes up. The same text arrives remotely
 * through CMP route_set.
 * Input: the routing-table string (NUL-terminated copy).
 */
#include "fuzz_common.h"
#include <csp/csp_rtable.h>

static csp_iface_t if_a = {.name = "LOOPX", .addr = 1, .netmask = 4, .nexthop = fuzz_nexthop};
static csp_iface_t if_b = {.name = "KISS", .addr = 2, .netmask = 4, .nexthop = fuzz_nexthop};
static csp_iface_t if_c = {.name = "CAN", .addr = 3, .netmask = 4, .nexthop = fuzz_nexthop};

int LLVMFuzzerInitialize(int * argc, char *** argv) {
	(void)argc; (void)argv;
	fuzz_csp_init();
	csp_iflist_add(&if_a);
	csp_iflist_add(&if_b);
	csp_iflist_add(&if_c);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
	char * text = malloc(size + 1);
	memcpy(text, data, size);
	text[size] = '\0';

	csp_rtable_clear();
	if (csp_rtable_check(text) > 0) {
		csp_rtable_load(text);
		char out[128];
		csp_rtable_save(out, sizeof(out));
		for (uint16_t a = 0; a < 64; a++) {
			(void)csp_rtable_find_route(a * 257);
		}
	}
	csp_rtable_clear();
	free(text);
	return 0;
}
