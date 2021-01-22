/* SPDX-License-Identifier: GPL-2.0 */

#include "uxdp.h"
#include "common.h"

int
main(int argc, char **argv)
{
	struct xdp_map xdp_map = {
		.prog = "xdp_srv6_func",
		.map = "prefix_map",
		.map_want = {
			.key_size = sizeof(__u32),
			.value_size = sizeof(struct cidr),
			.max_entries = 1,
		},
	};
	int ch;
	
	while ((ch = getopt(argc, argv, "d:f:p:")) != -1) {
		switch (ch) {
		case 'd':
			xdp_map.net = optarg;
			break;
		default:
			fprintf(stderr, "Invalid argument\n");
			exit(-1);
		}
	}
	if (!xdp_map.net) {
		fprintf(stderr, "invalid arguments\n");
		return -1;
	}

	if (map_lookup(&xdp_map)) {
		fprintf(stderr, "failed to xdp_map map\n");
		return -1;
	}

	return 0;
}
