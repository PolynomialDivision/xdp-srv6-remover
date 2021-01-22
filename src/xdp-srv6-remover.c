/* SPDX-License-Identifier: GPL-2.0 */

#include "uxdp.h"

int
main(int argc, char **argv)
{
	/*struct xdp_map xdp_map = {
		.prog = "xdp_srv6_func",
		.map = "ip_stats_map",
		.map_want = {
			.key_size = sizeof(__u32),
			.value_size = sizeof(struct ip_stats_rec),
			.max_entries = XDP_ACTION_MAX,
		},
	};
	int interval = 2;
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

	FILE *fp;
	fp = fopen("/tmp/ip-stats.csv", "w");
	if(fp == NULL)
		printf("Error!");

	fprintf(fp, "perid,ipv4_rx_packets,pps_ipv4,ipv4_rx_bytes,bytess_ipv4,ipv6_rx_packets,pps_ipv6,ipv6_rx_bytes,bytess_ipv6\n");
	fclose(fp);

	stats_poll(xdp_map.map_fd, xdp_map.map_info.type, interval);*/
	return 0;
}
