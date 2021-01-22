/* SPDX-License-Identifier: GPL-2.0 */

#include <arpa/inet.h>

#include "uxdp.h"
#include "common.h"

static struct cidr *cidr_parse6(const char *s) {
  char *p = NULL, *r;
  struct cidr *addr = malloc(sizeof(struct cidr));

  if (!addr || (strlen(s) >= sizeof(addr->buf.v6)))
    goto err;

  snprintf(addr->buf.v6, sizeof(addr->buf.v6), "%s", s);

  if ((p = strchr(addr->buf.v6, '/')) != NULL) {
    *p++ = 0;

    addr->prefix = strtoul(p, &r, 10);

    if ((p == r) || (*r != 0) || (addr->prefix > 128))
      goto err;
  } else {
    addr->prefix = 128;
  }

  if (p == addr->buf.v6 + 1)
    memset(&addr->addr.v6, 0, sizeof(addr->addr.v6));
  else if (inet_pton(AF_INET6, addr->buf.v6, &addr->addr.v6) != 1)
    goto err;

  return addr;

err:
  if (addr)
    free(addr);

  return NULL;
}

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

	struct cidr *cidr = cidr_parse6("::/0");

	int key = 0;
	if (bpf_map_update_elem(xdp_map.map_fd, &key, &cidr, 0) < 0) {
		fprintf(stderr,
			"WARN: Failed to update bpf map file: err(%d):%s\n",
			errno, strerror(errno));
		return -1;
	}

	return 0;
}
