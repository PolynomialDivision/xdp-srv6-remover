/* SPDX-License-Identifier: GPL-2.0 */

#include "common.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stddef.h>

#define IPV6_EXT_ROUTING   43
#define IPV6_ENCAP 41           // [RFC2473]

struct bpf_map_def SEC("maps") prefix_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct cidr),
	.max_entries = 1,
};

static inline int check(struct cidr *a, struct in6_addr ip) {
	/* copied from owipcalc.c */
	
	uint8_t i = (128 - a->prefix) / 8;
	uint8_t m = ~((1 << ((128 - a->prefix) % 8)) - 1);
	uint8_t net1 = a->v6.s6_addr[15-i] & m;
	uint8_t net2 = ip.s6_addr[15-i] & m;

	if ((net1 == net2) && ((i == 15) || !memcmp(&a->v6.s6_addr, &ip.s6_addr, 15-i)))
	{
		return 1;
	}

	return 0;
}

SEC("srv6-remover")
int xdp_srv6_func(struct xdp_md *ctx)
{
	volatile struct ethhdr old_ehdr;
	volatile struct ipv6hdr oldr_ipv6hdr;
	volatile struct ipv6hdr oldr_ipv6_orig_hdr;
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

	struct ethhdr *ehdr = data;
	if (ehdr + 1 > data_end) // bounds checking
		goto out;
	old_ehdr = *ehdr;

	if (bpf_ntohs(ehdr->h_proto) != ETH_P_IPV6) {
		goto out;
	}

	// IPv6 Header
	struct ipv6hdr *ip6_srv6_hdr = (void *)(ehdr + 1);
	if (ip6_srv6_hdr + 1 > data_end)
		goto out;
	if(ip6_srv6_hdr->nexthdr != IPV6_EXT_ROUTING) 
        goto out;
	oldr_ipv6hdr = *ip6_srv6_hdr;

	// Routing Header
	struct ipv6_rt_hdr* ip6_hdr = (struct ipv6_rt_hdr*) (ip6_srv6_hdr+1);
	if (ip6_hdr + 1 > data_end)
		goto out;
	if(ip6_hdr->nexthdr != IPV6_ENCAP) //htons correct?
        goto out;

	// "Orig" IPv6 Header
	struct ipv6hdr* ipv6_orig_header = (struct ipv6hdr*) (((void *)ip6_hdr) + ipv6_optlen(ip6_hdr));
	if (ipv6_orig_header + 1 > data_end)
		goto out;
	oldr_ipv6_orig_hdr = *ipv6_orig_header;

	// -------- checking --------

	__u32 key = 0;
	struct cidr *cidr = bpf_map_lookup_elem(&prefix_map, &key);
	if (!cidr)
		goto out;
	
	if(!check(cidr, ipv6_orig_header->daddr);)
		goto out;

	// -------- checking done --------

	// shrink by the size of ip6_srv6_hdr + ipv6_hdr->hdrlen*10 + ip6_hdr
	int offset = sizeof(struct ipv6hdr) +  ipv6_optlen(ip6_hdr);
	if (bpf_xdp_adjust_head(ctx, offset))
	{
		goto out;
	}
	
	data_end = (void *)(long)ctx->data_end;
	ehdr = (void *)(long)ctx->data;

	if (ehdr + 1 > data_end)
		goto out;
	
	*ehdr = old_ehdr;

	struct ipv6hdr* srhdr = (void *)(ehdr + 1);
	if (srhdr + 1 > data_end)
		goto out;
	
	*srhdr = oldr_ipv6_orig_hdr;
out:
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
