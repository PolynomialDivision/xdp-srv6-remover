/* SPDX-License-Identifier: GPL-2.0 */

#include "common.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <stddef.h>
#include <stdint.h>

#define IPV6_EXT_ROUTING 43
#define IPV6_ENCAP 41 // [RFC2473]

#define ipv6_optlen(p) (((p)->hdrlen + 1) << 3)

struct ip6_addr_t {
  unsigned long long hi;
  unsigned long long lo;
};

struct ip6_srh_t {
  unsigned char nexthdr;
  unsigned char hdrlen;
  unsigned char type;
  unsigned char segments_left;
  unsigned char first_segment;
  unsigned char flags;
  unsigned short tag;

  struct ip6_addr_t segments[0];
};

struct bpf_map_def SEC("maps") prefixmap = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct cidr),
    .max_entries = MAX_CIDR,
};

struct bpf_map_def SEC("maps") segpathmap = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct cidr),
    .max_entries = MAX_SEG_LIST,
};

struct bpf_map_def SEC("maps") segleftmap = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1,
};

static int in_prefix(unsigned char ip[16])
{
    // -------- checking --------

  int inprefix = 0;
  int j;
  for (j = 0; j <= MAX_CIDR; j++) {
    __u32 key = (__u32)j;
    struct cidr *cidr = bpf_map_lookup_elem(&prefixmap, &key);
    if (!cidr)
      goto loop;
    int prefix_limit = 15 - ((128 - cidr->prefix) / 8);
    int i;
    for (i = 0; i < 16; i++) {
      __u8 net1 = ip[i];
      __u8 net2 = cidr->addr.v6.s6_addr[i];

      if (i >= prefix_limit)
        break;

      if (net1 != net2) {
        goto loop;
      }
    }
    if (i >= 16)
      goto loop;

    __u8 net1 = ip[i];
    __u8 net2 = cidr->addr.v6.s6_addr[i];
    __u8 mask = ~((1 << ((128 - cidr->prefix) % 8)) - 1);

    net1 &= mask;
    net2 &= mask;

    if (net1 != net2) {
      goto loop;
    }

    // if we reach here, some prefix is announced
    inprefix = 1;
    break;
  loop:
    continue;
  }

  if (!inprefix)
    goto out;

  return 1;

  // -------- checking done --------
out:
  return 0;
}

SEC("srv6-remover")
int xdp_srv6_func(struct xdp_md *ctx) {
  volatile struct ethhdr old_ehdr;
  volatile struct ipv6hdr oldr_ipv6hdr;
  volatile struct ipv6hdr oldr_ipv6_orig_hdr;
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

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
  if (ip6_srv6_hdr->nexthdr != IPV6_EXT_ROUTING){
    if (in_prefix(ip6_srv6_hdr->daddr.s6_addr))
    {
      // Here we have the options:
      // - xdp_drop
      // - xdp_tx (but switch ethernet header before)
      // - bpf_redirect(...)
      return XDP_DROP;
    }
    goto out;
  }
  oldr_ipv6hdr = *ip6_srv6_hdr;

  // Routing Header
  struct ip6_srh_t *ip6_hdr = (struct ip6_srh_t *)(ip6_srv6_hdr + 1);
  if (ip6_hdr + 1 > data_end)
    goto out;
  if (ip6_hdr->nexthdr != IPV6_ENCAP) // htons correct?
    goto out;

  struct ip6_addr_t *seg;
  seg = (struct ip6_addr_t *)(ip6_hdr + 1);

  if (seg + MAX_SEG_LIST > data_end)
    goto out;

  // Here we need to check the whole segment-path
  // So we need to feed the segmentpath via a map from the userspace
  // into the kernel
  for (int i = 0; i < MAX_SEG_LIST; i++) 
  {
    __u32 key = (__u32)i;
    struct cidr *cidr = bpf_map_lookup_elem(&segpathmap, &key);
    if (!cidr)
      goto out;
    
    for (int j = 0; j < 16; j++)
    {
      if(((unsigned char*)seg)[j] != cidr->addr.v6.s6_addr[j]) {
        // here we have to check if we are the last hop
        goto out;
      }
    }
  }

  // "Orig" IPv6 Header
  struct ipv6hdr *ipv6_orig_header =
      (struct ipv6hdr *)(((void *)ip6_hdr) + ipv6_optlen(ip6_hdr));
  if (ipv6_orig_header + 1 > data_end)
    goto out;
  oldr_ipv6_orig_hdr = *ipv6_orig_header;

  if (!in_prefix(ipv6_orig_header->daddr.s6_addr))
  {
    goto out;
  }

  // shrink by the size of ip6_srv6_hdr + ipv6_hdr->hdrlen*10 + ip6_hdr
  int offset = sizeof(struct ipv6hdr) + ipv6_optlen(ip6_hdr);
  if (bpf_xdp_adjust_head(ctx, offset)) {
    goto out;
  }

  data_end = (void *)(long)ctx->data_end;
  ehdr = (void *)(long)ctx->data;

  if (ehdr + 1 > data_end)
    goto out;

  *ehdr = old_ehdr;

  struct ipv6hdr *srhdr = (void *)(ehdr + 1);
  if (srhdr + 1 > data_end)
    goto out;

  *srhdr = oldr_ipv6_orig_hdr;
out:
  return XDP_PASS;
}

SEC("srv6-inline-remover")
int xdp_srv6_inline_remover(struct xdp_md *ctx) {
  volatile struct ethhdr old_ehdr;
  volatile struct ipv6hdr oldr_ipv6_orig_hdr;
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  struct ethhdr *ehdr = data;
  if (ehdr + 1 > data_end)
    goto out;
  old_ehdr = *ehdr;

  if (bpf_ntohs(ehdr->h_proto) != ETH_P_IPV6) {
    goto out;
  }

  // IPv6 Header
  struct ipv6hdr *ipv6_orig_header = (void *)(ehdr + 1);
  if (ipv6_orig_header + 1 > data_end)
    goto out;
  if (ipv6_orig_header->nexthdr != IPV6_EXT_ROUTING)
    goto out;
  oldr_ipv6_orig_hdr = *ipv6_orig_header;

  // Routing Header
  struct ip6_srh_t *ip6_rhdr = (struct ip6_srh_t *)(ipv6_orig_header + 1);
  if (ip6_rhdr + 1 > data_end)
    goto out;
  if (ip6_rhdr->nexthdr == IPV6_ENCAP) // check for ipv6 encap
    goto out;

  // the first segment is now the actual destination
  struct in6_addr *seg;
  seg = (struct in6_addr *)(ip6_rhdr + 1);

  if (seg + 1 > data_end)
    goto out;

  __builtin_memcpy((void *)oldr_ipv6_orig_hdr.daddr.s6_addr, seg, 16);
  oldr_ipv6_orig_hdr.nexthdr = ip6_rhdr->nexthdr;
  oldr_ipv6_orig_hdr.payload_len -= bpf_ntohs(ipv6_optlen(ip6_rhdr));

  // ------- check in map

  int inprefix = 0;
  int j;
  for (j = 0; j <= MAX_CIDR; j++) {
    __u32 key = (__u32)j;
    struct cidr *cidr = bpf_map_lookup_elem(&prefixmap, &key);
    if (!cidr)
      goto loop;
    int prefix_limit = 15 - ((128 - cidr->prefix) / 8);
    int i;
    for (i = 0; i < 16; i++) {
      __u8 net1 = oldr_ipv6_orig_hdr.daddr.s6_addr[i];
      __u8 net2 = cidr->addr.v6.s6_addr[i];

      if (i >= prefix_limit)
        break;

      if (net1 != net2) {
        goto loop;
      }
    }
    if (i >= 16)
      goto loop;

    __u8 net1 = oldr_ipv6_orig_hdr.daddr.s6_addr[i];
    __u8 net2 = cidr->addr.v6.s6_addr[i];
    __u8 mask = ~((1 << ((128 - cidr->prefix) % 8)) - 1);

    net1 &= mask;
    net2 &= mask;

    if (net1 != net2) {
      goto loop;
    }

    // if we reach here, some prefix is announced
    inprefix = 1;
    break;
  loop:
    continue;
  }

  if (!inprefix)
    goto out;

  // -------- checking done --------

  int offset = ipv6_optlen(ip6_rhdr);
  if (bpf_xdp_adjust_head(ctx, offset)) {
    goto out;
  }

  data_end = (void *)(long)ctx->data_end;
  ehdr = (void *)(long)ctx->data;

  if (ehdr + 1 > data_end)
    goto out;

  *ehdr = old_ehdr;

  struct ipv6hdr *srhdr = (void *)(ehdr + 1);
  if (srhdr + 1 > data_end)
    goto out;

  *srhdr = oldr_ipv6_orig_hdr;
out:
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
