#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/bpf.h>
#include <linux/in.h>

#include <inttypes.h>

struct cidr {
	uint32_t prefix;
	struct in6_addr v6;
};