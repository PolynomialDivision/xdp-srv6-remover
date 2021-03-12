## XDP-SRv6-Remover

This package contains a userspace program and the corresponding kernel xdp program to encapsulate segment routing packets. This program is based on [ubpf](https://github.com/blogic/ubpf) and uses most of the userspace xdp code.

I have written everything again in inline because I had issues with the IPQ40xx SOC using outer encapsulation.

### Usage

Load xdp to the mesh interface

    xdpload -d br-mesh_one -f /usr/xdp/srv6_kern.o -p srv6-inline-remover

Specify prefixes that should be enpacked (you can specify up to CIDR_MAX prefixes):

    xdp-srv6-remover -d br-mesh_one -p 2003::/64 -k 0