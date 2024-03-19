For linking the xdp kern:

sudo ip link set dev wlp170s0 xdpgeneric obj hs_kern.o sec xdp

sudo bpftool prog list