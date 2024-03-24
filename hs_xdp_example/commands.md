For linking the xdp kern:

sudo ip link set dev wlp170s0 xdpgeneric obj hs_kern.o sec xdp

sudo bpftool prog list

For linking the xdp kern:

sudo ip link set dev wlp170s0 xdpgeneric obj hs_kern.o sec xdp

For unlinking the xdp kern:

sudo ip link set dev wlp170s0 xdpgeneric off

sudo bpftool prog list

compile kern -->

clang-14 -g -O2 -target bpf -D\_\_TARGET_ARCH_x86 -I /root/libbpf/include/uapi -I /usr/local/bpf/include -I/usr/local/include/hs -idirafter /usr/lib/llvm-14/lib/clang/14.0.0/include -idirafter /usr/local/include -idirafter /usr/include/x86_64-linux-gnu -idirafter /usr/include -c hs_kern.c

compile user -->

gcc -g -O2 -D\_\_TARGET_ARCH_x86 -I /usr/local/bpf/include -I/usr/local/include/hs -idirafter /usr/lib/llvm-14/lib/clang/14.0.0/include -idirafter /usr/local/include -idirafter /usr/include/x86_64-linux-gnu -idirafter /usr/include -o hs_user hs_user.c -L /usr/local/bpf/lib64 -lbpf -lelf -lz -L/usr/local/lib -lhs -lm -lstdc++

LIBBPF

LD_LIBRARY_PATH=/users/vijay4
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH

## IMP for cloudlab execs

manually setup env for shared library for user space program:
example
`sudo LD_LIBRARY_PATH=/users/vijay4/libbpf/src:/usr/lib64 ./hs_multi_pat_user`

## For debugging the traffic gen

`sudo bpftool map list`
`sudo bpftool map event_pipe id 1`
`sudo tcpdump -i enp3s0f0`