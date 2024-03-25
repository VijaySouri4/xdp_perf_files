Attach ring buffer kernel prog to interface
`sudo ip link set dev enp3s0f0 xdpgeneric obj hs_kern.o sec xdp`

`sudo ip link set dev enp3s0f0 xdpgeneric off`

`sudo LD_LIBRARY_PATH=/users/vijay4/libbpf/src:/usr/lib64 ./hs_user`