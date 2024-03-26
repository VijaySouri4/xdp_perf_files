Look at interfaces with xdp hook attached
`sudo ip link show`
Attach ring buffer kernel prog to interface
`sudo ip link set dev enp3s0f0 xdpgeneric obj hs_kern.o sec xdp`
Remove ring buffer kernel prog from interface
`sudo ip link set dev enp3s0f0 xdpgeneric off`
Run the use space program
`sudo LD_LIBRARY_PATH=/users/vijay4/libbpf/src:/usr/lib64 ./hs_user`