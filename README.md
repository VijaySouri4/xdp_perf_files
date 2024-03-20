## Dependencies [Ubuntu]

### Packages

`sudo apt install clang llvm libelf-dev libpcap-dev build-essential libc6-dev-i386`

perf utility for ubuntu

`sudo apt install linux-tools-$(uname -r)` 

### install Libbpf

The apt sources install old version which causes perf incompatibility
~~`apt install libbpf-dev`~~

Please use the official libbpf repository. 

`git clone https://github.com/libbpf/libbpf`  
`cd libbpf`  
`cd src`  
`make`
`sudo make install`



### Kernel Headers

`sudo apt install linux-headers-$(uname -r)`

### Tools

`sudo apt install linux-tools-common linux-tools-generic`

`sudo apt install tcpdump`

#### Source: https://github.com/xdp-project/xdp-tutorial/blob/master/setup_dependencies.org
