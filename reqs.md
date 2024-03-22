## Dependencies for Hyperscan

1. cmake: sudo apt -y install cmake
2. Ragel: sudo apt-get install -y ragel
3. Boost: sudo apt-get install libboost-all-dev
4. pcap: sudo apt-get install libpcap-dev
5. Ninja: sudo apt install ninja-

## Install Hyperscan

1. git clone https://github.com/intel/hyperscan
2. cd hyperscan
3. mkdir build
4. cd build
5. cmake -G Ninja ../
6. ninja
7. ninja install
8. bin/unit-hyperscan [checks]