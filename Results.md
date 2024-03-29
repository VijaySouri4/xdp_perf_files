## Sanity Check [Times for just hyper scan exec]

#### Perf + HS (with printable char check):

hs_multi_pat_user_new
Average time per loop: 0.005030 seconds
Maximum time taken in a single loop: 0.006021 seconds
Total time taken in hyperscan: 5.030049 seconds

Checked against payload: hello!Average time per loop: 0.005151 seconds
Maximum time taken in a single loop: 0.011696 seconds
Total time taken in hyperscan: 5.150556 seconds

#### HS:

Starting scan for hello!:Average time per loop: 0.002212 seconds
Maximum time taken in a single loop: 0.002454 seconds
Total time taken in the loop: 2.212273 seconds

#### perf + HS (without printable char check)

Total Packets received: 1000 
Average time per loop: 0.005537 seconds
Maximum time taken in a single loop: 0.005984 seconds
Total time taken in hyperscan: 5.537390 seconds

## HS with 2d array

Starting scan for buffers containing 'hello!':
Average time per buffer scan: 0.002209 seconds
Maximum time taken in a single buffer scan: 0.002500 seconds
Total time taken to scan all buffers: 2.208868 seconds

## HS with 2d array without any file writes

Starting scan for buffers containing 'hello!':
Average time per buffer scan: 0.000144 seconds
Maximum time taken in a single buffer scan: 0.000208 seconds
Total time taken to scan all buffers: 0.144312 seconds

## HS with 2d array of size 20 without file writes and stabilized clock
Starting scan for buffers containing 'hello!':
Average time per buffer scan: 0.000597 seconds
Maximum time taken in a single buffer scan: 0.000897 seconds
Total time taken to scan all buffers: 0.597097 seconds

## Perf Buffer 

#### Hyperscan Stats:
Total Packets received: 1000 
Average time per hyperscan loop: 0.005622 seconds
Maximum time taken in a single hyperscan loop: 0.006008 seconds
Total time taken in hyperscan: 5.622235 seconds
#### Callback function Stats:
Average time per callback function: 0.005642 seconds
Maximum time taken in a single callback function: 0.006030 seconds
Total time taken in callback function: 5.642144 seconds
Subsequent packet time difference: 
#### Packet stats:
The difference between two consequent packet start times: 0.005674 seconds

## Perf Buffer without any file writes
No packets received for 20 seconds. Exiting.
Hyperscan Stats:
Total Packets received: 1000 
Average time per hyperscan loop: 0.000333 seconds
Maximum time taken in a single hyperscan loop: 0.000391 seconds
Total time taken in hyperscan: 0.332568 seconds
Callback function Stats:
Average time per callback function: 0.000335 seconds
Maximum time taken in a single callback function: 0.000402 seconds
Total time taken in callback function: 0.335024 seconds
Subsequent packet time difference: 
The difference between two consequent packet start times: 0.000401 seconds

## Ring Buffer with file writes

No packets received for 20 seconds. Exiting.
Hyperscan Stats:
Total Packets received: 362 
Average time per hyperscan loop: 0.002030 seconds
Maximum time taken in a single hyperscan loop: 0.005857 seconds
Total time taken in hyperscan: 2.030205 seconds
Callback function Stats:
Average time per callback function: 0.002033 seconds
Maximum time taken in a single callback function: 0.005868 seconds
Total time taken in callback function: 2.033493 seconds
Subsequent packet time difference: 
The difference between two consequent packet start times: 0.005597 seconds

Processed 1000 packets
Hyperscan Stats:
Total Packets received: 1000 
Average time per hyperscan loop: 0.005745 seconds
Maximum time taken in a single hyperscan loop: 0.007922 seconds
Total time taken in hyperscan: 5.745267 seconds
OutsideHyperscan Stats:
Total Packets received: 1000 
Average time per hyperscan loop: 0.005745 seconds
Maximum time taken in a single hyperscan loop: 0.007922 seconds
Total time taken in hyperscan: 5.745267 seconds
Callback function Stats:
Average time per callback function: 0.005753 seconds
Maximum time taken in a single callback function: 0.007930 seconds
Total time taken in callback function: 5.753483 seconds
Time difference between the last two packets: 0.005921 seconds


### Stabilized cpu clock and variance
OutsideHyperscan Stats:
Total Packets received: 2001 
Average time per hyperscan loop: 0.000557 seconds
Maximum time taken in a single hyperscan loop: 0.000925 seconds
Total time taken in hyperscan: 1.115264 seconds
Callback function Stats:
Average time per callback function: 0.000559 seconds
Maximum time taken in a single callback function: 0.000928 seconds
Total time taken in callback function: 1.119455 seconds
Average time difference between subsequent packets: 0.000566 seconds
Variance of time differences: 0.000000000084655
