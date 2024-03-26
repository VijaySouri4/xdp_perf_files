# With hyperscan fd 


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

