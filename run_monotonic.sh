#! /bin/bash

# need to clear robustmlp cache

python batch_robust_reuse.py monotonic /home/yz/code/EvadeML/most_benign_genome 48 20 0.1 1 attack_monotonic_100learner 0;

for i in $(seq 2 5);
do python batch_robust_reuse_noseed.py monotonic /home/yz/code/EvadeML/most_benign_genome 48 20 0.1 $i attack_monotonic_100learner 0;
done

