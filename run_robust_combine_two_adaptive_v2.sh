#! /bin/bash

# need to clear robustmlp cache

python batch_adaptive_reuse.py robustmlp /home/yz/code/EvadeML/most_benign_genome 48 20 0.1 1 adaptive_attack_robust_combine_two_v7_pastswap 0;

for i in $(seq 2 10);
do python batch_adaptive_reuse_noseed.py robustmlp /home/yz/code/EvadeML/most_benign_genome 48 20 0.1 $i adaptive_attack_robust_combine_two_v7_pastswap 0;
done

