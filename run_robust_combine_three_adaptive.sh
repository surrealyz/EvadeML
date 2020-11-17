#! /bin/bash

# need to clear robustmlp cache

python batch_threeprop_adaptive.py threeprop /home/yz/code/EvadeML/most_benign_genome 48 20 0.1 1 adaptive_attack_robust_combine_three 0;

for i in $(seq 2 10);
do python batch_threeprop_adaptive_noseed.py threeprop /home/yz/code/EvadeML/most_benign_genome 48 20 0.1 $i adaptive_attack_robust_combine_three 0;
done

