#! /bin/bash

# need to clear robustmlp cache

python batch_robust_reuse.py robustmlp /home/yz/code/EvadeML/most_benign_genome 48 20 0.1 1 attack_robust_combine_two 0;

for i in $(seq 2 10);
do python batch_robust_reuse_noseed.py robustmlp /home/yz/code/EvadeML/most_benign_genome 48 20 0.1 $i attack_robust_combine_two 0;
done

