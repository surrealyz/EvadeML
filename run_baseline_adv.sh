#! /bin/bash

# need to clear baseline_adv cache

python batch_robust_reuse.py baseline_adv /home/yz/code/EvadeML/most_benign_genome 48 20 0.1 1 attack_baseline_adv_combine_two 0;

for i in $(seq 2 10);
do python batch_robust_reuse_noseed.py baseline_adv /home/yz/code/EvadeML/most_benign_genome 48 20 0.1 $i attack_baseline_adv_combine_two 0;
done

