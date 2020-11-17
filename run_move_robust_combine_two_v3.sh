#! /bin/bash

# need to clear robustmlp cache

python batch_choice_noswap.py robustmlp /home/yz/code/EvadeML/most_benign_genome 48 20 0.1 1 adaptive_attack_robustmlp_combine_two_v3_choice_noswap_20190717 0;

for i in $(seq 2 10);
do python batch_choice_noswap_noseed.py robustmlp /home/yz/code/EvadeML/most_benign_genome 48 20 0.1 $i adaptive_attack_robustmlp_combine_two_v3_choice_noswap_20190717 0;
done

