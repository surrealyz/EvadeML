#! /bin/bash

python batch_regular_reuse.py mlp /home/yz/code/EvadeML/most_benign_genome 48 20 0.1 1 attack_mlp 0;

for i in $(seq 2 10);
do python batch_regular_reuse_noseed.py mlp /home/yz/code/EvadeML/most_benign_genome 48 20 0.1 $i attack_mlp 0;
done

