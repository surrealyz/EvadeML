#! /usr/bin/env python
import os
import sys
from lib.common import list_file_paths
import pickle
import random

to_skip_pickle = "evade_both_to_skip.pickle"

if os.path.isfile(to_skip_pickle):
    to_skip = pickle.load(open(to_skip_pickle))
else:
    to_skip = ['1ec657f52bf1811af14d7da549cb6add70c778f0', 'b01be494ac00843796cb200caf91e7ab2e997c34', 'b4f13bf5f4174fd7a7c2a52b21309da8da0b33ce', 'f2a9170030b999834018203f468ea9bcf8e444c0', 'f3efb335a617ecb76e1e7519bc7c2c3df8fa47f6', 'c9d27b43899aa6aa6c81ee544209fc25cb10b98f', 'cd983d0d207cb848e511dbf0f63866600bb0cc60']


def main(argv):
    # robustmlp
    classifier_name = sys.argv[1]
    ext_genome_folder = sys.argv[2]
    ext_genome_tag = ext_genome_folder.split('/')[-1]
    pop = sys.argv[3]
    gen = sys.argv[4]
    mutation_rate = sys.argv[5]
    round_id = int(sys.argv[6])
    token = sys.argv[7]
    start = int(sys.argv[8])

    if not os.path.isdir(ext_genome_folder):
        print "Error: invalid ext genome folder."
        sys.exit(1)

    seed_paths = pickle.load(open('shuffled_seed_paths_most_benign.pickle', 'rb'))

    for seed_path in seed_paths[start:]:
        start_hash = seed_path.split('/')[-1].split('.')[0]
   
        if start_hash in to_skip:
            print "Skipped ", start_hash
            continue
        
        # get the seed state for this round
        # results/attack_mlp_most_benign_genome/00d3f97d86825dd7eae67b8cae2eda407cc9e0f3/log_r1/classifier=mlp,mut=0.1,xover=0.0,popsz=48,maxgen=20,stopfit=0.00,start=00d3f97d86825dd7eae67b8cae2eda407cc9e0f3/random_state.pickle
        #regular_task_token = 'attack_mlp_most_benign_genome/%s' % start_hash
        #regular_job_dir = "./results/%s/log_r%d/classifier=mlp,mut=0.1,xover=0.0,popsz=48,maxgen=20,stopfit=0.00,start=%s" \
        #        % (regular_task_token, round_id, start_hash)
        #random_state = os.path.join(regular_job_dir, "random_state.pickle")
        prev_job_dir = "./results/reuse_trace_attack_mlp_most_benign_genome/log_r%d/classifier=mlp,mut=0.1,xover=0.0,popsz=48,maxgen=20,stopfit=0.00,start=%s" \
                % (round_id, start_hash)
        random_state = os.path.join(prev_job_dir, "random_state.pickle")


        cmd = "./gp_1_replace_mix_threeprop_adaptive.py -c %s -s %s -e %s -p %s -g %s -m %s -x 0 -f 0 -t %s --round %d -r %s" \
            % (classifier_name, seed_path, ext_genome_folder, pop, gen, mutation_rate, token, round_id, random_state)

        try:
            print cmd
            os.system(cmd)
        except KeyboardInterrupt, error:
            break


if __name__ == '__main__':
    main(sys.argv)

