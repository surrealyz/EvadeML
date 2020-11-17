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
    to_skip = ['1ec657f52bf1811af14d7da549cb6add70c778f0', 'b01be494ac00843796cb200caf91e7ab2e997c34', 'b4f13bf5f4174fd7a7c2a52b21309da8da0b33ce', 'f2a9170030b999834018203f468ea9bcf8e444c0', 'f3efb335a617ecb76e1e7519bc7c2c3df8fa47f6']

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
        seed_path = '/home/yz/data/weilin_seeds/%s.pdf' % start_hash
   
        if start_hash in to_skip:
            print "Skipped ", start_hash
            continue
        
        cmd = "./gp_1_replace_mix_adaptive.py -c %s -s %s -e %s -p %s -g %s -m %s -x 0 -f 0 -t %s --round %d" \
            % (classifier_name, seed_path, ext_genome_folder, pop, gen, mutation_rate, token, round_id)

        try:
            print cmd
            os.system(cmd)
        except KeyboardInterrupt, error:
            break


if __name__ == '__main__':
    main(sys.argv)

