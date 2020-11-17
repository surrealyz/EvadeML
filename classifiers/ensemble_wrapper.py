#! /usr/bin/env python
import os
import sys
import requests
import numpy as np
import json
import pickle

_current_dir = os.path.abspath(os.path.dirname(__file__))
PROJECT_ROOT = os.path.normpath(os.path.join(_current_dir, ".."))
sys.path.append(PROJECT_ROOT)

from classifiers.hidost_wrapper import hidost_feature

from lib.config import config
HOST = config.get('ensemble', 'host')
PORT = int(config.get('ensemble', 'port'))

feat_trie = pickle.load(open('/home/yz/code/robustml/robustness_spec/feature_spec/pathtrie_filled.pickle', 'rb'))

def ensemble(pdf_paths):
    X = hidost_feature(pdf_paths, nfeat=3514, fpath='/home/yz/data/traintest_all_500test/features.nppf') 
    res = []
    # for each feature vector in X, do the delete one thing.
    for seed_feat in X:
        vec = [seed_feat.tolist()]
        # generate one interval for every node under root.
        for key, obj in feat_trie._root.children.iteritems():
            # insert all but not the current one.
            min_idx, max_idx = feat_trie[key]
            # change seed feature
            newvec = np.copy(seed_feat)
            for i in range(min_idx-1, max_idx):
                newvec[i] = 0
            if newvec.tolist() != vec:
                vec.append(newvec.tolist())
        y_pred = query_tf(vec)
        mal = [pred[1] for pred in y_pred if pred[1] > 0.5]
        benign = [pred[0] for pred in y_pred if pred[0] >= 0.5]
        if len(mal) > 0:
            res.append(sum(mal)/len(mal))
        else:
            res.append(1-sum(benign)/len(benign))
    return res

def query_tf(X):
    payload = {'instances': X}
    REST_URL='http://%s:%d/v1/models/adv_del_twocls:predict' % (HOST, PORT)
    r = requests.post(REST_URL, json=payload)
    if r.status_code == 200:
        json_decoder = json.JSONDecoder()
        res = json_decoder.decode(r.text)
        return [item['y_softmax'] for item in res['predictions']]

if __name__ == "__main__":
    pdf_list = sys.argv[1:]
    pdf_paths = map(os.path.abspath, pdf_list)
    print ensemble(pdf_paths)
