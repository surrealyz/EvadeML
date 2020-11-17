#! /usr/bin/env python
import os
import sys
import requests
import numpy as np
import json

_current_dir = os.path.abspath(os.path.dirname(__file__))
PROJECT_ROOT = os.path.normpath(os.path.join(_current_dir, ".."))
sys.path.append(PROJECT_ROOT)

from classifiers.hidost_wrapper import hidost_feature

from lib.config import config
HOST = config.get('threeprop', 'host')
PORT = int(config.get('threeprop', 'port'))

def threeprop(pdf_paths):
    X = hidost_feature(pdf_paths, nfeat=3514, fpath='/home/yz/data/traintest_all_500test/features.nppf') 
    return query_tf(X.tolist())

def query_tf(X):
    payload = {'instances': X}
    REST_URL='http://%s:%d/v1/models/robust_combine_three:predict' % (HOST, PORT)
    r = requests.post(REST_URL, json=payload)
    if r.status_code == 200:
        json_decoder = json.JSONDecoder()
        res = json_decoder.decode(r.text)
        return [item['y_softmax'] for item in res['predictions']]

if __name__ == "__main__":
    pdf_list = sys.argv[1:]
    pdf_paths = map(os.path.abspath, pdf_list)
    test_instance = hidost_feature(pdf_paths, nfeat=3514, fpath='/home/yz/data/traintest_all_500test/features.nppf')
    payload = {'instances': test_instance.tolist()}
    REST_URL='http://%s:%d/v1/models/robust_combine_three:predict' % (HOST, PORT)
    r = requests.post(REST_URL, json=payload)
    json_decoder = json.JSONDecoder()
    res = json_decoder.decode(r.text)
    print res['predictions']
    print [item['pre_softmax'] for item in res['predictions']]
