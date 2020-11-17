#! /usr/bin/env python
import os
import sys
import xgboost as xgb

_current_dir = os.path.abspath(os.path.dirname(__file__))
PROJECT_ROOT = os.path.normpath(os.path.join(_current_dir, ".."))
sys.path.append(PROJECT_ROOT)

from classifiers.hidost_wrapper import hidost_feature

from lib.config import config
model_path = config.get('monotonic', 'model_path')

model = xgb.Booster()  # init model
model.load_model(model_path)  # load data

def monotonic(pdf_paths):
    X = hidost_feature(pdf_paths, nfeat=3514, fpath='/home/yz/data/traintest_all_500test/features.nppf')
    feat = xgb.DMatrix(X.tolist())
    pred_val = [float(i) for i in model.predict(feat)]
    return pred_val
    """
    pred_leaf_indices = model.predict(feat, pred_leaf=True)
    #ben_leaf_percentage = []
    res = []
    for i in range(len(pred_leaf_indices)):
        index = pred_leaf_indices[i]
        res.append((pred_val[i], str(index)))
    return res
    """

if __name__ == "__main__":
    #pdf_list = sys.argv[1:]
    #pdf_paths = map(os.path.abspath, pdf_list)
    #print pdf_paths 

    pdf_dir = sys.argv[1]
    pdf_paths = [os.path.join(pdf_dir, item) for item in os.listdir(pdf_dir)]
    
    #print pdf_paths
    results = monotonic(pdf_paths)
    for idx in range(len(pdf_paths)):
        pred_score = results[idx][0]
        pdf = pdf_paths[idx]
        print '%s\t%s' % (pdf, pred_score)


