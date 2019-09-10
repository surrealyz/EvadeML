from common import *
from detector import query_classifier
import numpy as np

logger = logging.getLogger('gp.fitness')

def fitness_pos_neg(file_paths, seed_sha1, classifier_name, oracle_name, offset = 0):
    classifier = lambda *args:query_classifier(classifier_name, *args)
    oracle = lambda *args:query_classifier(oracle_name, *args)

    classified_scores = classifier(file_paths)
    oracle_results = oracle(file_paths, seed_sha1)

    while oracle_results == None or classified_scores == None:
        logger.warning("Invalid results: oracle %s classifier %s " % (oracle_results != None, classified_scores != None))
        classified_scores = classifier(file_paths)
        oracle_results = oracle(file_paths, seed_sha1)

    for i in range(len(file_paths)):
        short_path = '/'.join(file_paths[i].split('/')[-3:])
        logger.info("Variant: %s %s %s" % (oracle_results[i], classified_scores[i], short_path))

    fitness_scores = []
    for i in range(len(classified_scores)):
        if oracle_results[i] == 'malicious':
            score = (classified_scores[i]-offset) * float(-1)
        else:
            # big negative fitness
            score = LOW_SCORE
        fitness_scores.append(score)
    return fitness_scores

def fitness_pos_neg_percent(file_paths, seed_sha1, classifier_name, oracle_name, offset = 0):
    classifier = lambda *args:query_classifier(classifier_name, *args)
    oracle = lambda *args:query_classifier(oracle_name, *args)

    classified_scores = classifier(file_paths)
    oracle_results = oracle(file_paths, seed_sha1)

    while oracle_results == None or classified_scores == None:
        logger.warning("Invalid results: oracle %s classifier %s " % (oracle_results != None, classified_scores != None))
        classified_scores = classifier(file_paths)
        oracle_results = oracle(file_paths, seed_sha1)

    for i in range(len(file_paths)):
        short_path = '/'.join(file_paths[i].split('/')[-3:])
        logger.info("Variant: %s %s %s" % (oracle_results[i], classified_scores[i], short_path))

    fitness_scores = []
    for i in range(len(classified_scores)):
        if oracle_results[i] == 'malicious':
            #score = (classified_scores[i][0]-offset) * float(-1) * (1-classified_scores[i][1])
            score = (classified_scores[i][0]-offset) * float(-1)
        else:
            # big negative fitness
            score = LOW_SCORE
        fitness_scores.append(score)
    return fitness_scores

def fitness_pos_neg_cnt(file_paths, seed_sha1, classifier_name, oracle_name, offset = 0.5):
    classifier = lambda *args:query_classifier(classifier_name, *args)
    oracle = lambda *args:query_classifier(oracle_name, *args)

    classified_scores = classifier(file_paths)
    oracle_results = oracle(file_paths, seed_sha1)

    while oracle_results == None or classified_scores == None:
        logger.warning("Invalid results: oracle %s classifier %s " % (oracle_results != None, classified_scores != None))
        classified_scores = classifier(file_paths)
        oracle_results = oracle(file_paths, seed_sha1)

    for i in range(len(file_paths)):
        short_path = '/'.join(file_paths[i].split('/')[-3:])
        logger.info("Variant: %s %s %s" % (oracle_results[i], classified_scores[i], short_path))

    fitness_scores = []
    for i in range(len(classified_scores)):
        if oracle_results[i] == 'malicious':
            score = (classified_scores[i][0]-offset) * float(-1) * classified_scores[i][1]
        else:
            # big negative fitness
            score = LOW_SCORE
        fitness_scores.append(score)
    return fitness_scores



def fitness_pre_softmax(file_paths, seed_sha1, classifier_name, oracle_name):
    classifier = lambda *args:query_classifier(classifier_name, *args)
    oracle = lambda *args:query_classifier(oracle_name, *args)
        
    try:
        classified_scores = classifier(file_paths)
        oracle_results = oracle(file_paths, seed_sha1)
    except Exception:
        # try again
        classified_scores = classifier(file_paths)
        oracle_results = oracle(file_paths, seed_sha1)

    while oracle_results == None or classified_scores == None:
        logger.warning("Invalid results: oracle %s classifier %s " % (oracle_results != None, classified_scores != None))
        classified_scores = classifier(file_paths)
        oracle_results = oracle(file_paths, seed_sha1)

    for i in range(len(file_paths)):
        short_path = '/'.join(file_paths[i].split('/')[-3:])
        logger.info("Variant: %s %s %s" % (oracle_results[i], classified_scores[i], short_path))

    fitness_scores = []
    for i in range(len(classified_scores)):
        if oracle_results[i] == 'malicious':
            # distance between benign logit and malicous logit
            score = classified_scores[i][0] - classified_scores[i][1]
        else:
            # big negative fitness
            score = LOW_SCORE
        fitness_scores.append(score)
    return fitness_scores

def fitness_log_softmax(file_paths, seed_sha1, classifier_name, oracle_name):
    classifier = lambda *args:query_classifier(classifier_name, *args)
    oracle = lambda *args:query_classifier(oracle_name, *args)
        
    try:
        classified_scores = classifier(file_paths)
        oracle_results = oracle(file_paths, seed_sha1)
    except Exception:
        # try again
        classified_scores = classifier(file_paths)
        oracle_results = oracle(file_paths, seed_sha1)

    while oracle_results == None or classified_scores == None:
        logger.warning("Invalid results: oracle %s classifier %s " % (oracle_results != None, classified_scores != None))
        classified_scores = classifier(file_paths)
        oracle_results = oracle(file_paths, seed_sha1)

    for i in range(len(file_paths)):
        short_path = '/'.join(file_paths[i].split('/')[-3:])
        logger.info("Variant: %s %s %s" % (oracle_results[i], classified_scores[i], short_path))

    fitness_scores = []
    for i in range(len(classified_scores)):
        if oracle_results[i] == 'malicious':
            # distance between log benign and log malicous
            if classified_scores[i][0] != 0.0:
                benign = np.log(classified_scores[i][0])
            else:
                benign = LOW_SCORE
            if classified_scores[i][1] != 0.0:
                malicious = np.log(classified_scores[i][1])
            else:
                malicious = LOW_SCORE
            score = benign - malicious
            #score = np.log(classified_scores[i][0] + np.exp(-20)) - np.log(classified_scores[i][1] + np.exp(-20))
        else:
            # big negative fitness
            score = LOW_SCORE
        fitness_scores.append(score)
    return fitness_scores


# score: benign [0, 0.5), malicious (0.5, 1]
def fitness_01(file_paths, seed_sha1, classifier_name, oracle_name):
    return fitness_pos_neg(file_paths, seed_sha1, classifier_name, oracle_name, offset = 0.5)

def fitness_mlp(file_paths, seed_sha1):
    #return fitness_pre_softmax(file_paths, seed_sha1, 'mlp', 'cuckoo')
    return fitness_log_softmax(file_paths, seed_sha1, 'mlp', 'cuckoo')

def fitness_robustmlp(file_paths, seed_sha1):
    #return fitness_pre_softmax(file_paths, seed_sha1, 'robustmlp', 'cuckoo')
    return fitness_log_softmax(file_paths, seed_sha1, 'robustmlp', 'cuckoo')

def fitness_threeprop(file_paths, seed_sha1):
    return fitness_log_softmax(file_paths, seed_sha1, 'threeprop', 'cuckoo')

def fitness_baseline_adv(file_paths, seed_sha1):
    return fitness_log_softmax(file_paths, seed_sha1, 'baseline_adv', 'cuckoo')

def fitness_monotonic(file_paths, seed_sha1):
    return fitness_pos_neg(file_paths, seed_sha1, 'monotonic', 'cuckoo', offset = 0.5)

def fitness_ensemble(file_paths, seed_sha1):
    return fitness_pos_neg(file_paths, seed_sha1, 'ensemble', 'cuckoo', offset = 0.5)

def fitness_ensemblecnt(file_paths, seed_sha1):
    return fitness_pos_neg_cnt(file_paths, seed_sha1, 'ensemblecnt', 'cuckoo', offset = 0.5)

def fitness_pdfrate(file_paths, seed_sha1):
    return fitness_01(file_paths, seed_sha1, 'pdfrate', 'cuckoo')

def fitness_hidost(file_paths, seed_sha1):
    return fitness_pos_neg(file_paths, seed_sha1, 'hidost', 'cuckoo')

def fitness_hidost_pdfrate(file_paths, seed_sha1):
    return fitness_pos_neg(file_paths, seed_sha1, 'hidost_pdfrate', 'cuckoo')

def fitness_hidost_pdfrate_sigmoid(file_paths, seed_sha1):
    return fitness_pos_neg(file_paths, seed_sha1, 'hidost_pdfrate_sigmoid', 'cuckoo')

import math

def sigmoid(x):
    return 1 / (1 + math.exp(-x))

def mean(x):
    return sum(x)/float(len(x))

import operator
def geo_mean(iterable):
    return (reduce(operator.mul, iterable)) ** (1.0/len(iterable))

def fitness_hidost_pdfrate_mean(file_paths, seed_sha1):
    pdfrate = lambda *args:query_classifier('pdfrate', *args)
    hidost = lambda *args:query_classifier('hidost', *args)
    oracle = lambda *args:query_classifier('cuckoo', *args)

    p_scores = pdfrate(file_paths)
    h_scores = hidost(file_paths)
    h_scores = map(sigmoid, h_scores)
    oracle_results = oracle(file_paths, seed_sha1)

    assert (len(p_scores) == len(h_scores) == len(oracle_results) == len(file_paths))

    fitness_scores = []
    for i in range(len(file_paths)):
        short_path = '/'.join(file_paths[i].split('/')[-3:])
        p_score, h_score, oracle_result = p_scores[i], h_scores[i], oracle_results[i]

        if oracle_result == 'malicious':
            classify_score = [p_score, h_score]
            score = -mean(classify_score)
            if max(classify_score) < 0.5:
                score += 0.5
        else:
            # big negative fitness
            score = LOW_SCORE
        logger.info("Variant: %s %.2f %.2f %.2f %s" % (oracle_result, score, p_score, h_score, short_path))
        fitness_scores.append(score)
    return fitness_scores
