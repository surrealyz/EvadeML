#! /usr/bin/env python
import logging
import random
import pickle
import os
import sys
import getopt

from lib.common import LOW_SCORE, finished_flag, visited_flag, result_flag, error_flag
from lib.common import touch, deepcopy
from lib.common import setup_logging

import numpy as np
import pygtrie

# Import PDFRW later for controling the logging format.
# Note: The original pdfw should be used in parsing the repacked seeds for efficiency.
# No, we have to use the modified version, due to the additional trace issue.

class GPPdf:
    def __init__(self,
                 job_dir,
                 seed_sha1,
                 seed_file_path,
                 logger,
                 random_state_file_path,
                 ext_genome,
                 success_traces_path,
                 promising_traces_path,
                 gp_params,
                 fitness_function,
                 ):
        self.logger = logger
        self.job_dir = job_dir
        self.seed_sha1 = seed_sha1

        # Load the pre-defined random state for reproducing the existing results.
        if random_state_file_path:
            try:
                random_state = pickle.load(open(random_state_file_path, 'rb'))
                random.setstate(random_state)
                logger.debug("Loaded a random state from %s" % random_state_file_path)
            except:
                logger.warning("Failed to load random state from %s" % random_state_file_path)

        # Save random state for reproducing results in the future.
        random_state_file = os.path.join(self.job_dir, "random_state.pickle")
        random_state = random.getstate()
        pickle.dump(random_state, open(random_state_file, 'wb'))

        self.fitness_func = fitness_function

        # Load the seed.
        self.seed_file_path = seed_file_path
        self.seed_fitness = self.fitness([self.seed_file_path], self.seed_sha1)[0]
        #self.seed_fitness = LOW_SCORE
        self.seed_root = PdfGenome.load_genome(seed_file_path)
        self.logger.info("Loaded %s as PDF seed, fitness %.2f." % (seed_file_path, self.seed_fitness))
        

        # Load the external genome.
        self.ext_genome = ext_genome

        # initialize the ext_genome trie
        # it's possible that there is the path, but no value, because of the trie
        # the root is root, next = '', next is 'Root'...
        self.ext_trie = pygtrie.StringTrie(separator=os.path.sep)
        for ext_id in range(len(self.ext_genome)):
            parent, gene = ext_genome[ext_id]
            key = ''.join([item for item in gene if type(item) != int])
            try:
                self.ext_trie[key].append(ext_id)
            except KeyError:
                self.ext_trie[key] = [ext_id]
        # populate the ext_ids by recursion.
        # traverse every node..
        queue = []
        for child in self.ext_trie._root.children.iteritems():
            queue.append(child)

        while len(queue) > 0:
            key, node = queue.pop(0)
            if type(node.value) == object:
                node.value = self.descendent_value(node)
            else:
                node.value = list(set(node.value + self.descendent_value(node)))
            # put children back into the queue
            for subkey, obj in node.children.iteritems():
                queue.append((subkey, obj))
        

        # Load traces.
        self.success_traces_path = success_traces_path
        self.success_traces = Trace.load_traces(self.success_traces_path)
        self.promising_traces_path = promising_traces_path
        self.promising_traces = Trace.load_traces(self.promising_traces_path)

        # Initiate some parameters.
        self.gp_params = gp_params
        self.pop_size = gp_params['pop_size']
        self.max_gen = gp_params['max_gen']
        self.mut_rate = gp_params['mut_rate']
        self.xover_rate = gp_params['xover_rate']
        self.fitness_threshold = gp_params['fitness_threshold']        

    def descendent_value(self, node):
        # already visited
        if type(node.value) != object:
            return node.value
        # leaf node, there is no more children
        elif node.children == {}:
            return node.value
        else:
            # recurse
            res = []
            for key, childnode in node.children.iteritems():
                res += self.descendent_value(childnode)
            res = list(set(res))
            return res


    def save_variants_to_files(self):
        folder = "./variants/generation_%d" % (self.generation)
        folder = os.path.join(self.job_dir, folder)
        if not os.path.isdir(folder):
            os.makedirs(folder)
        file_paths = []
        for j in range(len(self.popul)):
            path = "./variants/generation_%d/%d.pdf" % (self.generation, j)
            path = os.path.join(self.job_dir, path)
            file_paths.append(path)
            PdfGenome.save_to_file(self.popul[j], path)
        return file_paths

    def load_variant(self, gen, vid):
        path = "./variants/generation_%d/%d.pdf" % (gen, vid)
        path = os.path.join(self.job_dir, path)
        pdf_obj = PdfGenome.load_genome(path)
        return pdf_obj

    def load_variant_trace(self, gen, vid):
        path = "./variants/generation_%d/%d.pdf" % (gen, vid)
        path = os.path.join(self.job_dir, path)
        trace = PdfGenome.load_trace(path)
        return trace

    def fitness(self, *args):
        return self.fitness_func(*args)

    def run(self):
        self.logger.info("Start a gp task with %s" % (self.gp_params))
        
        score_file_name = os.path.join(self.job_dir, "fitness_scores.pickle")
        self.fitness_scores = {}
        
        self.popul = self.initial_population()
        self.generation = 1

        while self.generation <= self.max_gen:
            self.logger.info("There're %d variants in population at generation %d." % (len(self.popul), self.generation))

            file_paths = self.save_variants_to_files()

            scores = self.fitness(file_paths, self.seed_sha1)
            # Introduce a fake score for testing tracing.
            # scores = [0.1, 0.2] * (self.pop_size/2)

            self.fitness_scores[self.generation] = scores
            pickle.dump(self.fitness_scores, open(score_file_name, 'wb'))
            
            self.logger.info("Fitness scores: %s" % scores)
            self.logger.info("Sorted fitness: %s" % sorted(scores, reverse=True))
            
            if max(scores) > self.fitness_threshold:
                self.best_score = max(scores)
                self.logger.info("Already got a high score [%.2f]>%.2f variant, break the GP process." % (max(scores), self.fitness_threshold))
                
                # Store the success traces.
                for i in range(len(scores)):
                    score = scores[i]
                    if score > self.fitness_threshold:
                        success_trace = self.popul[i].active_trace
                        self.success_traces.append(success_trace)

                # Dump the new generated traces.
                # We assume no concurrent GP tasks depending on the traces.
                Trace.dump_traces(self.success_traces, self.success_traces_path)
                touch(os.path.join(self.job_dir, finished_flag))
                break
            elif self.generation == max_gen:
                self.logger.info("Failed at max generation.")
                if max(scores) >= self.seed_fitness:
                    best_gen, best_vid, self.best_score = self.get_best_variant(1, self.generation)
                    promising_trace = self.load_variant_trace(best_gen, best_vid)
                    self.logger.info("Save the promising trace %.2f of %d:%d" % (self.best_score, best_gen, best_vid))
                    self.promising_traces.append(promising_trace)
                    Trace.dump_traces(self.promising_traces, self.promising_traces_path, exclude_traces=self.success_traces)
                break

            # Crossover
            if self.xover_rate > 0:
                self.popul = self.select(self.popul, scores, self.pop_size/2)
                self.logger.debug("After selecting goods and replacing bads, we have %d variants in population." % len(self.popul))

                for p1,p2 in zip(self.popul[0::2], self.popul[1::2]):
                    c1, c2 = PdfGenome.crossover(p1, p2)
                    self.popul.append(c1)
                    self.popul.append(c2)
                self.logger.debug("After crossover, we have %d variants in population." % len(self.popul))
            else: # No Crossover
                self.popul = self.select(self.popul, scores, self.pop_size)
                self.logger.debug("After selecting goods and replacing bads, we have %d variants in population." % len(self.popul))

            # Mutation
            for i in range(len(self.popul)):
                if i not in self.vid_from_trace:
                    self.logger.debug("Generating %d:%d variant" % (self.generation+1, i))
                    try:
                        self.popul[i] = PdfGenome.mutation_with_trace(self.ext_trie, self.popul[i], self.mut_rate, self.ext_genome)
                        #self.popul[i] = PdfGenome.mutation_with_trace_swap(self.ext_trie, self.popul[i], self.mut_rate, self.ext_genome)
                        #self.popul[i] = PdfGenome.mutation_with_trace_choice(self.ext_trie, self.popul[i], self.mut_rate, self.ext_genome)
                        #self.popul[i] = PdfGenome.mutation_with_trace_choice_noswap(self.ext_trie, self.popul[i], self.mut_rate, self.ext_genome)
                        #self.popul[i] = PdfGenome.mutation_with_trace_pastswap(self.ext_trie, self.popul[i], self.mut_rate, self.ext_genome)
                    except Exception, e:
                        self.logger.debug("Exception %s, replace with original seed" % e)
                        self.popul[i] = deepcopy(self.seed_root)
                else:
                    self.logger.debug("Keep %d:%d variant from trace." % (self.generation+1, i))

            self.generation = self.generation + 1

        self.logger.info("Stopped the GP process with max fitness %.2f." % self.best_score)
        touch(os.path.join(self.job_dir, result_flag % self.best_score))
        return True

    def initial_population(self):
        logger = self.logger
        logger.info("Getting initial population from existing mutation traces (success: %d, promising: %d)." \
                    % (len(self.success_traces), len(self.promising_traces)))
        popul = []

        traces = self.success_traces + self.promising_traces
        traces = Trace.get_distinct_traces(traces)
        logger.info("Got %d distinct traces" % len(traces))
        self.traces = traces

        self.remaining_traces_id = range(len(traces))

        if 0 < len(self.remaining_traces_id) <= self.pop_size:
            tid_picked = [stuff for stuff in self.remaining_traces_id]
        elif len(self.remaining_traces_id) > self.pop_size:
            tid_picked = random.sample(self.remaining_traces_id, self.pop_size)
            tid_picked.sort()
        else:
            tid_picked = []

        # generate_variants_from_traces
        for i in tid_picked:
            self.remaining_traces_id.remove(i)
            logger.debug("Generating %d variant from existing trace." % i)
            trace = traces[i]
            variant_root = Trace.generate_variant_from_trace(self.seed_root, trace, self.ext_genome)
            popul.append(variant_root)

        if len(popul) < int(self.pop_size):
            logger.info("Getting %d more variants in initial population by random mutation." \
                        % (int(self.pop_size) - len(popul)))

        while len(popul) < int(self.pop_size):
            i = len(popul)
            logger.debug("Getting variant %d in initial population." % i)
            root = deepcopy(self.seed_root)
            root = PdfGenome.mutation_with_trace(self.ext_trie, root, self.mut_rate, self.ext_genome)
            popul.append(root)
        return popul

    def get_best_variant(self, start_gen, end_gen):
        best_gen = 1
        best_vid = 0
        best_score = LOW_SCORE
        for gen in range(start_gen, end_gen+1):
            scores = self.fitness_scores[gen]
            if max(scores) > best_score:
                best_score = max(scores)
                best_gen = gen
                best_vid = scores.index(best_score)
        return best_gen, best_vid, best_score
    
    def get_random_k_variant(self, k, start_gen, end_gen):
        # add the seed to there as well.
        all_gen = []
        all_vid = []
        all_scores = []
        for gen in range(start_gen, end_gen+1):
            raw_scores = self.fitness_scores[gen]
            for i in range(len(raw_scores)):
                if raw_scores[i] != LOW_SCORE:
                    all_scores.append(raw_scores[i])
                    all_gen.append(gen)
                    all_vid.append(i)
        all_gen.append(0)
        all_vid.append(0)
        all_scores.append(self.seed_fitness)
        try:
            random_k_scores_idx = random.sample(range(len(all_scores)), k)
        except ValueError:
            random_k_scores_idx = random.sample(range(len(all_scores)), len(all_scores))
        random_k_scores = [all_scores[i] for i in random_k_scores_idx]
        # in case the original seed got LOW_SCORE from the cuckoo run
        random_k_gen = [all_gen[i] for i in random_k_scores_idx]
        random_k_vid = [all_vid[i] for i in random_k_scores_idx]
        return random_k_gen, random_k_vid, random_k_scores

    def get_best_k_variant(self, k, start_gen, end_gen):

        all_gen = []
        all_vid = []
        all_scores = []
        for gen in range(start_gen, end_gen+1):
            scores = self.fitness_scores[gen]
            all_scores += scores
            all_gen += [gen for i in range(len(scores))]
            all_vid += [i for i in range(len(scores))]
        # take best distinct k
        sorted_scores_idx = sorted(range(len(all_scores)), key=lambda j: all_scores[j], reverse=True)
        cnt = 0
        prev = None
        best_k_scores_idx = []
        for j in sorted_scores_idx:
            score = all_scores[j]
            if score != prev:
                prev = score
                best_k_scores_idx.append(j)
                cnt += 1
                if cnt == k:
                    break
        best_k_scores = [all_scores[i] for i in best_k_scores_idx if all_scores[i] != LOW_SCORE]
        best_k_gen = [all_gen[i] for i in best_k_scores_idx if all_scores[i] != LOW_SCORE]
        best_k_vid = [all_vid[i] for i in best_k_scores_idx if all_scores[i] != LOW_SCORE]
        return best_k_gen, best_k_vid, best_k_scores

    def select(self, orig_list, scores, sel_size):
        # when reverse==False, select variants with lower score, otherwise select higher scores.
        sorted_indices = [i[0] for i in sorted(enumerate(scores), key=lambda x:x[1], reverse=True)]
        
        ret = []
        self.vid_from_trace = []
        
        replace_size = 0
        for i in sorted_indices[:sel_size]:
            if scores[i] == LOW_SCORE:
                replace_size += 1
        
            else:
                self.logger.info("Selected a file with score %.2f" % scores[i])
                ret.append(orig_list[i])

        # replace i to sel_size by selecting from historic best, previous generations randomly (?) or distinct scores (?), and then the seed.
        self.logger.info("Need to find %d replacements" % replace_size)
        remain_size = replace_size
        if self.generation != 1:
            if replace_size == 0:
                size_best, size_topk, size_rand = 0, 0, 0
            elif replace_size == 1:
                size_best, size_topk, size_rand = 1, 0, 0
            elif replace_size == 2:
                size_best, size_topk, size_rand = 1, 1, 0
            else:
                size_best, size_topk, size_rand = int(replace_size/3), int(replace_size/3), int(replace_size/3)
                size_topk += replace_size % 3

            # 1/3 goes to the historic best.
            for j in range(size_best):
                best_gen, best_vid, best_score = self.get_best_variant(1, self.generation-1)
                best_root =  self.load_variant(best_gen, best_vid)
                ret.append(best_root)
                self.logger.info("Ignored a variant with low score, replace with best variant in historic generation[%d, %d]." % (best_gen, best_vid))
           
            # get best k
            if size_topk != 0:
                k_gen, k_vid, k_scores = self.get_best_k_variant(size_topk, 1, self.generation-1)
                for j in range(len(k_gen)):
                    this_gen = k_gen[j]
                    this_vid = k_vid[j]
                    if this_gen != 0:
                        new_root =  self.load_variant(this_gen, this_vid)
                    else:
                        new_root = deepcopy(self.seed_root)
                    ret.append(new_root)
                    self.logger.info("Ignored a variant with low score, replace with one of the good variants in historic generation[%d, %d]." % (this_gen, this_vid))
            else:
                k_gen = []
           
            remain_size = replace_size - size_best - len(k_gen)

            # half of remaining get random k from past 4 gen
            if self.generation - 5 <= 1:
                start_gen = 1
            else:
                start_gen = self.generation - 5
            # sample k that are not LOW_SCORE
            if size_rand != 0:
                k_gen, k_vid, k_scores = self.get_random_k_variant(size_rand, start_gen, self.generation-1)
                for j in range(len(k_gen)):
                    this_gen = k_gen[j]
                    this_vid = k_vid[j]
                    if this_gen != 0:
                        new_root =  self.load_variant(this_gen, this_vid)
                    else:
                        new_root = deepcopy(self.seed_root)
                    ret.append(new_root)
                    self.logger.info("Ignored a variant with low score, replace with one of the random variant in the last four generation[%d, %d]." % (this_gen, this_vid))
            else:
                k_gen = []
                
            # update remain_size
            remain_size -= len(k_gen)
        if remain_size > 0:
            for j in range(remain_size):
                self.logger.info("Ignored a variant with low score, replace with original seed.")
                ret.append(deepcopy(self.seed_root))
        return ret

def get_opt(argv):
    classifier_name = None
    start_file = None
    ext_genome_folder = None
    pop_size = None
    max_gen = None
    mut_rate = None
    xover_rate = 0
    stop_fitness = None
    random_state_file_path = None
    token = None
    round_id = 1

    help_msg = "gp.py -c <classifier name> -o <oracle name> \
        -s <start file location> -e <external genome folder> \
        -p <population size> -g <max generation> \-m <mutation rate> \
        -x <crossvoer rate> -r <random_state_file_path> -t <task_token>\
        --round <round_id>\
        -f <stop criterion in fitness score>"
    
    if len(argv) < 2:
        print help_msg
        sys.exit(2)

    try:
        opts, args = getopt.getopt(argv[1:],"hc:s:e:p:g:m:f:x:r:t:",["classifier=",
                                                                 "sfile=",
                                                                 "extgenome=",
                                                                 "popu=",
                                                                 "gen=",
                                                                 "mut=",
                                                                 "fitness=",
                                                                 "crossover=",
                                                                 "random_state=",
                                                                 "token=",
                                                                 "round=",
                                                                 ])
    except getopt.GetoptError:
        print help_msg
        sys.exit(2)

    for opt, arg in opts:
        if opt == '-h':
            print help_msg
            sys.exit()
        elif opt in ("-c", "--classifier"):
            classifier_name = arg
        elif opt in ("-s", "--sfile"):
            start_file = arg
        elif opt in ("-e", "--extgenome"):
            ext_genome_folder = arg
        elif opt in ("-p", "--popu"):
            pop_size = int(arg)
        elif opt in ("-g", "--gen"):
            max_gen = int(arg)
        elif opt in ("-m", "--mut"):
            mut_rate = float(arg)
        elif opt in ("-x", "--crossover"):
            xover_rate = float(arg)
        elif opt in ("-f", "--fitness"):
            stop_fitness = float(arg)
        elif opt in ("-r", "--random_state"):
            random_state_file_path = arg
        elif opt in ("-t", "--token"):
            token = arg
        elif opt in("--round"):
            round_id = int(arg)
    
    if xover_rate != 0 and pop_size % 4 != 0:
        print "The population size should be times of 4."
        sys.exit(2)

    print classifier_name, start_file, ext_genome_folder, \
        pop_size, max_gen, mut_rate, xover_rate, \
        stop_fitness, random_state_file_path, token, round_id

    return classifier_name, start_file, ext_genome_folder, \
        pop_size, max_gen, mut_rate, xover_rate, \
        stop_fitness, random_state_file_path, token, round_id

if __name__ == "__main__":
    classifier_name, start_file_path, \
        ext_genome_folder, pop_size, max_gen, mut_rate, \
        xover_rate, stop_fitness, random_state_file_path, \
        task_token, round_id = get_opt(sys.argv)

    start_hash = os.path.basename(start_file_path).split('.')[0]

    for rid in range(1, round_id + 1):
        job_dir = "./results/%s/log_r%d/classifier=%s,mut=%.1f,xover=%.1f,popsz=%d,maxgen=%d,stopfit=%.2f,start=%s" \
                    % (task_token, rid, classifier_name, mut_rate, xover_rate, pop_size, max_gen, stop_fitness, start_hash)
        if not os.path.isdir(job_dir):
            os.makedirs(job_dir)

        # skip the succeeded tasks in previous rounds.
        # skip all the visited tasks in the current round.
        if os.path.exists(os.path.join(job_dir, finished_flag)):
            sys.exit(0)
        if rid == round_id and os.path.exists(os.path.join(job_dir, visited_flag)):
            sys.exit(0)

    traces_dir = "./results/%s/trace/" % task_token
    if not os.path.isdir(traces_dir):
        os.makedirs(traces_dir)
    success_traces_path = traces_dir + "success_traces.pickle"
    promising_traces_path = traces_dir + "promising_traces.pickle"

    log_file_path = os.path.join(job_dir, visited_flag)
    setup_logging(log_file_path)
    logger = logging.getLogger('gp.core')
    logger.info("Starting logging for a GP process...")

    # Due to logging is called in pdfrw, they have to be imported after basicConfig of logging.
    # Otherwise, the above basicConfig would be overridden.
    from lib.pdf_genome import PdfGenome
    from lib.trace import Trace

    if classifier_name == 'pdfrate':
        from lib.fitness import fitness_pdfrate as fitness_func
    elif classifier_name == 'hidost':
        from lib.fitness import fitness_hidost as fitness_func
    elif classifier_name == 'mlp':
        from lib.fitness import fitness_mlp as fitness_func
    elif classifier_name == 'robustmlp':
        from lib.fitness import fitness_robustmlp as fitness_func
    elif classifier_name == "hidost_pdfrate":
        from lib.fitness import fitness_hidost_pdfrate as fitness_func
    elif classifier_name == "hidost_pdfrate_mean":
        from lib.fitness import fitness_hidost_pdfrate_mean as fitness_func
    elif classifier_name == "hidost_pdfrate_sigmoid":
        from lib.fitness import fitness_hidost_pdfrate_sigmoid as fitness_func

    gp_params = {'pop_size': pop_size, 'max_gen': max_gen, \
             'mut_rate': mut_rate, 'xover_rate': xover_rate, \
             'fitness_threshold': stop_fitness}
    ext_genome = PdfGenome.load_external_genome(ext_genome_folder, noxref=True)

    try:
        gp = GPPdf( job_dir = job_dir,
                    seed_sha1 = start_hash,
                    seed_file_path = start_file_path,
                    logger = logger,
                    random_state_file_path = random_state_file_path,
                    ext_genome = ext_genome,
                    success_traces_path = success_traces_path,
                    promising_traces_path = promising_traces_path,
                    gp_params = gp_params,
                    fitness_function = fitness_func,
                    )
        gp.run()
    except Exception, e:
        touch(os.path.join(job_dir, error_flag))
        logger.exception(e)
        sys.exit(1)
