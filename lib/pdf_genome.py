from common import *
import pickle
import random

import pdfrw
from pdfrw import PdfReader, PdfWriter, PdfString, PdfArray
from pdfrw.objects import PdfDict, PdfArray, PdfName, PdfObject, PdfIndirect
from peepdf.PDFFilters import decodeStream, encodeStream

logger = logging.getLogger('gp.pdf_genome')


class PdfGenome:
    def __init__(self):
        pass

    @staticmethod
    def load_genome(pdf_file_path, pickleable = False, noxref = False):
        pdf_obj = PdfReader(pdf_file_path, slow_parsing=noxref)

        if pickleable:
            # Remove the dynamic contents to make it pickleable.
            PdfGenome.save_to_file(pdf_obj, os.devnull)
            del pdf_obj.source
        return pdf_obj

    @staticmethod
    def save_to_file(pdf_obj, file_path):
        short_path_for_logging = '/'.join(file_path.split('/')[-3:])
        logger.debug("Saving to file: " + short_path_for_logging)
        y = PdfWriter()
        y.write(file_path, pdf_obj)
        logger.debug("Done")

    @staticmethod
    def load_trace(pdf_file_path):
        fpath = pdf_file_path + ".trace"
        if os.path.isfile(fpath):
            f = open(fpath, 'rb')
            trace = pickle.load(f)
            return trace
        else:
            return None

    @staticmethod
    def load_external_genome(folder, pickleable = False, noxref=False):
        ext_pdf_paths = [] # element: (entry, path)
        for file_path in list_file_paths(folder):
            try:
                pdf_obj = PdfGenome.load_genome(file_path, pickleable, noxref=noxref)
            except Exception:
                continue
            paths = PdfGenome.get_object_paths(pdf_obj)
            for path in paths:
                ext_pdf_paths.append((pdf_obj, path))
        return ext_pdf_paths

    @staticmethod
    def get_object_paths(entry, exclude_paths = set()):
        group_types = [pdfrw.pdfreader.PdfReader, pdfrw.objects.pdfdict.PdfDict, pdfrw.objects.pdfarray.PdfArray]
        logger.debug("Fetch object paths from an entry.")
        if entry.Root == None:
            logger.warning("No /Root. in %s " % entry.keys())
            entry.Root = pdfrw.objects.pdfdict.PdfDict()
            return []
        obj_queue = entry.Root.items() # queue for tree node traversal, (path, obj) pairs

        # Track the visited objs during traversal, actually only PdfArray and PdfDict
        visited_objs_paths = {}
        paths_collection = []

        while len(obj_queue)>0:
            (path, obj) = obj_queue.pop(0)
            if type(path) != list:
                path = ['/Root', path]
            if pickle.dumps(path) in exclude_paths:
                continue
            if type(obj) not in group_types:
                # Terminal nodes, no need to expand, so directly add to the returned list of paths.
                paths_collection.append(path)
            else:
                # Non-terminal nodes. Need further traversal.
                obj_id = id(obj)
                if visited_objs_paths.has_key(obj_id):
                    #paths_collection.append(path) # Why should we add a visited obj?
                    visited_objs_paths[obj_id].append(path)
                    continue
                visited_objs_paths[obj_id] = [path]
                paths_collection.append(path)
                
                try:
                    references = obj.keys()
                except AttributeError:
                    references = range(len(obj))
                for reference in references:
                    child_obj = obj[reference]
                    new_path = path[:]
                    new_path.append(reference)
                    obj_queue.append((new_path, child_obj))

        logger.debug("Fetch %d object paths." % len(paths_collection))
        return paths_collection

    @staticmethod
    def get_parent_key(entry, path):
        parent = entry
        for key in path[:-1]:
            parent = parent[key]
        key = path[-1]
        return parent, key

    @staticmethod
    def delete(entry, path):
        logger.debug("###delete %s" % (path))
        parent, key = PdfGenome.get_parent_key(entry, path)
        if isinstance(parent, list):
            if key >= len(parent):
                logger.error("Cannot delete invalid index in PdfArray: %s" % path)
                return False
        elif isinstance(parent, dict):
            if not parent.has_key(key):
                logger.error("Cannot delete invalid key in PdfDict: %s" % path)
                return False
        else:
            logger.error("The parent node is not PdfArray or PdfDict, but %s!" % type(parent))

        if isinstance(parent, dict):
            parent[key] = None
        elif type(key) == int and isinstance(parent, list):
            del parent[key]
        else:
            # TODO: ERROR:GPPdf:The key is not a string or integer but <class 'pdfrw.objects.pdfobject.PdfObject'>: /Filter
            logger.error("The key is not a string or integer but %s: %s" % (type(key), key))
            return False
        return True

    @staticmethod
    def swap(src_entry, src_path, tgt_entry, tgt_path):
        logger.debug("###swap %s and %s" % (str(src_path), str(tgt_path)))

        src_parent, src_key = PdfGenome.get_parent_key(src_entry, src_path)
        src_obj = src_parent[src_key]

        tgt_parent, tgt_key = PdfGenome.get_parent_key(tgt_entry, tgt_path)
        tgt_obj = tgt_parent[tgt_key]

        tgt_obj = deepcopy(tgt_obj)
        src_parent[src_key] = tgt_obj
        return True

    @staticmethod
    def move_exploit(src_entry, src_path, tgt_path):
        logger.debug("###try to move_exploit from %s to %s" % (str(src_path), str(tgt_path)))

        # get the object containing the exploit
        payload, key = PdfGenome.get_parent_key(src_entry, src_path)
        """
        try:
            payload, key = PdfGenome.get_parent_key(src_entry, src_path)
        except TypeError:
            return False
        """
        if payload is None:
            #return False
            raise Exception('payload is None')

        logger.debug("###move_exploit from %s to %s" % (str(src_path), str(tgt_path)))
        if src_path == ['/Root', '/Names', '/JavaScript', '/Names']:
            ### concat multiple JS parts if necessary
            names_array = payload[key]
            js_code = ''
            jsobj = ''
            # default filter
            cur_filter = '/FlateDecode'
            for i in range(1, len(names_array), 2):
                # cur_obj is either plaintext JS or some encoded stream.
                cur_obj = names_array[i]['/JS']
                if type(cur_obj) == PdfString:
                    jsobj += cur_obj
                    cur_filter = None
                else:
                    cur_filter = cur_obj['/Filter']
                    if type(cur_filter) == PdfArray:
                        cur_stream = cur_obj.stream
                        for i in range(len(cur_filter)):
                            onefilter = cur_filter[i]
                            ret = decodeStream(cur_stream, onefilter)
                            cur_stream = ret[1]
                        js_code += cur_stream
                        js_code += '\n'
                    # this is PdfName
                    elif type(cur_filter) == PdfObject:
                        cur_stream = cur_obj.stream
                        if cur_filter is not None:
                            ret = decodeStream(cur_stream, cur_filter)
                            cur_stream = ret[1]
                        js_code += cur_stream
                        js_code += '\n'
                    elif cur_filter is None:
                        cur_stream = cur_obj.stream
                        js_code += cur_stream
                        js_code += '\n'
                    # What about dictionary
                    else:
                        print cur_filter
                        print type(cur_filter)
                        print 'not supported yet.'
                        return
                    
                    #print js_code
                    # this runs repeatedly but it's fine for now.
                    if cur_filter is not None:
                        jsobj = PdfDict({'/Filter': cur_filter})
                        encode_ret = encodeStream(js_code, cur_filter)
                        jsobj.stream = encode_ret[1]
                    else:
                        jsobj = PdfDict({'/Filter': PdfName('FlateDecode')})
                        encode_ret = encodeStream(js_code, '/FlateDecode')
                        jsobj.stream = encode_ret[1] 
            #print cur_filter
            # construct PdfDict
            newobj = PdfDict({'/S':PdfName('JavaScript')})
            newobj['/JS'] = jsobj
            #PdfGenome.delete(src_entry, src_path[:-2])

        elif src_path == ['/Root', '/OpenAction', '/JS']:
            newobj = payload
            #PdfGenome.delete(src_entry, src_path[:-1])
        else:
            logger.debug("### this trigger swap not supported yet")
            return False

        PdfGenome.delete(src_entry, src_path[:-1])
        
        # everything in the target entry needs to exist
        # insert the new object to src_entry
        if tgt_path == '/Root/Pages/Kids/AA':
            # Semantically this is not enough
            if src_entry['/Root']['/Pages'] is None:
                tmpobj = PdfDict()
                src_entry['/Root']['/Pages'] = PdfDict({'/Count': 1, '/Type': PdfName('Pages'), '/Kids': PdfArray([tmpobj])})
            src_entry['/Root']['/Pages']['/Kids'][0]['/AA'] = PdfDict({'/O':newobj})
        elif tgt_path == '/Root/Names/JavaScript/Names':
	    if type(src_entry['/Root']['/Names']) == PdfDict:
		src_entry['/Root']['/Names']['/JavaScript']['/Names'].append('abc')
		src_entry['/Root']['/Names']['/JavaScript']['/Names'].append(newobj)
	    else:
		src_entry['/Root']['/Names'] = PdfDict({'/JavaScript': PdfDict({'/Names': PdfArray(['abc', newobj])})})
        elif tgt_path == '/Root/OpenAction/JS':
            src_entry['/Root']['/OpenAction'] = newobj
        elif tgt_path == '/Root/StructTreeRoot/JS':
            # Make StructTreeRoot
            src_entry['/Root']['/StructTreeRoot'] = newobj
            # Semantically this is not enough
            if src_entry['/Root']['/Pages'] is None:
                tmpobj = PdfDict()
                src_entry['/Root']['/Pages'] = PdfDict({'/Count': 1, '/Type': PdfName('Pages'), '/Kids': PdfArray([tmpobj])})
            # /Pages/Kids/AA link
            src_entry['/Root']['/Pages']['/Kids'][0]['/AA'] = PdfDict({'/O':newobj})
        else:
            logger.debug("### this trigger swap not supported yet")
            return False
        return True


    @staticmethod
    def insert(src_entry, src_path, tgt_entry, tgt_path):
        logger.debug("###insert %s after %s" % (str(tgt_path), str(src_path)))
    
        # we only need the src_key here in case it exists
        src_parent, src_key = PdfGenome.get_parent_key(src_entry, src_path)

        tgt_parent, tgt_key = PdfGenome.get_parent_key(tgt_entry, tgt_path)
        tgt_obj = tgt_parent[tgt_key]

        if not src_entry is tgt_entry:
            # TODO: RuntimeError: maximum recursion depth exceeded in cmp
            tgt_obj = deepcopy(tgt_obj)

        if isinstance(src_parent, list):
            src_parent.insert(src_key+1, tgt_obj)
        elif isinstance(src_parent, dict):
            # Same: ['/Size'], [PdfObject("/Size")]
            real_key = str(tgt_key) # it can be an integer.
            if "/" not in real_key:
                real_key = PdfObject("/"+real_key)
            src_parent[real_key] = tgt_obj
        
        return True
 
    @staticmethod
    def insert_under(src_entry, src_path, tgt_entry, tgt_path):
        logger.debug("###insert %s under %s" % (str(tgt_path), str(src_path)))
        
        src_parent, src_key = PdfGenome.get_parent_key(src_entry, src_path)

        src_obj = src_parent[src_key]

        tgt_parent, tgt_key = PdfGenome.get_parent_key(tgt_entry, tgt_path)
        tgt_obj = tgt_parent[tgt_key]

        if not src_entry is tgt_entry:
            # TODO: RuntimeError: maximum recursion depth exceeded in cmp
            tgt_obj = deepcopy(tgt_obj)

        if isinstance(src_obj, list):
            src_obj.insert(len(src_obj), tgt_obj)
        elif isinstance(src_obj, dict):
            real_key = str(tgt_key) # it can be an integer.
            if "/" not in real_key:
                real_key = PdfObject("/"+real_key)
            """
            if src_obj[real_key] != {}:
                newsrc = src_obj[real_key]
                if isinstance(newsrc, list):
                    src_obj[real_key].insert(len(newsrc), tgt_obj)
                if isinstance(newsrc, dict):
                    src_obj[real_key].update(tgt_obj)
            else:
                src_obj[real_key] = tgt_obj
            """
            src_obj[real_key] = tgt_obj
        
        return True
   
  

    @staticmethod
    def swap_change_feat(trie, src_entry, src_path, tgt_entry, tgt_path):
        # src_parent[src_key] = tgt_obj
        group_types = [pdfrw.pdfreader.PdfReader, pdfrw.objects.pdfdict.PdfDict, pdfrw.objects.pdfarray.PdfArray]
        src_parent, src_key = PdfGenome.get_parent_key(src_entry, src_path)
        src_obj = src_parent[src_key]

        tgt_parent, tgt_key = PdfGenome.get_parent_key(tgt_entry, tgt_path)
        tgt_obj = tgt_parent[tgt_key]
        #logger.debug("*** src_obj type: %s, tgt_obj type: %s" % (type(src_obj), type(tgt_obj)))
        # if src_obj and tgt_obj are both terminal, then it doesn't change feature.
        if type(src_obj) not in group_types and type(tgt_obj) not in group_types:
            return False
        # if src_obj is non-terminal and tgt_obj is, there is deletion involved, it changes feature.
        if type(tgt_obj) not in group_types:
            return True
        # if src_obj is terminal and tgt_obj is non-terminal, check whether insert changes feat
        if type(src_obj) not in group_types:
            try:
                references = tgt_obj.keys()
            except AttributeError:
                idx_refs = range(len(tgt_obj))
                references = []
                for ref in idx_refs:
                    child_obj = tgt_obj[ref]
                    if type(child_obj) not in group_types:
                        continue
                    else:
                        try:
                            references += child_obj.keys()
                        except AttributeError:
                            pass
            # need to remove all array indices
            src_parent_str = [item for item in src_path[:-1] if type(item) == str and item != '/Root']
            src_parent_path = '/'.join(src_parent_str)
            if src_parent_path == '':
                available_keys = trie._root.children.keys()
            else:
                available_keys = trie._get_node(src_parent_path)[0].children.keys()
            logger.debug("*** available_keys: %s, references: %s" % (available_keys, references))
            for reference in references:
                if reference in available_keys:
                    return True
            return False

    @staticmethod
    def insert_change_feat(trie, src_path, tgt_entry, tgt_path):
        group_types = [pdfrw.pdfreader.PdfReader, pdfrw.objects.pdfdict.PdfDict, pdfrw.objects.pdfarray.PdfArray]
        tgt_parent, tgt_key = PdfGenome.get_parent_key(tgt_entry, tgt_path)
        tgt_obj = tgt_parent[tgt_key]
        #logger.debug("*** tgt_obj type: %s" % type(tgt_obj))
        # src_path + whatever sub paths in tgt_obj should change the feature
        # terminal nodes don't make a difference
        if type(tgt_obj) not in group_types:
            return False
        else:
            # need to remove all array indices
            src_parent_str = [item for item in src_path[:-1] if type(item) == str and item != '/Root']
            src_parent_path = '/'.join(src_parent_str)
            if src_parent_path == '':
                available_keys = trie._root.children.keys()
            else:
                available_keys = trie._get_node(src_parent_path)[0].children.keys()
            logger.debug("*** available_keys: %s, tgt_key: %s" % (available_keys, tgt_key))
            if tgt_key in available_keys:
                return True
            # only need to check the first level keys in the kid tgt_obj
            # get "references"
            if type(tgt_obj) == pdfrw.objects.pdfarray.PdfArray:
                try:
                    references = tgt_obj.keys()
                except AttributeError:
                    idx_refs = range(len(tgt_obj))
                    references = []
                    for ref in idx_refs:
                        child_obj = tgt_obj[ref]
                        if type(child_obj) not in group_types:
                            continue
                        else:
                            try:
                                references += child_obj.keys()
                            except AttributeError:
                                pass
                logger.debug("*** available_keys: %s, references: %s" % (available_keys, references))
                for reference in references:
                    if reference in available_keys:
                        return True
            return False
    
    @staticmethod
    def find_insert_ext_id(ext_trie, src_path):
        ext_id = -1
        # INSERT DOES THIS: src_parent[real_key] = tgt_obj
        # need to remove all array indices
        src_parent_str = [item for item in src_path[:-1] if type(item) != int]
        src_parent_path = '/'.join(src_parent_str)
        try:
            ids = ext_trie[src_parent_path]
        except KeyError:
            #logger.debug('*** insert: nothing with the same prefix')
            return -1
        ext_id = random.choice(ids)
        return ext_id
    
    @staticmethod
    def find_swap_ext_id(ext_trie, src_entry, src_path, ext_genome):
        ext_id = -1
        # src_parent[src_key] = tgt_obj need to use the entire src_path
        # strongest swap first
        # use src_path to find candidate ext_id
        src_swap_str = [item for item in src_path if type(item) != int]
        src_swap_path = '/'.join(src_swap_str)
        try:
            ids = ext_trie[src_swap_path]
            ext_id = random.choice(ids)
        except KeyError:
            logger.debug('*** swap: nothing with the same prefix')
            pass
        if ext_id == -1:
            group_types = [pdfrw.pdfreader.PdfReader, pdfrw.objects.pdfdict.PdfDict, pdfrw.objects.pdfarray.PdfArray]
            src_parent, src_key = PdfGenome.get_parent_key(src_entry, src_path)
            src_obj = src_parent[src_key]
            # src_obj is non-terminal -> deletion
            if type(src_obj) in group_types:
                logger.debug('*** swap: src_object is non-terminal')
                # find a terminal
                for i in range(50):
                    ext_id = random.choice(range(len(ext_genome)))
                    tgt_entry, tgt_obj_path = ext_genome[ext_id]
                    tgt_parent, tgt_key = PdfGenome.get_parent_key(tgt_entry, tgt_obj_path)
                    tgt_obj = tgt_parent[tgt_key]
                    # tgt_obj is terminal
                    if type(tgt_obj) not in group_types:
                        return ext_id
                return -1
            # src_obj is terminal and cannot find something with the same prefix -> insertion
            else:
                logger.debug('*** swap: src_object is terminal')
                return -1
        return ext_id

    
    @staticmethod
    def mutation_deletion(entry, mut_prob, ext_genome, clone = False):
        if not entry:
            return False
        if clone == True:
            entry = deepcopy(entry)

        # visited path in string, updated after each mutation on node
        visited_paths = set()
        remaining_paths = list()
        remaining_paths = PdfGenome.get_object_paths(entry, visited_paths)
        trace = []

        while len(remaining_paths) > 0:
            op_obj_path = remaining_paths.pop(0)
            if random.uniform(0,1) <= mut_prob:
                op = 'delete'
                ext_id = random.choice(range(len(ext_genome)))
                tgt_entry, tgt_obj_path = ext_genome[ext_id]
                operation = (op, op_obj_path, ext_id)
                PdfGenome.delete(entry, op_obj_path)
                logger.debug("Perform %s" % str(operation))
                trace.append(operation)
                visited_paths.add(pickle.dumps(op_obj_path))
                # update remaining_paths in case changed by mutation
                remaining_paths = PdfGenome.get_object_paths(entry, visited_paths)
            visited_paths.add(pickle.dumps(op_obj_path))
        if entry.active_trace == None:
            entry.private.active_trace = trace
        else:
            entry.active_trace.extend(trace)
        return entry
    
    @staticmethod
    def mutation_deletion_with_trace(entry, mut_prob, ext_genome, clone = False):
        if not entry:
            return False
        if clone == True:
            entry = deepcopy(entry)
        
        past_delete = set([])
        trace = []
        # get insert and delete operations from the past trace
        if entry.active_trace == None:
            past_delete = set([])
        else:
            for operation in entry.active_trace:
                op, op_obj_path, ext_id = operation
                etgt_entry, tgt_obj_path = ext_genome[ext_id]
                past_delete.add(op_obj_path[1])

        visited_paths = set()
        remaining_paths = PdfGenome.get_object_paths(entry, visited_paths)
        for path in remaining_paths:
            if path[1] in past_delete:
                visited_paths.add(pickle.dumps(path))
        remaining_paths = PdfGenome.get_object_paths(entry, visited_paths)

        # visited path in string, updated after each mutation on node
        trace = []

        while len(remaining_paths) > 0:
            op_obj_path = remaining_paths.pop(0)
            if op_obj_path[1] in past_delete:
                continue
            if random.uniform(0,1) <= mut_prob:
                op = 'delete'
                ext_id = random.choice(range(len(ext_genome)))
                tgt_entry, tgt_obj_path = ext_genome[ext_id]
                operation = (op, op_obj_path, ext_id)
                PdfGenome.delete(entry, op_obj_path)
                logger.debug("Perform %s" % str(operation))
                trace.append(operation)
                visited_paths.add(pickle.dumps(op_obj_path))
                # update remaining_paths in case changed by mutation
                past_delete.add(op_obj_path[1])
                remaining_paths = PdfGenome.get_object_paths(entry, visited_paths)
            visited_paths.add(pickle.dumps(op_obj_path))
        if entry.active_trace == None:
            entry.private.active_trace = trace
        else:
            entry.active_trace.extend(trace)
        return entry
 
 
    @staticmethod
    def mutation_noinsert(ext_trie, entry, mut_prob, ext_genome, clone = False):
        if not entry:
            return False
        if clone == True:
            entry = deepcopy(entry)

        # visited path in string, updated after each mutation on node
        visited_paths = set()
        remaining_paths = list()
        remaining_paths = PdfGenome.get_object_paths(entry, visited_paths)
        trace = []

        ops = ['swap', 'delete']
        
        while len(remaining_paths) > 0:
            op_obj_path = remaining_paths.pop(0)
            #if op_obj_path[1] == 'OpenAction' and op_obj_path[-1] != 'Length':
            #    continue
            if random.uniform(0,1) <= mut_prob:
                no_swap = False
                done = False
                while not done:
                    # give up those that were unlucky for swap
                    if no_swap:
                        op = None
                    else:
                        op = random.choice(ops)

                    if op == 'delete':
                        ext_id = random.choice(range(len(ext_genome)))
                        tgt_entry, tgt_obj_path = ext_genome[ext_id]
                        operation = (op, op_obj_path, ext_id)
                        PdfGenome.delete(entry, op_obj_path)
                        logger.debug("Perform %s" % str(operation))
                        trace.append(operation)
                    elif op == 'swap':
                        ext_id = PdfGenome.find_swap_ext_id(ext_trie, entry, op_obj_path, ext_genome)
                        if ext_id == -1:
                            no_swap = True
                            continue
                        tgt_entry, tgt_obj_path = ext_genome[ext_id]
                        operation = (op, op_obj_path, ext_id)
                        PdfGenome.swap(entry, op_obj_path, tgt_entry, tgt_obj_path)
                        logger.debug("Perform %s" % str(operation))
                        trace.append(operation)
                    else:
                        logger.debug("No swap this path")
                    done = True
                visited_paths.add(pickle.dumps(op_obj_path))
                # update remaining_paths in case changed by mutation
                remaining_paths = PdfGenome.get_object_paths(entry, visited_paths)
            
            visited_paths.add(pickle.dumps(op_obj_path))
        if entry.active_trace == None:
            entry.private.active_trace = trace
        else:
            entry.active_trace.extend(trace)
        return entry
    
    
    @staticmethod
    def mutation_del_move(exploit_source, entry, mut_prob, ext_genome, clone = False):
        if not entry:
            return False
        if clone == True:
            entry = deepcopy(entry)

        # visited path in string, updated after each mutation on node
        visited_paths = set()
        remaining_paths = list()
        remaining_paths = PdfGenome.get_object_paths(entry, visited_paths)
        trace = []

        ops = ['move', 'delete']
        move_targets = ['/Root/Pages/Kids/AA', '/Root/Names/JavaScript/Names', '/Root/OpenAction/JS', '/Root/StructTreeRoot/JS']
        
        has_move = False
        while len(remaining_paths) > 0:
            op_obj_path = remaining_paths.pop(0)
            if random.uniform(0,1) <= mut_prob:
                if entry.active_trace == None:
                    if has_move is False:
                        op = random.choice(ops)
                    else:
                        op = 'delete'
                else:
                    if has_move is True:
                        op = 'delete'
                    else:
                        if entry.active_trace != None or len(trace) != 0:
                            for past_tr in entry.active_trace:
                                if past_tr[0] == 'move':
                                    op = 'delete'
                                    has_move = True
                            for past_tr in trace:
                                if past_tr[0] == 'move':
                                    op = 'delete'
                                    has_move = True
                        if has_move is False:
                            op = random.choice(ops)
                if op == 'delete':
                    ext_id = random.choice(range(len(ext_genome)))
                    tgt_entry, tgt_obj_path = ext_genome[ext_id]
                    operation = (op, op_obj_path, ext_id)
                    PdfGenome.delete(entry, op_obj_path)
                    logger.debug("Perform %s" % str(operation))
                    trace.append(operation)
                elif op == 'move' and (has_move is False):
                    cur_targets = [item for item in move_targets if item != exploit_source]
                    tgt_path = random.choice(cur_targets)
                    epath = ['/%s' % item for item in exploit_source.split('/')[1:]]
                    operation = (op, epath, tgt_path)
                    try:
                        ret = PdfGenome.move_exploit(entry, epath, tgt_path)
                    except Exception, e:
                        logger.debug("Move Exception: %s" % e)
                        continue
                    if ret is False:
                        continue
                    logger.debug("Perform %s" % str(operation))
                    visited_paths.add(pickle.dumps(epath[:-1]))
                    #visited_paths.add(pickle.dumps(epath))
                    trace.append(operation)
                    has_move = True
                visited_paths.add(pickle.dumps(op_obj_path))
                # update remaining_paths in case changed by mutation
                remaining_paths = PdfGenome.get_object_paths(entry, visited_paths)
            
            visited_paths.add(pickle.dumps(op_obj_path))
        if entry.active_trace == None:
            entry.private.active_trace = trace
        else:
            entry.active_trace.extend(trace)
        return entry
    
    #TODO: write this only with additional move
    @staticmethod
    def mutation_plus_move(ext_trie, entry, mut_prob, ext_genome, clone = False):
        if not entry:
            return False
        if clone == True:
            entry = deepcopy(entry)

        # visited path in string, updated after each mutation on node
        visited_paths = set()
        remaining_paths = list()
        remaining_paths = PdfGenome.get_object_paths(entry, visited_paths)
        trace = []

        ops = ['insert', 'swap', 'delete']
        
        # TODO: replaced with a collection of visited path for determining next node that should visit. (breadth-first traversal)
        while len(remaining_paths) > 0:
            op_obj_path = remaining_paths.pop(0)
            if random.uniform(0,1) <= mut_prob:
                no_insert = False
                no_swap = False
                done = False
                while not done:
                    # give up those that were unlucky for insert and swap
                    if no_insert and no_swap:
                        op = None
                    elif no_insert:
                        op = 'swap'
                    elif no_swap:
                        op = 'insert'
                    else:
                        op = random.choice(ops)

                    if op == 'delete':
                        ext_id = random.choice(range(len(ext_genome)))
                        tgt_entry, tgt_obj_path = ext_genome[ext_id]
                        operation = (op, op_obj_path, ext_id)
                        PdfGenome.delete(entry, op_obj_path)
                        logger.debug("Perform %s" % str(operation))
                        trace.append(operation)
                    elif op == 'insert':
                        ### select something we can insert with
                        ext_id = PdfGenome.find_insert_ext_id(ext_trie, op_obj_path)
                        if ext_id == -1:
                            no_insert = True
                            logger.debug('*** insert: nothing with the same prefix')
                            continue
                        tgt_entry, tgt_obj_path = ext_genome[ext_id]
                        operation = (op, op_obj_path, ext_id)
                        PdfGenome.insert(entry, op_obj_path, tgt_entry, tgt_obj_path)
                        logger.debug("Perform %s" % str(operation))
                        trace.append(operation)
                    elif op == 'swap':
                        ext_id = PdfGenome.find_swap_ext_id(ext_trie, entry, op_obj_path, ext_genome)
                        if ext_id == -1:
                            no_swap = True
                            continue
                        tgt_entry, tgt_obj_path = ext_genome[ext_id]
                        operation = (op, op_obj_path, ext_id)
                        PdfGenome.swap(entry, op_obj_path, tgt_entry, tgt_obj_path)
                        logger.debug("Perform %s" % str(operation))
                        trace.append(operation)
                    else:
                        logger.debug("No insert/swap this path")
                    done = True
                visited_paths.add(pickle.dumps(op_obj_path))
                # update remaining_paths in case changed by mutation
                remaining_paths = PdfGenome.get_object_paths(entry, visited_paths)
            
            visited_paths.add(pickle.dumps(op_obj_path))
        if entry.active_trace == None:
            entry.private.active_trace = trace
        else:
            entry.active_trace.extend(trace)
        return entry


    @staticmethod
    def mutation(ext_trie, entry, mut_prob, ext_genome, clone = False):
        if not entry:
            return False
        if clone == True:
            entry = deepcopy(entry)

        # visited path in string, updated after each mutation on node
        visited_paths = set()
        remaining_paths = list()
        remaining_paths = PdfGenome.get_object_paths(entry, visited_paths)
        trace = []

        ops = ['insert', 'swap', 'delete']
        
        # TODO: replaced with a collection of visited path for determining next node that should visit. (breadth-first traversal)
        while len(remaining_paths) > 0:
            op_obj_path = remaining_paths.pop(0)
            if random.uniform(0,1) <= mut_prob:
                no_insert = False
                no_swap = False
                done = False
                while not done:
                    # give up those that were unlucky for insert and swap
                    if no_insert and no_swap:
                        op = None
                    elif no_insert:
                        op = 'swap'
                    elif no_swap:
                        op = 'insert'
                    else:
                        op = random.choice(ops)

                    if op == 'delete':
                        ext_id = random.choice(range(len(ext_genome)))
                        tgt_entry, tgt_obj_path = ext_genome[ext_id]
                        operation = (op, op_obj_path, ext_id)
                        PdfGenome.delete(entry, op_obj_path)
                        logger.debug("Perform %s" % str(operation))
                        trace.append(operation)
                    elif op == 'insert':
                        ### select something we can insert with
                        ext_id = PdfGenome.find_insert_ext_id(ext_trie, op_obj_path)
                        if ext_id == -1:
                            no_insert = True
                            logger.debug('*** insert: nothing with the same prefix')
                            continue
                        tgt_entry, tgt_obj_path = ext_genome[ext_id]
                        operation = (op, op_obj_path, ext_id)
                        PdfGenome.insert(entry, op_obj_path, tgt_entry, tgt_obj_path)
                        logger.debug("Perform %s" % str(operation))
                        trace.append(operation)
                    elif op == 'swap':
                        ext_id = PdfGenome.find_swap_ext_id(ext_trie, entry, op_obj_path, ext_genome)
                        if ext_id == -1:
                            no_swap = True
                            continue
                        tgt_entry, tgt_obj_path = ext_genome[ext_id]
                        operation = (op, op_obj_path, ext_id)
                        PdfGenome.swap(entry, op_obj_path, tgt_entry, tgt_obj_path)
                        logger.debug("Perform %s" % str(operation))
                        trace.append(operation)
                    else:
                        logger.debug("No insert/swap this path")
                    done = True
                visited_paths.add(pickle.dumps(op_obj_path))
                # update remaining_paths in case changed by mutation
                remaining_paths = PdfGenome.get_object_paths(entry, visited_paths)
            
            visited_paths.add(pickle.dumps(op_obj_path))
        if entry.active_trace == None:
            entry.private.active_trace = trace
        else:
            entry.active_trace.extend(trace)
        return entry
    
    """
    Return if the current path is a prefix for the exploit path.
    """
    @staticmethod
    def is_prefix(path, exploit_paths):
        for epath in exploit_paths:
            try:
                if ''.join([str(k) for k in epath]).startswith(''.join([str(k) for k in path])):
                    return True
            except Exception:
                pass
        return False

    @staticmethod
    def mutation_with_trace(ext_trie, entry, mut_prob, ext_genome, clone = False):
        if not entry:
            return False
        if clone == True:
            entry = deepcopy(entry)
    
        # initially , all paths are remaining_paths
        remaining_paths = PdfGenome.get_object_paths(entry)

        past_insert = set([])
        past_delete = set([])
        trace = []
        # get insert and delete operations from the past trace
        if entry.active_trace == None:
            past_insert = set([])
            past_delete = set([])
        else:
            for operation in entry.active_trace:
                op, op_obj_path, ext_id = operation
                etgt_entry, tgt_obj_path = ext_genome[ext_id]
                if op == 'insert':
                    past_insert.add(op_obj_path[1])
                elif op == 'delete':
                    past_delete.add(op_obj_path[1])
                elif op == 'swap':
                    past_delete.add(op_obj_path[1])
                    past_insert.add(op_obj_path[1])

        insert_visited_paths = set()
        for path in remaining_paths:
            if path[1] in past_insert:
                insert_visited_paths.add(pickle.dumps(path))
        insert_remaining_paths = PdfGenome.get_object_paths(entry, insert_visited_paths)
        
        delete_visited_paths = set()
        for path in remaining_paths:
            if path[1] in past_delete:
                delete_visited_paths.add(pickle.dumps(path))
        delete_remaining_paths = PdfGenome.get_object_paths(entry, delete_visited_paths)
        
        ### 2. Deletion
        # visited path in string, updated after each mutation on node
        no_delete = True
        while len(delete_remaining_paths) > 0:
            op_obj_path = delete_remaining_paths.pop(0)
            ### NEW 20190714. try adding this. Does it make a difference?
            ### Within the same round, multiple things from the same subtree cannot be deleted.
            if op_obj_path[1] in past_delete:
                delete_visited_paths.add(pickle.dumps(op_obj_path))
                delete_remaining_paths = PdfGenome.get_object_paths(entry, delete_visited_paths)
                continue
            new_mut_prob = mut_prob/2
            if random.uniform(0,1) <= new_mut_prob:
                op = 'delete'
                ext_id = random.choice(range(len(ext_genome)))
                operation = (op, op_obj_path, ext_id)
                PdfGenome.delete(entry, op_obj_path)
                logger.debug("Perform %s" % str(operation))
                no_delete = False
                trace.append(operation)
                # update remaining_paths in case changed by mutation
                delete_visited_paths.add(pickle.dumps(op_obj_path))
                delete_remaining_paths = PdfGenome.get_object_paths(entry, delete_visited_paths)
            delete_visited_paths.add(pickle.dumps(op_obj_path))
        
        ### 1. Insertion.
        # Remove the random.uniform(0, 1), enforce that the first few with ext_id will be inserted.
        no_insert = True
        while len(insert_remaining_paths) > 0:
            op_obj_path = insert_remaining_paths.pop(0)
            if random.uniform(0,1) <= mut_prob/2:
                op = 'insert'
                ### select something we can insert with
                ext_id = PdfGenome.find_insert_ext_id(ext_trie, op_obj_path)
                if ext_id == -1:
                    continue
                else:
                    no_insert = False
                tgt_entry, tgt_obj_path = ext_genome[ext_id]
                operation = (op, op_obj_path, ext_id)
                PdfGenome.insert(entry, op_obj_path, tgt_entry, tgt_obj_path)
                logger.debug("Perform %s" % str(operation))
                trace.append(operation)
                past_insert.add(op_obj_path[1])

        if no_insert is True:
            logger.debug('*** insert: nothing with the same prefix')

        if entry.active_trace == None:
            entry.private.active_trace = trace
        else:
            entry.active_trace.extend(trace)

        return entry

    @staticmethod
    def mutation_with_trace_lessrand(ext_trie, entry, mut_prob, ext_genome, clone = False):
        if not entry:
            return False
        if clone == True:
            entry = deepcopy(entry)
    
        # initially , all paths are remaining_paths
        remaining_paths = PdfGenome.get_object_paths(entry)
        
        past_insert = set([])
        past_delete = set([])
        trace = []
        # get insert and delete operations from the past trace
        if entry.active_trace == None:
            past_insert = set([])
            past_delete = set([])
        else:
            for operation in entry.active_trace:
                op, op_obj_path, ext_id = operation
                etgt_entry, tgt_obj_path = ext_genome[ext_id]
                if op == 'insert':
                    past_insert.add(op_obj_path[1])
                    # NEW: do not waste effort to delete something we inserted
                    past_delete.add(op_obj_path[1])
                elif op == 'delete':
                    past_delete.add(op_obj_path[1])
                elif op == 'swap':
                    past_delete.add(op_obj_path[1])
                    past_insert.add(op_obj_path[1])

        insert_visited_paths = set()
        for path in remaining_paths:
            if path[1] in past_insert:
                insert_visited_paths.add(pickle.dumps(path))
        insert_remaining_paths = PdfGenome.get_object_paths(entry, insert_visited_paths)
        delete_visited_paths = set()
        for path in remaining_paths:
            if path[1] in past_delete:
                delete_visited_paths.add(pickle.dumps(path))
        delete_remaining_paths = PdfGenome.get_object_paths(entry, delete_visited_paths)

        ### 2. Deletion
        # visited path in string, updated after each mutation on node
        no_delete = True
        #random.shuffle(delete_remaining_paths)
        while len(delete_remaining_paths) > 0:
            op_obj_path = delete_remaining_paths.pop(0)
            ### NEW 20190714. try removing this. Does it make a difference?
            ### Within the same round, multiple things from the same subtree can be deleted.
            if op_obj_path[1] in past_delete:
                delete_visited_paths.add(pickle.dumps(op_obj_path))
                delete_remaining_paths = PdfGenome.get_object_paths(entry, delete_visited_paths)
                continue
            if random.uniform(0,1) <= mut_prob/2:
                op = 'delete'
                ext_id = random.choice(range(len(ext_genome)))
                operation = (op, op_obj_path, ext_id)
                PdfGenome.delete(entry, op_obj_path)
                logger.debug("Perform %s" % str(operation))
                no_delete = False
                trace.append(operation)
                # update remaining_paths in case changed by mutation
                past_delete.add(op_obj_path[1])
                delete_visited_paths.add(pickle.dumps(op_obj_path))
                delete_remaining_paths = PdfGenome.get_object_paths(entry, delete_visited_paths)
            delete_visited_paths.add(pickle.dumps(op_obj_path))
        #logger.debug("*** Total %s deletions..." % half)

        ### 1. Insertion.
        # Remove the random.uniform(0, 1), enforce that the first few with ext_id will be inserted.
        # try adding back some randomness.
        no_insert = True
        #logger.debug("*** Maximum %s insertions left..." % half)
        #random.shuffle(insert_remaining_paths)
        while len(insert_remaining_paths) > 0:
            op_obj_path = insert_remaining_paths.pop(0)
            if op_obj_path[1] in past_insert:
                # TODO: run the version without the extra inserted paths
                #insert_visited_paths.add(pickle.dumps(op_obj_path))
                #insert_remaining_paths = PdfGenome.get_object_paths(entry, insert_visited_paths)
                continue
            # TODO: change to mut_prob/2
            if random.uniform(0,1) <= mut_prob:
                op = 'insert'
                ### select something we can insert with
                ext_id = PdfGenome.find_insert_ext_id(ext_trie, op_obj_path)
                if ext_id == -1:
                    continue
                else:
                    no_insert = False
                tgt_entry, tgt_obj_path = ext_genome[ext_id]
                operation = (op, op_obj_path, ext_id)
                PdfGenome.insert(entry, op_obj_path, tgt_entry, tgt_obj_path)
                logger.debug("Perform %s" % str(operation))
                trace.append(operation)
                past_insert.add(op_obj_path[1])

        if no_insert is True:
            logger.debug('*** insert: nothing with the same prefix')

        if entry.active_trace == None:
            entry.private.active_trace = trace
        else:
            entry.active_trace.extend(trace)


        return entry


    @staticmethod
    def mutation_with_trace_evenlessrand(ext_trie, exploit_paths, entry, mut_prob, ext_genome, clone = False):
        if not entry:
            return False
        if clone == True:
            entry = deepcopy(entry)
    
        # initially , all paths are remaining_paths
        remaining_paths = PdfGenome.get_object_paths(entry)
        
        past_insert = set([])
        past_delete = set([])
        trace = []
        # get insert and delete operations from the past trace
        if entry.active_trace == None:
            past_insert = set([])
            past_delete = set([])
        else:
            for operation in entry.active_trace:
                op, op_obj_path, ext_id = operation
                etgt_entry, tgt_obj_path = ext_genome[ext_id]
                if op == 'insert':
                    past_insert.add(op_obj_path[1])
                elif op == 'delete':
                    # remove everything under the same prefix of op_obj_path from the adaptive knowledge.
                    #if not PdfGenome.is_prefix(op_obj_path, exploit_paths):
                    past_delete.add(op_obj_path[1])
                elif op == 'swap':
                    #if not PdfGenome.is_prefix(op_obj_path, exploit_paths):
                    past_delete.add(op_obj_path[1])
                    past_insert.add(op_obj_path[1])

        insert_visited_paths = set()
        for path in remaining_paths:
            if path[1] in past_insert:
                insert_visited_paths.add(pickle.dumps(path))
        insert_remaining_paths = PdfGenome.get_object_paths(entry, insert_visited_paths)
        delete_visited_paths = set()
        for path in remaining_paths:
            if path[1] in past_delete:
                delete_visited_paths.add(pickle.dumps(path))
        delete_remaining_paths = PdfGenome.get_object_paths(entry, delete_visited_paths)

        ### 2. Deletion
        # visited path in string, updated after each mutation on node
        no_delete = True
        random.shuffle(delete_remaining_paths)
        half = len(delete_remaining_paths) * mut_prob/2
        while len(delete_remaining_paths) > 0:
            op_obj_path = delete_remaining_paths.pop(0)
            if op_obj_path[1] in past_delete:
                delete_visited_paths.add(pickle.dumps(op_obj_path))
                delete_remaining_paths = PdfGenome.get_object_paths(entry, delete_visited_paths)
                continue
            if random.uniform(0,1) <= mut_prob/2:
                op = 'delete'
                ext_id = random.choice(range(len(ext_genome)))
                operation = (op, op_obj_path, ext_id)
                PdfGenome.delete(entry, op_obj_path)
                logger.debug("Perform %s" % str(operation))
                no_delete = False
                trace.append(operation)
                # update remaining_paths in case changed by mutation
                past_delete.add(op_obj_path[1])
                delete_visited_paths.add(pickle.dumps(op_obj_path))
                delete_remaining_paths = PdfGenome.get_object_paths(entry, delete_visited_paths)
            delete_visited_paths.add(pickle.dumps(op_obj_path))
        #logger.debug("*** Total %s deletions..." % half)
        
        ### TODO: this is bug
        if entry.active_trace == None:
            entry.private.active_trace = trace
        else:
            entry.active_trace.extend(trace)

        ### 1. Insertion.
        # Remove the random.uniform(0, 1), enforce that the first few with ext_id will be inserted.
        # try adding back some randomness.
        no_insert = True
        # get insertable paths first
        actual_insert_remaining_paths = []
        while len(insert_remaining_paths) > 0:
            op_obj_path = insert_remaining_paths.pop(0)
            ext_id = PdfGenome.find_insert_ext_id(ext_trie, op_obj_path)
            if ext_id != -1:
                actual_insert_remaining_paths.append(op_obj_path)

        logger.debug("*** actual_insert_remaining_paths %d ..." % len(actual_insert_remaining_paths))
        random.shuffle(actual_insert_remaining_paths)
        while len(actual_insert_remaining_paths) > 0:
            #if half <= 0:
            #    break
            op_obj_path = actual_insert_remaining_paths.pop(0)
            if op_obj_path[1] in past_insert:
                #insert_visited_paths.add(pickle.dumps(op_obj_path))
                #actual_insert_remaining_paths = PdfGenome.get_object_paths(entry, insert_visited_paths)
                continue
            if random.uniform(0,1) <= mut_prob:
                op = 'insert'
                ### select something we can insert with
                ext_id = PdfGenome.find_insert_ext_id(ext_trie, op_obj_path)
                if ext_id == -1:
                    continue
                else:
                    no_insert = False
                tgt_entry, tgt_obj_path = ext_genome[ext_id]
                operation = (op, op_obj_path, ext_id)
                PdfGenome.insert(entry, op_obj_path, tgt_entry, tgt_obj_path)
                logger.debug("Perform %s" % str(operation))
                trace.append(operation)
                past_insert.add(op_obj_path[1])
                insert_visited_paths.add(pickle.dumps(op_obj_path))
                #actual_insert_remaining_paths = PdfGenome.get_object_paths(entry, insert_visited_paths)
                #half -= 1

        if no_insert is True:
            logger.debug('*** insert: nothing inserted')

        return entry




    @staticmethod
    def mutation_with_trace_inswap(ext_trie, entry, mut_prob, ext_genome, clone = False):
        if not entry:
            return False
        if clone == True:
            entry = deepcopy(entry)
    
        # initially , all paths are remaining_paths
        remaining_paths = PdfGenome.get_object_paths(entry)

        past_insert = set([])
        past_delete = set([])
        trace = []
        # get insert and delete operations from the past trace
        if entry.active_trace == None:
            past_insert = set([])
            past_delete = set([])
        else:
            for operation in entry.active_trace:
                op, op_obj_path, ext_id = operation
                etgt_entry, tgt_obj_path = ext_genome[ext_id]
                if op == 'insert':
                    past_insert.add(op_obj_path[1])
                    # NEW: do not waste effort to delete something we inserted
                    past_delete.add(op_obj_path[1])
                elif op == 'delete':
                    # remove everything under the same prefix of op_obj_path from the adaptive knowledge.
                    #if not PdfGenome.is_prefix(op_obj_path, exploit_paths):
                    past_delete.add(op_obj_path[1])
                elif op == 'swap':
                    #if not PdfGenome.is_prefix(op_obj_path, exploit_paths):
                    past_delete.add(op_obj_path[1])
                    past_insert.add(op_obj_path[1])

        insert_visited_paths = set()
        for path in remaining_paths:
            if path[1] in past_insert:
                insert_visited_paths.add(pickle.dumps(path))
        insert_remaining_paths = PdfGenome.get_object_paths(entry, insert_visited_paths)
        
        delete_visited_paths = set()
        for path in remaining_paths:
            if path[1] in past_delete:
                delete_visited_paths.add(pickle.dumps(path))
        delete_remaining_paths = PdfGenome.get_object_paths(entry, delete_visited_paths)
        
        ### 2. Deletion
        # visited path in string, updated after each mutation on node
        no_delete = True
        while len(delete_remaining_paths) > 0:
            op_obj_path = delete_remaining_paths.pop(0)
            if op_obj_path[1] in past_delete:
                continue
            new_mut_prob = mut_prob/3
            if random.uniform(0,1) <= new_mut_prob:
                op = 'delete'
                ext_id = random.choice(range(len(ext_genome)))
                operation = (op, op_obj_path, ext_id)
                PdfGenome.delete(entry, op_obj_path)
                logger.debug("Perform %s" % str(operation))
                no_delete = False
                trace.append(operation)
                # update remaining_paths in case changed by mutation
                past_delete.add(op_obj_path[1])
                delete_visited_paths.add(pickle.dumps(op_obj_path))
                delete_remaining_paths = PdfGenome.get_object_paths(entry, delete_visited_paths)
            delete_visited_paths.add(pickle.dumps(op_obj_path))


        ### 1. Insertion
        no_insert = True
        no_swap = True
        while len(insert_remaining_paths) > 0:
            op_obj_path = insert_remaining_paths.pop(0)
            if op_obj_path[1] in past_insert:
                continue
            if random.uniform(0,1) <= mut_prob*2/3:
                op = random.choice(['insert', 'swap'])
                if op == 'insert':
                    ### select something we can insert with
                    ext_id = PdfGenome.find_insert_ext_id(ext_trie, op_obj_path)
                    if ext_id == -1:
                        continue
                    else:
                        no_insert = False
                    tgt_entry, tgt_obj_path = ext_genome[ext_id]
                    operation = (op, op_obj_path, ext_id)
                    PdfGenome.insert(entry, op_obj_path, tgt_entry, tgt_obj_path)
                    logger.debug("Perform %s" % str(operation))
                    trace.append(operation)
                else:
                    ext_id = PdfGenome.find_swap_ext_id(ext_trie, entry, op_obj_path, ext_genome)
                    if ext_id == -1:
                        continue
                    no_swap = False
                    tgt_entry, tgt_obj_path = ext_genome[ext_id]
                    operation = (op, op_obj_path, ext_id)
                    PdfGenome.swap(entry, op_obj_path, tgt_entry, tgt_obj_path)
                    logger.debug("Perform %s" % str(operation))
                    trace.append(operation)
                    #delete_visited_paths.add(pickle.dumps(op_obj_path))
                    #delete_remaining_paths = PdfGenome.get_object_paths(entry, delete_visited_paths)
                past_insert.add(op_obj_path[1])
                # update remaining_paths in case changed by mutation
                #insert_visited_paths.add(pickle.dumps(op_obj_path))
                #insert_remaining_paths = PdfGenome.get_object_paths(entry, insert_visited_paths)
            #insert_visited_paths.add(pickle.dumps(op_obj_path))

        if no_insert is True:
            logger.debug('*** insert: nothing with the same prefix')

        if no_swap is True:
            logger.debug('*** swap: nothing')

        if entry.active_trace == None:
            entry.private.active_trace = trace
        else:
            entry.active_trace.extend(trace)

        return entry


    @staticmethod
    def mutation_with_trace_swap(ext_trie, entry, mut_prob, ext_genome, clone = False):
        if not entry:
            return False
        if clone == True:
            entry = deepcopy(entry)

        # visited path in string, updated after each mutation on node
        visited_paths = set()
        remaining_paths = PdfGenome.get_object_paths(entry, visited_paths)
        trace = []

        past_insert = set([])
        past_delete = set([])
        # get insert and delete operations from the past trace
        if entry.active_trace == None:
            past_insert = set([])
            past_delete = set([])
        else:
            for operation in entry.active_trace:
                op, op_obj_path, ext_id = operation
                etgt_entry, tgt_obj_path = ext_genome[ext_id]
                if op == 'insert':
                    past_insert.add(op_obj_path[1])
                    # NEW: do not waste effort to delete something we inserted
                    # 20190715 & 20190726: remove this
                    # v2: 20190726: adding this back
                    past_delete.add(op_obj_path[1])
                elif op == 'delete':
                    # remove everything under the same prefix of op_obj_path from the adaptive knowledge.
                    past_delete.add(op_obj_path[1])
                # 20190726: try removing this restriction
                #elif op == 'swap':
                #    past_delete.add(op_obj_path[1])
                #    past_insert.add(op_obj_path[1])
        
        ops = ['insert', 'swap', 'delete']
        
        while len(remaining_paths) > 0:
            op_obj_path = remaining_paths.pop(0)
            if random.uniform(0,1) <= mut_prob:
                no_delete = False
                no_insert = False
                no_swap = False
                done = False
                # four cases. make an operation choice.
                subtree = op_obj_path[1]
                if subtree in past_insert and subtree in past_delete:
                    # 20190726 v2: change this back
                    op = 'swap'
                    # 20190726: try this
                    #op = random.choice(ops)
                elif subtree in past_insert and subtree not in past_delete:
                    #no_insert = True
                    op = 'delete'
                elif subtree in past_delete and subtree not in past_insert:
                    #no_delete = True
                    op = 'insert'
                else:
                    op = random.choice(ops)
                first = True
                while not done:
                    if not first:
                        # 20190726: consider removing this part.
                        if no_insert and no_swap:
                            op = None
                        elif no_insert:
                            op = 'swap'
                        elif no_swap:
                            op = 'insert'
                        else:
                            op = random.choice(ops)
                            #op = None
                    first = False

                    if op == 'delete':
                        ext_id = random.choice(range(len(ext_genome)))
                        tgt_entry, tgt_obj_path = ext_genome[ext_id]
                        operation = (op, op_obj_path, ext_id)
                        PdfGenome.delete(entry, op_obj_path)
                        logger.debug("Perform %s" % str(operation))
                        trace.append(operation)
                        # keep track of deletion
                        past_delete.add(op_obj_path[1])
                        #delete_visited_paths.add(pickle.dumps(op_obj_path))
                        #delete_remaining_paths = PdfGenome.get_object_paths(entry, delete_visited_paths)
                    elif op == 'insert':
                        ### select something we can insert with
                        ext_id = PdfGenome.find_insert_ext_id(ext_trie, op_obj_path)
                        if ext_id == -1:
                            no_insert = True
                            logger.debug('*** insert: nothing with the same prefix')
                            continue
                        tgt_entry, tgt_obj_path = ext_genome[ext_id]
                        operation = (op, op_obj_path, ext_id)
                        PdfGenome.insert(entry, op_obj_path, tgt_entry, tgt_obj_path)
                        logger.debug("Perform %s" % str(operation))
                        trace.append(operation)
                        # keep track of insertion
                        past_insert.add(op_obj_path[1])
                        #insert_visited_paths.add(pickle.dumps(op_obj_path))
                        #insert_remaining_paths = PdfGenome.get_object_paths(entry, insert_visited_paths)
                    elif op == 'swap':
                        ### TEST THIS
                        ext_id = PdfGenome.find_swap_ext_id(ext_trie, entry, op_obj_path, ext_genome)
                        if ext_id == -1:
                            no_swap = True
                            continue
                        tgt_entry, tgt_obj_path = ext_genome[ext_id]
                        operation = (op, op_obj_path, ext_id)
                        PdfGenome.swap(entry, op_obj_path, tgt_entry, tgt_obj_path)
                        logger.debug("Perform %s" % str(operation))
                        trace.append(operation)
                        # keep track of both deletion and insertion
                        #delete_visited_paths.add(pickle.dumps(op_obj_path))
                        #delete_remaining_paths = PdfGenome.get_object_paths(entry, delete_visited_paths)
                        #insert_visited_paths.add(pickle.dumps(op_obj_path))
                        #insert_remaining_paths = PdfGenome.get_object_paths(entry, insert_visited_paths)
                    else:
                        logger.debug("No insert/swap this path")
                    done = True
                visited_paths.add(pickle.dumps(op_obj_path))
                # update remaining_paths
                remaining_paths = PdfGenome.get_object_paths(entry, visited_paths)
            
            visited_paths.add(pickle.dumps(op_obj_path))
        if entry.active_trace == None:
            entry.private.active_trace = trace
        else:
            entry.active_trace.extend(trace)
        return entry
 
 
    @staticmethod
    def mutation_with_trace_swap_move(exploit_source, ext_trie, entry, mut_prob, ext_genome, clone = False):
        if not entry:
            return False
        if clone == True:
            entry = deepcopy(entry)

        # visited path in string, updated after each mutation on node
        visited_paths = set()
        remaining_paths = PdfGenome.get_object_paths(entry, visited_paths)
        trace = []

        ops = ['insert', 'swap', 'delete', 'move']
        simpleops = ['insert', 'swap', 'delete']
        move_targets = ['/Root/Pages/Kids/AA', '/Root/Names/JavaScript/Names', '/Root/OpenAction/JS', '/Root/StructTreeRoot/JS']
        
        has_move = False
        past_insert = set([])
        past_delete = set([])
        # get insert and delete operations from the past trace
        if entry.active_trace == None:
            past_insert = set([])
            past_delete = set([])
        else:
            for operation in entry.active_trace:
                op, op_obj_path, ext_id = operation
                etgt_entry, tgt_obj_path = ext_genome[ext_id]
                if op == 'insert':
                    past_insert.add(op_obj_path[1])
                    # NEW: do not waste effort to delete something we inserted
                    # 20190715 & 20190726: remove this
                    # v2: 20190726: adding this back
                    past_delete.add(op_obj_path[1])
                elif op == 'delete':
                    # remove everything under the same prefix of op_obj_path from the adaptive knowledge.
                    past_delete.add(op_obj_path[1])
                # exploit_source matches op_obj_path
                elif op == 'move':
                    str_path = ''.join(['/'+str(item) if type(item) == int else item for item in op_obj_path])
                    if exploit_source == op_obj_path:
                        has_move = True
                    past_delete.add(op_obj_path[1])
                # 20190726: try removing this restriction
                #elif op == 'swap':
                #    past_delete.add(op_obj_path[1])
                #    past_insert.add(op_obj_path[1])
        
        while len(remaining_paths) > 0:
            op_obj_path = remaining_paths.pop(0)
            if random.uniform(0,1) <= mut_prob:
                no_delete = False
                no_insert = False
                no_swap = False
                done = False
                # four cases. make an operation choice.
                subtree = op_obj_path[1]
                if subtree in past_insert and subtree in past_delete:
                    if not has_move:
                        op = random.choice(['swap', 'move'])
                    else:
                        op = 'swap'
                    # 20190726 v2: change this back
                    #op = 'swap'
                    # 20190726: try this
                    #op = random.choice(ops)
                elif subtree in past_insert and subtree not in past_delete:
                    #no_insert = True
                    op = 'delete'
                elif subtree in past_delete and subtree not in past_insert:
                    #no_delete = True
                    op = 'insert'
                else:
                    if has_move:
                        op = random.choice(simpleops)
                    else:
                        op = random.choice(ops)
                first = True
                while not done:
                    if not first:
                        # 20190726: consider removing this part.
                        if no_insert and no_swap:
                            op = None
                        elif no_insert:
                            op = 'swap'
                        elif no_swap:
                            op = 'insert'
                        else:
                            op = random.choice(ops)
                            #op = None
                    first = False

                    if op == 'delete':
                        ext_id = random.choice(range(len(ext_genome)))
                        tgt_entry, tgt_obj_path = ext_genome[ext_id]
                        operation = (op, op_obj_path, ext_id)
                        try:
                            PdfGenome.delete(entry, op_obj_path)
                        except Exception, e:
                            logger.debug("Delete Exception: %s" % e)
                            continue
                        logger.debug("Perform %s" % str(operation))
                        trace.append(operation)
                        # keep track of deletion
                        past_delete.add(op_obj_path[1])
                        #delete_visited_paths.add(pickle.dumps(op_obj_path))
                        #delete_remaining_paths = PdfGenome.get_object_paths(entry, delete_visited_paths)
                    elif op == 'insert':
                        ### select something we can insert with
                        ext_id = PdfGenome.find_insert_ext_id(ext_trie, op_obj_path)
                        if ext_id == -1:
                            no_insert = True
                            logger.debug('*** insert: nothing with the same prefix')
                            continue
                        tgt_entry, tgt_obj_path = ext_genome[ext_id]
                        operation = (op, op_obj_path, ext_id)
                        PdfGenome.insert(entry, op_obj_path, tgt_entry, tgt_obj_path)
                        logger.debug("Perform %s" % str(operation))
                        trace.append(operation)
                        # keep track of insertion
                        past_insert.add(op_obj_path[1])
                    elif op == 'swap':
                        ### TEST THIS
                        ext_id = PdfGenome.find_swap_ext_id(ext_trie, entry, op_obj_path, ext_genome)
                        if ext_id == -1:
                            no_swap = True
                            continue
                        tgt_entry, tgt_obj_path = ext_genome[ext_id]
                        operation = (op, op_obj_path, ext_id)
                        PdfGenome.swap(entry, op_obj_path, tgt_entry, tgt_obj_path)
                        logger.debug("Perform %s" % str(operation))
                        trace.append(operation)
                    elif op == 'move' and (has_move is False):
                        cur_targets = [item for item in move_targets if item != exploit_source]
                        tgt_path = random.choice(cur_targets)
                        epath = ['/%s' % item for item in exploit_source.split('/')[1:]]
                        operation = (op, epath, tgt_path)
                        try:
                            ret = PdfGenome.move_exploit(entry, epath, tgt_path)
                        except Exception, e:
                            logger.debug("Move Exception: %s" % e)
                            continue
                        if ret is False:
                            continue
                        logger.debug("Perform %s" % str(operation))
                        visited_paths.add(pickle.dumps(epath[:-1]))
                        #visited_paths.add(pickle.dumps(epath))
                        trace.append(operation)
                        has_move = True
                        past_delete.add(op_obj_path[1])
                    else:
                        logger.debug("No op for this path")
                    done = True
                visited_paths.add(pickle.dumps(op_obj_path))
                # update remaining_paths
                remaining_paths = PdfGenome.get_object_paths(entry, visited_paths)
            
            visited_paths.add(pickle.dumps(op_obj_path))
        if entry.active_trace == None:
            entry.private.active_trace = trace
        else:
            entry.active_trace.extend(trace)
        return entry
 
    @staticmethod
    def mutation_with_trace_swap_move_v2(exploit_source, ext_trie, entry, mut_prob, ext_genome, clone = False):
        if not entry:
            return False
        if clone == True:
            entry = deepcopy(entry)

        # visited path in string, updated after each mutation on node
        visited_paths = set()
        remaining_paths = PdfGenome.get_object_paths(entry, visited_paths)
        trace = []

        ops = ['insert', 'swap', 'delete', 'move']
        simpleops = ['insert', 'swap', 'delete']
        move_targets = ['/Root/Pages/Kids/AA', '/Root/Names/JavaScript/Names', '/Root/OpenAction/JS', '/Root/StructTreeRoot/JS']
        
        has_move = False
        past_insert = set([])
        past_delete = set([])
        # get insert and delete operations from the past trace
        if entry.active_trace == None:
            past_insert = set([])
            past_delete = set([])
        else:
            for operation in entry.active_trace:
                op, op_obj_path, ext_id = operation
                etgt_entry, tgt_obj_path = ext_genome[ext_id]
                if op == 'insert':
                    past_insert.add(op_obj_path[1])
                    past_delete.add(op_obj_path[1])
                elif op == 'delete':
                    # remove everything under the same prefix of op_obj_path from the adaptive knowledge.
                    past_delete.add(op_obj_path[1])
                # exploit_source matches op_obj_path
                elif op == 'move':
                    str_path = ''.join(['/'+str(item) if type(item) == int else item for item in op_obj_path])
                    if exploit_source == op_obj_path:
                        has_move = True
        
        while len(remaining_paths) > 0:
            op_obj_path = remaining_paths.pop(0)
            if random.uniform(0,1) <= mut_prob:
                no_delete = False
                no_insert = False
                no_swap = False
                done = False
                # four cases. make an operation choice.
                subtree = op_obj_path[1]
                if subtree in past_insert and subtree in past_delete:
                    if not has_move:
                        op = random.choice(['swap', 'move'])
                    else:
                        op = 'swap'
                elif subtree in past_insert and subtree not in past_delete:
                    if not has_move:
                        op = random.choice(['swap', 'delete', 'move'])
                    else:
                        op = random.choice(['swap', 'delete'])
                    #op = 'delete'
                elif subtree in past_delete and subtree not in past_insert:
                    if not has_move:
                        op = random.choice(['swap', 'insert', 'move'])
                    else:
                        op = random.choice(['swap', 'insert'])
                    #op = 'insert'
                else:
                    if has_move:
                        op = random.choice(simpleops)
                    else:
                        op = random.choice(ops)
                first = True
                while not done:
                    if not first:
                        # 20190726: consider removing this part.
                        if no_insert and no_swap:
                            op = None
                        elif no_insert:
                            op = 'swap'
                        elif no_swap:
                            op = 'insert'
                        else:
                            op = random.choice(ops)
                            #op = None
                    first = False

                    if op == 'delete':
                        ext_id = random.choice(range(len(ext_genome)))
                        tgt_entry, tgt_obj_path = ext_genome[ext_id]
                        operation = (op, op_obj_path, ext_id)
                        PdfGenome.delete(entry, op_obj_path)
                        logger.debug("Perform %s" % str(operation))
                        trace.append(operation)
                        # keep track of deletion
                        past_delete.add(op_obj_path[1])
                        #delete_visited_paths.add(pickle.dumps(op_obj_path))
                        #delete_remaining_paths = PdfGenome.get_object_paths(entry, delete_visited_paths)
                    elif op == 'insert':
                        ### select something we can insert with
                        ext_id = PdfGenome.find_insert_ext_id(ext_trie, op_obj_path)
                        if ext_id == -1:
                            no_insert = True
                            logger.debug('*** insert: nothing with the same prefix')
                            continue
                        tgt_entry, tgt_obj_path = ext_genome[ext_id]
                        operation = (op, op_obj_path, ext_id)
                        PdfGenome.insert(entry, op_obj_path, tgt_entry, tgt_obj_path)
                        logger.debug("Perform %s" % str(operation))
                        trace.append(operation)
                        # keep track of insertion
                        past_insert.add(op_obj_path[1])
                    elif op == 'swap':
                        ### TEST THIS
                        ext_id = PdfGenome.find_swap_ext_id(ext_trie, entry, op_obj_path, ext_genome)
                        if ext_id == -1:
                            no_swap = True
                            continue
                        tgt_entry, tgt_obj_path = ext_genome[ext_id]
                        operation = (op, op_obj_path, ext_id)
                        PdfGenome.swap(entry, op_obj_path, tgt_entry, tgt_obj_path)
                        logger.debug("Perform %s" % str(operation))
                        trace.append(operation)
                    elif op == 'move' and (has_move is False):
                        cur_targets = [item for item in move_targets if item != exploit_source]
                        tgt_path = random.choice(cur_targets)
                        epath = ['/%s' % item for item in exploit_source.split('/')[1:]]
                        operation = (op, epath, tgt_path)
                        try:
                            ret = PdfGenome.move_exploit(entry, epath, tgt_path)
                        except Exception, e:
                            logger.debug("Move Exception: %s" % e)
                            continue
                        if ret is False:
                            continue
                        logger.debug("Perform %s" % str(operation))
                        visited_paths.add(pickle.dumps(epath[:-1]))
                        #visited_paths.add(pickle.dumps(epath))
                        trace.append(operation)
                        has_move = True
                        past_delete.add(op_obj_path[1])
                    else:
                        logger.debug("No op for this path")
                    done = True
                visited_paths.add(pickle.dumps(op_obj_path))
                # update remaining_paths
                remaining_paths = PdfGenome.get_object_paths(entry, visited_paths)
            
            visited_paths.add(pickle.dumps(op_obj_path))
        if entry.active_trace == None:
            entry.private.active_trace = trace
        else:
            entry.active_trace.extend(trace)
        return entry
 



    @staticmethod
    def mutation_with_trace_pastswap(ext_trie, entry, mut_prob, ext_genome, clone = False):
        if not entry:
            return False
        if clone == True:
            entry = deepcopy(entry)

        # visited path in string, updated after each mutation on node
        visited_paths = set()
        remaining_paths = PdfGenome.get_object_paths(entry, visited_paths)
        trace = []

        past_insert = set([])
        past_delete = set([])
        past_swap = set([])
        # get insert and delete operations from the past trace
        if entry.active_trace == None:
            past_insert = set([])
            past_delete = set([])
        else:
            for operation in entry.active_trace:
                op, op_obj_path, ext_id = operation
                etgt_entry, tgt_obj_path = ext_genome[ext_id]
                if op == 'insert':
                    past_insert.add(op_obj_path[1])
                    # NEW: do not waste effort to delete something we inserted
                    # 20190715 & 20190726: remove this
                    #past_delete.add(op_obj_path[1])
                elif op == 'delete':
                    # remove everything under the same prefix of op_obj_path from the adaptive knowledge.
                    past_delete.add(op_obj_path[1])
                elif op == 'swap':
                    past_swap.add(op_obj_path[1])
        
        ops = ['insert', 'swap', 'delete']
        
        while len(remaining_paths) > 0:
            op_obj_path = remaining_paths.pop(0)
            if random.uniform(0,1) <= mut_prob:
                no_delete = False
                no_insert = False
                no_swap = False
                done = False
                # four cases. make an operation choice.
                subtree = op_obj_path[1]
                if subtree in past_insert and subtree in past_delete and sub_tree in past_swap:
                    #op = 'swap'
                    # 20190726: try this
                    op = random.choice(ops)
                elif subtree in past_insert and subtree not in past_delete:
                    #no_insert = True
                    op = 'delete'
                elif subtree in past_delete and subtree not in past_insert:
                    #no_delete = True
                    op = 'insert'
                else:
                    # 20190726: don't know what to do here.
                    op = random.choice(ops)
                first = True
                while not done:
                    if not first:
                        # 20190726: consider removing this part.
                        if no_insert and no_swap:
                            op = None
                        elif no_insert:
                            op = 'swap'
                        elif no_swap:
                            op = 'insert'
                        else:
                            op = random.choice(ops)
                            #op = None
                    first = False

                    if op == 'delete':
                        ext_id = random.choice(range(len(ext_genome)))
                        tgt_entry, tgt_obj_path = ext_genome[ext_id]
                        operation = (op, op_obj_path, ext_id)
                        PdfGenome.delete(entry, op_obj_path)
                        logger.debug("Perform %s" % str(operation))
                        trace.append(operation)
                        # keep track of deletion
                        past_delete.add(op_obj_path[1])
                        #delete_visited_paths.add(pickle.dumps(op_obj_path))
                        #delete_remaining_paths = PdfGenome.get_object_paths(entry, delete_visited_paths)
                    elif op == 'insert':
                        ### select something we can insert with
                        ext_id = PdfGenome.find_insert_ext_id(ext_trie, op_obj_path)
                        if ext_id == -1:
                            no_insert = True
                            logger.debug('*** insert: nothing with the same prefix')
                            continue
                        tgt_entry, tgt_obj_path = ext_genome[ext_id]
                        operation = (op, op_obj_path, ext_id)
                        PdfGenome.insert(entry, op_obj_path, tgt_entry, tgt_obj_path)
                        logger.debug("Perform %s" % str(operation))
                        trace.append(operation)
                        # keep track of insertion
                        past_insert.add(op_obj_path[1])
                        #insert_visited_paths.add(pickle.dumps(op_obj_path))
                        #insert_remaining_paths = PdfGenome.get_object_paths(entry, insert_visited_paths)
                    elif op == 'swap':
                        ### TEST THIS
                        ext_id = PdfGenome.find_swap_ext_id(ext_trie, entry, op_obj_path, ext_genome)
                        if ext_id == -1:
                            no_swap = True
                            continue
                        tgt_entry, tgt_obj_path = ext_genome[ext_id]
                        operation = (op, op_obj_path, ext_id)
                        PdfGenome.swap(entry, op_obj_path, tgt_entry, tgt_obj_path)
                        logger.debug("Perform %s" % str(operation))
                        trace.append(operation)
                        # keep track of swap
                        past_swap.add(op_obj_path[1])
                        # keep track of both deletion and insertion
                        #delete_visited_paths.add(pickle.dumps(op_obj_path))
                        #delete_remaining_paths = PdfGenome.get_object_paths(entry, delete_visited_paths)
                        #insert_visited_paths.add(pickle.dumps(op_obj_path))
                        #insert_remaining_paths = PdfGenome.get_object_paths(entry, insert_visited_paths)
                    else:
                        logger.debug("No insert/swap this path")
                    done = True
                visited_paths.add(pickle.dumps(op_obj_path))
                # update remaining_paths
                remaining_paths = PdfGenome.get_object_paths(entry, visited_paths)
            
            visited_paths.add(pickle.dumps(op_obj_path))
        if entry.active_trace == None:
            entry.private.active_trace = trace
        else:
            entry.active_trace.extend(trace)
        return entry
 


    @staticmethod
    def mutation_with_trace_choice_noswap(ext_trie, entry, mut_prob, ext_genome, clone = False):
        if not entry:
            return False
        if clone == True:
            entry = deepcopy(entry)

        # visited path in string, updated after each mutation on node
        visited_paths = set()
        remaining_paths = PdfGenome.get_object_paths(entry, visited_paths)
        trace = []

        past_insert = set([])
        past_delete = set([])
        # get insert and delete operations from the past trace
        if entry.active_trace == None:
            past_insert = set([])
            past_delete = set([])
        else:
            for operation in entry.active_trace:
                op, op_obj_path, ext_id = operation
                etgt_entry, tgt_obj_path = ext_genome[ext_id]
                if op == 'insert':
                    past_insert.add(op_obj_path[1])
                elif op == 'delete':
                    past_delete.add(op_obj_path[1])
        
        ops = ['insert', 'delete']
        
        while len(remaining_paths) > 0:
            op_obj_path = remaining_paths.pop(0)
            if random.uniform(0,1) <= mut_prob:
                no_delete = False
                no_insert = False
                done = False
                # four cases. make an operation choice.
                subtree = op_obj_path[1]
                if subtree in past_insert and subtree in past_delete:
                    ### 20190715: do not put so much emphasize on swap
                    op = random.choice(ops)
                elif subtree in past_insert and subtree not in past_delete:
                    op = 'delete'
                elif subtree in past_delete and subtree not in past_insert:
                    op = 'insert'
                else:
                    op = random.choice(ops)
                first = True
                while not done:
                    # If it's delete, then it's already done
                    if not first:
                        if no_insert:
                            ### TEST: change to delete?
                            #op = None
                            op = 'delete'
                        else:
                            # this should never happen
                            op = random.choice(ops)
                    first = False

                    if op == 'delete':
                        ext_id = random.choice(range(len(ext_genome)))
                        tgt_entry, tgt_obj_path = ext_genome[ext_id]
                        operation = (op, op_obj_path, ext_id)
                        PdfGenome.delete(entry, op_obj_path)
                        logger.debug("Perform %s" % str(operation))
                        trace.append(operation)
                        # keep track of deletion
                        past_delete.add(op_obj_path[1])
                    elif op == 'insert':
                        ### select something we can insert with
                        ext_id = PdfGenome.find_insert_ext_id(ext_trie, op_obj_path)
                        if ext_id == -1:
                            no_insert = True
                            logger.debug('*** insert: nothing with the same prefix')
                            continue
                        tgt_entry, tgt_obj_path = ext_genome[ext_id]
                        operation = (op, op_obj_path, ext_id)
                        PdfGenome.insert(entry, op_obj_path, tgt_entry, tgt_obj_path)
                        logger.debug("Perform %s" % str(operation))
                        trace.append(operation)
                        # keep track of insertion
                        past_insert.add(op_obj_path[1])
                    else:
                        logger.debug("No insert this path")
                    done = True
                visited_paths.add(pickle.dumps(op_obj_path))
                # update remaining_paths
                remaining_paths = PdfGenome.get_object_paths(entry, visited_paths)
            
            visited_paths.add(pickle.dumps(op_obj_path))
        if entry.active_trace == None:
            entry.private.active_trace = trace
        else:
            entry.active_trace.extend(trace)
        return entry


    @staticmethod
    def mutation_with_trace_choice(ext_trie, entry, mut_prob, ext_genome, clone = False):
        if not entry:
            return False
        if clone == True:
            entry = deepcopy(entry)

        # visited path in string, updated after each mutation on node
        visited_paths = set()
        remaining_paths = PdfGenome.get_object_paths(entry, visited_paths)
        trace = []

        past_insert = set([])
        past_delete = set([])
        # get insert and delete operations from the past trace
        if entry.active_trace == None:
            past_insert = set([])
            past_delete = set([])
        else:
            for operation in entry.active_trace:
                op, op_obj_path, ext_id = operation
                etgt_entry, tgt_obj_path = ext_genome[ext_id]
                if op == 'insert':
                    past_insert.add(op_obj_path[1])
                elif op == 'delete':
                    past_delete.add(op_obj_path[1])
        
        ops = ['insert', 'swap', 'delete']
        
        while len(remaining_paths) > 0:
            op_obj_path = remaining_paths.pop(0)
            if random.uniform(0,1) <= mut_prob:
                no_delete = False
                no_insert = False
                no_swap = False
                done = False
                # four cases. make an operation choice.
                subtree = op_obj_path[1]
                if subtree in past_insert and subtree in past_delete:
                    ### 20190715: do not put so much emphasize on swap
                    op = random.choice(ops)
                elif subtree in past_insert and subtree not in past_delete:
                    op = 'delete'
                elif subtree in past_delete and subtree not in past_insert:
                    op = 'insert'
                else:
                    op = random.choice(ops)
                first = True
                while not done:
                    # If it's delete, then it's already done
                    if not first:
                        if no_insert and no_swap:
                            ### TEST: change to delete?
                            op = None
                            #op = 'delete'
                        elif no_insert:
                            op = 'swap'
                        elif no_swap:
                            op = 'insert'
                        else:
                            # this should never happen
                            op = random.choice(ops)
                    first = False

                    if op == 'delete':
                        ext_id = random.choice(range(len(ext_genome)))
                        tgt_entry, tgt_obj_path = ext_genome[ext_id]
                        operation = (op, op_obj_path, ext_id)
                        PdfGenome.delete(entry, op_obj_path)
                        logger.debug("Perform %s" % str(operation))
                        trace.append(operation)
                        # keep track of deletion
                        past_delete.add(op_obj_path[1])
                    elif op == 'insert':
                        ### select something we can insert with
                        ext_id = PdfGenome.find_insert_ext_id(ext_trie, op_obj_path)
                        if ext_id == -1:
                            no_insert = True
                            logger.debug('*** insert: nothing with the same prefix')
                            continue
                        tgt_entry, tgt_obj_path = ext_genome[ext_id]
                        operation = (op, op_obj_path, ext_id)
                        PdfGenome.insert(entry, op_obj_path, tgt_entry, tgt_obj_path)
                        logger.debug("Perform %s" % str(operation))
                        trace.append(operation)
                        # keep track of insertion
                        past_insert.add(op_obj_path[1])
                    elif op == 'swap':
                        ### TEST THIS
                        ext_id = PdfGenome.find_swap_ext_id(ext_trie, entry, op_obj_path, ext_genome)
                        if ext_id == -1:
                            no_swap = True
                            continue
                        tgt_entry, tgt_obj_path = ext_genome[ext_id]
                        operation = (op, op_obj_path, ext_id)
                        PdfGenome.swap(entry, op_obj_path, tgt_entry, tgt_obj_path)
                        logger.debug("Perform %s" % str(operation))
                        trace.append(operation)
                    else:
                        logger.debug("No insert/swap this path")
                    done = True
                visited_paths.add(pickle.dumps(op_obj_path))
                # update remaining_paths
                remaining_paths = PdfGenome.get_object_paths(entry, visited_paths)
            
            visited_paths.add(pickle.dumps(op_obj_path))
        if entry.active_trace == None:
            entry.private.active_trace = trace
        else:
            entry.active_trace.extend(trace)
        return entry

    @staticmethod
    def get_crossover_point(entry):
        obj_paths = PdfGenome.get_object_paths(entry)
        if len(obj_paths) > 0:
            return random.choice(obj_paths)
        else:
            return None

    @staticmethod
    def crossover(entry_a, entry_b):
        c1 = deepcopy(entry_a)
        c2 = deepcopy(entry_b)

        path_a = PdfGenome.get_crossover_point(c1)
        path_b = PdfGenome.get_crossover_point(c2)
        
        if not path_a or not path_b:
            logger.error("###crossover failed due to null variant.")
            return c1, c2

        logger.debug("###crossover between %s and %s" % (str(path_a), str(path_b)))

        parent_a, key_a = PdfGenome.get_parent_key(c1, path_a)
        parent_b, key_b = PdfGenome.get_parent_key(c2, path_b)

        obj_a = parent_a[key_a]
        obj_b = parent_b[key_b]

        parent_a[key_a] = obj_b
        parent_b[key_b] = obj_a
        return c1, c2

# Parameters in a tuple.
def _mutation(ntuples):
    return PdfGenome.mutation(*ntuples)

# Test: A multiprocessing method with no requirement for pickable pdfrw objects.
def _mutation_on_file(ntuples):
    src_path, dst_path, mut_prob, ext_folder = ntuples
    pdf_obj = PdfGenome.load_genome(src_path)
    ext_genome = PdfGenome.load_external_genome(ext_folder)
    mutated_pdf_obj = PdfGenome.mutation(pdf_obj, mut_prob, ext_genome)
    PdfGenome.save_to_file(mutated_pdf_obj, dst_path)
    return True

