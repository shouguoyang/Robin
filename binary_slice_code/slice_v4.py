#encoding=utf-8

import os
import sys
import pickle
import pydot
import json
import signal

import time

from .graph_dataflow_track_all_funcion import data_analysis

from .shortest_distance import *

'''
import cPickle as pickle
import pickle as WINpickle

import pydot
import json

from depgraph import depgraph
from graph_dataflow_version0 import data_analysis
import signal
'''

def parse_dot_file(dotfile):
    graph = pydot.graph_from_dot_file(dotfile)
    #print type(graph)
    #print graph
    edge_dict = {} #src: [[dest,label],[dest,label], ...]
    edgelist = graph[0].get_edge_list()
    for e in edgelist:
        tempAttr = json.dumps(e.get_attributes())
        edgeAttr = json.loads(tempAttr)
        source = e.get_source()
        destination = e.get_destination()
        #print e
        #print 'source', e.get_source()
        #print 'destination', e.get_destination()
        #print e.get_attributes()
        label = None
        #if edgeAttr.has_key('label'):
        if 'label' in edgeAttr:
            label = edgeAttr['label']
            #print colored(edgeAttr['label'], 'red')
        #if edge_dict.has_key(source):
        if source in edge_dict:
            edge_dict[source].append([destination, label])
        else:
            edge_dict[source] = [[destination, label]]

    node_dict = {} #position: code
    node_info_dict = {} #node_id: [code, position, type] 
    nodelist = graph[0].get_node_list()
    for node in nodelist:
        #print node
        node_id = node.get_name()
        #print 'name', node.get_name()
        #print 'pos', node.get_pos()
        tempAttr = json.dumps(node.get_attributes())
        nodeAttr = json.loads(tempAttr)
        if 'label' not in nodeAttr:
            continue
        label = nodeAttr['label']
        #print colored(nodeAttr['label'], 'red')

        label_list = []
        label = label[1:-1].replace('\\\n', '')
        if label.find('\\n') != -1 and label.find('patch_location:') != -1:
            label_list = label.split('\\n')
            #print label_list
            for item in label_list:
                if item.find('code:') == 0:
                    code = item[5:].replace('\\','')
                elif item.find('patch_location:') == 0:
                    location = item[9:]
                elif item.find('type') == 0:
                    node_type = item[5:]
            #print 'code', code
            #print 'patch_location', patch_location
            #print 'node_type', node_type
            #print

            line_num = int(location.split(':')[0])

            node_dict[line_num] = [code]
            node_info_dict[node_id] = [code, location, node_type, line_num]

    #for key in sorted(node_dict):
    #    print key, node_dict[key]

    return (edge_dict, node_info_dict, node_dict)


def get_sorted_line_nums(node_info_dict):
    line_nums = []
    for node, infos in node_info_dict.items():
        line_num = infos[3]
        line_nums.append(line_num)
    return line_nums

def find_line_num(line_num, line_nums):
    goal_line_num = line_nums[0]
    for tmp_line_num in line_nums:
        if tmp_line_num - line_num < 0:
            goal_line_num = tmp_line_num
        else:
            return goal_line_num

#return ture if str2 in str1, or false if str2 is not part of str1.
def strstr(_str1, _str2):
    _str1 = _str1.replace(' ', '')
    _str2 = _str2.replace(' ', '')
    if _str2.endswith(';'):
        _str2 = _str2[:-1]
    if _str2.endswith(')'):
        _str2 = _str2[:-1]
    if _str1.find(_str2) != -1:
        return True
    return False


def get_node_ids_by_line_num(line_nums, node_dict_info):
    node_ids = []
    for line_num in line_nums:
        for _id in node_dict_info.keys():
            if line_num == node_dict_info[_id][3]:
                node_ids.append(_id)
    return node_ids

#sort node list by position
def get_sorted_result_list(node_list, node_dict):

    #print 'node_dict'
    #print node_dict

    pos_node_dict = {} #pos: node_id
    for node in node_list:
        #if node_dict.has_key(node) == False:
        if node not in node_dict:
            continue
        pos = int(node_dict[node][1].split(':')[0])
        pos_node_dict[pos] = node
    result_node_list = []
    for key in sorted(pos_node_dict):
        #print key, pos_node_dict[key], node_dict[pos_node_dict[key]][0]
        result_node_list.append(pos_node_dict[key])
    return result_node_list



#data only
def get_backslice_result(_id, edge_dict, node_dict):
    result_rel_list = []
    track_node_list = [_id]
    visited_node_list = []
    while len(track_node_list):
        goal_id = track_node_list[0]
        track_node_list = track_node_list[1:]
        if goal_id in visited_node_list:
            continue
        visited_node_list.append(goal_id)

        for src, dest_list in edge_dict.items():
            for dest in dest_list:
                if dest[1] != None and dest[0] == goal_id:
                    track_node_list.append(src)
                    result_rel_list.append([src, dest[0], dest[1]])
    visited_node_list = list(set(visited_node_list))
    visited_node_list = get_sorted_result_list(visited_node_list, node_dict)
    if len(visited_node_list) > 6:
        visited_node_list = visited_node_list[-6:]
    return visited_node_list, result_rel_list


#对goal_node单纯获取前向数据依赖--变体 (只对某些变量进行切片)
def forward_slice_data_only_variant(goal_list, edge_dict, node_dict, result_rel_list, goal):
    track_node_list = []
    #result_rel_list = []
    visited_node_list = []
    for item in goal_list:
        node = item[0]
        variable = item[1]
        visited_node_list.append(node)
        for dest_item in edge_dict[node]:
            if dest_item[1] == variable:
                track_node_list.append(dest_item[0])
                result_rel_list.append([node, dest_item[0], dest_item[1]])
    while len(track_node_list):
        goal_id = track_node_list[0]
        track_node_list = track_node_list[1:]
        if goal_id in visited_node_list:
            continue
        visited_node_list.append(goal_id)
        if edge_dict.has_key(goal_id) == False:
            continue
        for dest_item in edge_dict[goal_id]:
            if dest_item[1] != None:
                track_node_list.append(dest_item[0])
                result_rel_list.append([goal_id, dest_item[0], dest_item[1]])
    return visited_node_list

#对goal_node单纯获取前向数据依赖--变体 (只对某些变量进行切片)
def forward_slice_data_only_variant_v1(goal_list, edge_dict, node_dict, result_rel_list, goal):
    track_node_list = []
    #result_rel_list = []
    visited_node_list = []
    for item in goal_list:
        node = item[0]
        variable = item[1]
        visited_node_list.append(node)
        for dest_item in edge_dict[node]:
            #if dest_item[1] == variable and node_dict.has_key(dest_item[0]) and node_dict[dest_item[0]][3] > node_dict[goal][3]:
            if dest_item[1] == variable and dest_item[0] in node_dict and node_dict[dest_item[0]][3] > node_dict[goal][3]:
                track_node_list.append(dest_item[0])
                result_rel_list.append([node, dest_item[0], dest_item[1]])
    while len(track_node_list):
        goal_id = track_node_list[0]
        track_node_list = track_node_list[1:]
        if goal_id in visited_node_list:
            continue
        visited_node_list.append(goal_id)
        #if edge_dict.has_key(goal_id) == False:
        if goal_id not in edge_dict:
            continue
        for dest_item in edge_dict[goal_id]:
            if dest_item[1] != None:
                track_node_list.append(dest_item[0])
                result_rel_list.append([goal_id, dest_item[0], dest_item[1]])
    return visited_node_list

def forward_slice_data_only(goal_list, edge_dict, node_dict, result_rel_list):
    track_node_list = goal_list
    visited_node_list = []
    while len(track_node_list):
        goal_id = track_node_list[0]
        #print 'goal_id', goal_id
        track_node_list = track_node_list[1:]
        if goal_id in visited_node_list:
            continue
        visited_node_list.append(goal_id)
        #print goal_id, node_dict[goal_id]
        #print goal_id, edge_dict[goal_id]
        #if edge_dict.has_key(goal_id) == False:
        if goal_id not in edge_dict:
            continue
        for dest_item in edge_dict[goal_id]:
            #如果是数据依赖，则dest_item[1]为变量名
            #如果为控制依赖，则dest_item为None
            if dest_item[1] != None:
                track_node_list.append(dest_item[0])
                result_rel_list.append([goal_id, dest_item[0], dest_item[1]])
    return visited_node_list


#data only
def get_forwslice_result(goal, edge_dict, node_dict):
    result_node_list = []
    stmt_line = node_dict[goal][0]
    type_goal_node = node_dict[goal][2]
    result_rel_list = []


    if stmt_line.find('=') != -1 and type_goal_node != 'Condition':
        result_node_list = forward_slice_data_only([goal], edge_dict, node_dict, result_rel_list)
    elif type_goal_node == 'IdentifierDeclStatement':
        pass
    else:
        backslice_node_list = []
        for src_node, dest_item_list in edge_dict.items():
            for dest_item in dest_item_list:
                if dest_item[0] == goal and dest_item[1] != None:
                    backslice_node_list.append([src_node, dest_item[1]])

        result_node_list_tmp = forward_slice_data_only_variant_v1(\
            backslice_node_list, edge_dict, node_dict, result_rel_list, goal)

        #tmp_node_list = [backslice_node_list[i][0] for i in xrange(len(backslice_node_list))]
        tmp_node_list = [backslice_node_list[i][0] for i in range(len(backslice_node_list))]
        backslice_node_list = tmp_node_list
        result_node_list = list(set(result_node_list_tmp) - set(backslice_node_list))

    result_node_list = list(set(result_node_list))
    result_node_list = get_sorted_result_list(result_node_list, node_dict)
    result_node_list = result_node_list[:10]
    return result_node_list, result_rel_list



def slice_for_one_node(_id, edge_dict, node_info_dict):
    """给一个基本块节点进行切片"""
    back_ids, back_rels = get_backslice_result(_id, edge_dict, node_info_dict)
    forw_ids, forw_rels = get_forwslice_result(_id, edge_dict, node_info_dict)
    return back_ids, back_rels, forw_ids, forw_rels

def get_slice_result(node_ids, edge_dict, node_info_dict):
    print ('..........')
    res_back_node_ids = []
    res_back_rels = []
    res_forw_node_ids = []
    res_forw_rels = []
    for _id in node_ids:
        back_ids, back_rels, forw_ids, forw_rels = slice_for_one_node(_id, edge_dict, node_info_dict)
        res_back_node_ids += back_ids
        res_back_rels += back_rels
        res_forw_node_ids += forw_ids
        res_forw_rels += forw_rels
    print ('#back_nodes, #forw_nodes', len(set(res_back_node_ids)), len(set(res_forw_node_ids)))

    node_list_final = get_sorted_result_list(list(set(res_back_node_ids + res_forw_node_ids)), node_info_dict)
    print ([node_info_dict[_id][3] for _id in node_list_final])
    return res_back_rels + res_forw_rels, node_list_final

def instr_addr_list_with_stmt_list(stmt_line_nums, key, repo_name, flag):
    addr_list = []
    stmt_addr_mapping_dir = '../stmt_addr_mapping/%s/' % repo_name

    arr = key.split('---')

    if flag == 'vul':
        mapping_path = stmt_addr_mapping_dir + arr[1] + '__%s__address' % arr[3]
    else:
        mapping_path = stmt_addr_mapping_dir + arr[2] + '__%s__address' % arr[3]


    with open(mapping_path) as f:
        mapping_content = f.read()
    
    mapping_items = mapping_content.split('\n')
    mapping_items = [item.replace('\r', '') for item in mapping_items]

    for line_num in stmt_line_nums:
        _addr_list = mapping_items[3*(line_num-1)+1].split(',')
        addr_list += _addr_list

    addr_list = list(set(addr_list))
    addr_list.sort()

    addr_list = [item for item in addr_list if len(item) > 0]

    return addr_list


def get_addr_list_by_pat(addr_mapping_rel, addr_list):
    #print addr_mapping_rel.items()[0]
    res_list = []
    for addr in addr_list:
        if addr.endswith('L'):
            addr = addr[:-1]
        _addr = int(addr, 0)
        #if addr_mapping_rel.has_key(_addr):
        if _addr in addr_mapping_rel:
            res_list.append(str(hex(addr_mapping_rel[_addr])))
        else:
            print ('not found!!!', hex(_addr))
    return res_list


def load_func_obj(filepath):
    with open(filepath, 'rb') as f:
        func_info = pickle.load(f)
    return func_info



def find_instr(target_addr, func_info):
    #target_addr '0xa3425L'

    instr = None
    for bb in func_info.bbs:
        for binstr in bb.binstrs:
            #576603L -> '0x8cc5bL'
            addr = hex(binstr.start_address)
            if addr == target_addr:
                instr = binstr.disasm_striped
                return instr
    return instr


def find_regs_in_func_info_with_addr(target_addr, func_info):
    CMP_REGS_X64 = ["rax", "eax", "ax", "al", "rbx", "ebx", "bx", "bl", "rcx", "ecx", "cx", "cl", 
    "rdx", "edx", "dx", "dl", "rsi", "esi", "si", "sil", "rdi", "edi", "di", "dil", "rbp", "ebp", 
    "bp", "bpl", "rsp", "esp", "sp", "spl", "r8", "r8d", "r8w", "r8b", "r9", "r9d", "r9w", "r9b", 
    "r10", "r10d", "r10w", "r10b", "r11", "r11d", "r11w", "r11b", "r12", "r12d", "r12w", "r12b", 
    "r13", "r13d", "r13w", "r13b", "r14", "r14d", "r14w", "r14b", "r15", "r15d", "r15w", "r15b"]

    instr = find_instr(target_addr, func_info)

    if instr == None:
        return None, None

    regs = []
    for reg in CMP_REGS_X64:
        if instr.find(reg) != -1:
            regs.append(reg)

    return regs, instr

def filter_register(reg):
    if(reg[0]=='E'):
        reg='R'+reg[1:]
    if(len(reg)==2 and reg[0]!='R'):
        reg='R'+reg
    if(reg[-1]=='L'):
        reg=reg[:-1]+'X'
    if reg[-1] == 'D' or reg[-1] == 'W' or reg[-1] == 'B':
        reg = reg[:-1]
    return reg

def handler(signum, frame):
    raise Exception("end of time")

def backward_slice_with_depgraph(addresses, func_info, binfile_path):
    func_addr = str(func_info.start_address)

    result_addr_list = []
    
    for target_addr in addresses:
        regs, instr = find_regs_in_func_info_with_addr(target_addr, func_info)
        if regs == None:
            continue

        print ('PROCESSING ADDR back depgraph', hex(int(func_addr)), target_addr, instr)
        if target_addr.endswith('L'):
            target_addr = target_addr[:-1]

        if func_addr.endswith('L'):
            func_addr = func_addr[:-1]

        '''
        print 'before processing ...', regs
        regs = [filter_register(reg.upper()) for reg in regs]
        regs = list(set(regs))

        for idx in xrange(len(regs)):
            reg = regs[idx]
            if reg == 'RBP':
                regs[idx] = '[RBP]'
        print 'after processing ...', regs
        '''

        signal.signal(signal.SIGALRM, handler)
        signal.alarm(60)
        
        try:
            #res = depgraph(binfile_path, func_addr, target_addr, regs)
            res = depgraph(binfile_path, func_addr, target_addr)
        
            print ('SLICING RESULT', res)
            print
            result_addr_list += res
        except Exception as exc:
            print (exc)
            print
        signal.alarm(0)
    result_addr_list = list(set(result_addr_list))
    result_addr_list.sort()

    result_addr_list = [addr+'L' for addr in result_addr_list]
    return result_addr_list

def slice_with_datagraph(addresses, func_info, binfile_path):
    func_addr = str(func_info.start_address)
    if func_addr.endswith('L'):
        func_addr = func_addr[:-1]

    func_addr = int(func_addr)

    result_addr_list_back = []
    result_addr_list_forw = []
    for target_addr in addresses:

        if target_addr.endswith('L'):
            target_addr = target_addr[:-1]

        print ('\nPROCESSING ADDR datagraph', hex(func_addr), target_addr)
        target_addr = int(target_addr, 16)
        try:
            data_res = data_analysis(binfile_path, func_addr, target_addr)
            result_addr_list_back += data_res[0]   #from
            result_addr_list_forw += data_res[1]   #to
            print ('------------data-from--------------')
            print (data_res[0])
            print ('-------------data-to---------------')
            print (data_res[1])
        except Exception as e:
            print (e, 'in function slice_with_datagraph')

    result_addr_list_back = list(set(result_addr_list_back))
    result_addr_list_forw = list(set(result_addr_list_forw))
    result_addr_list_back.sort()
    result_addr_list_forw.sort()
    result_addr_list_back = [addr+'L' for addr in result_addr_list_back]
    result_addr_list_forw = [addr+'L' for addr in result_addr_list_forw]

    return result_addr_list_back, result_addr_list_forw

def extract_sig_by_pdg(key, pdg_path, _dict1, _dict2, diff_info):
    print('\n\nEXTRACT_SIG_BY_PDG')
    key = key.replace('\r', '')
    arr_key = key.split('---')
    vul_file = arr_key[1] + arr_key[3]
    pat_file = arr_key[2] + arr_key[3]

    _key_for_mapping = arr_key[1]+'-'+arr_key[2]+'-'+arr_key[3]

    vul_pdg_path = pdg_path + 'function_pdg_%s__%s.c.dot' % (arr_key[1], arr_key[3])
    pat_pdg_path = pdg_path + 'function_pdg_%s__%s.c.dot' % (arr_key[2], arr_key[3])

    #vul_edge_dict, vul_node_info_dict, vul_node_dict = parse_dot_file(vul_pdg_path)
    #pat_edge_dict, pat_node_info_dict, pat_node_dict = parse_dot_file(pat_pdg_path)

    #'''
    try:
        vul_edge_dict, vul_node_info_dict, vul_node_dict = parse_dot_file(vul_pdg_path)
        pat_edge_dict, pat_node_info_dict, pat_node_dict = parse_dot_file(pat_pdg_path)
    except Exception as e:
        print (e, 'in extract_sig_by_pdg function try/except')
        return [], [], [], [], _key_for_mapping
    #'''
    #vul_line_nums = get_sorted_line_nums(vul_node_info_dict)
    #pat_line_nums = get_sorted_line_nums(pat_node_info_dict)
    '''
    vul_line_nums = vul_node_dict.keys()
    vul_line_nums.sort()
    pat_line_nums = pat_node_dict.keys()
    pat_line_nums.sort()
    '''

    vul_line_nums = sorted(vul_node_dict)
    pat_line_nums = sorted(pat_node_dict)

    vul_slice_line_nums_bef = _dict1.keys()
    pat_slice_line_nums_bef = _dict2.keys()

    vul_slice_line_nums = []
    for item in vul_slice_line_nums_bef:
        if item in vul_line_nums:
            vul_slice_line_nums.append(item)
        else:
            if len(_dict1[item].strip()) == 0:
                continue
            line_num = find_line_num(item, vul_line_nums)

            #print key, 'vul'
            #print item, _dict1[item]
            if line_num == None or strstr(''.join(vul_node_dict[line_num]), _dict1[item]) == False:
                #print 'max line num', vul_line_nums[-1]
                #if line_num != None:
                #    print 'found stmt', line_num, vul_node_dict[line_num]
                #print
                continue
            #print line_num, vul_node_dict[line_num]
            #print 
            vul_slice_line_nums.append(line_num)

    pat_slice_line_nums = []
    for item in pat_slice_line_nums_bef:
        if item in pat_line_nums:
            pat_slice_line_nums.append(item)
        else:
            if len(_dict2[item].strip()) == 0:
                continue
            line_num = find_line_num(item, pat_line_nums)
            #print key, 'pat'
            #print item, _dict2[item]
            if line_num == None or strstr(''.join(pat_node_dict[line_num][0]), _dict2[item]) == False:
                #print 'max line num', pat_line_nums[-1]
                #if line_num != None:
                #    print 'found stmt', line_num, pat_node_dict[line_num]
                #print
                continue
            #print line_num, pat_node_dict[line_num]
            #print 
            pat_slice_line_nums.append(line_num)

    vul_node_ids = get_node_ids_by_line_num(vul_slice_line_nums, vul_node_info_dict)
    pat_node_ids = get_node_ids_by_line_num(pat_slice_line_nums, pat_node_info_dict)
    #'''
    print (key)
    print ('#vul_stmts, #vul_nodes', len(vul_slice_line_nums), len(vul_node_ids))
    vul_slice_line_nums.sort()
    print (vul_slice_line_nums)
    '''
    if len(vul_slice_line_nums) != len(vul_node_ids):
        print vul_slice_line_nums
        print vul_node_ids
    '''
    #'''
    #print vul_node_ids, len(vul_edge_dict.items()), len(vul_node_info_dict.items())
    slice_res_vul, node_list_vul = get_slice_result(vul_node_ids, vul_edge_dict, vul_node_info_dict)    
    print ('\n#pat_stmts, #pat_nodes', len(pat_slice_line_nums), len(pat_node_ids))
    pat_slice_line_nums.sort()
    print (pat_slice_line_nums)
    '''
    if len(pat_slice_line_nums) != len(pat_node_ids):
        print pat_slice_line_nums
        print pat_node_ids
    '''

    slice_res_pat, node_list_pat = get_slice_result(pat_node_ids, pat_edge_dict, pat_node_info_dict)
    print ('#vul_nodes_slice, #pat_nodes_slice', len(node_list_vul), len(node_list_pat))


    #based on results of slicing (node id list), we get its corresponding line num of stmt
    stmt_line_nums_vul = [vul_node_info_dict[_id][3] for _id in node_list_vul]
    stmt_line_nums_pat = [pat_node_info_dict[_id][3] for _id in node_list_pat]

    stmt_line_nums_vul = list(set(stmt_line_nums_vul))
    stmt_line_nums_vul.sort()

    stmt_line_nums_pat = list(set(stmt_line_nums_pat))
    stmt_line_nums_pat.sort()

    instr_addr_list_vul = instr_addr_list_with_stmt_list(stmt_line_nums_vul, key, repo_name, 'vul')
    instr_addr_list_pat = instr_addr_list_with_stmt_list(stmt_line_nums_pat, key, repo_name, 'pat')
    '''
    print 'instrction address in vul', len(instr_addr_list_vul)
    print instr_addr_list_vul
    print 'instruction address in pat', len(instr_addr_list_pat)
    print instr_addr_list_pat
    '''
    #'''
    #print diff_info[key]
    vul_diff_info_addr = diff_info[key][0]
    vul_diff_info_addr_list = []
    for item in vul_diff_info_addr:
        vul_diff_info_addr_list += item
    pat_diff_info_addr = diff_info[key][1]
    pat_diff_info_addr_list = []
    for item in pat_diff_info_addr:
        pat_diff_info_addr_list += item
    #print pat_diff_info_addr_list
    #res_instr_addr_list_pat = list(set(instr_addr_list_pat) - set(pat_diff_info_addr_list))
    #res_instr_addr_list_pat.sort()
    #print len(res_instr_addr_list_pat)
    #'''

    return instr_addr_list_vul, instr_addr_list_pat, vul_diff_info_addr_list, pat_diff_info_addr_list, _key_for_mapping

def find_bb_with_addr(addr, bbs):
    for bb in bbs:
        start_addr = int(bb.start_address[:-1], 16)
        end_addr = int(bb.end_address[:-1], 16)
        #print 'start_addr', start_addr
        #print 'end_addr', end_addr
        if addr >= start_addr and addr < end_addr:
            return bb
        '''
        else:
            #print 'NOT FOUND BB FOR ADDR', addr, start_addr, end_addr
            return None
        '''
def find_succ_bbs_with_addr(addrs, func_info):
    res_bbs = []
    for bb in func_info.bbs:
        if bb.start_address in addrs:
            res_bbs.append(bb)
    return res_bbs

def forward_slice_with_ctrl(addrs, func_info):
    #TODO: put child block into result if there is instruction include cmp or test

    bbs = func_info.bbs

    result_addr_list = []
    bb_flag = False
  
    for addr in addrs:
        if addr.endswith('L'):
            addr = addr[:-1]
        addr = int(addr, 16)
        #print ('addr', hex(addr), addr)

        bb = find_bb_with_addr(addr, bbs)
        if bb == None:
            print ('NOT FOUND!!!', addr)
            continue
        for instr in bb.binstrs:
            if addr == instr.start_address:
                #print ('INSTR', instr.disasm)
                mnem = instr.mnem
                #print ('MNEM', mnem)
                #print
                if mnem == 'cmp' or mnem == 'test':
                    bb_flag = True
                    #print ('We should take succs into consideration')
                    #print (bb.succs)
                else:
                    bb_flag = False
                #print
        #if the instruction is 'cmp' or 'test', we take succs into feature
        if bb_flag:
            succs = bb.succs
            succ_bbs = find_succ_bbs_with_addr(succs, func_info)
            for succ in succ_bbs:
                for instr in succ.binstrs:
                    result_addr_list.append(instr.start_address)
    result_addr_list = list(set(result_addr_list))
    result_addr_list.sort()
    #print 'result_addr_list_bef', result_addr_list
    result_addr_list = [hex(addr) for addr in result_addr_list]
    #print 'result_addr_list', result_addr_list
    #exit(1)
    return result_addr_list


def forward_slice_with_ctrl_and_layer(addrs, func_info):
    bbs = func_info.bbs

    result_addr_list = []
    addr_distance_map = dict()
    bb_flag = False
  
    for addr in addrs:
        if addr.endswith('L'):
            addr = addr[:-1]
        addr = int(addr, 16)
        #print ('addr', hex(addr), addr)

        bb = find_bb_with_addr(addr, bbs)
        if bb == None:
            print ('NOT FOUND!!!', addr)
            continue
        for instr in bb.binstrs:
            if addr == instr.start_address:
                #print ('INSTR', instr.disasm)
                mnem = instr.mnem
                #print ('MNEM', mnem)
                #print
                if mnem == 'cmp' or mnem == 'test':
                    bb_flag = True
                    #print ('We should take succs into consideration')
                    #print (bb.succs)
                else:
                    bb_flag = False
                #print
        #if the instruction is 'cmp' or 'test', we take succs into feature
        if bb_flag:
            prev_bb_list = [bb]
            #res_bb_list = [bb]
            layer = 3 
            for i in range(layer):
                tmp_bb_list = []
                for item_bb in prev_bb_list:
                    succs = item_bb.succs
                    succ_bbs = find_succ_bbs_with_addr(succs, func_info)
                    #res_bb_list += succ_bbs
                    tmp_bb_list += succ_bbs
                    for succ in succ_bbs:
                        for instr in succ.binstrs:
                            tmp_addr = hex(instr.start_address)
                            result_addr_list.append(tmp_addr)

                            if tmp_addr not in addr_distance_map:
                                addr_distance_map[tmp_addr] = (i + 1)
                            else:
                                if addr_distance_map[tmp_addr] > i+1:
                                    addr_distance_map[tmp_addr] = (i+1)

                prev_bb_list = tmp_bb_list
    result_addr_list = list(set(result_addr_list))
    result_addr_list.sort()
    #print 'result_addr_list_bef', result_addr_list
    result_addr_list = [addr for addr in result_addr_list]
    #print 'result_addr_list', result_addr_list
    #exit(1)
    return result_addr_list, addr_distance_map



def extract_sig_by_depgraph(key, function_info_dir, diff_info_corresponding, bins_dir):
    print ('EXTRACT_SIG_BY_DEPGRAPH')
    key = key.replace('\r', '')
    arr_key = key.split('---')
    #vul_file = arr_key[1] + arr_key[3]
    #pat_file = arr_key[2] + arr_key[3]

    #############################################################################################
    #slice with depgraph (backward only)
    vul_func_info_path = function_info_dir + ("%s_%s.pkl" % (arr_key[1], arr_key[3]))
    pat_func_info_path = function_info_dir + ("%s_%s.pkl" % (arr_key[2], arr_key[3]))

    #if diff_info_corresponding.has_key(key) == False:
    if key not in diff_info_corresponding:
        return [], [], [], []

    #['0xa3425L', '0xa3429L', '0xa342dL', '0xa342fL', '0xa3433L']
    vul_addresses = diff_info_corresponding[key][0]
    pat_addresses = diff_info_corresponding[key][1]

    #libfreetype_26.so
    vul_file_path = bins_dir + arr_key[1]
    pat_file_path = bins_dir + arr_key[2]

    #result of addresses which gotten by applying backward slicing on vulnerable function
    vul_slice_res_back = []
    vul_slice_res_forw = []
    print ('\nslice in vul ...')
    if len(vul_addresses):
        vul_func_info = load_func_obj(vul_func_info_path)
        vul_slice_res_back = backward_slice_with_depgraph(vul_addresses, vul_func_info, vul_file_path) 
        #print 'VUL_SLICE_RES_BACK', vul_slice_res_back
        vul_slice_res_forw = forward_slice_with_ctrl(vul_addresses, vul_func_info)

    #results of addresses which gotten by applying backward slicing on patched function
    pat_slice_res_back = []
    pat_slice_res_forw = []
    print ('\nslice in patched ...')
    if len(pat_addresses):
        pat_func_info = load_func_obj(pat_func_info_path)
        pat_slice_res_back = backward_slice_with_depgraph(pat_addresses, pat_func_info, pat_file_path)
        pat_slice_res_forw = forward_slice_with_ctrl(pat_addresses, pat_func_info)

    #############################################################################################
    vul_slice_res = vul_slice_res_back + vul_slice_res_forw
    pat_slice_res = pat_slice_res_back + pat_slice_res_forw

    return vul_addresses, pat_addresses, vul_slice_res, pat_slice_res

def extract_sig_by_datagraph(key, function_info_dir, diff_info_corresponding, bins_dir):
    print ('EXTRACT_SIG_BY_DATAGRAPH')
    key = key.replace('\r', '')
    arr_key = key.split('---')
    #vul_file = arr_key[1] + arr_key[3]
    #pat_file = arr_key[2] + arr_key[3]

    #############################################################################################
    #slice with depgraph (backward only)
    vul_func_info_path = function_info_dir + ("%s_%s.pkl" % (arr_key[1], arr_key[3]))
    pat_func_info_path = function_info_dir + ("%s_%s.pkl" % (arr_key[2], arr_key[3]))

    if diff_info_corresponding.has_key(key) == False:
        return [], [], [], []

    #['0xa3425L', '0xa3429L', '0xa342dL', '0xa342fL', '0xa3433L']
    vul_addresses = diff_info_corresponding[key][0]
    pat_addresses = diff_info_corresponding[key][1]

    #libfreetype_26.so
    vul_file_path = bins_dir + arr_key[1]
    pat_file_path = bins_dir + arr_key[2]

    #result of addresses which gotten by applying backward slicing on vulnerable function
    vul_slice_res_back = []
    vul_slice_res_forw = []
    print ('\nslice in vul ...')
    if len(vul_addresses):
        vul_func_info = load_func_obj(vul_func_info_path)
        vul_slice_res_back, vul_slice_res_forw = slice_with_datagraph(vul_addresses, \
                vul_func_info, vul_file_path)
        #vul_slice_res_back = backward_slice_with_depgraph(vul_addresses, \
        #        vul_func_info, vul_file_path) 
        #print 'VUL_SLICE_RES_BACK', vul_slice_res_back
        #vul_slice_res_forw = forward_slice_with_ctrl(vul_addresses, vul_func_info)

    #results of addresses which gotten by applying backward slicing on patched function
    pat_slice_res_back = []
    pat_slice_res_forw = []
    print ('\nslice in patched ...')
    if len(pat_addresses):
        pat_func_info = load_func_obj(pat_func_info_path)
        pat_slice_res_back, pat_slice_res_forw = slice_with_datagraph(pat_addresses, \
                pat_func_info, pat_file_path)
        #pat_slice_res_back = backward_slice_with_depgraph(pat_addresses, \
        #        pat_func_info, pat_file_path)
        #pat_slice_res_forw = forward_slice_with_ctrl(pat_addresses, pat_func_info)

    #############################################################################################
    vul_slice_res = vul_slice_res_back + vul_slice_res_forw
    pat_slice_res = pat_slice_res_back + pat_slice_res_forw

    return vul_addresses, pat_addresses, vul_slice_res, pat_slice_res


def compute_distance(addr, slice_addr, graph, instr_blk_map):

    if addr not in instr_blk_map or \
            slice_addr not in instr_blk_map:
        print("addr not found in instr_blk_map!!!!", addr, slice_addr)
        return 20

    if instr_blk_map[slice_addr] == instr_blk_map[addr]:
        return 0

    res = dijsktra(graph, instr_blk_map[slice_addr], instr_blk_map[addr])
    #print(addr, slice_addr, res)
    return len(res)-1
    

def update_res_addr_forw_with_distance(forw_addrs, slice_addr, graph, instr_blk_map, res_addr_forw_with_distance):

    for addr in forw_addrs:
        distance = compute_distance(addr, slice_addr, graph, instr_blk_map)
        if addr not in res_addr_forw_with_distance:
            res_addr_forw_with_distance[addr] = distance
        else:
            if res_addr_forw_with_distance[addr] < distance:
                res_addr_forw_with_distance[addr] = distance


def get_distance(slice_result, graph, instr_blk_map):
    res_addr_forw_with_distance = {}

    for res in slice_result:
        forw_addrs = res.data_to
        slice_addr = res.track_addr
        update_res_addr_forw_with_distance(forw_addrs, slice_addr, graph, instr_blk_map, res_addr_forw_with_distance)

    return res_addr_forw_with_distance

def slice_with_graph_dataflow(addresses, func_info, binfile_path, graph, instr_blk_map):
    func_addr = str(func_info.start_address)
    if func_addr.endswith('L'):
        func_addr = func_addr[:-1]

    func_addr = int(func_addr)

    result_addr_list_back = []
    result_addr_list_forw = []

    target_addrs = []
    for target_addr in addresses:
        if target_addr.endswith('L'):
            target_addr = target_addr[:-1]

        target_addr = int(target_addr, 16)
        if target_addr <= func_addr+5:
            continue
        target_addrs.append(target_addr)

    print('Going to process', binfile_path, hex(func_addr), [hex(addr) for addr in target_addrs], '\n')
    slice_result = data_analysis(binfile_path, func_addr, target_addrs)
    #print ('slice_result', slice_result)

    for res in slice_result:
        res.print_track_result()
        result_addr_list_back += res.data_from
        result_addr_list_forw += res.data_to

    result_addr_list_forw_with_distance = get_distance(slice_result, graph, instr_blk_map)
    print('result_addr_list_forw_with_distance', result_addr_list_forw_with_distance)


    result_addr_list_back = list(set(result_addr_list_back))
    result_addr_list_forw = list(set(result_addr_list_forw))
    result_addr_list_back.sort()
    result_addr_list_forw.sort()
    result_addr_list_back = [addr+'L' for addr in result_addr_list_back]
    result_addr_list_forw = [addr+'L' for addr in result_addr_list_forw]
    return result_addr_list_back, result_addr_list_forw, result_addr_list_forw_with_distance

def update_addr_distance_map(pat_result_addr_list_forw_with_distance, pat_result_addr_list_forw_with_distance_tmp):
    for addr in pat_result_addr_list_forw_with_distance_tmp:
        if addr not in pat_result_addr_list_forw_with_distance:
            pat_result_addr_list_forw_with_distance[addr] = pat_result_addr_list_forw_with_distance_tmp[addr]
        else:
            if pat_result_addr_list_forw_with_distance_tmp[addr] < pat_result_addr_list_forw_with_distance[addr]:
                pat_result_addr_list_forw_with_distance[addr] = pat_result_addr_list_forw_with_distance_tmp[addr]


def extract_sig_by_graph_dataflow(key, function_info_dir, diff_info_corresponding, bins_dir):
    print ('\n\nEXTRACT_SIG_BY_GRAPH_DATAFLOW')
    key = key.replace('\r', '')
    arr_key = key.split('---')

    #############################################################################################
    #slice with depgraph (backward only)
    vul_func_info_path = function_info_dir + ("%s_%s.pkl" % (arr_key[1], arr_key[3]))
    pat_func_info_path = function_info_dir + ("%s_%s.pkl" % (arr_key[2], arr_key[3]))

    if key not in diff_info_corresponding:
        return [], [], [], [], {}, {}, [], {}, [], {}

    vul_addresses = diff_info_corresponding[key][0]
    pat_addresses = diff_info_corresponding[key][1]
    #print('vul_addresses', vul_addresses, len(vul_addresses))
    #print('pat_addresses', pat_addresses)

    vul_file_path = bins_dir + arr_key[1]
    pat_file_path = bins_dir + arr_key[2]

    #result of addresses which gotten by applying backward slicing on vulnerable function
    vul_slice_res_back = []
    vul_slice_res_forw = []
    vul_result_addr_list_forw_with_distance = dict()
    vul_result_addr_list = []
    vul_addr_distance_map = dict()
    print ('\nslice in vul ...', vul_func_info_path, len(vul_addresses))

    if len(vul_addresses) != 0:
        vul_func_info = load_func_obj(vul_func_info_path)
        vul_graph, vul_instr_blk_map = construct_graph(vul_func_info)
        vul_slice_res_back, vul_slice_res_forw, vul_result_addr_list_forw_with_distance = \
                slice_with_graph_dataflow(vul_addresses, \
                    vul_func_info, vul_file_path, vul_graph, vul_instr_blk_map)

        vul_result_addr_list, vul_addr_distance_map = \
                forward_slice_with_ctrl_and_layer(vul_addresses, vul_func_info)


    #results of addresses which gotten by applying backward slicing on patched function
    pat_slice_res_back = []
    pat_slice_res_forw = []
    pat_result_addr_list_forw_with_distance = dict()
    pat_result_addr_list = []
    pat_addr_distance_map = dict()
    print('\nslice in pat ...', pat_func_info_path, len(pat_addresses))

    if len(pat_addresses):
        pat_func_info = load_func_obj(pat_func_info_path)
        pat_graph, pat_instr_blk_map = construct_graph(pat_func_info)
        if len(pat_addresses) < 11:
            pat_slice_res_back, pat_slice_res_forw, pat_result_addr_list_forw_with_distance = \
                    slice_with_graph_dataflow(pat_addresses, \
                        pat_func_info, pat_file_path, pat_graph, pat_instr_blk_map)
            pat_result_addr_list, pat_addr_distance_map = \
                    forward_slice_with_ctrl_and_layer(pat_addresses, pat_func_info)
        else:
            pat_slice_res_back = []
            pat_slice_res_forw = []
            pat_result_addr_list_forw_with_distance = {}
            for i in range(int(len(pat_addresses)/10)):
                pat_slice_res_back_tmp, pat_slice_res_forw_tmp, pat_result_addr_list_forw_with_distance_tmp = \
                        slice_with_graph_dataflow(pat_addresses[i*10:(i+1)*10], \
                            pat_func_info, pat_file_path, pat_graph, pat_instr_blk_map)
                pat_slice_res_back += pat_slice_res_back_tmp
                pat_slice_res_forw += pat_slice_res_forw_tmp
                update_addr_distance_map(pat_result_addr_list_forw_with_distance, pat_result_addr_list_forw_with_distance_tmp)
            pat_slice_res_back_tmp, pat_slice_res_forw_tmp, pat_result_addr_list_forw_with_distance_tmp = \
                    slice_with_graph_dataflow(pat_addresses[(int(len(pat_addresses)/10))*10:], \
                        pat_func_info, pat_file_path, pat_graph, pat_instr_blk_map)
            pat_slice_res_back += pat_slice_res_back_tmp
            pat_slice_res_forw += pat_slice_res_forw_tmp
            update_addr_distance_map(pat_result_addr_list_forw_with_distance, pat_result_addr_list_forw_with_distance_tmp)
            pat_result_addr_list, pat_addr_distance_map = \
                    forward_slice_with_ctrl_and_layer(pat_addresses, pat_func_info)


    vul_slice_res = vul_slice_res_back + vul_slice_res_forw
    pat_slice_res = pat_slice_res_back + pat_slice_res_forw

    return vul_addresses, pat_addresses, vul_slice_res, pat_slice_res, \
            vul_result_addr_list_forw_with_distance, pat_result_addr_list_forw_with_distance, \
            vul_result_addr_list, vul_addr_distance_map, \
            pat_result_addr_list, pat_addr_distance_map

def get_stmt_addr_map(filepath):
    addr_item_list = list()
    try:
        with open(filepath) as f:
            content = f.read().split('\n')

        for idx in range(len(content)):
            line = content[idx]
            line = line.replace('\r', '')
            if line.startswith('0x'):
                tmp_addrs = line.split(',')
                addr_item_list.append(tmp_addrs)
    except Exception as e:
        print (e, 'in function get_stmts')
    return addr_item_list

def get_res_vul_addr(vul_addr, addr_item_list):
    res_vul_addr = []
    for addr_item in addr_item_list:
        if len(set(vul_addr) & set(addr_item)) > 0:
            res_vul_addr += addr_item
    res_vul_addr = list(set(res_vul_addr) | set(vul_addr))
    res_vul_addr.sort()
    return res_vul_addr

def get_res_pat_addr_w_remove_futher(addr_dist_map):
    addr_list = []
    for addr in addr_dist_map:
        distance = addr_dist_map[addr]
        if distance > 5 and distance != 21:
            continue
        addr_list.append(addr)
    return addr_list

def get_res_pat_addr_w_layer(ctrl_addr_dist_map, layer_num):
    addr_list = []
    for addr in ctrl_addr_dist_map:
        distance = ctrl_addr_dist_map[addr]
        if distance <= layer_num:
            addr_list.append(addr)
    return addr_list

#key: libfreetype_overflow_eaa9adf325e1612bdc7134648205597d055cb99c---libfreetype_281.so---libfreetype_29.so---Ins_SHPIX
#_dict1: line num to stmt in vulnerable function
#_dict2: line num to stmt in patched function
#pdg: function_pdg_libfreetype_29.so__Ins_MIRP.c.dot
#pseudocode: libfreetype_29.so__T1_Open_Face.c
#stmt_instr_map: libfreetype_29.so__TT_Set_Var_Design__address
def extract_sig(repo_name, key, _dict1, _dict2, pdg_path, pseudcode_path, \
        stmt_instr_map_path, diff_info, slice_res_dict_list, addr_mapping, \
        diff_info_corresponding, function_info_dir, bins_dir):

    print('GOING TO PROCESS ITEM', key)
    key = key.replace('\r', '')
    arr_key = key.split('---')
    goal_stmt_instr_map_path = os.path.join(stmt_instr_map_path, '%s__%s__address'%(arr_key[1], arr_key[-1]))
    addr_item_list = get_stmt_addr_map(goal_stmt_instr_map_path)


    #instr_addr_list_vul: addresses of instrs sliced by pdg of vulnerable function
    #instr_addr_list_pat: addresses of instrs sliced by pdg of patched function
    #vul_diff_info_addr_list: addresses of instrs in vulnerable function which differs with patched function
    #pat_diff_info_addr_list: addresses of instrs in patched function which differs with vulnerable function
    instr_addr_list_vul, instr_addr_list_pat, vul_diff_info_addr_list, \
        pat_diff_info_addr_list, _key_for_mapping = \
            extract_sig_by_pdg(key, pdg_path, _dict1, _dict2, diff_info)

    #vul_addresses: diff addresses in vulnerable function
    #pat_addresses: diff addresses in patched function
    #vul_slice_res: result of address list with datagraph in vulnerable function
    #pat_slice_res: result of address list with datagraph in patched function
    #vul_addr_dist_map: mapping between addr and distance in vlunerable function(addr from slicing criterion)
    #pat_addr_list_map: mapping between addr and distance in patched function(addr from slicing criterion)
    #vul_ctrl_res: result of address list with ctrl (cmp, test) in vul func
    #vul_ctrl_addr_dist_map: mapping between addr and distance in vul function with ctrl 
    #pat_ctrl_res: result of address list with ctrl (cmp, test) in pat func
    #pat_ctrl_addr_dist_map: mapping between addr and distance in pat function with ctrl
    vul_addresses, pat_addresses, vul_slice_res, pat_slice_res, vul_addr_dist_map, pat_addr_dist_map, \
            vul_ctrl_res, vul_ctrl_addr_dist_map, pat_ctrl_res, pat_ctrl_addr_dist_map = \
            extract_sig_by_graph_dataflow(key, function_info_dir, \
                diff_info_corresponding, bins_dir)


    #pdg only
    res_instr_addr_list_pat_1 = list(set(instr_addr_list_pat) - set(pat_addresses))
    addr_list_vul_by_pat_1 = get_addr_list_by_pat(addr_mapping[_key_for_mapping], res_instr_addr_list_pat_1)
    vul_addr_1 = list(set(instr_addr_list_vul) | set(vul_diff_info_addr_list) | set(addr_list_vul_by_pat_1))
    res_vul_addr_1 = get_res_vul_addr(vul_addr_1, addr_item_list)
    vul_addr_1.sort()
    print ('solution 1:', len(vul_addr_1), len(res_vul_addr_1))
    slice_res_dict_list[0][key] = [vul_addr_1, pat_addresses]
    slice_res_dict_list[1][key] = [res_vul_addr_1, pat_addresses]

    #datagraph only
    res_instr_addr_list_pat_2 = list(set(pat_slice_res) - set(pat_addresses))
    addr_list_vul_by_pat_2 = get_addr_list_by_pat(addr_mapping[_key_for_mapping], res_instr_addr_list_pat_2)
    vul_addr_2 = list(set(vul_addresses)|set(vul_slice_res)|set(addr_list_vul_by_pat_2))
    res_vul_addr_2 = get_res_vul_addr(vul_addr_2, addr_item_list)
    vul_addr_2.sort()
    print ('solution 2:', len(vul_addr_2), len(res_vul_addr_2))
    slice_res_dict_list[2][key] = [vul_addr_2, pat_addresses]
    slice_res_dict_list[3][key] = [res_vul_addr_2, pat_addresses]

    #ctrl_res only
    res_instr_addr_list_pat_3 = list(set(pat_ctrl_res) - set(pat_addresses))
    addr_list_vul_by_pat_3 = get_addr_list_by_pat(addr_mapping[_key_for_mapping], res_instr_addr_list_pat_3)
    vul_addr_3 = list(set(vul_addresses)|set(vul_ctrl_res)|set(addr_list_vul_by_pat_3))
    res_vul_addr_3 = get_res_vul_addr(vul_addr_3, addr_item_list)
    vul_addr_3.sort()
    print ('solution 3:', len(vul_addr_3), len(res_vul_addr_3))
    slice_res_dict_list[4][key] = [vul_addr_3, pat_addresses]
    slice_res_dict_list[5][key] = [res_vul_addr_3, pat_addresses]

    #datagraph only w/ removing futher addr
    res_pat_addr_aft = get_res_pat_addr_w_remove_futher(pat_addr_dist_map)
    res_vul_addr_aft = get_res_pat_addr_w_remove_futher(vul_addr_dist_map)
    res_instr_addr_list_pat_4 = list(set(res_pat_addr_aft) - set(pat_addresses))
    addr_list_vul_by_pat_4 = get_addr_list_by_pat(addr_mapping[_key_for_mapping], res_instr_addr_list_pat_4)
    vul_addr_4 = list(set(vul_addresses) | set(res_vul_addr_aft) | set(addr_list_vul_by_pat_4))
    res_vul_addr_4 = get_res_vul_addr(vul_addr_4, addr_item_list)
    vul_addr_4.sort()
    print ('solution 4:', len(vul_addr_4), len(res_vul_addr_4))
    slice_res_dict_list[6][key] = [vul_addr_4, pat_addresses]
    slice_res_dict_list[7][key] = [res_vul_addr_4, pat_addresses]

    #ctrl_res w/ 1 layer
    res_pat_addr_aft = get_res_pat_addr_w_layer(pat_ctrl_addr_dist_map, 1)
    res_vul_addr_aft = get_res_pat_addr_w_layer(vul_ctrl_addr_dist_map, 1)
    res_instr_addr_list_pat_5 = list(set(res_pat_addr_aft) - set(pat_addresses))
    addr_list_vul_by_pat_5 = get_addr_list_by_pat(addr_mapping[_key_for_mapping], res_instr_addr_list_pat_5)
    vul_addr_5 = list(set(vul_addresses) | set(res_vul_addr_aft) | set(addr_list_vul_by_pat_5))
    res_vul_addr_5 = get_res_vul_addr(vul_addr_5, addr_item_list)
    vul_addr_5.sort()
    print ('solution 5:', len(vul_addr_5), len(res_vul_addr_5))
    slice_res_dict_list[8][key] = [vul_addr_5, pat_addresses]
    slice_res_dict_list[9][key] = [res_vul_addr_5, pat_addresses]

    #ctrl_res w/ 2 layer
    res_pat_addr_aft = get_res_pat_addr_w_layer(pat_ctrl_addr_dist_map, 2)
    res_vul_addr_aft = get_res_pat_addr_w_layer(vul_ctrl_addr_dist_map, 2)
    res_instr_addr_list_pat_6 = list(set(res_pat_addr_aft) - set(pat_addresses))
    addr_list_vul_by_pat_6 = get_addr_list_by_pat(addr_mapping[_key_for_mapping], res_instr_addr_list_pat_6)
    vul_addr_6 = list(set(vul_addresses) | set(res_vul_addr_aft) | set(addr_list_vul_by_pat_6))
    res_vul_addr_6 = get_res_vul_addr(vul_addr_6, addr_item_list)
    vul_addr_6.sort()
    print ('solution 6:', len(vul_addr_6), len(res_vul_addr_6))
    slice_res_dict_list[10][key] = [vul_addr_6, pat_addresses]
    slice_res_dict_list[11][key] = [res_vul_addr_6, pat_addresses]

    #pdg + datagraph
    vul_addr_7 = list(set(vul_addr_1) | set(vul_addr_2))
    res_vul_addr_7 = list(set(res_vul_addr_1) | set(res_vul_addr_2))
    vul_addr_7.sort()
    res_vul_addr_7.sort()
    print ('solution 7:', len(vul_addr_7), len(res_vul_addr_7))
    slice_res_dict_list[12][key] = [vul_addr_7, pat_addresses]
    slice_res_dict_list[13][key] = [res_vul_addr_7, pat_addresses]

    #datagraph + ctrl_res
    vul_addr_8 = list(set(vul_addr_2) | set(vul_addr_3))
    res_vul_addr_8 = list(set(res_vul_addr_2) | set(res_vul_addr_3))
    vul_addr_8.sort()
    res_vul_addr_8.sort()
    print ('solution 8:', len(vul_addr_8), len(res_vul_addr_8))
    slice_res_dict_list[14][key] = [vul_addr_8, pat_addresses]
    slice_res_dict_list[15][key] = [res_vul_addr_8, pat_addresses]

    #datagraph + ctrl_res w/ 1
    vul_addr_9 = list(set(vul_addr_2) | set(vul_addr_5))
    res_vul_addr_9 = list(set(res_vul_addr_2) | set(res_vul_addr_5))
    vul_addr_9.sort()
    res_vul_addr_9.sort()
    print ('solution 9:', len(vul_addr_9), len(res_vul_addr_9))
    slice_res_dict_list[16][key] = [vul_addr_9, pat_addresses]
    slice_res_dict_list[17][key] = [res_vul_addr_9, pat_addresses]

    #datagraph + ctrl_res w/ 2
    vul_addr_10 = list(set(vul_addr_2) | set(vul_addr_6))
    res_vul_addr_10 = list(set(res_vul_addr_2) | set(res_vul_addr_6))
    vul_addr_10.sort()
    res_vul_addr_10.sort()
    print ('solution 10:', len(vul_addr_10), len(res_vul_addr_10))
    slice_res_dict_list[18][key] = [vul_addr_10, pat_addresses]
    slice_res_dict_list[19][key] = [res_vul_addr_10, pat_addresses]


    #pdg + datagraph + ctrl_res
    vul_addr_11 = list(set(vul_addr_1) | set(vul_addr_2) | set(vul_addr_3))
    res_vul_addr_11 = list(set(res_vul_addr_1) | set(res_vul_addr_2) | set(res_vul_addr_3))
    vul_addr_11.sort()
    res_vul_addr_11.sort()
    print ('solution 11:', len(vul_addr_11), len(res_vul_addr_11))
    slice_res_dict_list[20][key] = [vul_addr_11, pat_addresses]
    slice_res_dict_list[21][key] = [res_vul_addr_11, pat_addresses]

    #pdg + datagraph + ctrl_res w/ 1 
    vul_addr_12 = list(set(vul_addr_1) | set(vul_addr_2) | set(vul_addr_5))
    res_vul_addr_12 = list(set(res_vul_addr_1) | set(res_vul_addr_2) | set(res_vul_addr_5))
    vul_addr_12.sort()
    res_vul_addr_12.sort()
    print ('solution 12:', len(vul_addr_12), len(res_vul_addr_12))
    slice_res_dict_list[22][key] = [vul_addr_12, pat_addresses]
    slice_res_dict_list[23][key] = [res_vul_addr_12, pat_addresses]

    #pdg + datagraph + ctrl_res w/ 2
    vul_addr_13 = list(set(vul_addr_1) | set(vul_addr_2) | set(vul_addr_6))
    res_vul_addr_13 = list(set(res_vul_addr_1) | set(res_vul_addr_2) | set(res_vul_addr_6))
    vul_addr_13.sort()
    res_vul_addr_13.sort()
    print ('solution 13:', len(vul_addr_13), len(res_vul_addr_13))
    slice_res_dict_list[24][key] = [vul_addr_13, pat_addresses]
    slice_res_dict_list[25][key] = [res_vul_addr_13, pat_addresses]

    #pdg + datagraph w/ removing + ctrl_res
    vul_addr_14 = list(set(vul_addr_1) | set(vul_addr_3) | set(vul_addr_4))
    res_vul_addr_14 = list(set(res_vul_addr_1) | set(res_vul_addr_3) | set(res_vul_addr_4))
    vul_addr_14.sort()
    res_vul_addr_14.sort()
    print ('solution 14:', len(vul_addr_14), len(res_vul_addr_14))
    slice_res_dict_list[26][key] = [vul_addr_14, pat_addresses]
    slice_res_dict_list[27][key] = [res_vul_addr_14, pat_addresses]


    #pdg + datagraph w/ removing + ctrl_res w/ 1 
    vul_addr_15 = list(set(vul_addr_1) | set(vul_addr_4) | set(vul_addr_5))
    res_vul_addr_15 = list(set(res_vul_addr_1) | set(res_vul_addr_4) | set(res_vul_addr_5))
    vul_addr_15.sort()
    res_vul_addr_15.sort()
    print ('solution 15:', len(vul_addr_15), len(res_vul_addr_15))
    slice_res_dict_list[28][key] = [vul_addr_15, pat_addresses]
    slice_res_dict_list[29][key] = [res_vul_addr_15, pat_addresses]


    #pdg + datagraph w/ removing + ctrl_res w/2
    vul_addr_16 = list(set(vul_addr_1) | set(vul_addr_4) | set(vul_addr_6))
    res_vul_addr_16 = list(set(res_vul_addr_1) | set(res_vul_addr_4) | set(res_vul_addr_6))
    vul_addr_16.sort()
    res_vul_addr_16.sort()
    print ('solution 16:', len(vul_addr_16), len(res_vul_addr_16))
    slice_res_dict_list[30][key] = [vul_addr_16, pat_addresses]
    slice_res_dict_list[31][key] = [res_vul_addr_16, pat_addresses]


    '''
    #res_instr_addr_list_pat_x: list of addresses that exclude instructions that occur only in patched function
    res_instr_addr_list_pat_1 = list(set(instr_addr_list_pat) - set(pat_addresses)) #pdg
    res_instr_addr_list_pat_2 = list(set(pat_slice_res) - set(pat_addresses))       #datagraph
    res_instr_addr_list_pat_3 = list(set(pat_ctrl_res)-set(pat_addresses))
    res_instr_addr_list_pat_1.sort()
    res_instr_addr_list_pat_2.sort()
    res_instr_addr_list_pat_3.sort()

    addr_list_vul_by_pat_1 = get_addr_list_by_pat(addr_mapping[_key_for_mapping], res_instr_addr_list_pat_1)
    addr_list_vul_by_pat_2 = get_addr_list_by_pat(addr_mapping[_key_for_mapping], res_instr_addr_list_pat_2)


    print ('len of instr found by pdg', len(set(instr_addr_list_vul)|set(vul_diff_info_addr_list)|set(addr_list_vul_by_pat_1)))
    print ('instr found by pdg', set(instr_addr_list_vul)|set(vul_diff_info_addr_list)|set(addr_list_vul_by_pat_1))
    print ('len of instr found by miasm', len(set(vul_slice_res)|set(addr_list_vul_by_pat_2)))
    print ('instr found by miasm', set(vul_slice_res)|set(addr_list_vul_by_pat_2))
    vul_addr = list(set(instr_addr_list_vul) | set(vul_diff_info_addr_list) | \
            set(vul_slice_res) | set(addr_list_vul_by_pat_1) | set(addr_list_vul_by_pat_2))
    vul_addr.sort()

    slice_res_dict[key] = [vul_addr, pat_addresses]

    print ('instruction addr for vul sig', len(vul_addr))
    '''

def main(repo_name, slice_criterion_file, pdg_path, pseudocode_path, stmt_instr_map_path, \
                diff_info_file, addr_mapping_path, diff_info_corresponding_file, function_info_dir, bins_dir):
    slice_criterion = None
    with open(slice_criterion_file, 'rb') as f:
        slice_criterion = pickle.load(f)

    diff_info = None
    with open(diff_info_file, 'rb') as f:
        diff_info = pickle.load(f)

    diff_info_corresponding = None
    with open(diff_info_corresponding_file, 'rb') as f:
        diff_info_corresponding = pickle.load(f)

    addr_mapping = None
    with open(addr_mapping_path, 'rb') as f:
        addr_mapping = pickle.load(f)
    #print ('addr_mapping', list(addr_mapping.items())[0])

    cnt = 0

    slice_res_dict_list = []
    for i in range(32):
        slice_res_dict_list.append(dict())
    for key, values in slice_criterion.items():
        #if key != 'tcpdump_CVE-2017-13014_cc356512f512e7fa423b3674db4bb31dbe40ffec---tcpdump_4.9.1.bin---tcpdump_4.9.2.bin---wb_prep':
        #    continue
        #_dict1: slice_criterion_for_vul_func
        #_dict2: slice_criterion_for_pat_func
        #_dict line_num (key) : statement (value)
        _dict1 = values[0]
        _dict2 = values[1]
        if len(_dict1.items()) == 0 and len(_dict2.items()) == 0:
            print ('len of dict1', len(_dict1.items()))
            print ('len of dict2', len(_dict2.items()))
            continue
        try:
            extract_sig(repo_name, key, _dict1, _dict2, pdg_path, pseudocode_path, \
                stmt_instr_map_path, diff_info, slice_res_dict_list, addr_mapping, \
                diff_info_corresponding, function_info_dir, bins_dir)
        except Exception as e:
            print (e, key)
        cnt += 1
        print ('\n\n\n')
    print ('Total cnt', cnt)

    #'''
    with open('slice_res/slice_res_%s_v4' % repo_name, 'wb') as f:
        pickle.dump(slice_res_dict_list, f)
    #'''

'''
difference with v3:

    1) if there is not result of slicing => take succeeds into consideration
    2) if there are many instructions (result of slicing), remove instruction that are far away from slicing criterion
    3) when generating signature, mapping instruction to stmts to get whole instruction group
'''

if __name__ == '__main__':
    repo_name = sys.argv[1]
    start_t = time.time()
    slice_criterion_file = 'slice_criterion_res/slice_criterion_res_%s' % repo_name
    diff_info_file = 'diff_info_processed/diff_info_%s' % repo_name
    diff_info_corresponding_file = 'diff_info_processed/diff_info_corresponding_%s' % repo_name
    pdg_path = '../generated_pdg/%s/' % repo_name
    pseudocode_path = '../pseudo_codes/%s/' % repo_name
    #stmt_instr_map: mapping relation between stmt and addresses
    stmt_instr_map_path = '../stmt_addr_mapping/%s/' % repo_name
    #addr_mapping: mapping relation between addr in patched function and vulnerable function
    addr_mapping_path = 'addr_mapping_rel/addr_mapping_rel_%s.pkl' % repo_name
    #function_info: serialized function info (BFunc, BBasicBlock, BInstr)
    function_info_dir = '../function_info/%s/' % repo_name
    bins_dir = '../../data/bins/%s/' % repo_name
    main(repo_name, slice_criterion_file, pdg_path, pseudocode_path, stmt_instr_map_path, \
                diff_info_file, addr_mapping_path, diff_info_corresponding_file, function_info_dir, bins_dir)
    end_t = time.time()
    print('total time ...', end_t - start_t)
