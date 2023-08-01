# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     utils
   Description :
   Author :
   date：          2021/1/8
-------------------------------------------------
   Change Activity:
                   2021/1/8:
-------------------------------------------------
"""
import os
import logging
import glob
import angr
import networkx as nx
from pathlib import Path

PROJECT_ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
# PROJECT_ROOT_DIR = Path('/home/angr/PatchDiff')
TARGET_SIGNATURE_DIR = os.path.join(PROJECT_ROOT_DIR, "./data/target_sigs")  # a dir path to save target function signatures
CVE_SIGNATURE_DIR = os.path.join(PROJECT_ROOT_DIR, "./data/cve_sigs") # a dir path to save Vulnerability signatures
CVE_FUNCTION_INPUTS_PATH = os.path.join(PROJECT_ROOT_DIR, "./data/cve_inputs")  #a dir path to save PoC

LOG_LEVEL=logging.INFO

if not os.path.exists(TARGET_SIGNATURE_DIR):
    os.mkdir(TARGET_SIGNATURE_DIR)

if not os.path.exists(CVE_SIGNATURE_DIR):
    os.mkdir(CVE_SIGNATURE_DIR)

if not os.path.exists(CVE_FUNCTION_INPUTS_PATH):
    os.mkdir(CVE_FUNCTION_INPUTS_PATH)


class FunctionNotFound(Exception):
    pass


def get_cve_vul_sig_file_path(cve_id, function_name, OPT=None):
    '''
    :param cve_id: e.g. CVE-2016-2410
    :param function_name
    :param OPT: to specify the optimization of signature
    :return: vulnerable function signature path
    '''
    dir_p = CVE_SIGNATURE_DIR
    if OPT:
        dir_p = os.path.join(CVE_SIGNATURE_DIR, OPT)
    return os.path.join(dir_p, ("+".join([cve_id, "vul", function_name]) + '.sig'))


def get_cve_patch_sig_file_path(cve_id, function_name, OPT=None):
    '''
    :param cve_id: e.g. CVE-2016-2410
    :param function_name
    :param OPT: to specify the optimization of signature
    :return: patched function signature path
    '''
    dir_p = CVE_SIGNATURE_DIR
    if OPT:
        dir_p = os.path.join(CVE_SIGNATURE_DIR, OPT)
    return os.path.join(dir_p, "+".join([cve_id, "patched", function_name]) + ".sig")


def get_any_cve_state_file_path(cve_id):
    '''
    :param cve_id:
    :return: state file of cve
    '''
    state_file = os.path.join(CVE_FUNCTION_INPUTS_PATH, cve_id + "+*" + ".state")
    match_result = glob.glob(state_file)
    if len(match_result) < 1:
        return None
    return match_result[0]


def get_cve_state_file_path(cve_id, function_name):
    '''
    :param cve_id:
    :param function_name:
    :return: state file of this cve
    '''
    return os.path.join(CVE_FUNCTION_INPUTS_PATH, cve_id + "+{}".format(function_name) + ".state")


def get_PoC_file_path(cve_id, function_name):
    return os.path.join(CVE_FUNCTION_INPUTS_PATH, cve_id + "+{}".format(function_name) + ".poc")


def get_target_binary_trace_file_path(cve_id, target_binary, function_name):
    '''
    :param cve_id:
    :param target_binary
    :param function_name
    :return:  memory access file path
    '''
    return target_binary + "+" + cve_id + "+" + function_name + ".sig"


def get_target_cve_flag(cve_id, target_binary, function_name):
    '''
    :param cve_id:
    :param target_binary:
    :param function_name:
    :return: a flag file which signs function_name in target_binary triggering null pointer dereference
    '''
    return target_binary + "+" + cve_id + "+" + function_name + ".flag"


def mk_sig_file_path(basedir, CVE, extra):
    '''
    :return:    signature file path
    '''
    if type(extra) is list:
        extra.insert(0, CVE)
    return os.path.join(basedir, "+".join(extra) + ".sig")


def addr_to_func_name(p, addr):
    sym = p.loader.find_symbol(addr)
    if sym is not None:
        name = sym.name
    else:
        name = p.loader.find_plt_stub_name(addr)
    if name is not None:
        return name
    logging.getLogger(__name__).warning("No function name founded in addr {}".format(hex(addr)))
    return ""


def get_shortest_paths_in_graph(project, G, source, target, weight='weight'):
    '''find the shortest path from source to target in function CFG
    :project: angr project
    :param source: int: address
    :return two dimension of list [[]]
    '''
    # get the node in the CFG
    source_node = None
    target_node = None
    if type(G) is angr.analyses.cfg.CFGFast:
        # ! ！！It should be noted that the path may include nodes outside the function！！！
        source_node = G.model.get_node(source)
        target_node = G.model.get_node(target)
        G = G.graph
    elif isinstance(source, int):  # networkx.classes.digraph.DiGraph
        source_node = project.factory.block(source).codenode
        target_node = project.factory.block(target).codenode
        # check if target_node is a sub-node of source_node. if true, return [source_node]
        if source_node.addr <= target_node.addr < source_node.addr + source_node.size:
            return [[source_node]]
    else:
        source_node = source
        target_node = target

    if target_node not in G.nodes:
        for n in G.nodes:
            if target_node.addr >= n.addr and target_node.addr <= n.addr + n.size:
                target_node = n
                break
        else:
            raise NotImplementedError("[!] Cound not relocation target node {}".format(hex(target_node.addr)))

    if source_node not in G.nodes:
        for n in G.nodes:
            if source_node.addr >= n.addr and source_node.addr <= n.addr + n.size:
                source_node = n
                break
        else:
            raise NotImplementedError("[!] Cound not relocation sorce node {}".format(hex(source_node.addr)))
    try:
        paths = list(nx.all_shortest_paths(G, source_node, target_node, weight=weight))
    except nx.NetworkXNoPath:
        for node in G.nodes:
            if node.addr < target_node.addr < node.addr + node.size:
                paths = list(nx.all_shortest_paths(G, source_node, node, weight=weight))
                break
        else:
            if not isinstance(source, int):
                source = source.addr
            if not isinstance(target, int):
                target = target.addr
            raise NotImplementedError("No path founded from {} to {}".format(hex(source), hex(target)))
    return paths


import json


def load_json_data(file_name):
    with open(file_name, 'r') as f:
        data = json.load(f)
    return data
