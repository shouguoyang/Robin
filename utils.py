# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     utils
   Description :
   date：          2021/1/8
-------------------------------------------------
   Change Activity:
                   2021/1/8:
-------------------------------------------------
"""
import os
import glob
PROJECT_ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
TARGET_SIGNATURE_DIR = os.path.join(PROJECT_ROOT_DIR, "./data/target_sigs")  #
CVE_SIGNATURE_DIR = os.path.join(PROJECT_ROOT_DIR, "./data/cve_sigs")# the dir to save CVE signatures
CVE_FUNCTION_INPUTS = os.path.join(PROJECT_ROOT_DIR, "./data/cve_inputs")  # the dir to save CVE PoC inputs

if not os.path.exists(TARGET_SIGNATURE_DIR):
    os.mkdir(TARGET_SIGNATURE_DIR)

if not os.path.exists(CVE_SIGNATURE_DIR):
    os.mkdir(CVE_SIGNATURE_DIR)

if not os.path.exists(CVE_FUNCTION_INPUTS):
    os.mkdir(CVE_FUNCTION_INPUTS)


def get_cve_vul_sig_file_path(cve_id, function_name, OPT = None):
    '''
    :param cve_id: e.g. CVE-2016-2410
    :param function_name:
    :param OPT: optimization levels: O1, O2, O3
    :return: The signature file of vulnerable function.
    '''
    dir_p = CVE_SIGNATURE_DIR
    if OPT:
        dir_p = os.path.join(CVE_SIGNATURE_DIR, OPT)
    return os.path.join(dir_p, ("+".join([cve_id, "vul", function_name]) + '.sig'))


def get_cve_patch_sig_file_path(cve_id, function_name, OPT=None):
    '''
    :param cve_id: e.g. CVE-2016-2410
    :param function_name:
    :param OPT: optimization levels: O1, O2, O3
    :return: The signature file of patched function.
    '''
    dir_p = CVE_SIGNATURE_DIR
    if OPT:
        dir_p =os.path.join(CVE_SIGNATURE_DIR, OPT)
    return os.path.join(dir_p, "+".join([cve_id, "patched", function_name]) + ".sig")


def get_any_cve_state_file_path(cve_id):
    '''
    :param cve_id:
    :return: a PoC input for CVE
    '''
    state_file = os.path.join(CVE_FUNCTION_INPUTS, cve_id + "+*" + ".state")
    match_result = glob.glob(state_file)
    if len(match_result) < 1:
        return None
    return match_result[0]


def get_cve_state_file_path(cve_id, function_name):
    '''
    :param cve_id:
    :param function_name:
    :return: The state file saved by pickle.dump
    '''
    return os.path.join(CVE_FUNCTION_INPUTS, cve_id + "+{}".format(function_name) + ".state")


def get_target_binary_trace_file_path(cve_id, target_binary, function_name):
    '''
    :param cve_id:
    :param target_binary: binary name
    :param function_name:
    :return: semantic file path
    '''
    return target_binary+"+"+cve_id+"+"+function_name+".sig"


def get_target_cve_flag(cve_id, target_binary, function_name):
    '''
    :param cve_id:
    :param target_binary:
    :param function_name:
    :return: A symbol of target_binary containing vulnerable function 'function_name' of cve_id.
    '''
    return target_binary+"+"+cve_id+"+"+function_name+".flag"


def mk_sig_file_path(basedir, CVE, extra):
    '''
    the signature file
    :return:
    '''
    if type(extra) is list:
        extra.insert(0, CVE)
    return os.path.join(basedir, "+".join(extra) + ".sig")


def mk_cve_confirm_file(basedir, cve, binpath, func_name):
    # A symbol file of 'binpath' contains cve.
    return os.path.join(basedir, "+".join([cve, binpath, func_name]) + ".null_flag")
