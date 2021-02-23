# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     utils
   Description :
   Author :       ysg
   date：          2021/1/8
-------------------------------------------------
   Change Activity:
                   2021/1/8:
-------------------------------------------------
"""
__author__ = 'ysg'
import os
import glob
PROJECT_ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
TARGET_SIGNATURE_DIR = os.path.join(PROJECT_ROOT_DIR, "./data/target_sigs")  # 存访目标二进制签名的根路径
CVE_SIGNATURE_DIR = os.path.join(PROJECT_ROOT_DIR, "./data/cve_sigs")
CVE_FUNCTION_INPUTS = os.path.join(PROJECT_ROOT_DIR, "./data/cve_inputs")  # 存放生成的补丁函数state

if not os.path.exists(TARGET_SIGNATURE_DIR):
    os.mkdir(TARGET_SIGNATURE_DIR)

if not os.path.exists(CVE_SIGNATURE_DIR):
    os.mkdir(CVE_SIGNATURE_DIR)

if not os.path.exists(CVE_FUNCTION_INPUTS):
    os.mkdir(CVE_FUNCTION_INPUTS)


def get_cve_vul_sig_file_path(cve_id, function_name, OPT = None):
    '''
    :param cve_id: e.g. CVE-2016-2410
    :param function_name: 漏洞函数名
    :param OPT:
    :return: cve 对应此漏洞函数的签名文件路径
    '''
    dir_p = CVE_SIGNATURE_DIR
    if OPT:
        dir_p = os.path.join(CVE_SIGNATURE_DIR, OPT)
    return os.path.join(dir_p, ("+".join([cve_id, "vul", function_name]) + '.sig'))


def get_cve_patch_sig_file_path(cve_id, function_name, OPT=None):
    '''
    :param cve_id: e.g. CVE-2016-2410
    :param function_name: 补丁函数名
    :param OPT: 不同编译优化生成的 sig 保存路径
    :return: cve 对应此补丁函数的签名文件路径
    '''
    dir_p = CVE_SIGNATURE_DIR
    if OPT:
        dir_p =os.path.join(CVE_SIGNATURE_DIR, OPT)
    return os.path.join(dir_p, "+".join([cve_id, "patched", function_name]) + ".sig")


def get_any_cve_state_file_path(cve_id):
    '''
    :param cve_id:
    :return: 返回此CVE对应的任意一个state文件
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
    :return: 返回CVE对应的 angr.state(pickle.dump保存) 文件路径
    '''
    return os.path.join(CVE_FUNCTION_INPUTS, cve_id + "+{}".format(function_name) + ".state")


def get_target_binary_trace_file_path(cve_id, target_binary, function_name):
    '''
    :param cve_id:
    :param target_binary: 目标二进制文件名称
    :param function_name: 函数名
    :return: 二进制文件对应函数在 CVE state 输入下运行得到的内存访问文件序列
    '''
    return target_binary+"+"+cve_id+"+"+function_name+".sig"


def get_target_cve_flag(cve_id, target_binary, function_name):
    '''
    :param cve_id:
    :param target_binary:
    :param function_name:
    :return: 该文件用于记录 target_binary 是否触发了空指针解引用的漏洞
    '''
    return target_binary+"+"+cve_id+"+"+function_name+".flag"


def mk_sig_file_path(basedir, CVE, extra):
    '''
    生成函数运行时的签名文件
    :return:
    '''
    if type(extra) is list:
        extra.insert(0, CVE)
    return os.path.join(basedir, "+".join(extra) + ".sig")


def mk_cve_confirm_file(basedir, cve, binpath, func_name):
    # 生成二进制文件binpath 在确认存在cve 漏洞函数时的标记文件
    return os.path.join(basedir, "+".join([cve, binpath, func_name]) + ".null_flag")
