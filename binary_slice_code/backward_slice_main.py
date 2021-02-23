# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     backward_slice_main
   Description :
   Author :       ysg
   date：          2021/1/7
-------------------------------------------------
   Change Activity:
                   2021/1/7:
-------------------------------------------------
"""
__author__ = 'ysg'
from .slice_v4 import data_analysis
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB


def backward_slice(binfile_path, func_addr, target_addrs):
    # print('Going to process', binfile_path, hex(func_addr), [hex(addr) for addr in target_addrs], '\n')
    try:
        slice_result = data_analysis(binfile_path, func_addr, target_addrs)
    except KeyError as e:
        return []

    # print ('slice_result', slice_result)
    result_addr_list_back = []
    for res in slice_result:
        # res.print_track_result()
        result_addr_list_back += res.data_from
    return result_addr_list_back
    # result_addr_list_forw_with_distance = get_distance(slice_result, graph, instr_blk_map)
    # print('result_addr_list_forw_with_distance', result_addr_list_forw_with_distance)


def iterate_slice(binfile_path, func_addr, target_addrs: list, func_cfg):
    to_slice_instr_addr = target_addrs
    slice_res_all = []
    while len(to_slice_instr_addr) > 0:
        slice_res = backward_slice(binfile_path, func_addr, to_slice_instr_addr)
        to_slice_instr_addr = []
        for x in slice_res:
            x = int(x, 16)
            if x not in slice_res_all:
                to_slice_instr_addr.append(x)
                slice_res_all.append(x)

    # 将切片得到的指令地址集合 映射成 基本块地址集合
    mapped_block_set = set()
    for slice_addr in slice_res_all:
        for block in func_cfg.blocks:
            if slice_addr in block.get_offsets():
                mapped_block_set.add(block.get_offsets()[0])

    return sorted(mapped_block_set)


if __name__ == '__main__':
    res = iterate_slice('./example/freetype-2.4.0', func_addr=0x36370, target_addrs=[0x3642A])
    print(",".join([hex(r) for r in res]))
