# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     important_VALUEs
   Author :       ysg
   date：          2021/1/19
-------------------------------------------------
   Change Activity:
                   2021/1/19:
-------------------------------------------------
"""
import angr
__author__ = 'ysg'
CALL_WHITE_LIST = ['__x86.get_pc_thunk.bx'] + list(angr.SIM_PROCEDURES['libc'].keys())  # list中函数可以进行符号执行
min_mem_addr_npd = 0x1000 # 待测函数所使用内存的最小值；如果访问低于该内存中的数据，则认为是空指针解引用操作
mem_page_size = 0x10000 # 内存页大小。 每次符号内存具体化时，都要放在上一个符号内存的下一页
stack_segment_base = 0xffff0000  # 将堆栈指定范围，方便检测空指针解引用（引用很低范围的地址即视为空指针解引用）
heap_segment_base = 0xf0000000  # 将堆栈指定范围，方便检测空指针解引用（引用很低范围的地址即视为空指针解引用）
reg_gs = 0x1000  # global register section  相当于从0x10000000 地址开始使用

dream_argument_value_min = 0x1000 # 理想参数值的最小值
dream_argument_value_max = 0x1000 + 0x1000 # 理想参数值的最大值