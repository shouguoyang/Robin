# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     important_VALUEs
   Author :
   date：          2021/1/19
-------------------------------------------------
   Change Activity:
                   2021/1/19:
-------------------------------------------------
"""
import angr
import os
TMP_DIR = '/tmp/poc' # temporary dir to store internal files e.g. cfg files.
if not os.path.exists(TMP_DIR):
    os.mkdir(TMP_DIR)
ida = "/home/angr/idapro-7.5/idat" #!!! Important!!! The path to the ida executable.
CALL_WHITE_LIST = ['__x86.get_pc_thunk.bx'] + list(angr.SIM_PROCEDURES['libc'].keys())  # symbolic execution can step into these functions
min_mem_addr_npd = 0x1000 # a value X. if memory space is lower X, the access to memory space is treated as null pointer dereference
mem_page_size = 0x10000 # size of memory pages
stack_segment_base = 0xffff0000  # the stack base
heap_segment_base = 0xf0000000  # the heap base
reg_gs = 0x1000  # global register section  , which means global section starting from 0x10000000

dream_argument_value_min = 0x1000 # the bottom of argument space
dream_argument_value_max = 0x1000 + 0x1000 # the head of argument space

MAX_NUMBER_OF_ARGUMENT = 14 # the max number of arguments to support