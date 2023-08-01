# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     Memory_Access
   Description :
   Author :
   date：          2020/11/10
-------------------------------------------------
   Change Activity:
                   2020/11/10:
-------------------------------------------------
"""
import angr

import logging
import traceback
from running_setting import mem_page_size
from utils import LOG_LEVEL

l = logging.getLogger("Memory_Access")
l.setLevel(LOG_LEVEL)


class SimConcretizationStrategyMap(angr.concretization_strategies.SimConcretizationStrategy):
    '''
    To make sure the symbolic memory address locates defined heap space (0xf0000000~0xff000000).
    when: to access a memory object which is uninitialized.
    '''

    def __init__(self, min_addr, max_addr):
        angr.concretization_strategies.SimConcretizationStrategy.__init__(self)
        self._min = min_addr
        self._max = max_addr
        self._seg_size = mem_page_size

    def _concretize(self, memory, addr):
        # careful about the new added constrains
        try:
            ms = [self._any(memory, addr, extra_constraints=[addr > self._min, addr < self._min + self._seg_size])]
            self._min += self._seg_size
        except angr.SimUnsatError as e:
            # the symbolic mem has only one solution
            ms = [self._any(memory, addr)]

        # l.debug("[*] Memory concretize {}".format(" ".join([hex(x) for x in ms])))
        return ms


def mem_read_write_monitor(state):
    '''
    :param state:
    : 监测 内存读写
    '''

    def ieval(state, bv):
        try:
            return state.solver.eval(bv)
        except angr.SimUnsatError as e:
            state.solver.add(False)
            l.error(traceback.format_exc())
            l.error(str(e))

    def track_mem_reads(state):
        mem_read_addr = ieval(state, state.inspect.mem_read_address)
        # below two lines cause the state early stop
        # if mem_read_addr < 0x10000000:
        #     state.solver.add(False) # for what ???????? i forget
        l.debug("[M] Read at 0x{:x}: mem_addr is 0x{:x} (ebp - 0x{})".
                format(state.addr, mem_read_addr, str(state.regs.bp - state.inspect.mem_read_address)))
        state.project._acc_seq.append(("R", mem_read_addr))

    def track_mem_write(state):
        mem_write_addr = ieval(state, state.inspect.mem_write_address)
        # below two lines cause the state early stop
        # if mem_write_addr < 0x10000000:
        #     state.solver.add(False)
        l.debug("[M] Write at 0x{:x}: mem_addr is {:x} (ebp - 0x{})".
                format(state.addr, mem_write_addr, str(state.regs.bp - state.inspect.mem_write_address)))
        state.project._acc_seq.append(("W", mem_write_addr))

    state.inspect.b('mem_read', when=angr.BP_BEFORE, action=track_mem_reads)
    state.inspect.b("mem_write", when=angr.BP_BEFORE, action=track_mem_write)
