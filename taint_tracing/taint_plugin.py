# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     shadow_memory
   Description :
   Author :       None
   date：          2021/4/15
-------------------------------------------------
   Change Activity:
                   2021/4/15:
-------------------------------------------------
use angr's DefaultMemory as shadow memory.
We tag every byte with a tag string.
"""
from angr import SimStatePlugin

__author__ = 'None'
from angr.storage import DefaultMemory
import angr
from collections import defaultdict
from claripy import BV


def taint_memory(state: angr.SimState, addr, data: BV, tags: set):
    '''
    Set the memory and ShadowMem of state simultaneously
    :param state:
    :param addr: the target mem address or a reg name
    :param data: the data saved to memory
    :param tags: taint tag
    '''
    if isinstance(addr, str):
        if addr in state.arch.registers:
            addr = state.arch.registers[addr][0]
        else:
            raise KeyError("{} is not a register name".format(addr))
    state.memory.store(addr, data, endness=state.project.arch.memory_endness)
    state.ShadowMem.taint(addr, data.size()//8, tags)


class ShadowMemory(DefaultMemory):

    def __init__(self, proj: angr.Project):
        super().__init__(memory_id='mem')
        self._proj = proj
        self._bytes = proj.arch.bytes
        self._tags = defaultdict(set)

    def taint(self, addr: int, size: int, tags: set,
              keep = False):
        '''
        :param addr: The memory address to taint
        :param tags: The tag string attached to addr
        :param size: size in byte. Default is the arch.bytes
        :param keep: Whether keep the old tags
        '''
        if size is None:
            size = self._proj.arch.bytes
        data = b'\xff' * size
        self.store(addr, data, disable_action=True, inspect=False) # taint in shadow memories
        # add tags
        if keep:
            for addr_r in range(addr, addr + size):
                self._tags[addr_r] |= tags
        else:
            for addr_r in range(addr, addr + size):
                self._tags[addr_r] = tags

    @property
    def mem_tag(self):
        return self._tags

    def mem_chunk_tags(self, addr, size = None):
        if size is None:
            size = self._bytes
        if isinstance(addr, str):
            if addr in self.state.arch.registers:
                addr = self.state.arch.registers[addr][0]
            else:
                raise KeyError("{} is not a register name".format(addr))

        tags = set()
        for a in range(addr, addr + size):
            tags |= self._tags[a]
        return tags

    def set_mem_tag(self, addr: int, tags: set):
        self._tags[addr] |= tags

    def is_tainted(self, addr):
        '''see if the byte is tainted
        addr: int: memory address
        addr: str: register name
        '''
        if isinstance(addr, str):
            if addr in self.state.arch.registers:
                addr = self.state.arch.registers[addr][0]
            else:
                raise KeyError("{} is not a register name".format(addr))

        data = self.load(addr, 0x1, disable_action=True, inspect=False)
        # the value is not symbolic and it's value is not equal 0.
        if not data.symbolic and data.args[0] != 0:
            return True
        return False

    def is_mem_chunk_tainted(self, addr, size):
        for a in range(addr, addr + size):
            if self.is_tainted(a):
                return True
        return False

    @SimStatePlugin.memo
    def copy(self, memo):
        # o = super().__init__()
        o = ShadowMemory(self._proj)
        o._proj = self._proj
        o._tags = self._tags

        o.page_size = self.page_size
        o._pages = dict(self._pages)
        o._permissions_map = self._permissions_map
        o._default_permissions = self._default_permissions

        for page in o._pages.values():
            if page is not None:
                page.acquire_shared()

        return o


def sm_test():
    import angr
    from taint_tracing.taint_engine_v2 import TaintMixim
    p = angr.Project("../binaries/tcpdump/O0/tcpdump-4.9.2", load_options={'auto_load_libs': False}, engine=TaintMixim)
    # p = angr.Project("/bin/bash", load_options={'auto_load_libs': False}, engine=TaintMixim)
    import claripy

    arg0 = claripy.BVV(0, p.arch.bits)
    arg1 = claripy.BVV(1, p.arch.bits)
    arg2 = claripy.BVV(2, p.arch.bits)
    call_state = p.factory.call_state(addr=0x804D910)

    '''
    prepare the stack frame
    '''
    stack_bp = 0x400000
    call_state.regs.sp = stack_bp

    call_state.memory.store(stack_bp + 8, arg0)
    call_state.memory.store(stack_bp + 12, arg1)
    call_state.memory.store(stack_bp + 16, arg2)
    # Plugin registration and vairable taints
    call_state.register_plugin('ShadowMem', ShadowMemory(proj=p))
    call_state.ShadowMem.taint(0x100, tags={'test'}, size=10)
    print(call_state.ShadowMem.is_tainted(0x100))
    print(call_state.ShadowMem.mem_tag[0x101])
    call_state.ShadowMem.set_mem_tag(0x102, {"test2"})
    print(call_state.ShadowMem.mem_tag[0x102])


if __name__ == '__main__':
    sm_test()
