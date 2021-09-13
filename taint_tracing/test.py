# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     test
   Description :
   Author :
   date：          2021/4/1
-------------------------------------------------
   Change Activity:
                   2021/4/1:
-------------------------------------------------
"""


def taint_spread_test():
    import angr
    from taint_tracing import ShadowMemory, TaintEngine, taint_memory
    p = angr.Project("../binaries/tcpdump/O0/tcpdump-4.9.2", load_options={'auto_load_libs': False}, engine=TaintEngine)
    # p = angr.Project("/bin/bash", load_options={'auto_load_libs': False}, engine=TaintMixim)
    import claripy
    call_state = p.factory.call_state(addr=0x807F95E)
    call_state.register_plugin('ShadowMem', ShadowMemory(p))

    '''
    prepare the stack frame
    '''
    arg0 = claripy.BVV(0x500000, p.arch.bits)
    arg0_d = claripy.BVV(0x100, p.arch.bits)  # arg dereference
    arg0_ds = claripy.BVV(0x300, p.arch.bits)  # arg dereference and shift
    arg0_cs = claripy.BVV(0x8081A7C, p.arch.bits) # call site
    arg1 = claripy.BVV(0x300000, p.arch.bits)
    arg2 = claripy.BVV(2, p.arch.bits)
    arg3 = claripy.BVV(1, p.arch.bits)
    arg1d = claripy.BVV(0x1000, p.arch.bits)

    stack_bp = 0x400000
    call_state.regs.sp = stack_bp + 4
    taint_memory(call_state, stack_bp + 8, arg0, {"arg0"})
    taint_memory(call_state, 0x500000, arg0_d, {"arg0_d"})
    taint_memory(call_state, 0x500068, arg0_ds, {"arg0_ds"})
    taint_memory(call_state, 0x500074, arg0_cs, {"arg0_cs"})
    taint_memory(call_state, stack_bp + 12, arg1, {"arg1"})
    taint_memory(call_state, stack_bp + 16, arg2, {"arg2"})
    taint_memory(call_state, stack_bp + 20, arg3, {"arg3"})
    taint_memory(call_state, 0x300000, arg1d, {"arg1d"})

    assert call_state.ShadowMem.is_mem_chunk_tainted(0x500068, 4) == True
    assert call_state.ShadowMem.is_tainted('eax') == False
    '''
    # Prepare the parameters
    call_state.regs.rdi = arg0
    call_state.regs.rsi = arg1
    call_state.regs.rdx = arg2

    # Plugin registration and Taint the variables!
    call_state.register_plugin('TaintRecorder', TaintRecorder(call_state.arch))
    call_state.TaintRecorder.taint_register('rdi', tags={'arg0'})
    call_state.TaintRecorder.taint_register('rsi', tags={'arg1'})
    call_state.TaintRecorder.taint_register('rdx', tags={'arg3'})
    '''

    # add a breakpoint
    def inspect_instructions(state):
        print(hex(state.addr))

    call_state.inspect.b('instruction', when=angr.BP_BEFORE, action=inspect_instructions)

    simgr = p.factory.simgr(call_state)
    simgr.run()

    actives = simgr.active

    print('Run end.')


if __name__ == '__main__':
    taint_spread_test()
