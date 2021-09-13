# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     taint_engine_v2
   Description :
   Author :       None
   date：          2021/4/2
-------------------------------------------------
   Change Activity:
                   2021/4/2:
-------------------------------------------------
"""
__author__ = 'None'
from taint_tracing import TBV_from_BV, TaintBV
import pyvex
import claripy
from angr.engines import HeavyVEXMixin, SimEngineFailure, SimEngineSyscall, HooksMixin, \
    SuperFastpathMixin, TrackActionsMixin, SimInspectMixin, HeavyResilienceMixin
from angr.engines.vex.claripy import ClaripyDataMixin


class TaintMixim(HeavyVEXMixin, ClaripyDataMixin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def _ty_to_bytes(self, ty):
        return pyvex.get_type_size(ty) // getattr(getattr(getattr(self, 'state', None), 'arch', None), 'byte_width', 8)

    def _perform_vex_expr_Get(self, offset, ty, **kwargs):
        '''
        1. check whether the source register is tainted
        2. if tainted, create a taintBV to return
        '''
        # 1
        data = super()._perform_vex_expr_Get(offset, ty, **kwargs)
        data_width = self._ty_to_bytes(ty)
        if isinstance(offset, claripy.ast.bv.BV):
            offset = self.state.solver.eval(offset)
        # reg_name = self.state.arch.register_size_names[(offset, data_width)]
        if self.state.ShadowMem.is_mem_chunk_tainted(offset, data_width):
            # 2
            taint_tags = self.state.ShadowMem.mem_chunk_tags(offset, data_width)
            data = TBV_from_BV(data, taint_tags)

        return data

    def _perform_vex_expr_Load(self, addr, ty, endness, **kwargs):
        '''
        1. check whether the source memory cell is tainted
        2. if tainted, create a taintBV to return
        '''
        if ty == 'Ity_F32':
            print('')
        data = super()._perform_vex_expr_Load(addr, ty, endness, **kwargs)
        data_width = self._ty_to_bytes(ty)
        if isinstance(addr, claripy.ast.bv.BV):
            addr = self.state.solver.eval(addr)

        if self.state.ShadowMem.is_mem_chunk_tainted(addr, data_width):
            taint_tags = self.state.ShadowMem.mem_chunk_tags(addr, data_width)
            data = TBV_from_BV(data, taint_tags)

        return data

    def _perform_vex_stmt_Put(self, offset, data, **kwargs):
        '''
        1. check whether the data is tainted
        2. If data is tainted, taint the target register with taint tags.
        '''
        # 1. check
        reg_offset = offset
        if isinstance(offset, claripy.ast.bv.BV):
            reg_offset = self.state.solver.eval(offset)
        if type(data) is TaintBV:
            taint_tags = data.tags
            # get the target register
            byte_size = data.args[1] // 8
            # target_reg_name = self.state.arch.register_size_names[(reg_offset, byte_size)]
            self.state.ShadowMem.taint(reg_offset, byte_size, taint_tags)

        return super()._perform_vex_stmt_Put(offset, data, **kwargs)

    def _perform_vex_stmt_Store(self, addr, data, endness, **kwargs):
        '''
        1. check whether the data is tainted
        2. If data is tainted, taint the target memory with taint tags.
        '''
        mem_addr = addr
        if isinstance(addr, claripy.ast.bv.BV):
            mem_addr = self.state.solver.eval(addr)

        if type(data) is TaintBV:
            taint_tags = data.tags
            # Taint the target memory
            byte_size = data.args[1] // 8
            self.state.ShadowMem.taint(mem_addr, byte_size, taint_tags)

        return super()._perform_vex_stmt_Store(addr, data, endness, **kwargs)

    def _perform_vex_expr_Op(self, op, args):
        '''
        Taint spreads in arithmetic instructions
        The length of args may be 1 or 2. For example Sub(t1, t2) and 64to32(t3)
        '''


        op_result = super()._perform_vex_expr_Op(op, args)

        tainted_tags = set()
        IS_TAINTED = False
        for opr in args:
            if type(opr) == TaintBV:
                IS_TAINTED = True
                tainted_tags |= opr.tags

        if IS_TAINTED:
            op_result = TBV_from_BV(op_result, tainted_tags)

        return op_result

    def _perform_vex_stmt_Exit(self, guard, target, jumpkind):

        return super()._perform_vex_stmt_Exit(guard, target, jumpkind)

    def _perform_vex_defaultexit(self, expr, jumpkind):

        if jumpkind == 'Ijk_Call':
            # function call handling here.
            pass
        return super()._perform_vex_defaultexit(expr, jumpkind)


class TaintEngine(
    SimEngineFailure,
    SimEngineSyscall,
    HooksMixin,
    SuperFastpathMixin,
    TrackActionsMixin,
    SimInspectMixin,
    HeavyResilienceMixin,
    TaintMixim
):
    pass
