# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     PoC_load
   Description :
   Author :
   date：          2021/5/27
-------------------------------------------------
   Change Activity:
                   2021/5/27:
-------------------------------------------------
"""
# -*- coding: utf-8 -*-
from datetime import datetime
import logging
import angr
import os
import json
from important_VALUEs import stack_segment_base, MAX_NUMBER_OF_ARGUMENT
from taint_tracing import ShadowMemory, taint_memory

l = logging.getLogger('LoadPoC')
l.setLevel(logging.DEBUG)
from .PoC_solve import SolvePoC


class LoadPoC:
    # Calling Conventions
    FASTCALL = 'fastcall'
    CDECL = 'cdecl'
    STDCALL = 'stdcall'
    WATCOM = 'watcom'
    PASCAL = 'pascal'
    OPTLINK = 'optlink'
    BORLAND = 'borland'
    MAX_ARG_NUMBER = MAX_NUMBER_OF_ARGUMENT

    def __init__(self, poc_file,
                 target_state: angr.SimState):
        '''
        :param poc_file: file path to PoC input
        :param target_state: state of target function
        '''

        if not os.path.isfile(poc_file):
            raise FileNotFoundError("PoC file does not exist")

        self._PoC = json.load(open(poc_file, 'r'))
        self._to_detect_state = target_state
        self._arch_name = target_state.arch.name
        # for taint analysis of arguments
        self._endness = target_state.memory.endness
        self._to_detect_state.register_plugin('ShadowMem', ShadowMemory(target_state.project))
        if self._arch_name in ['X86', 'AMD64']:  # ARMEL has only one calling convention
            from calling_convention import CallingConvention2
            cc = CallingConvention2(target_state)
            # self._cc = self._calling_convention_test()
            target_addr = target_state.addr
            if target_state.project.loader.main_object.pic:
                target_addr -= 0x400000
            # self._cc = cc.get_cc(target_addr)
            c_t = datetime.now()
            self._cc = cc.get_cc()
            l.debug('[T] Time for Calling Convention Identification: {:f}'.format((datetime.now() - c_t).total_seconds()))
            if self._cc == '':
                l.warning("CC is NULL. {} in {}".format(hex(target_state.addr), target_state.project.filename))
                self._cc = self.STDCALL
        self._arg0_addr = stack_segment_base + target_state.arch.bytes
        self._byte_width = int(target_state.arch.bits / 8)
        self._call_sites = []
        # self._callees_and_rets = callee_site_in_order  # (callsite, func_name): ret_val # 在符号执行过程中遇到的函数调用func_name，以及约束求解得到的函数返回值ret_val
        self._arg_cache = [None for i in range(self.MAX_ARG_NUMBER)]
        self._init_cc_args()
        self._calleename_and_rets = ()

    def load(self):
        # main
        for order, arg_tuple in enumerate(self._PoC[SolvePoC.ARGUMENTS]):
            if arg_tuple:
                val, size = arg_tuple
                self._init_arg(arg_order=order, value=val, width=size)

        for addr, memory in self._PoC[SolvePoC.MEMORY].items():
            val, size = memory
            self._init_mem(mem_addr=int(addr), value=val, width=size)

        for name, val in self._PoC[SolvePoC.REGISTERS].items():
            self._set_reg_by_name(name, val)

        self._calleename_and_rets = self._PoC[SolvePoC.FAKE_RETURNS]
        l.debug('PoC loaded.')

    @property
    def callee_rets(self):
        return self._calleename_and_rets

    def _init_cc_args(self):
        # initial argument spaces for different calling conventions
        # all cc argument list is formatted by "reg + stack".
        # we assume the max number of arguments is 12
        stack_for_arg = stack_segment_base + self._to_detect_state.arch.bytes
        cdecl = [stack_for_arg + self._byte_width * i for i in range(self.MAX_ARG_NUMBER)]
        fast_call = ['ecx', 'edx'] + [stack_for_arg + self._byte_width * i for i in range(self.MAX_ARG_NUMBER - 2)]
        borland_call = ['eax', 'edx', 'ecx'] + [stack_for_arg + self._byte_width * i for i in
                                                range(self.MAX_ARG_NUMBER - 3)]
        optlink = ['eax', 'edx', 'ecx'] + [stack_for_arg + self._byte_width * i for i in range(self.MAX_ARG_NUMBER - 3)]
        watcom = ['eax', 'edx', 'ebx', 'ecx'] + [stack_for_arg + self._byte_width * i for i in
                                                 range(self.MAX_ARG_NUMBER - 4)]
        self._x86_cc = {self.FASTCALL: fast_call, self.BORLAND: borland_call,
                        self.OPTLINK: optlink, self.WATCOM: watcom,
                        self.CDECL: cdecl, self.STDCALL: cdecl}
        self._arm_cc = ['r0', 'r1', 'r2', 'r3'] + [stack_for_arg + self._byte_width * i for i in
                                                   range(self.MAX_ARG_NUMBER - 4)]
        self._arm64_cc = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]

    def _calling_convention_test(self, step_limit=10):
        # 识别调用约定，初始化参数
        # 首先step 10 次获得之后的state
        l.info("[*] calling convention detecting...")
        succ = self._to_detect_state.step()
        jmp_target = None
        try:
            while len(succ.successors) >= 1 and step_limit > 0:
                jmp_target = succ.successors[0]
                if len(jmp_target.solver.constraints) > 10:
                    break
                succ = jmp_target.step()
                step_limit -= 1
        except Exception as e:
            l.debug('[*] step early stop in calling convention identificaiton')

        if len(succ.all_successors) > 0:
            jmp_target = succ.all_successors[0]

        # 判断获得的state中的约束是否存在符号值 eax, edx, ecx

        for var in jmp_target.solver.get_variables('reg'):
            try:
                (name, addr, _), ast = var
                # if len(var[0]) == 3:
                #     (name, addr, _), ast = var
                #
                # elif len(var[0]) == 4:
                #     (name, _, _, addr), ast = var
                # else:
                #     raise Exception()
                if name == 'reg':
                    if addr <= 16:
                        l.warning("[!] Guess fastcall!")
                        return self.FASTCALL
            except Exception as e:
                l.warning("[*] unpack error: {} ".format(var))
        l.debug("[*] calling convention is: cdecl")
        return self.CDECL

    def _set_reg_by_name(self, reg_name, value):
        reg_number, reg_width = self._to_detect_state.arch.registers[reg_name]
        if type(value) is int:
            l.debug("\tReg: {} = {}".format(reg_name, hex(value)))
        self._to_detect_state.registers.store(reg_number, value, endness=self._to_detect_state.arch.register_endness)

    def _init_mem(self, mem_addr, value, width):
        # if a memory address is related with argument, it should be tainted with a tag.
        # e.g.  arg0 = 0x100000, if the mem_addr is 0x100010, then it is tainted with "arg0+0x10"
        data = self._to_detect_state.solver.BVV(value, width * 8)

        for i, arg_value in enumerate(self._arg_cache):
            if arg_value and mem_addr - arg_value < 0x1000:
                margin = mem_addr - arg_value
                tag = 'arg{}+{}'.format(i, hex(margin))
                taint_memory(self._to_detect_state, mem_addr, data, {tag})
                break

        l.debug("\tMem: {} ={}".format(hex(mem_addr), hex(value)))
        self._to_detect_state.memory.store(mem_addr, data, endness=self._endness)
        taint_memory(self._to_detect_state, mem_addr, data, {'mem_{}'.format(mem_addr)})

    def _init_arg(self, arg_order, value, width):
        '''
        :param arg_order: the order of argument
        :param value: value
        :param width: size in byte
        '''
        self._arg_cache[arg_order] = value
        data = self._to_detect_state.solver.BVV(value, width * 8)
        arg_addr = None
        if self._arch_name == 'X86':
            arg_addr = self._x86_cc[self._cc][arg_order]
            l.debug("\tArg: {}({} bytes)({}) = 0x{:x}".format(arg_order, width, arg_addr, value))
            if self._cc == self.CDECL or self._cc == self.STDCALL:
                self._to_detect_state.memory.store(arg_addr, data, endness=self._endness)
            elif self._cc == self.FASTCALL:
                if arg_order < 2:
                    self._set_reg_by_name(arg_addr, data)
                else:
                    self._to_detect_state.memory.store(arg_addr, data, endness=self._endness)
            elif self._cc == self.WATCOM:
                if arg_order < 4:
                    self._set_reg_by_name(arg_addr, data)
                else:
                    self._to_detect_state.memory.store(arg_addr, data, endness=self._endness)
            elif self._cc == self.BORLAND:
                if arg_order < 3:
                    self._set_reg_by_name(arg_addr, data)
                else:
                    self._to_detect_state.memory.store(arg_addr, data, endness=self._endness)
            else:
                raise Exception("Not supported calling convention.")

        elif self._arch_name == 'AMD64':
            reg_name = self._arm64_cc[arg_order]
            self._to_detect_state.registers.store(
                self._to_detect_state.arch.registers[reg_name][0], data,
                endness=self._to_detect_state.arch.register_endness)
            l.debug('\t Reg: {} = {}'.format(reg_name, hex(value)))

        elif self._arch_name == 'ARMEL':
            arg_addr = self._arm_cc[arg_order]
            if arg_order < 4:
                l.debug("\tArg: {}({} bytes)({}) = 0x{:x}".format(arg_order, width, arg_addr, value))
                self._set_reg_by_name(arg_addr, data)
            else:
                l.debug("\tArg: {}({} bytes)(0x{:x}) = 0x{:x}".format(arg_order, width, arg_addr, value))
                self._to_detect_state.memory.store(arg_addr, data, endness=self._endness)

        else:
            raise Exception("not support arch {} in init_arg".format(self._arch_name))

        taint_memory(self._to_detect_state, arg_addr, data, {'arg{}'.format(arg_order)})
