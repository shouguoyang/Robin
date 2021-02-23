# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     preparetion_for_detection
   Description :
   date：          2021/1/11
-------------------------------------------------
   Change Activity:
                   2021/1/11:
-------------------------------------------------
"""
import logging
import angr
import re
import random
from important_VALUEs import dream_argument_value_min, dream_argument_value_max

l = logging.getLogger('preparation')
l.setLevel(logging.DEBUG)


class PreDetection:
    FASTCALL = 'fastcall'
    CDECL = 'CDECL'

    def __init__(self, patch_state: angr.SimState,
                 to_detect_state: angr.SimState,
                 arg_addr, arch_name,
                 callee_site_in_order):
        '''

        '''
        self._patch_state = patch_state
        self._solver = patch_state.solver
        self._to_detect_state = to_detect_state
        self._cc = self._calling_convention_test()
        self._arg0_addr = arg_addr
        self._arch_name = arch_name
        self._byte_width = int(to_detect_state.arch.bits / 8)
        self._call_sites = []
        self._callees_and_rets = callee_site_in_order  # (callsite, func_name): ret_val #

        self. _fastcall_arg_addr = ['eax', 'edx', 'ecx',
                                   self._arg0_addr,
                                   self._arg0_addr + self._byte_width,
                                   self._arg0_addr + self._byte_width * 2,
                                   self._arg0_addr + self._byte_width * 3,
                                   self._arg0_addr + self._byte_width * 4,
                                   self._arg0_addr + self._byte_width * 5,
                                   self._arg0_addr + self._byte_width * 6]
        # main function
        self._resolve_constraints()

    def _calling_convention_test(self, step_limit=10):

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


        for var in jmp_target.solver.get_variables():
            try:
                if len(var[0]) == 3:
                    (name, addr, _), ast = var

                elif len(var[0]) == 4:
                    (name, _, _, addr), ast = var
                else:
                    raise Exception()
                if name == 'reg':
                    if addr <= 16:
                        l.warning("[!] Guess fastcall!")
                        return self.FASTCALL
            except Exception as e:
                l.warning("[*] unpack error: {} ".format(var))
        l.debug("[*] calling convention is: cdecl")
        return self.CDECL

    def _resolve_constraints(self):  #
        for const in self._patch_state.solver.constraints:
            for leaf_ast in const.leaf_asts():
                if leaf_ast.symbolic:
                    try:
                        self.parse_leaf_ast(leaf_ast)
                    except angr.SimUnsatError:
                        l.warning("[!] SimUnsatError for {}".format(leaf_ast))

    def _parse_fake_ret(self, ast):
        '''

        fake_ret_ssl_generate_pkey_16_32
        '''
        try:
            ret_vals = self._solver.eval_upto(ast, 5,
                                              extra_constraints=[ast > dream_argument_value_min,
                                                                 ast < dream_argument_value_max])
            ret_val = ret_vals[random.randint(0, len(ret_vals) - 1)]
            self._solver.add(ast == ret_val)
        except Exception:
            try:
                ret_val = self._solver.eval(ast)  #
            except angr.SimUnsatError as e:
                l.error("[!] {}".format(e.args))
                return
        #fake_ret__0x423772_104_32; fake_ret_foo_101_32
        pattern = 'fake_ret_(?P<function_name>[\w_\.]*)_(?P<call_addr>0x[0-9a-fA-F]+)_(?P<v1>[0-9]{1,})_(?P<v2>[0-9]{1,})'
        res = re.search(pattern, ast.shallow_repr(max_depth=10))
        if not res:
            raise Exception("[!] _parse_fake_ret {}".format(ast.shallow_repr()))
        function_name = res.group('function_name')
        call_site = int(res.group('call_addr'), 16)
        if (call_site, function_name) in self._callees_and_rets:
            l.debug("\t {} called in {} returns {}".format(function_name, hex(call_site), hex(ret_val)))
            self._callees_and_rets[(call_site, function_name)] = ret_val
        else:
            l.warning("\t unrecorded function call {}".format(ast.shallow_repr()))

    def _parse_mem_(self, ast):
        '''
        mem_f0000100_15_32{UNINITIALIZED}
        :param ast:
        '''
        try:
            ret_val = self._solver.eval(ast,
                                        extra_constraints=[ast > dream_argument_value_min,
                                                           ast < dream_argument_value_max])
        except angr.SimUnsatError as e:
            ret_val = self._solver.eval(ast)

        pattern = 'mem_(?P<mem_addr>.*?)_(?P<id>\d+?)_(?P<bits>\d+)'
        res = re.search(pattern, ast.shallow_repr(max_depth=10))
        if not res:
            raise Exception("[!] _parse_mem_ {}".format(ast.shallow_repr()))
        mem_addr = int(res.group('mem_addr'), 16)
        size_bits = ast.size()
        self.init_mem(mem_addr, ret_val, size_bits, endness=self._to_detect_state.arch.memory_endness)

    def _parse_reg_(self, ast):
        '''
        mem_f0000100_15_32{UNINITIALIZED}
        '''
        try:
            ret_val = self._solver.eval(ast,
                                        extra_constraints=[ast > dream_argument_value_min,
                                                           ast < dream_argument_value_max])
        except angr.SimUnsatError as e:
            ret_val = self._solver.eval(ast)
        pattern = 'reg_(?P<reg_addr>.*?)_(?P<id>\d+?)_(?P<bits>\d+)'
        res = re.search(pattern, ast.shallow_repr(max_depth=10))
        if not res:
            raise Exception("[!] _parse_reg_ {}".format(ast.shallow_repr()))
        reg_addr = res.group('reg_addr')
        size_bits = ast.size()
        reg_number = int(reg_addr, 16) & 0xff8  #
        reg_name = self._to_detect_state.arch.register_names[reg_number]
        self._set_reg_by_name(reg_name, ret_val)

    def _parse_arg(self, ast):
        '''
        :param ast:
        :return:
        '''
        try:
            ret_val = self._solver.eval(ast,
                                        extra_constraints=[ast > dream_argument_value_min,
                                                           ast < dream_argument_value_max])
        except angr.SimUnsatError as e:
            ret_val = self._solver.eval(ast)
        pattern = 'arg_(?P<arg_n>.*?)_(?P<id>\d+?)_(?P<bits>\d+)'
        res = re.search(pattern, ast.shallow_repr(max_depth=10))
        if not res:
            raise Exception("[!] _parse_reg_ {}".format(ast.shallow_repr()))
        arg_n = int(res.group('arg_n'), 16)
        size_bits = ast.size()
        self.init_arg(arg_n, ret_val, size_bits, endness=self._to_detect_state.arch.memory_endness)

    def parse_leaf_ast(self, ast):
        cons_str = ast.shallow_repr(max_depth=10)
        if 'fake_ret_' in cons_str:
            self._parse_fake_ret(ast)
        elif 'mem_' in cons_str:
            self._parse_mem_(ast)
        elif 'reg_' in cons_str:
            self._parse_reg_(ast)
        elif 'arg_' in cons_str:
            self._parse_arg(ast)
        else:
            l.error("Can not parse ast {}".format(cons_str))
            # raise Exception()

    def _set_reg_by_name(self, reg_name, value):
        reg_number, reg_width = self._to_detect_state.arch.registers[reg_name]
        if type(value) is int:
            l.debug("\tReg: {} = {}".format(reg_name, hex(value)))
        self._to_detect_state.registers.store(reg_number, value)

    def init_mem(self, mem_addr, value, width, endness="Iend_LE"):
        l.debug("\tMem: {} ={}".format(hex(mem_addr), hex(value)))
        self._to_detect_state.memory.store(mem_addr, self._to_detect_state.solver.BVV(value, width),
                                           endness=endness)

    def init_arg(self, arg_order, value, width, endness="Iend_LE"):

        if self._arch_name == 'X86':
            if self._cc == self.CDECL:
                arg_addr = self._arg0_addr + arg_order * self._byte_width
                l.debug("\tArg: {}({}bits)(0x{:x}) = 0x{:x}".format(arg_order, width, arg_addr, value))
                self._to_detect_state.memory.store(arg_addr, self._to_detect_state.solver.BVV(value, width),
                                                   endness=endness)
            elif self._cc == self.FASTCALL:
                arg_addr = self._fastcall_arg_addr[arg_order]
                if arg_order < 3:
                    l.debug("\tArg: {}({}bits)({}) = 0x{:x}".format(arg_order, width, arg_addr, value))
                    self._set_reg_by_name(arg_addr, value)
                else:
                    l.debug("\tArg: {}({}bits)(0x{:x}) = 0x{:x}".format(arg_order, width, arg_addr, value))
                    self._to_detect_state.memory.store(arg_addr, self._to_detect_state.solver.BVV(value, width),
                                                       endness=endness)
            else:
                raise Exception("Not supported calling convention.")
        elif self._arch_name == 'AMD64':
            reg_parameter = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
            reg_name = reg_parameter[arg_order]
            self._to_detect_state.registers.store(
                self._to_detect_state.arch.registers[reg_name][0],
                self._to_detect_state.solver.BVV(value, width), endness=endness)
            l.debug('\t Reg: {} = {}'.format(reg_name, hex(value)))
        else:
            raise Exception("not support arch {} in init_arg".format(self._arch_name))
