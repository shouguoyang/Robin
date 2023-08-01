# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     PoC_solve
   Description :
   Author :
   date：          2021/5/27
-------------------------------------------------
   Change Activity:
                   2021/5/27:
-------------------------------------------------
"""
import logging
import random
import re
import time
from running_setting import dream_argument_value_max, dream_argument_value_min, MAX_NUMBER_OF_ARGUMENT
from utils import PROJECT_ROOT_DIR

import angr

l = logging.getLogger('SolvePoC')
fh = logging.FileHandler("{}/logs/SolvePoC.log-{}".format(PROJECT_ROOT_DIR,time.strftime('%Y-%m-%d')))
format = logging.Formatter("%(asctime)s-%(name)s-%(message)s")
fh.setFormatter(format)
l.addHandler(fh)
from utils import LOG_LEVEL
l.setLevel(LOG_LEVEL)


class SolvePoC():
    '''
    given a state, this class solve all the constraints and save them by PoC format:
    {
  "arguments": [arg0 with format (value, size_in_bytes), arg1, arg2, ..., ],
  "fake_function_return": { "function_name+callsite":return_value},
  "memory": {"address": (value, size_in_bytes)},
  "registers": {"edx": value}
    }
    '''
    ARGUMENTS = "arguments"
    FAKE_RETURNS = "fake_function_return"
    MEMORY = 'memory'
    REGISTERS = 'registers'

    def __init__(self, state, callees_and_rets):
        '''
        :param state: program state which executes from entry to patch
        :param callee_and_rets: the function call address and callee names during the execution
        '''
        self._state = state
        self._solver = state.solver
        self._callees_and_rets = callees_and_rets
        self._PoC = {self.ARGUMENTS: [None for i in range(MAX_NUMBER_OF_ARGUMENT)],
                     self.FAKE_RETURNS: [],
                     self.MEMORY: {},
                     self.REGISTERS:{}}

    def solve(self):
        self._resolve_constraints()
        self._convert_callee_return()
        return self._PoC

    def _resolve_constraints(self):
        # utilize const.leaf_asts() to eval all symbolic variables for initialize running environment
        for const in self._state.solver.constraints:
            l.debug("[C] {}".format(const))
            for leaf_ast in const.leaf_asts():
                if leaf_ast.symbolic:
                    try:
                        self._parse_leaf_ast(leaf_ast)
                    except angr.SimUnsatError:
                        l.warning("[!] Sim-Unsat-Error for {}".format(leaf_ast))

    def _parse_leaf_ast(self, ast):
        '''parse an ast in constraint'''
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

    def _parse_fake_ret(self, ast):
        '''
        to solve the function callsite, function name, function return
        e.g., ast: fake_ret_ssl_generate_pkey_16_32
        '''
        try:
            ret_vals = self._solver.eval_upto(ast, 5,
                                              extra_constraints=[ast > dream_argument_value_min,
                                                                 ast < dream_argument_value_max])
            ret_val = ret_vals[random.randint(0, len(ret_vals) - 1)]
            self._solver.add(ast == ret_val)
            # obtain a minimal vale
        except Exception:
            try:
                ret_val = self._solver.eval(ast)  # if there are not many solutions.
            except angr.SimUnsatError as e:
                l.error("[!] {}".format(e.args))
                return
        # use regular expression to match targets.
        # fake_ret__0x423772_104_32; fake_ret_foo_101_32
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
        eval the ast and set the memory
        '''
        try:
            mem_val = self._solver.eval(ast,
                                        extra_constraints=[ast > dream_argument_value_min,
                                                           ast < dream_argument_value_max])
        except angr.SimUnsatError as e:
            mem_val = self._solver.eval(ast)

        pattern = 'mem_(?P<mem_addr>.*?)_(?P<id>\d+?)_(?P<bits>\d+)'
        res = re.search(pattern, ast.shallow_repr(max_depth=10))
        if not res:
            raise Exception("[!] _parse_mem_ {}".format(ast.shallow_repr()))
        mem_addr = int(res.group('mem_addr'), 16)
        size_bits = ast.size()
        self._PoC[self.MEMORY][mem_addr] = (mem_val, size_bits//8)

    def _parse_reg_(self, ast):
        '''
        Some register is initialized by ???
        e.g., bfd_generic_archive_p in addr2line-2.29 O0
        64-bit values afaik are returned in edx:eax on x86
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
        reg_number = int(reg_addr, 16) & 0xff8  # lower 3 bits are not used for seek register.
        reg_name = self._state.arch.register_names[reg_number]
        self._PoC[self.REGISTERS][reg_name] = ret_val
        l.debug("register {} has value {}".format(reg_name, ret_val))

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
        arg_n = int(res.group('arg_n'), 10)
        size_bits = ast.size()
        self._PoC[self.ARGUMENTS][arg_n] = (ret_val, size_bits//8)

    def _convert_callee_return(self):
        for (call_site, function_name), ret_val in self._callees_and_rets.items():
            self._PoC[self.FAKE_RETURNS].append([function_name, ret_val])
