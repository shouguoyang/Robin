# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     calling_convention
   Description : Given a function, we identify its calling convention (mainly focus on arguments)
   Author :       None
   date：          2021/5/1
-------------------------------------------------
   Change Activity:
                   2021/5/1:
-------------------------------------------------
"""
import r2pipe
import json
import logging
import traceback
l = logging.getLogger(__file__)
l.setLevel(logging.DEBUG)

# Calling Conventions
FASTCALL = 'fastcall'
CDECL = 'cdecl'
STDCALL = 'stdcall'
WATCOM = 'watcom'
PASCAL = 'pascal'
OPTLINK = 'optlink'
BORLAND = 'borland'

class CallingConvention:

    def __init__(self, binary):
        r2 = r2pipe.open(binary, flags=['-2'])
        r2.cmd('aa')
        self._r2 = r2
        # inss = self.get_instructions(func_addr, func_size)

    def get_cc(self, function_name):
        if type(function_name) is str:
            func_addr, func_size = self._get_func_addr_and_size(function_name)
        else:
            func_addr = function_name

        cc_str = self._r2.cmd('s {}; afc'.format(hex(func_addr)))
        self._r2.quit()
        return cc_str.strip()

    def _get_func_addr_and_size(self, name):
        symbols = json.loads(self._r2.cmd('isj'))
        for s in symbols:
            if s['type'] == 'FUNC' and s['name'] == name:
                return s['vaddr'], s['size']

    def get_instructions(self, addr, size):
        end_addr = addr + size

    def get_cfg(self, addr):
        return json.loads(self._r2.cmd('agj {}'.format(hex(addr))))[0]

class CallingConvention2():
    # employing angr symbolic execution to determine calling convention
    def __init__(self, state):
        self._to_detect_state = state

    def get_cc(self):
        return self._calling_convention_test()

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
            l.debug('[*] step early stop in calling convention identification')

        if len(succ.all_successors) > 0:
            jmp_target = succ.all_successors[0]

        GUEST_FAST_CALL = False
        for var in jmp_target.solver.get_variables():
            try:
                if len(var[0]) == 3:
                    (name, addr, _), ast = var

                elif len(var[0]) == 4:
                    (name, _, _, addr), ast = var
                else:
                    raise Exception()
                if name == 'reg': # eax:8, ecx:12, edx:16
                    if addr == 8: # eax is used as argument register, which means cc is borland
                        l.debug('eax is used as argument register')
                        return BORLAND
                    if addr <= 16:
                        l.warning("[!] Guess fastcall!")
                        GUEST_FAST_CALL = True
            except Exception as e:
                l.warning("[*] unpack error: {} ".format(var))

        if GUEST_FAST_CALL:
            return FASTCALL
        l.debug("[*] calling convention is: cdecl")
        return CDECL


if __name__ == '__main__':
    bin = "binaries/tcpdump/O0/tcpdump-4.9.2"
    func_name = 'lookup_bytestring'
    cc = CallingConvention(bin)
    print(cc.get_cc(func_name))
