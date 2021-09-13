# encoding:utf-8
'''
@author: yangshouguo
@date: 20201110 20:56:31
This class records semantic features during execution with given PoC.
Besides, this class detects null pointer dereference during execution.
'''

import logging
import re
import angr
import traceback
from memory_access_recorder import mem_read_write_monitor
from important_VALUEs import min_mem_addr_npd, CALL_WHITE_LIST
from taint_tracing import NotConcreteError
from capstone.x86 import *
from utils import addr_to_func_name

l = logging.getLogger("RuntimeRecorder")
l.setLevel(logging.DEBUG)


class NullPointerDereference(angr.exploration_techniques.ExplorationTechnique):
    NULLPOINTER_STASH = "nullpointer"
    MULTIBRANCH = "mutilplebranch"
    ABORT = 'abort'

    def __init__(self, callees_and_rets, project, bound=30, NPD = False):
        '''
        :param callees_and_rets: a queue to provide return values of function call
        :param project : angr project
        :param bound: upper bound of loop
        :param NPD: whether to detect null pointer dereference
        '''
        self._NPD = NPD
        angr.exploration_techniques.ExplorationTechnique.__init__(self)
        self.callees_and_rets = callees_and_rets
        self.FUNCTION_CALL_INSTRUCTION = {'X86': ['call'],
                                          'AMD64': ['call'],
                                          'ARMEL':['bl','blx', 'bx']}  # mnemonic of function calls e.g. for ARM: bx, ldr pc, pop;
        self.dic_addr_func = {}
        self.p = project
        # self.ret_value = None
        self._state_after_call = None  # if the return value can be popped from "self.callees_and_rets", then it is the state after function call returns
        self._multi_brach_flag = False  # A flag to note the execution encounter multiple possible ways to step due to a symbolic value

        self._ARITHMETIC_INSTRUCTION = {"X86": ['add', 'inc', 'neg', 'sub', 'mul', 'div', 'dec'],
                                        "AMD64": ['add', 'inc', 'neg', 'sub', 'mul', 'div', 'dec'],
                                        "ARMEL": ['add','adc','sub','sbc','rsb','rsc','and','mul','div']}  # ARM MIPS To support
        self._DEREFERENCE_INSTRUCTION = {"X86": ['mov', 'movxz', 'movsx', 'cmp','and',
                                                 'test', 'add', "sub", 'inc', 'dec', 'mul', 'imul','push'],
                                         "AMD64": ['mov', 'movxz', 'movsx', 'cmp','and',
                                                   'test', 'add', "sub", 'inc', 'dec', 'mul', 'imul', 'push'],
                                         "ARMEL": ['ldr','str', 'ldrb', 'strb', 'ldrh','strh','ldm', 'stm']}  # ARM MIPS To support
        self._COMPARE_INSTRUCTION = {"X86": ['cmp', 'test'], "AMD64": ['cmp', 'test'], 'ARMEL':['cmp','cmn']}
        self._arithmetic_sequence = []  # mnemonic for arithmetic instructions
        self._constants_in_cmp_instruction = []  # constants in cmp instructions
        self._arguments = []  # arguments in function calls
        self._memory_unit_size = int(project.arch.bits / 8)  # word length
        self._taints_in_cmp_instruction = []  # record arguments in cmp instructions
        self._unsat = False
        self.bound = bound
        self._loop_detector = {}

    @property
    def taint_seq(self):
        return self._taints_in_cmp_instruction

    @property
    def first_arg_value(self):
        return self._arguments

    @property
    def ariths(self):
        return self._arithmetic_sequence

    @property
    def cmp_consts(self):
        return self._constants_in_cmp_instruction

    def setup(self, simgr):
        if self.NULLPOINTER_STASH not in simgr.stashes:
            simgr.stashes[self.NULLPOINTER_STASH] = []  # the state that tries to dereference a null pointer is put into this list

    def eval_addr(self, state, expression):
        '''
        get the expression concrete value
        We need determine whether the register is symbolic
        :param state: angr state
        :param expression: e.g. rax+r8*2
        :return: string format of a formula, e.g., '0x19 + 100'
        '''
        regs_pattern = "(?P<reg1>[er][a-z0-9]{1,4})"
        regs = re.finditer(regs_pattern, expression)
        regs_value = []
        regs_tainted = []
        for res in regs:
            reg_name = res.group(1)
            if reg_name not in dir(state.regs):
                continue
            reg = state.registers.load(reg_name)
            if reg.symbolic:
                return [], [], []
            regs_value.append(state.solver.eval(reg))
            regs_tainted.append(state.ShadowMem.is_tainted(reg_name))
            expression = re.sub(reg_name, str(state.solver.eval(state.registers.load(reg_name))), expression)
        return expression, regs_value, regs_tainted

    def step_state(self, simgr, state, **kwargs):
        '''
        :param simgr:
        :param state:
        :param kwargs:
        :return: This function is to detect loop and feed the return value from "self.callees_and_rets" to function call
        '''
        # loop detection
        if state.addr not in self._loop_detector:
            self._loop_detector[state.addr] = 0
        else:
            self._loop_detector[state.addr] += 1
            if self._loop_detector[state.addr] > self.bound:
                l.debug("[!] Loop time reach limit {} in block {}".format(self.bound, hex(state.addr)))
                stash = {None: []}
                return stash
        # end detection

        l.debug("[>] step_state in block {}".format(hex(state.addr)))
        if self._state_after_call:
            stash = {None: [self._state_after_call]}
            self._state_after_call = None
            return stash
        try:
            succ = simgr.step_state(state, **kwargs)
            return succ
        except NotConcreteError as e:
            l.warning("Taint Engine tries to access SYMBOLIC data in {}".format((hex(state.addr))))
            return {}
        except RecursionError:
            l.warning("Recursion Error in {}. Execution stops.".format(hex(state.addr)))
            return {}
        except NotImplementedError as e:
            l.warning(e.args)
            return {}

    def skip_function_call(self, state, ins, is_indirected=False):
        '''
        :param state:  A state.block ends with call instruction
        :param ins:   call instruction
        :param is_indirected: if it is a indirect call: e.g. call eax;
        :return: fake function call return value if self.callees_and_rets is not empty
        '''
        if len(self.callees_and_rets) <= 0:  # pop return values from collected solved sequence
            return None

        name, ret_val = self.callees_and_rets.pop(0)

        if is_indirected and name != 'indirect_call':
            l.warning("[!] function call mismatch when execute instr {:x}".format(state.addr))
            l.warning("[!] wrong function {} returns {}".format(name, ret_val))
            return None

        # This means the function call return value does not affect the control flow, so we assign an arbitrarily value
        if ret_val is None:
            ret_val = 1

        l.debug("[*] function {} return {:x}".format(name, ret_val))
        nstate = state
        nstate.regs.ip = ins.address + ins.size
        if state.arch.name == 'X86' or state.arch.name == 'AMD64':
            nstate.regs.eax = ret_val
        elif state.arch.name == 'ARM':
            nstate.regs.r0 = ret_val

        # nstate.registers.store(state.arch.registers['eax'][0], ret_val, endness=nstate.memory.endness)
        # delete breakpoints to prevent outputting mem acc repeatedly.
        for bp in nstate.inspect._breakpoints['mem_write']:
            nstate.inspect.remove_breakpoint('mem_write', bp)
        for bp in nstate.inspect._breakpoints['mem_read']:
            nstate.inspect.remove_breakpoint('mem_read', bp)

        return nstate

    def filter(self, simgr, state, filter_func=None):

        def _record_arithmetic_inst(state, instruction):
            '''
            record arithmetic mnemonic
            inc eax ,  sub eax,2
            state.scratch.tmp_expr
            '''
            STACK_POINTER = ['sp', 'bp']
            mnemonic = instruction.mnemonic
            op_str = instruction.op_str

            # To filter instructions that operate on stack e.g. 'sub esp, 10'
            for x in STACK_POINTER:
                if x in op_str:
                    if instruction.operands[0].type == 1 and instruction.operands[1].type == 2:
                        l.debug("[*] ignore Instruction: {} in {}".format(op_str, instruction.address))
                    return
            else:
                self._arithmetic_sequence.append(mnemonic)

        def _record_constant_in_cmp(state, instruction):
            '''
            record
            1. constants
            2. arguments
            in comparison instructions
            '''
            for x in instruction.operands:
                if x.type == X86_OP_IMM:  # constant
                    self._constants_in_cmp_instruction.append(x.imm)
                elif x.type == X86_OP_REG:  # register
                    # get the name of register and eval it
                    name = instruction.reg_name(x.reg)
                    reg_content = state.registers.load(name)
                    if not reg_content.symbolic:
                        try:
                            val = state.solver.eval(reg_content)
                            self._constants_in_cmp_instruction.append(val)
                        except Exception as e:
                            l.error("[!] eval for reg_content {} unsat in 0x{:x}".format(name, state.addr))
                        if state.ShadowMem.is_tainted(name):
                            self._taints_in_cmp_instruction.append(list(state.ShadowMem.mem_chunk_tags(name)))
                elif x.type == X86_OP_MEM: # memory reference
                    # get memory address
                    if x.mem.base != 0:
                        base_reg = instruction.reg_name(x.mem.base)
                        displacement = x.mem.disp
                        base_addr = state.registers.load(base_reg).args[0]
                        if isinstance(base_addr, str):
                            l.warning('base reg is symbolic in {}'.format(str(instruction)))
                            break
                        mem_addr = base_addr + displacement

                    elif x.mem.segment != 0:
                        l.error("{} not support with mem.segment {}".format(str(instruction), instruction.reg_name(x.mem.segment)))
                        raise NotImplementedError
                    elif x.mem.index != 0:# [eax*4 + 0x82bddcc]
                        reg_name = instruction.reg_name(x.mem.index)
                        reg_val = state.solver.eval(state.registers.load(reg_name))
                        mem_addr = reg_val * x.mem.scale + x.mem.disp
                    elif x.mem.disp != 0:
                        mem_addr = x.mem.disp

                    if state.ShadowMem.is_tainted(mem_addr):
                        tags = list(state.ShadowMem.mem_chunk_tags(mem_addr))
                        self._taints_in_cmp_instruction.append(tags)
                        val = state.memory.load(mem_addr, state.arch.bytes)
                        self._constants_in_cmp_instruction.append(val.args[0])




        def _record_call_first_argument(state, instruction):
            '''
            record the arguments
            :param state:
            :param instruction:
            '''
            arg1 = state.memory.load(state.regs.sp, size=self._memory_unit_size)
            if arg1.symbolic:
                res = 'sym'
            else:
                res = state.solver.eval(arg1)
            self._arguments.append(res)

        def _check_null_pointer_in_oprand(state, op_str, reg_threshold=min_mem_addr_npd):
            '''
            :param state: state to detect
            :param op_str: oprand of instruction
            :return: return True if null pointer dereference occurs
            '''
            # regular expression to locate the [] content
            '''
            filter out instructions such as mov eax, dword ptr gs:[0x14]
            '''
            # don't detect null pointer dereference
            if not self._NPD:
                return False

            oprands_str = op_str
            res = re.search("\[.*\]", oprands_str)
            if not res:
                return False
            # mov eax, dword ptr gs:[0x14]
            if "gs:" in oprands_str:
                l.debug("Global Register instruction {}".format(oprands_str))
                return False
            expression = res.group(0)[1:-1]
            if state.arch.name == 'ARMEL':
                '''
                ldr r2, [r0]      @ load the value (0x03) at memory address found in R0 to register R2 
                str r2, [r1, #2]  @ address mode: offset. Store the value found in R2 (0x03) to the memory address found in R1 plus 2. Base register (R1) unmodified. 
                str r2, [r1, #4]! @ address mode: pre-indexed. Store the value found in R2 (0x03) to the memory address found in R1 plus 4. Base register (R1) modified: R1 = R1+4 
                ldr r3, [r1], #4  @ address mode: post-indexed. Load the value at memory address found in R1 to register R3. Base register (R1) modified: R1 = R1+4 
                ldr/str r1 [r2, #4]; offset: immediate 4
                 ;The effective memory address is calculated as r2+4
                ldr/str r1 [r2, r3]; offset: value in register r3
                 ;The effective memory address is calculated as r2+r3
                ldr/str r1 [r2, r3, LSL #3]; offset: register value *(2^3)
                 ;The effective memory address is calculated as r2+r3*(2^3) 
                '''
                if ', #' in expression: #ldr r3, [r3, #0xc]
                    expression = expression.replace(", #", '+')
                elif ', lsl #' in expression:
                    expression = expression.replace(', lsl #', '*pow(2,')
                    expression += ')'
                if ", " in expression:# ldrb r1, [r2, r3]
                    expression = expression.replace(", ", '+')
                    #<CsInsn 0x13f6f0 [021183e7]: str r1, [r3, r2, lsl #2]>

            eval_str, regs_value_list, reg_taint_flags = self.eval_addr(state, expression)
            if len(regs_value_list) == 0:
                return False

            memory_addr_tobe_derenferenced = eval(eval_str)

            # If the dereferenced address is located 0~0x1000, we think the null pointer dereference occurs
            if memory_addr_tobe_derenferenced < reg_threshold:
                    #and state.memory.load(memory_addr_tobe_derenferenced, self._memory_unit_size).symbolic:
                    for v, taint_flag in zip(regs_value_list, reg_taint_flags):
                        if v == 0 and taint_flag:
                            return True

            return False


        def check_Null_pointer_dereference(state):
            '''
            1. traverse each instruction in the block of state, and find the null pointer dereference in oprands
            such as:
                1."movzx   edx, word ptr [rax+rsi*2]"
                Caculate the target address of dereference

            2. record features
            :return: True if null pointer dereference exists or false
            '''
            mem_read_write_monitor(state)
            dereference_instruction_types = self._DEREFERENCE_INSTRUCTION[self.p.arch.name]  # instructions that may dereference a pointer
            arithmentic_instructions = self._ARITHMETIC_INSTRUCTION[self.p.arch.name]
            compare_instructions = self._COMPARE_INSTRUCTION[self.p.arch.name]
            function_call_mnemonic = self.FUNCTION_CALL_INSTRUCTION[self.p.arch.name]
            for insn in state.block().capstone.insns:
                instruction = insn.insn
                mnemonic = instruction.mnemonic
                '''
                Null pointer dereference detection start
                '''
                if mnemonic not in dereference_instruction_types:
                    if mnemonic in function_call_mnemonic:
                        '''
                        call 0x8038383
                        '''
                        _record_call_first_argument(state, instruction)
                        if instruction.op_str.startswith('0x'):
                            #if it hints libc functions such as memset, it goes on with Simprocedure
                            func_name = addr_to_func_name(self.p, int(instruction.op_str, 16))
                            if func_name not in CALL_WHITE_LIST:
                                '''generating the state after function call'''
                                self._state_after_call = self.skip_function_call(state, instruction)
                            continue
                        else:  # indirect call; 1. call    [ebp+arg_10] 2. call eax
                            '''TO detect null pointer dereference bug'''
                            if _check_null_pointer_in_oprand(state, instruction.op_str):
                                l.debug(
                                    "Null Pointer Dereference founded at instruction 0x{:x}: {}".format(state.addr,
                                                                                                        instruction))
                                return False # only report, do not stop execution
                            '''Try to assign function return value'''
                            call_instr = state.block().capstone.insns[0].insn
                            self._state_after_call = self.skip_function_call(state, call_instr, is_indirected=True)
                else:
                    if _check_null_pointer_in_oprand(state, instruction.op_str):
                        l.debug(
                            "Null Pointer Dereference founded at instruction 0x{:x}: {}".format(state.addr,
                                                                                                instruction))
                        return False
                '''
                Null pointer dereference detection end
                '''

                '''
                Record Features start
                '''
                if mnemonic in arithmentic_instructions:
                    _record_arithmetic_inst(state, instruction)
                elif mnemonic in compare_instructions:
                    _record_constant_in_cmp(state, instruction)

                '''
                step one instruction
                '''
                try:
                    succ = state.step(num_inst=1)
                    successors = succ.successors
                    if len(successors) == 0:
                        if len(succ.unconstrained_successors) > 0 and \
                                state.block().capstone.insns[-1].insn.mnemonic == 'call':
                            #Indirect function call if 'self.call_ret' are empty
                            self._state_after_call = self.skip_function_call(state,
                                                                             state.block().capstone.insns[-1].insn)
                            return False

                        else:
                            l.error(
                                '[-] Execution has no successors in block : {}.\n It is considered as function exit'.format(
                                    str(state.block().capstone.insns)))
                            return False

                    if len(successors) > 1:
                        l.warning("[*] Block {} has mutiple successors".format(hex(state.addr)))
                        self._multi_brach_flag = True

                    state = successors[0]  # execute one instruction. the execution has only one successor since instruction is within a block.
                    if not state.satisfiable():
                        # Unsat states may be produced since we can not model all arguments precisely
                        self._unsat = True
                        return False
                except NotConcreteError as e:
                    l.warning("Taint Engine tries to access SYMBOLIC value in instruction {}".format(hex(state.addr)))

                except Exception as e:
                    l.error("Error. "+str(e))
                    l.error("\n".join([str(ins) for ins in state.block().capstone.insns]))
                    l.error(traceback.format_exc())
                    self._unsat = True
                    return False

            return False

        l.debug("[*] Detecting in block {}".format(hex(state.addr)))

        if state.addr < state.project.loader.main_object.min_addr or state.addr > state.project.loader.main_object.max_addr:
            return simgr.filter(state, filter_func=filter_func)

        if check_Null_pointer_dereference(state.copy()):
            return self.NULLPOINTER_STASH

        # multiple branches cause execution to stop
        if self._multi_brach_flag:
            return self.MULTIBRANCH
        # unsat state
        if self._unsat:
            return self.ABORT

        return simgr.filter(state, filter_func=filter_func)
