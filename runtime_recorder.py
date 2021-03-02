# encoding:utf-8
'''
@date: 20201110 20:56:31

This class detects NULL POINTER DEREFERENCE and records semantic informations during execution.
'''

import logging
import re
import angr
import traceback
from memory_access_recorder import mem_read_write_monitor
from important_VALUEs import min_mem_addr_npd, CALL_WHITE_LIST

l = logging.getLogger("RuntimeRecorder")
l.setLevel(logging.DEBUG)


class NullPointerDereference(angr.exploration_techniques.ExplorationTechnique):
    '''
    It checks every single instruction.
    '''
    NULLPOINTER_STASH = "nullpointer"
    MULTIBRANCH = "mutilplebranch"
    ABORT = 'abort'

    def __init__(self, callees_and_rets, project, bound=30):
        '''
        :param callees_and_rets: a queue of callee returns
        :param project : angr project
        '''
        angr.exploration_techniques.ExplorationTechnique.__init__(self)
        self.callees_and_rets = callees_and_rets
        self.FUNCTION_CALL_INSTRUCTION = {'X86': ['call'], 'AMD64': ['call']}  # the mnemonics of function calls
        self.dic_addr_func = {}
        self.p = project
        self.ret_value = None  # the return value of function call
        self._state_after_call = None  # the state after function call
        self._multi_brach_flag = False  # a flag denotes the program executing into multiple branch

        self._ARITHMETIC_INSTRUCTION = {"X86": ['add', 'inc', 'neg', 'sub', 'mul', 'div', 'dec'],
                                        "AMD64": ['add', 'inc', 'neg', 'sub', 'mul', 'div', 'dec'],
                                        "ARM": []}  # ARM MIPS To support
        self._DEREFERENCE_INSTRUCTION = {"X86": ['mov', 'movxz', 'movsx', 'cmp','and',
                                                 'test', 'add', "sub", 'inc', 'dec', 'mul', 'imul','push'],
                                         "AMD64": ['mov', 'movxz', 'movsx', 'cmp','and',
                                                   'test', 'add', "sub", 'inc', 'dec', 'mul', 'imul', 'push'],
                                         "ARM": []}  # ARM MIPS To support
        self._COMPARE_INSTRUCTION = {"X86": ['cmp', 'test'], "AMD64": ['cmp', 'test']}
        self._arithmetic_sequence = []  # the arithmetic instructions during execution; (ins, value, 1 or 0)
        self._constants_in_cmp_instruction = []  # the constants in CMP instruction.
        self._arguments = []  # the first argument for function calls.
        self._memory_unit_size = int(project.arch.bits / 8)  # the memory unit sizes
        self._args_in_cmp_instruction = []  # the comparison of function arguments
        self._unsat = False
        self.bound = bound
        self._loop_detector = {}

    def setup(self, simgr):
        if self.NULLPOINTER_STASH not in simgr.stashes:
            simgr.stashes[self.NULLPOINTER_STASH] = []  # the states where NULL POINTER DEREFERENCE ocurring

    def eval_addr(self, state, expression):
        '''
        First the registers are tested to be symbolic or not symbolic.
        Then, the address of dereference is tested.
        :param state: angr state
        :param expression: e.g. rax+r8*2
        :return: The expression of instruction. e.g. '0x19 + 100'
        '''
        regs_pattern = "(?P<reg1>[er][a-z0-9]{1,4})"
        regs = re.finditer(regs_pattern, expression)
        regs_value = []
        for res in regs:
            reg_name = res.group(1)
            if reg_name not in dir(state.regs):
                continue
            reg = state.registers.load(reg_name)
            if reg.symbolic:
                return [], ''
            regs_value.append(state.solver.eval(reg))
            expression = re.sub(reg_name, str(state.solver.eval(state.registers.load(reg_name))), expression)
        return expression, regs_value

    def step_state(self, simgr, state, **kwargs):
        '''
        :param simgr:
        :param state:
        :param kwargs:
        :return: If the self.callee is not empty, pop a return value for function call.
                Else, step into the function.
        '''
        # Loop detection
        if state.addr not in self._loop_detector:
            self._loop_detector[state.addr] = 0
        else:
            self._loop_detector[state.addr] += 1
            if self._loop_detector[state.addr] > self.bound:
                l.debug("[!] Loop time reach limit {} in block {}".format(self.bound, hex(state.addr)))
                stash = {None: []}
                return stash
        # End

        l.debug("[>] step_state in block {}".format(hex(state.addr)))
        if self._state_after_call:
            stash = {None: [self._state_after_call]}
            self._state_after_call = None
            return stash
        return simgr.step_state(state, **kwargs)

    def addr_to_func_name(self, p, addr):
        sym = p.loader.find_symbol(addr)
        if sym is not None:
            name = sym.name
        else:
            name = p.loader.find_plt_stub_name(addr)
        if name is not None:
            return name
        l.warning("No func name founded by addr {}".format(hex(addr)))
        return ""

    def skip_function_call(self, state, ins, is_indirected=False):
        '''
        :param state:  A state ends with function call
        :param ins:   call instruction
        :param is_indirected: e.g. call eax;
        :return: If self.callees_and_rets is not empty, pop a value and construct a state after function call.
        '''
        if len(self.callees_and_rets) <= 0:  # pop a value
            return None

        name, retval = self.callees_and_rets.pop(0)
        if is_indirected and name != 'indirect_call':
            l.warning("[!] function call mismatch when execute instr {:x}".format(state.addr))
            l.warning("[!] wrong function {} returns {}".format(name, retval))
            return None

        if retval is None:
            retval = 1
        l.debug("[*] function {} return {:x}".format(name, retval))
        nstate = state
        nstate.regs.ip = ins.address + ins.size
        nstate.regs.eax = retval
        # delete breakpoints
        for bp in nstate.inspect._breakpoints['mem_write']:
            nstate.inspect.remove_breakpoint('mem_write', bp)
        for bp in nstate.inspect._breakpoints['mem_read']:
            nstate.inspect.remove_breakpoint('mem_read', bp)

        return nstate

    def filter(self, simgr, state, filter_func=None):

        def _record_arithmetic_inst(state, instruction):
            '''
            Record the mnemonics and calculation results of arithmetic instructions.
            inc eax ,  sub eax,2
            state.scratch.tmp_expr
            '''
            STACK_POINTER = ['sp', 'bp']
            mnemonic = instruction.mnemonic
            op_str = instruction.op_str

            # filter out the stack instructions
            for x in STACK_POINTER:
                if x in op_str:
                    if instruction.operands[0].type == 1 and instruction.operands[1].type == 2:
                        l.debug("[*] filtered Instruction: {}".format(op_str))
                    return
            else:
                self._arithmetic_sequence.append(mnemonic)

        def _record_constant_in_cmp(state, instruction):
            '''
            record constants in CMP instruction
            :return:
            '''
            for x in instruction.operands:
                if x.type == 2:  #  If the operand is constant
                    self._constants_in_cmp_instruction.append(x.imm)
                elif x.type == 1:  # register
                    # eval the reg
                    name = instruction.reg_name(x.imm)
                    reg = state.registers.load(name)
                    if not reg.symbolic:
                        try:
                            val = state.solver.eval(reg)
                            self._constants_in_cmp_instruction.append(val)
                        except Exception as e:
                            l.error("[!] eval for reg {} unsat in 0x{:x}".format(name, state.addr))

        def _record_cmp_about_argument(state, instruction):
            '''
            例如： cmp eax, arg1; jz addr=>  [1, ==]
                   cmp arg1, arg3; jg => [1, >] ;
            '''
            self._args_in_cmp_instruction = []

        def _record_call_first_argument(state, instruction):
            '''
            Record the first argument for function call.
            :param state:
            :param instruction:
            :return:
            '''
            arg1 = state.memory.load(state.regs.sp, size=self._memory_unit_size)
            if arg1.symbolic:
                res = 'sym'
            else:
                res = state.solver.eval(arg1)
            self._arguments.append(res)

        def _check_null_pointer_in_oprand(state, op_str, reg_threshold=min_mem_addr_npd):
            '''
            :param state: the state to be detected
            :param op_str: string format of operands
            :return: If null pointer dereference happens return True, else return False.
            '''
            # regular expression to locate the [] content
            '''
            :except mov eax, dword ptr gs:[0x14]
            '''
            oprands_str = op_str
            res = re.search("\[.*\]", oprands_str)
            if not res:
                return False
            # mov eax, dword ptr gs:[0x14]
            if "gs:" in oprands_str:
                l.debug("Global Register instruction {}".format(oprands_str))
                return False
            expression = res.group(0)[1:-1]
            eval_str, regs_value_list = self.eval_addr(state, expression)
            if len(regs_value_list) == 0:
                return False

            memory_addr_tobe_derenferenced = eval(eval_str)

            # If the dereference memory address is very low.
            if memory_addr_tobe_derenferenced < reg_threshold and state.memory.load(
                    memory_addr_tobe_derenferenced, self._memory_unit_size).symbolic:
                #
                for v in regs_value_list:
                    if v == 0:
                        return True
                else:
                    return False

        def check_Null_pointer_dereference(state):
            '''
            1. traverse each instruction in the block of state, and find the null pointer dereference in oprands
            such as:
                1."movzx   edx, word ptr [rax+rsi*2]"
                calculate the value in []

            2. record features
            :return: True if null pointer dereference exists or false
            '''
            mem_read_write_monitor(state)
            dereference_instruction_types = self._DEREFERENCE_INSTRUCTION[self.p.arch.name]  # instructions that dereference memory
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
                            # continue to execute lib functions such as memset  Simprocedure
                            func_name = self.addr_to_func_name(self.p, int(instruction.op_str, 16))
                            if func_name not in CALL_WHITE_LIST:
                                '''state after function call'''
                                self._state_after_call = self.skip_function_call(state, instruction)
                            continue
                        else:  # indirect function call; 1. call    [ebp+arg_10] 2. call eax
                            ''''''
                            if _check_null_pointer_in_oprand(state, instruction.op_str):
                                l.debug(
                                    "Null Pointer Dereference founded at instruction 0x{:x}: {}".format(state.addr,
                                                                                                        instruction))
                                return True
                            ''''''
                            call_instr = state.block().capstone.insns[0].insn
                            self._state_after_call = self.skip_function_call(state, call_instr, is_indirected=True)
                else:
                    if _check_null_pointer_in_oprand(state, instruction.op_str):
                        l.warning(
                            "Null Pointer Dereference founded at instruction 0x{:x}: {}".format(state.addr,
                                                                                                instruction))
                        return True
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
                    _record_cmp_about_argument(state, instruction)

                '''
                step one instruction
                '''
                try:
                    succ = state.step(num_inst=1)
                    successors = succ.successors
                    if len(successors) == 0:
                        if len(succ.unconstrained_successors) > 0 and \
                                state.block().capstone.insns[-1].insn.mnemonic == 'call':
                            # indirect function call
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

                    state = successors[0]  # there will be just one successor since the instruction executed is in a block.
                    if not state.satisfiable():
                        #
                        self._unsat = True
                        return False
                except Exception as e:
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

        # The detection stops if multiple branches.
        if self._multi_brach_flag:
            return self.MULTIBRANCH
        # unsatisfiable.
        if self._unsat:
            return self.ABORT

        return simgr.filter(state, filter_func=filter_func)
