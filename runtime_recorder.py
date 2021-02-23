# encoding:utf-8
'''
@author: yangshouguo
@date: 2020年11月10日 20:56:31

该类记录函数在给定 内存布局/输入 的情况下，运行路径中的一些信息
包括对运行时进行空指针解引用的检测
记录执行过程中的 算术指令，call指令信息
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
    在angr符号执行的过程中检测每条指令 记录需要的信息
    '''
    NULLPOINTER_STASH = "nullpointer"
    MULTIBRANCH = "mutilplebranch"
    ABORT = 'abort'

    def __init__(self, callees_and_rets, project, bound=30):
        '''
        :param callees_and_rets: 在执行过程中遇到的函数调用序列和对应的返回值
        :param project : angr project
        '''
        angr.exploration_techniques.ExplorationTechnique.__init__(self)
        self.callees_and_rets = callees_and_rets
        self.FUNCTION_CALL_INSTRUCTION = {'X86': ['call'], 'AMD64': ['call']}  # 函数调用的助记符
        self.dic_addr_func = {}
        self.p = project
        self.ret_value = None  # 上次函数调用返回值的和函数调用的下一个基本块的地址
        self._state_after_call = None  # 执行过程中feed给后继state的函数返回值。 如果基本块的函数调用的值已经求解得到。那么直接对其下一个基本块的state进行构建返回
        self._multi_brach_flag = False  # 记录在符号执行过程中，是否有基本块存在多个分支。如果存在，则认定为检测失败

        self._ARITHMETIC_INSTRUCTION = {"X86": ['add', 'inc', 'neg', 'sub', 'mul', 'div', 'dec'],
                                        "AMD64": ['add', 'inc', 'neg', 'sub', 'mul', 'div', 'dec'],
                                        "ARM": []}  # ARM MIPS To support
        self._DEREFERENCE_INSTRUCTION = {"X86": ['mov', 'movxz', 'movsx', 'cmp','and',
                                                 'test', 'add', "sub", 'inc', 'dec', 'mul', 'imul','push'],
                                         "AMD64": ['mov', 'movxz', 'movsx', 'cmp','and',
                                                   'test', 'add', "sub", 'inc', 'dec', 'mul', 'imul', 'push'],
                                         "ARM": []}  # ARM MIPS To support
        self._COMPARE_INSTRUCTION = {"X86": ['cmp', 'test'], "AMD64": ['cmp', 'test']}
        self._arithmetic_sequence = []  # 记录执行路径中的算术指令，结果，是否是符号值 (ins, value, 1 or 0)
        self._constants_in_cmp_instruction = []  # 记录比较指令中的常量
        self._arguments = []  # 记录函数调用中的第一个参数
        self._memory_unit_size = int(project.arch.bits / 8)  # 内存单元的字节数 32bit是4个字节
        self._args_in_cmp_instruction = []  # 记录对函数参数的比较
        self._unsat = False
        self.bound = bound
        self._loop_detector = {}

    def setup(self, simgr):
        if self.NULLPOINTER_STASH not in simgr.stashes:
            simgr.stashes[self.NULLPOINTER_STASH] = []  # 包含空指针异常的state会被放在这个stash

    def eval_addr(self, state, expression):
        '''
        首先判断寄存器是不是符号值，不是符号值再进行求解！
        :param state: angr state
        :param expression: e.g. rax+r8*2
        :return: 返回表达式的字符串形式，例如 '0x19 + 100' 和寄存器的值
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
        :return: 如果函数调用返回值在 self.callees_and_rets, 则直接返回结果；否则进入被调用函数执行
        '''
        # 循环检测
        if state.addr not in self._loop_detector:
            self._loop_detector[state.addr] = 0
        else:
            self._loop_detector[state.addr] += 1
            if self._loop_detector[state.addr] > self.bound:
                l.debug("[!] Loop time reach limit {} in block {}".format(self.bound, hex(state.addr)))
                stash = {None: []}
                return stash
        # 循环检测结束

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
        :param state:  该state.block的以call 结尾
        :param ins:   call instruction
        :param is_indirected: 是否是间接调用: e.g. call eax;
        :return: 如果函数调用记录在 self.callees_and_rets, 则直接根据函数返回值构造下一个state
        '''
        if len(self.callees_and_rets) <= 0:  # 从函数返回值序列按照顺序弹出返回值
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
        # 删除断点，防止重复输出内存访问记录
        for bp in nstate.inspect._breakpoints['mem_write']:
            nstate.inspect.remove_breakpoint('mem_write', bp)
        for bp in nstate.inspect._breakpoints['mem_read']:
            nstate.inspect.remove_breakpoint('mem_read', bp)

        return nstate

    def filter(self, simgr, state, filter_func=None):

        def _record_arithmetic_inst(state, instruction):
            '''
            记录算术指令 和 算术指令的结果 到 self._arithmetic_sequence
            inc eax ,  sub eax,2
            state.scratch.tmp_expr
            '''
            STACK_POINTER = ['sp', 'bp']
            mnemonic = instruction.mnemonic
            op_str = instruction.op_str

            # 过滤掉对栈指针进行操作的指令
            for x in STACK_POINTER:
                if x in op_str:
                    if instruction.operands[0].type == 1 and instruction.operands[1].type == 2:
                        l.debug("[*] filtered Instruction: {}".format(op_str))
                    return
            else:
                self._arithmetic_sequence.append(mnemonic)

        def _record_constant_in_cmp(state, instruction):
            '''
            记录比较指令中的常量
            :return:
            '''
            for x in instruction.operands:
                if x.type == 2:  # 如果是常量
                    self._constants_in_cmp_instruction.append(x.imm)
                elif x.type == 1:  # register
                    # 得到寄存器名字，然后求值。
                    name = instruction.reg_name(x.imm)
                    reg = state.registers.load(name)
                    if not reg.symbolic:
                        try:
                            val = state.solver.eval(reg)
                            self._constants_in_cmp_instruction.append(val)
                        except Exception as e:
                            l.error("[!] eval for reg {} unsat in 0x{:x}".format(name, state.addr))

        def _record_cmp_about_argument(state, instruction):
            '''TODO 记录比较的参数序号 和 比较类型
            例如： cmp eax, arg1; jz addr=>  [1, ==]
                   cmp arg1, arg3; jg => [1, >] ; 只记录对较小次序的参数
            '''
            self._args_in_cmp_instruction = []

        def _record_call_first_argument(state, instruction):
            '''
            记录函数调用中的第一个参数
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
            :param state: 待检测的state
            :param op_str: 指令操作数
            :return: 如果有空指针解引用，返回True，否则返回False
            '''
            # regular expression to locate the [] content
            '''
            排除 mov eax, dword ptr gs:[0x14] 这样的指令
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

            # 如果待解引用的地址很小，并且内存中对应地址的内容为符号值
            if memory_addr_tobe_derenferenced < reg_threshold and state.memory.load(
                    memory_addr_tobe_derenferenced, self._memory_unit_size).symbolic:
                # 如果某一个寄存器的值是0，则认为是空指针解引用
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
                计算 [] 中的结果!!!

            2. record features
            :return: True if null pointer dereference exists or false
            '''
            mem_read_write_monitor(state)
            dereference_instruction_types = self._DEREFERENCE_INSTRUCTION[self.p.arch.name]  # 可能发生解引用的指令
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
                            # memset 等库函数调用继续执行, 使用 Simprocedure
                            func_name = self.addr_to_func_name(self.p, int(instruction.op_str, 16))
                            if func_name not in CALL_WHITE_LIST:
                                '''生成函数调用返回之后的state'''
                                self._state_after_call = self.skip_function_call(state, instruction)
                            continue
                        else:  # 处理间接调用; 1. call    [ebp+arg_10] 2. call eax
                            '''首先判断是否存在空指针解引用'''
                            if _check_null_pointer_in_oprand(state, instruction.op_str):
                                l.debug(
                                    "Null Pointer Dereference founded at instruction 0x{:x}: {}".format(state.addr,
                                                                                                        instruction))
                                return True
                            '''尝试构造函数调用返回值'''
                            call_instr = state.block().capstone.insns[0].insn
                            self._state_after_call = self.skip_function_call(state, call_instr, is_indirected=True)
                else:
                    if _check_null_pointer_in_oprand(state, instruction.op_str):
                        l.debug(
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
                            # 间接函数调用; 当fake 的值用完之后.
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

                    state = successors[0]  # 执行一条指令, 因为在基本块内，所以肯定没有分支，只有一个successor
                    if not state.satisfiable():
                        # 运行过程中产生unsat, 有可能是不同编译优化造成函数调用约定不同，参数设置失败
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

        # 出现多个分支，表示无法检测到漏洞,检测停止
        if self._multi_brach_flag:
            return self.MULTIBRANCH
        # 不满足约束
        if self._unsat:
            return self.ABORT

        return simgr.filter(state, filter_func=filter_func)
