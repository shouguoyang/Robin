'''
To find a feasible path from function entry to patched blocks with symbolic execution
'''

import datetime
import logging
import math
import os
import traceback
import angr
from MFI_operation import SolvePoC, LoadPoC
import networkx as nx
from taint_tracing import TaintEngine
from Exceptions import StateFileNotExitsException
from cfg_pruning_with_slice import CFG_PS
from running_setting import heap_segment_base, stack_segment_base, reg_gs, CALL_WHITE_LIST
from memory_access_recorder import SimConcretizationStrategyMap
from runtime_recorder import NullPointerDereference
import pickle
import time
import json
from utils import get_cve_state_file_path, \
    get_target_binary_trace_file_path, get_target_cve_flag, \
    get_cve_patch_sig_file_path, \
    get_cve_vul_sig_file_path, \
    get_PoC_file_path, addr_to_func_name, get_shortest_paths_in_graph, \
    FunctionNotFound


rootdir = os.path.dirname(os.path.abspath(__file__))
l = logging.getLogger("patch_detection")

from datetime import datetime


# reset angr logger
def mute_angr():
    logging.getLogger("angr.analyses.cfg.cfg_fast").setLevel(logging.CRITICAL)  # mute the error
    logging.getLogger("pyvex.lifting.libvex").setLevel(logging.CRITICAL)  # mute the error
    logging.getLogger("angr.analyses.propagator.engine_vex.SimEnginePropagatorVEX").setLevel(
        logging.CRITICAL)  # mute the error
    logging.getLogger("angr.analyses.loopfinder").setLevel(logging.CRITICAL)  # mute the error
    logging.getLogger("angr.state_plugins.symbolic_memory").setLevel(logging.ERROR)
    logging.getLogger("angr.storage.memory_mixins.default_filler_mixin").setLevel(logging.ERROR)
    logging.getLogger("cle.backends.externs").setLevel(logging.ERROR)
    logging.getLogger("angr.state_plugins.posix").setLevel(logging.ERROR)
    logging.getLogger("angr.engines.successors").setLevel(logging.ERROR)
    logging.getLogger("angr.analyses.cfg.cfg_base").setLevel(logging.ERROR)
    logging.getLogger('angr.project').setLevel(logging.ERROR)


def set_logger_level(log_level):
    # local loggers
    l.setLevel(log_level)
    logging.getLogger("Memory_Access").setLevel(log_level)
    logging.getLogger("RuntimeRecorder").setLevel(log_level)
    logging.getLogger('preparation').setLevel(log_level)


mute_angr()

l.info("=================={}================".format(time.strftime("%Y-%m-%d %H:%M", time.localtime())))


class Executor():
    '''generate the signature with given PoC'''

    def __init__(self, CVEid, func_name):
        '''
        :param CVEid:
        :param patched_bin: binary that contains patched function
        :param vul_bin:  binary that contains vulnerable function
        :param func_name: function name
        :param check_block_addr:
        :param patch_block_addr:
        :param saved_file: signature file
        :param vul_func:
        '''
        self._path_hash_record = []  # to prune execute path
        self.cveid = CVEid
        self.func_name = func_name
        self.states_found_for_patch = []  # states corresponding feasible paths
        self.CALL_WHITE_LIST = CALL_WHITE_LIST  # functions to step into rather than fake a return value
        self.callees_and_rets = {}  # (callsite, func_name): ret_val # function call return values
        self._stack_segment_base = stack_segment_base  # stack memory address
        self._heap_segment_base = heap_segment_base  # heap memory address
        self._reg_gs = reg_gs  # global section
        self.state_file = get_cve_state_file_path(cve_id=CVEid, function_name=func_name)
        self._poc_file = get_PoC_file_path(cve_id=CVEid, function_name=func_name)
        self._loopfinder = None  #
        self.unsat_block_pairs = []  # conflict blocks in a path
        self._length_of_shortest_path = 10
        self._patch_func_addr = None  # function address
        self._program_cfg = None  # CFG for whole program
        self._function_cfg_graph = None  # function CFG
        self._path_from_check_to_patch = None
        self.patch_project = None  # angr.project
        self._patch_func_size = None
        self._cutoff = None

    def _collect_arch_info(self, project: angr.Project):
        self._bits = project.arch.bits
        self._arch_name = project.arch.name
        self._memory_endness = project.arch.memory_endness
        self._byte_width = int(self._bits / 8)  # architecture word length
        self._target_pic_code = project.loader.main_object.pic  # PIC denotes position independent code

    def _hook_libc_functions(self, project):

        # default libc function hook
        for import_func_name in project.loader.main_object.plt:
            plt_addr = project.loader.main_object.plt[import_func_name]
            if import_func_name in angr.SIM_PROCEDURES['libc']:
                project.hook_symbol(plt_addr, angr.SIM_PROCEDURES['libc'][import_func_name]())

        from hook.memcpy import memcpy
        from hook.memset import memset
        if 'memcpy' in project.loader.main_object.plt:
            project.hook_symbol(project.loader.main_object.plt['memcpy'], memcpy())
        if 'memset' in project.loader.main_object.plt:
            project.hook_symbol(project.loader.main_object.plt['memset'], memset())

    def func_name_to_addr(self, p, name):
        '''
        :param p: angr Project
        :param name: function name
        :return: the address of function symbol, function size
        '''
        # 0000000000066130 l     F .text  0000000000000111        tls1_check_sig_alg.part.10
        func_sym = p.loader.find_symbol(name)  # try fuzzy = True?
        if not func_sym:
            raise FunctionNotFound('Function name not found in func_name_to_addr')
        return func_sym.rebased_addr, func_sym.size

    def _null_pointer_test_and_sig_generation(self, bin_path, func_name, sig_save_path, bound=30,
                                              poc_file=None,
                                              NPD=True):
        '''
        1. Run the target function
        2. Detect the null pointer dereference during the execution
        3. Record the signatures during the execution.
        :param bin_path: path to binary
        :param func_name: function name
        :param sig_save_path: the path to save the signatures
        :param bound: the upper bound of loop
        :return: True if null pointer dereference occurs
        '''
        p, to_detect_state, callees_and_rets \
            = self._prepare_running_environment_for_detection(bin_path, func_name, poc_file)
        p._acc_seq = []  # record the memory access sequences
        # state.options.add(angr.options.CALLLESS)
        sm = p.factory.simgr(to_detect_state, save_unconstrained=True, save_unsat=True)

        runtime_check = NullPointerDereference(callees_and_rets, p, bound=bound, NPD=NPD)
        sm.use_technique(runtime_check)
        l.debug("[+] detection start in function {} of {}".format(func_name, bin_path))
        count = 0
        null_dereference = False
        while len(sm.stashes['active']) > 0 and count < 1000:
            sm.step()  # 4. run the target function(candidate function) with the initialized state
            count += 1
            if len(sm.stashes[NullPointerDereference.NULLPOINTER_STASH]) > 0:
                l.debug("[+] Null pointer dereference founded in function {} of {} for {}".format(func_name
                                                                                                  , bin_path,
                                                                                                  self.cveid))
                null_dereference = True
                break
            if len(sm.stashes[NullPointerDereference.MULTIBRANCH]) > 0:
                l.debug("[!] Detected multiple branches, stop...")
                break
            if len(sm.stashes[NullPointerDereference.ABORT]) > 0:
                l.warning("[!] Execution aborted. It is usually caused by unsat state")
                break
        self.save_mem_acc_seq(p._acc_seq, sig_save_path)
        self.save_other_features(runtime_check, sig_save_path)
        self.save_taint_argument_sequence(runtime_check, sig_save_path)
        return null_dereference

    def save_taint_argument_sequence(self, runtime_check, sig_save_path):
        file_name = sig_save_path + ".taint_seqs"
        with open(file_name, 'w') as f:
            json.dump(runtime_check.taint_seq, f)

        l.info('taint feature saved in {}'.format(file_name))

    def save_other_features(self, recorder, mem_acc_seq_file):
        '''
        save semantic features
        :param recorder:
        :return:
        '''
        file_name = mem_acc_seq_file + ".others"
        dic = {'args': recorder.first_arg_value,
               'arith': recorder.ariths,
               'cmp_constant': recorder.cmp_consts}
        with open(file_name, 'w') as f:
            json.dump(dic, f)

        l.info("[*] other features saved : {}".format(file_name))

    def save_mem_acc_seq(self, acc_seq, mem_acc_seq_file):
        '''
        save memory access
        '''
        tdir = os.path.dirname(mem_acc_seq_file)
        if not os.path.exists(tdir):
            os.mkdir(tdir)
        with open(mem_acc_seq_file, 'w') as f:
            json.dump(acc_seq, f)
        l.info("[*] trace file saved : {}".format(mem_acc_seq_file))

    def get_nodes_from_cfg_by_addrs(self, addrs):
        '''
        :param cfg_graph: program cfg is preferred
        :param addrs: instruction address from a block
        :return: dict: key is block address，value is node class of angr
        '''
        ret_dic = {}

        for addr in addrs:
            block = self.patch_project.factory.block(addr)
            ret_dic[addr] = block.codenode

        return ret_dic

    def _prepare_parameters_and_initilization(self, state):
        # Initialize runtime stack

        # X86 : cdecl & fastcall
        def _init_stack(state):
            # for 32bit program
            # now only consider cdecl calling convention; supposing that arguments less than 17
            for i in range(16):
                state.memory.store(self.arg_addr + self._byte_width * i,
                                   state.solver.BVS('arg_{}'.format(i), self._bits)
                                   , endness=state.arch.memory_endness)


        # X64
        def _init_regs(state, reg_parameter):
            '''reg_parameter: register names to pass arguments'''
            # push register

            for i in range(len(reg_parameter)):
                self._set_reg_by_name(
                    state,
                    reg_parameter[i],
                    state.solver.BVS('arg_{}'.format(i), self._bits)
                )
            # push stack
            for i in range(6):
                state.memory.store(self.arg_addr + self._byte_width * i,
                                   state.solver.BVS('arg_{}'.format(i + len(reg_parameter)), self._bits),
                                   endness=state.arch.memory_endness)

        state.regs.sp = self._stack_segment_base
        state.regs.bp = self._stack_segment_base

        if self._arch_name == 'AMD64':
            state.regs.gs = self._reg_gs
            reg_parameter = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
            _init_regs(state, reg_parameter)
        elif self._arch_name == 'X86':
            state.regs.gs = self._reg_gs
            _init_stack(state)
        elif self._arch_name == 'ARMEL':
            reg_parameter = ["r0", "r1", "r2", "r3"]
            _init_regs(state, reg_parameter)
        else:
            raise Exception("arch not supported.")

    def _get_shortest_path(self, func_cfg, program_cfg, source, target, use_program_cfg=False):
        '''
        :param func_cfg: function cfg
        :param program_cfg:
        :param source: address of block
        :param target: address of block
        :param use_program_cfg: whether to use program cfg
        :return: [[]]
        '''
        try:
            return get_shortest_paths_in_graph(self.patch_project, func_cfg, source, target)
        except Exception as e:
            if use_program_cfg:
                l.warning(
                    "[!] can not calculate shortest path from function cfg, use program cfg instead \n\t {}".format(
                        e.args))
                return get_shortest_paths_in_graph(self.patch_project, program_cfg, source, target)
            else:
                raise e

    def _hash_path(self, path: list):
        '''
        :return:hash value of a path
        '''
        x = path[0]
        for y in path[1:]:
            x ^= y
        return x

    def get_state_by_se(self, patch_bin_path, check_addr, patch_addr, patch_bin_project=None):
        '''
        Just find any feasible path.
        Run the path and get the state.
        '''
        l.debug("[*] finding a feasible path to generate the angr state")
        if patch_bin_project:
            self.patch_project = patch_bin_project
        else:
            self.patch_project = angr.Project(patch_bin_path,
                                              auto_load_libs="False")  # patched binary angr project
        function_symbol = self.patch_project.loader.find_symbol(self.func_name)
        if not function_symbol:
            l.error("No name {} in symbol".format(self.func_name))
            return None

        self._patch_func_addr = function_symbol.rebased_addr
        self._patch_func_size = function_symbol.size
        self._collect_arch_info(self.patch_project)
        self._hook_libc_functions(self.patch_project)
        self.arg_addr = self._stack_segment_base + self._byte_width  # memory address of first argument
        check_addr = check_addr + 0x400000 if self._target_pic_code else check_addr
        if patch_addr is not None:
            patch_addr = patch_addr + 0x400000 if self._target_pic_code else patch_addr

        cfg_path = patch_bin_path + ".angr_cfg"
        cfg = None

        def angr_cfg_gen():
            l.debug("[*] Constructing CFG for {}. It may take long time.".format(patch_bin_path))
            cfg = self.patch_project.analyses.CFGFast()
            # regions=[(self._patch_func_addr, self._patch_func_addr
            #                                     + self._patch_func_size)])
            # dump cfg
            pickle.dump(cfg, open(cfg_path, 'wb'))
            return cfg

        if os.path.exists(cfg_path):
            try:
                cfg = pickle.load(open(cfg_path, 'rb'))
            except Exception as e:
                cfg = angr_cfg_gen()
        else:
            cfg = angr_cfg_gen()

        self._program_cfg = cfg
        # patch_function_instance = cfg.functions[self.func_name] #
        # Intercept objective function subgraph
        # Only find the path from the function entry point to the patch block in a single function
        if self._patch_func_addr not in cfg.functions:
            l.warning("The function address not in angr.cfg.")
            return None

        function_cfg_graph = cfg.functions[self._patch_func_addr].graph
        l.debug("[p] function size:{}".format(len(function_cfg_graph.nodes)))
        self._function_cfg_graph = function_cfg_graph
        if patch_addr is not None:
            # find path from check block to guard block
            try:
                path = \
                    list(self._get_shortest_path(function_cfg_graph, cfg, check_addr, patch_addr))[0]
                if len(path) > 1:
                    path.pop(0)  # remove check block address
                self._path_from_check_to_patch = path
            except NotImplementedError as e:
                l.warning(e.args)
        l.debug("[*] Find paths from 0x%x To 0x%x" % (self._patch_func_addr, check_addr))
        call_state = self.patch_project.factory.call_state(self._patch_func_addr)
        # self.state.inspect.b('address_concretization', angr.BP_BEFORE, action=self.concretization_symbolic_address)
        call_state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
        call_state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
        call_state.options.add(angr.sim_options.LAZY_SOLVES)
        # self.state.options.add(angr.sim_options.CONSTRAINT_TRACKING_IN_SOLVER) #!!! don't enable. the reason cause
        # invalid dec_ref command self.state.options.remove(angr.sim_options.COMPOSITE_SOLVER)
        self._prepare_parameters_and_initilization(call_state)
        l.debug("[*] Try the shortest path...\n")
        try:
            # Using the CFG of the entire program to generate the path, nodes outside the function (function call) will be added.
            # paths = list(nx.all_shortest_paths(function_cfg_graph,
            #                                    nodes_dic[self._patch_func_addr], nodes_dic[self._check_block_addr]))
            t1 = datetime.now()
            paths = self._get_shortest_path(function_cfg_graph, cfg, self._patch_func_addr, check_addr)
            self._cutoff = len(paths[0])
            state = None
            if self._cutoff > 0:
                if patch_addr is not None:  # If the patch block address is not empty, add the path to the patch block address to the path
                    for path in paths:
                        path += self._path_from_check_to_patch
                        self._cutoff = len(path) * 1.5

                state = self._get_state_from_paths(call_state, paths, path_limit=10,
                                                   heuristic=True, calibration_time=int(self._cutoff / 4.5))
                if state is not None:
                    t2 = datetime.now()
                    l.debug('[T] State from Shortest Path Time: {:f}'.format((t2 - t1).total_seconds()))
                    l.debug("[+] state found by shortest paths!")
                    return state
        except Exception as e:
            # Challenge: Static analysis cannot get the path from the function entry to the check block. There may be indirect calls e.g. CVE-2014-9656
            l.error("[!] error {}".format(e.args))
            l.error(traceback.format_exc())
            state = None
        try:
            # slice CFG and re-weight the edges in CFG
            l.debug("[*] Trying the sliced CFG...")
            if self._target_pic_code:
                func_addr = self._patch_func_addr - 0x400000
                check_addr = check_addr - 0x400000
                patch_addr = patch_addr - 0x400000
            else:
                func_addr = self._patch_func_addr
            t3 = datetime.now()
            cfgps = CFG_PS(patch_bin_path, self._function_cfg_graph, func_addr,
                           check_addr, patch_addr, self.patch_project)
            cfgps.do_slicing()
            t4 = datetime.now()
            l.debug('[T] Slicing Time: {:f}'.format((t4 - t3).total_seconds()))
            paths = list(cfgps.get_shortest_paths())
            if patch_addr is not None:  # If the patch block address is not empty, add the path to the patch block address to the path
                for path in paths:
                    path += self._path_from_check_to_patch
            state = self._get_state_from_paths(call_state, paths, path_limit=10,
                                               heuristic=True, calibration_time=int(self._cutoff / 6 / len(paths)))

            if state is not None:
                t5 = datetime.now()
                l.debug('[T] Time of sliced shortest path: {:f}'.format((t5 - t4).total_seconds()))
                l.debug("[+] state is founded by sliced shortest paths!")
                return state
            # Try all other paths without loops # cut off means the deepest depth of the generated path
            l.debug("[*] trying all_simple_paths paths, limit path len:{}\n".format(
                self._cutoff))
            t6 = datetime.now()
            paths = cfgps.get_simple_paths(cutoff=self._cutoff)
            found = self._get_state_from_paths(call_state, paths,
                                               path_limit=100, calibration_time=2)
            if found:
                t7 = datetime.now()
                l.debug('[T] Time of sliced simple path: {:f}'.format((t7 - t6).total_seconds()))
                l.debug("[+] state found by simple paths!")
                return found
        except Exception as e:
            l.warning("[-] slicing error: {}".format(traceback.format_exc()))
            return None

        # Try fully and blindly symbolic execution
        l.warning(
            "[!] all simple path failed, try to seek with blind symbolic execution, time consuming")
        # return self._get_state_without_paths(call_state, check_addr, patch_addr, step_time_limit=100)
        return None

    def _get_all_unreacheable_blocks(self, check_node):
        '''
        :param check_node: address
        :return:  the set of all nodes that are not reachable to check_node_addr in the function control flow graph.
        '''
        cfg = self._program_cfg.graph
        if check_node not in cfg.nodes:
            raise Exception("check node in not in cfg.nodes")

        reacheable_blocks = []  # Record the addresses of other basic blocks that can reach the patch block
        predecessor_queue = [check_node]
        while len(predecessor_queue) > 0:
            current_node = predecessor_queue.pop(0)

            for parentnode in cfg.predecessors(current_node):
                if parentnode.addr not in reacheable_blocks:
                    reacheable_blocks.append(parentnode.addr)
                    predecessor_queue.append(parentnode)

        # Record all unreachable basic block addresses
        for node in cfg.nodes:
            if node.addr not in reacheable_blocks:
                yield node


    def _get_state_from_paths(self, init_state, paths, path_limit=10000, heuristic=False, calibration_time=1):
        '''
        symbolic execute given paths
        :param init_state: under constrained runtime environment
        :param paths: paths that start from function beginning to patch block
        :param path_limit: maximum number of paths to execute
        :param heuristic: Whether to continue to recalculate the path from nodes that do not meet the constraints
        :return: True： Find the feasible path
        '''

        path_i = 0
        for path in paths:
            if path_limit != -1 and path_i > path_limit:
                return None

            # Eliminate function calls
            path_address = [p.addr for p in path
                            if self._patch_func_addr <= p.addr <= self._patch_func_addr + self._patch_func_size]

            # Path deduplication
            path_hash = self._hash_path(path_address)
            if path_hash in self._path_hash_record:
                continue
            else:
                self._path_hash_record.append(path_hash)

            # Record the shortest path length
            if self._length_of_shortest_path is None:
                self._length_of_shortest_path = len(path_address)
                self._cutoff = self._length_of_shortest_path + int(math.log2(self._length_of_shortest_path) * 2)

            path_i += 1
            func_entry_to_check_state = self._run_path(init_state, path_address,
                                                       heuristic=heuristic, calibration_time=calibration_time)

            if func_entry_to_check_state:
                if func_entry_to_check_state.satisfiable():
                    func_entry_to_check_state._call_seq = self.callees_and_rets
                    self.states_found_for_patch.append(func_entry_to_check_state)
                    return func_entry_to_check_state
            else:  # if the path is unsatisfied, try to add loop to the path
                continue

        return None

    def _is_contain_conflict_block(self, path):
        '''
        :param path: list of node objects
        :return: True if the nodes in the path conflicts
        '''
        # raise Exception("Not implement {}".format(sys._getframe().f_code.co_name))
        for b1, b2 in self.unsat_block_pairs:
            if b1 in path and b2 in path:
                return True
        else:
            return False

    def _collect_conflict_blocks(self, unsat_state):
        '''
        TODO From the unsatisfied program state, find the basic block address corresponding to the conflict condition and add it to the global variable unsat_block_pairs
        '''
        def analysis_conflict_by_data_flow(check_block_addr, run_trace_addrs, des=0):
            '''

            '''
            check_block = self.patch_project.factory.block(check_block_addr)
            for ins in reversed(check_block.capstone.insns):
                if ins.insn.mnemonic in ['cmp', 'test', 'xor']:
                    op0 = ins.insn.operands[0].type
                    op1 = ins.insn.operands[1].type
                    if op0 + op1 == 5 and op0 * op1 == 6:  # cmp value, [mem] or  cmp [mem], value
                        if op0 == 3:  # mem access
                            mem_access = ins.insn.op_str.split(',')[0]
                        else:
                            mem_access = ins.insn.op_str.split(',')[1]
                    elif op0 + op1 == 3 and op0 * op1 == 2:  # cmp value, reg or  cmp reg, value
                        if op0 == 1:  # reg
                            mem_access = ins.insn.op_str.split(',')[0]
                        else:
                            mem_access = ins.insn.op_str.split(',')[1]
                    elif op0 + op1 == 4 and op0 * op1 == 3:  # cmp eax, dword ptr [ebp - 0x5c]
                        if op0 == 3:  # mem access
                            mem_access = ins.insn.op_str.split(',')[0]
                        else:
                            mem_access = ins.insn.op_str.split(',')[1]
                    elif op0 == 1 and op1 == 1:  # test eax, eax
                        mem_access = ins.insn.op_str.split(',')[0]
                    else:
                        raise Exception("Not Support")
                    break
            else:
                l.warning("No cmp instruction in {}?".format(hex(check_block_addr)))
                return None

            # Retrieve which basic block instruction has assigned mem_access
            for bbl in reversed(run_trace_addrs):
                block = self.patch_project.factory.block(bbl)
                for ins in reversed(block.capstone.insns):
                    if ins.insn.mnemonic in ['mov', 'add', 'sub', 'movzx', 'movsx']:  #data transfer
                        if mem_access in ins.insn.op_str.split(',')[des]:
                            return (check_block_addr, bbl)

        l.debug("\t[*] !Conflict state: {}".format(hex(unsat_state.addr)))

        addr_pair = None
        cons = unsat_state.solver.constraints
        if len(cons) > 0 and cons[-1].is_false():
            addr_pair = analysis_conflict_by_data_flow(unsat_state.history.addr, unsat_state.history.bbl_addrs)
        # else:
        #     raise Exception("Z3 unimplemented")
        #     # find the constraints that conflict with each other

        if addr_pair is not None:
            self.unsat_block_pairs.append(addr_pair)

    def _run_path(self, start_state, path_address, heuristic=False, calibration_time=10):
        '''
        execute consecutive blocks with symbolic execution
        :param start_state: initial runtime env
        :param path_address: sequence of block addresses
        :param heuristic: Recalculate the path from nodes that do not meet the constraints.
        :param calibration_time: The number of times to recalculate the path; therefore, there is a loop, so you may not be able to jump out of the loop when you adjust the path.
        :return: a state for a feasible path, or None
        '''

        end_block_addr = path_address[-1]  # end_block_addr: target block address

        # Initialize symbolic memory reification strategy; store the effective memory to a high address to facilitate the detection of null pointer dereference
        sim_strategy = SimConcretizationStrategyMap(self._heap_segment_base, self._heap_segment_base + 0x800000)
        start_state.memory.write_strategies.insert(0, sim_strategy)
        start_state.memory.read_strategies.insert(0, sim_strategy)

        self._length_of_shortest_path = len(path_address)
        if start_state.addr not in path_address:
            return None

        if self._is_contain_conflict_block(path_address):
            l.debug("[!] path contain conflict_block, early stop")
            return None
        candidate_states = [start_state]  # state queue to execute
        ret = None
        while len(candidate_states) > 0:  # queue are not empty
            state = candidate_states.pop(0)  # pop a state
            addr_to_step = path_address.pop(0)
            if state.addr != addr_to_step:
                l.error(
                    "\t[!] the address of state {} mismatch with the path, stop the execution".format(hex(state.addr)))
                break

            if state.addr == end_block_addr:  # arriving at check block
                ret = state
                break
            else:
                try:
                    succ = state.step()
                except angr.SimMemoryAddressError as e:
                    l.warning('[!] angr.SimMemoryAddressError when concrete symbolic memory address' + str(
                        e))  # Constraint conflict occurs when address is concreted
                    break
                if len(succ.successors) > 0:
                    for sstate in succ.all_successors:
                        if sstate.addr == path_address[0]:  # make sure the successive node is in the queue
                            if sstate.satisfiable():
                                candidate_states.append(sstate)
                                continue
                            else:  # The selected child node constraints have conflicted
                                try:
                                    # self._collect_conflict_blocks(sstate)
                                    l.debug(
                                        "\t[*] The successor state {} is not satisfiable, early stop.".format(
                                            hex(sstate.addr)))
                                except Exception as e:
                                    l.error("[!] " + str(e.args))
                                    l.error(traceback.format_exc())
                            #     return None
                        elif sstate.addr < self._patch_func_addr or \
                                sstate.addr > self._patch_func_addr + self._patch_func_size:
                            '''
                            For a function call, return a fake(symbolic) value and not step into callee function.
                            '''
                            called_function_name = addr_to_func_name(self.patch_project,
                                                                     sstate.addr)
                            new_state = sstate
                            if called_function_name not in self.CALL_WHITE_LIST:  # functions in WHITE_LIST will be executed
                                new_state = self._fake_function_call(sstate, called_function_name)
                                candidate_states.append(new_state)
                            else:
                                succ = new_state.step()
                                candidate_states += succ.successors

                    if len(candidate_states) == 0 and heuristic:
                        # when all successive nodes are not in feasible paths
                        # try another state
                        for source_state in succ.successors:
                            if source_state.satisfiable():
                                dic = self.get_nodes_from_cfg_by_addrs((source_state.addr, end_block_addr,))
                                return self._path_calibration(source_state,
                                                              source_state.addr,
                                                              end_block_addr, times=calibration_time)

                elif state.block().vex.jumpkind == "Ijk_Call" and \
                        len(succ.unconstrained_successors) > 0:  # call reg;
                    nstate = succ.unconstrained_successors[0]
                    nstate.ip = nstate.stack_pop()  # imitate ret instruction

                    # construct a fake function return value
                    function_name = 'indirect_call'
                    call_site = state.block().instruction_addrs[-1]
                    self.callees_and_rets[(call_site, function_name)] = None
                    nstate.regs.eax = nstate.solver.BVS(
                        "fake_ret_" + function_name + "_{}".format(hex(call_site)),
                        32)  # eax stores return value
                    # The return value of some functions may not participate in the condition judgment, and has not been added to the constraint condition,
                    # so a weak constraint condition is added
                    magic_value = 0xdeadbeef
                    nstate.add_constraints(nstate.regs.eax != magic_value)  # add weak constraint
                    candidate_states.append(nstate)
                else:
                    l.warning("[*] state {} has no successors".format(hex(state.addr)))
        return ret

    def _path_calibration(self, interval_state, start_node_addr, end_node_addr, times=1):
        # Recalculate the path from a certain point that produce infeasible states in the path to the end point
        if times < 1:
            return None
        l.debug("[*] Path recalculation from {} to {}".format(hex(start_node_addr), hex(end_node_addr)))
        try:
            paths = self._get_shortest_path(self._function_cfg_graph, self._program_cfg, start_node_addr, end_node_addr)
            if len(paths[0]) == 0:
                return None
            return self._get_state_from_paths(interval_state, paths, path_limit=100, heuristic=True,
                                              calibration_time=times - 1)
        except nx.NetworkXNoPath as e:
            l.debug(
                "[!] NexworkXNoPATH between {} and {} in heuristic search".format(hex(start_node_addr),
                                                                                  hex(end_node_addr)))
        except NotImplementedError:
            pass  # node not found in cfg or target node is not reachable

        return None

    def _fake_function_call(self, state, function_name):
        '''
        When come across a function call, not step into this function, instead assign a symbolic value to eax.
        :state:
        :param new_pc:
        :return: new state with symbolic eax
        '''
        new_state = state.copy()
        # l.debug("\t[*] faking function call: {}".format(function_name))
        call_site_block = state.callstack.call_site_addr
        call_site = state.block(addr=call_site_block).instruction_addrs[-1]
        self.callees_and_rets[(call_site, function_name)] = None
        new_state.regs.eax = new_state.solver.BVS("fake_ret_" + function_name + "_{}".format(hex(call_site)),
                                                  32)  #
        magic_value = 0xdeadbeef
        new_state.add_constraints(new_state.regs.eax != magic_value)  #
        new_state.regs.ip = new_state.stack_pop()  #
        return new_state

    def _get_trace(self, state):
        import copy
        x = copy.deepcopy(state.history.bbl_addrs.hardcopy)
        x.append(state.addr)
        return x

    def _set_reg_by_name(self, state, reg_name, value):
        reg_number, reg_width = state.arch.registers[reg_name]
        if type(value) is int:
            l.debug("\tReg: {} = {}".format(reg_name, hex(value)))
        state.registers.store(reg_number, value, reg_width)

    def _prepare_running_environment_for_detection(self, to_detect_binary_path, func_name, poc_file):
        '''
        Load poc from file, init the running environment
        :return: state and callees_and_rets. callees_and_rets saves the fake returns of callees
        '''
        l.debug("[*] preparing memory and register layout for detection ......")
        if not os.path.exists(to_detect_binary_path):
            raise FileNotFoundError("File {} not exists".format(to_detect_binary_path))
        to_detect_project = angr.Project(to_detect_binary_path, auto_load_libs=False, engine=TaintEngine)
        self._collect_arch_info(to_detect_project)
        self.arg_addr = self._stack_segment_base + self._byte_width  # address of first argument
        self._hook_libc_functions(to_detect_project)
        to_detect_state = to_detect_project.factory.call_state(
            addr=self.func_name_to_addr(to_detect_project, func_name)[0])
        to_detect_state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
        # to_detect_state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
        # self._prepare_parameters_and_initilization(to_detect_state)
        to_detect_state.regs.sp = self._stack_segment_base
        to_detect_state.regs.bp = self._stack_segment_base
        # state_found_in_patch = self.states_found_for_patch[0]
        # self.print_constraints()
        # self.callees_and_rets = state_found_in_patch._call_seq
        # constraints_pd = PreDetection(self._poc_file, to_detect_state, self.arg_addr, self._arch_name, self.callees_and_rets)
        if poc_file:
            lp = LoadPoC(poc_file, to_detect_state)
        else:
            lp = LoadPoC(self._poc_file, to_detect_state)
        lp.load()
        return to_detect_project, to_detect_state, lp.callee_rets

    def print_constraints(self):
        for state in self.states_found_for_patch:
            trace = [hex(x) for x in self._get_trace(state)]
            l.debug("[>] The State Constraints:")
            l.debug("\tTrace: {}".format(trace))
            l.debug("\tEBP: 0x{:x}".format(state.solver.eval(state.regs.bp)))
            cons = state.solver.constraints
            l.debug("\t Constraints:")
            for c in cons:
                l.debug("\t {}".format(c))

    def _load_state_cache(self):
        '''
        :return: angr state cache
        '''
        if os.path.exists(self.state_file):
            try:
                state = pickle.load(open(self.state_file, 'rb'))
                return state
            except Exception:
                pass
        return None

    def _dump_PoC_from_state(self, state, specific_path):
        '''
        solve all the constraints from state, and save them to PoC file
        :param state: A program state which runs from function entry to patch
        '''
        t1 = datetime.now()
        sp = SolvePoC(state, self.callees_and_rets)
        PoC = sp.solve()
        t2 = datetime.now()
        l.debug('[T] Function Input Solving Time (for one input solving): {:f}'.format((t2-t1).total_seconds()))
        if specific_path:
            with open(specific_path, 'w') as f:
                json.dump(PoC, f)
        else:
            with open(self._poc_file, 'w') as f:
                json.dump(PoC, f)

    def input_generation(self, patch_bin_path, check_addr, patch_addr, forced=False, save=None,
                         patch_bin_project=None):
        '''
        to generate an input which drives function execution to check_addr and patch_addr
        :param forced: force to generate new state and PoC file
        :param patch_bin_path: patched binary path
        :param check_addr: address for check block
        :param patch_addr: address for guard block
        :param force_generation: force to generate function input
        :param save: a path to save input file
        :param patch_bin_project: angr project for patch binary.
        :return: True if an input is generated.
        '''

        if save:  # if specify a function input path, save state file to the same dir
            self.state_file = save + '.state'

        state = self._load_state_cache()
        if forced or not state:
            t1 = datetime.now()
            state = self.get_state_by_se(patch_bin_path, check_addr, patch_addr, patch_bin_project=patch_bin_project)
            if state is None:
                l.error("[-] Input Generation failed")
                return False
            else:
                t2 = datetime.now()
                l.debug('[T] Patch Block Selection Time (for one selection decision): {:f}'.format((t2 - t1).total_seconds()))
                l.debug("[+] Input Generation is successful. path len:{}".format(len(state.history.bbl_addrs)))
                self.dump = pickle.dump(state, open(self.state_file, 'wb'))

        self._dump_PoC_from_state(state, save)
        return True

    def sig_gen(self, to_detect_bin, to_detect_func_name, sig_save_path, poc_file=None,
                NPD=True):
        '''
        :param to_detect_bin: path to binary
        :param sig_save_path: path to save signatures
        :param poc_file: path to poc file
        :param NPD: detect null pointer dereference
        :return: True if null pointer dereference occurs
        '''
        l.info("[*] start null pointer dereference detection for {} of {} in {}".format(
            to_detect_func_name, self.cveid, to_detect_bin))
        # self.print_constraints()
        t2 = datetime.now()
        # 2. detecte null pointer dereference and record semantic features
        is_vulnerable = self._null_pointer_test_and_sig_generation(
            to_detect_bin, to_detect_func_name, sig_save_path, poc_file=poc_file, NPD=NPD)
        t3 = datetime.now()
        l.debug("[*] CVE Signature Generation Time: {:f}".format((t3 - t2).total_seconds()))
        return is_vulnerable

def PatchDetection(CVE, target_bin, vul_func_name, supplementary_feature=True, force_new=False,
                   to_detect_func_name=None, sig=None, poc_file=None):
    '''
    main function for patch detection
    :param target_bin: target binary to detect
    :param to_detect_func_name: The name of the function to be detected, the default is None, the same name as the vulnerable function func_name
    :param vul_func_name: function name in CVE description
    :param CVE: e.g. 20201234
    :param sig: what kind of signature to use
    :param supplementary_feature: bool: Whether to use auxiliary information such as arithmetic operation instruction sequence for auxiliary calculation
    :param force_new: to force generate new feature of target function
    :return: float: -1~1 (vul ~ patch)
    '''
    if to_detect_func_name is None:
        to_detect_func_name = vul_func_name

    ttrace_file = get_target_binary_trace_file_path(cve_id=CVE, target_binary=target_bin,
                                                    function_name=to_detect_func_name)
    vul_flag_file = get_target_cve_flag(cve_id=CVE, target_binary=target_bin,
                                        function_name=to_detect_func_name)

    '''
    First determine if there is a null pointer dereference vulnerability
     If no, then compare by feature
    '''
    if os.path.exists(vul_flag_file) and not force_new:
        return -1

    if not os.path.exists(ttrace_file) or force_new:
        sp = Executor(CVEid=CVE, func_name=vul_func_name)
        if sp.sig_gen(target_bin, to_detect_func_name=to_detect_func_name,
                      sig_save_path=ttrace_file,
                      poc_file=poc_file):
        # If it is determined that there is a vulnerability, create a special file to mark that the func_name of the binary file is vulnerable to CVE
            if not os.path.exists(vul_flag_file):
                os.mknod(vul_flag_file)
            return -1

    try:
        l.debug("[*] signature optimization {}".format(sig))
        patch_trace = get_cve_patch_sig_file_path(CVE, vul_func_name, OPT=sig)
        vul_trace = get_cve_vul_sig_file_path(CVE, vul_func_name, OPT=sig)

        if not os.path.exists(patch_trace):
            raise Exception
        with open(patch_trace, 'r') as f:
            ptrace = json.load(f)
        with open(vul_trace, 'r') as f:
            vtrace = json.load(f)
    except:
        l.error("signature file of {} loaded failed".format(CVE))
        raise FileNotFoundError()

    with open(ttrace_file, 'r') as f:
        ttrace = json.load(f)

    # ttrace = remove_duplicate_stack_reading(ttrace, window_size = 3)

    t_p = longest_common_subsequence(ptrace, ttrace, element_equal)
    t_v = longest_common_subsequence(ttrace, vtrace, element_equal)
    p_v = longest_common_subsequence(ptrace, vtrace, element_equal)
    Np = len(ptrace)
    Nv = len(vtrace)
    Nt = len(ttrace)
    factor1 = (abs(Nt - Nv) + 1) / (abs(Nt - Np) + 1)  # (0, N] , when N>1, patched
    factor2 = (t_p + 1) / (t_v + 1)  # (0, N], when N>1, patched
    factor3 = (abs(t_p - p_v) + 1) / (abs(t_v - p_v) + 1)  # (0, N], when N>1, patched
    p1 = math.tanh(math.log2(factor1))
    p2 = math.tanh(math.log2(factor2))
    p3 = math.tanh(math.log2(factor3))
    prob_patched = p1 * 0.2 + p2 * 0.8
    # calculate similarity between other features
    if supplementary_feature:
        supplementary_feature_file = ttrace_file + ".others"
        vul_supple_feature_file = vul_trace + ".others"
        patch_supple_feature_file = patch_trace + ".others"
        try:
            with open(supplementary_feature_file, 'r') as f:
                target_sup_feature = json.load(f)
            with open(vul_supple_feature_file, 'r') as f:
                vul_sup_feature = json.load(f)
            with open(patch_supple_feature_file, 'r') as f:
                patch_supple_feature = json.load(f)
            sup_t_v = supplementary_feature_sim(target_sup_feature, vul_sup_feature)
            sup_t_p = supplementary_feature_sim(target_sup_feature, patch_supple_feature)
            if sup_t_v == 0:
                prob_patched_sup = 1
            else:
                prob_patched_sup = math.tanh(math.log2(sup_t_p / sup_t_v + 0.00000000001))
            l.info("[>] mem sim:{:f}, supp sim:{:f}".format(prob_patched, prob_patched_sup))

        except FileNotFoundError as e:
            prob_patched_sup = 0.0
            l.error("Supplementary Feature: file not found {}".format(e.filename))

        # similarity between tainted argument sequences
        target_tainted_feature_file = ttrace_file + ".taint_seqs"
        vul_tainted_feature_file = vul_trace + ".taint_seqs"
        patch_tainted_feature_file = patch_trace + ".taint_seqs"
        try:
            with open(target_tainted_feature_file, 'r') as f:
                ttf = json.load(f)
            with open(vul_tainted_feature_file, 'r') as f:
                vtf = json.load(f)
            with open(patch_tainted_feature_file, 'r') as f:
                ptf = json.load(f)
            sim_t_v = tainted_feature_sim(ttf, vtf)
            sim_t_p = tainted_feature_sim(ttf, ptf)
            if sim_t_v == 0:
                prob_patched_taint = 1.0
            else:
                prob_patched_taint = math.tanh(math.log2(sim_t_p / sim_t_v + 0.00000000001))
            l.info("[>] taint sim: {:f}".format(prob_patched_taint))
        except FileNotFoundError as e:
            prob_patched_taint = 0.0
            l.error("Tainted Feature File Missing: {}".format(e.filename))
        prob_patched = prob_patched * 2.251 + prob_patched_sup * 1.418 + 0.436 * prob_patched_taint + 0.0387
        prob_patched = (1/(1+math.exp(-prob_patched)) - 0.5) * 2 # Sigmoid function
    return prob_patched


def tainted_feature_sim(taint1, taint2):
    def taint_tags_eq(a: list, b: list):
        # to determine whether two sets are the same
        if len(a) != len(b):
            return False
        a.sort()
        b.sort()
        for i in range(len(a)):
            if a[i] != b[i]:
                return False
        return True

    return longest_common_subsequence(taint1, taint2, taint_tags_eq)


def supplementary_feature_sim(supp_dic1: dict, supp_dic2: dict):
    '''Calculate the similarity of other features'''
    element_sim = lambda x, y: x == y
    args1 = supp_dic1['args']
    args2 = supp_dic2['args']
    arg_max_len = max(len(args2), len(args1))
    arg_sim = longest_common_subsequence(args1, args2, element_sim) / arg_max_len if arg_max_len > 0 else 1
    arith1 = supp_dic1['arith']
    arith2 = supp_dic2['arith']
    arith_max_len = max(len(arith1), len(arith2))
    arith_sim = longest_common_subsequence(arith1, arith2, element_sim) / arith_max_len if arith_max_len > 0 else 1
    cmp_const1 = supp_dic1['cmp_constant']
    cmp_const2 = supp_dic2['cmp_constant']
    cmp_const_max_len = max(len(cmp_const1), len(cmp_const2))
    cmp_const_sim = longest_common_subsequence(cmp_const1, cmp_const2,
                                               element_sim) / cmp_const_max_len if cmp_const_max_len > 0 else 1
    weight_sim = [0.4, 0.3, 0.3]
    return arg_sim * weight_sim[0] + arith_sim * weight_sim[1] + cmp_const_sim * weight_sim[2]


def element_equal(x, y):
    if x[0] == y[0] and x[1] == y[1]:
        return True
    return False


def longest_common_subsequence(a, b, element_equal):
    m = [[0 for j in range(len(b) + 1)] for i in range(len(a) + 1)]
    for ai, aa in enumerate(a):
        for bi, bb in enumerate(b):
            if element_equal(aa, bb):
                m[ai + 1][bi + 1] = m[ai][bi] + 1
            else:
                m[ai + 1][bi + 1] = max(m[ai + 1][bi], m[ai][bi + 1])
    return m[len(a)][len(b)]


def input_gen(cveid, patched_bin, func_name, check_addr, patch_addr, force_generation=False):
    "function input generation for PoC"
    cve_entry = [cveid, patched_bin, func_name, str(check_addr), str(patch_addr)]
    l.debug("[*] Gen Input for {}".format(",".join(cve_entry)))
    patched_bin = os.path.join(rootdir, patched_bin)
    p_exe = Executor(CVEid=cveid, func_name=func_name)
    try:
        p_exe.input_generation(patched_bin, check_addr, patch_addr, forced=force_generation)
    except Exception as e:
        l.error(traceback.format_exc())



def generate_cve_sig(cveid, vul_bin, patched_bin, func_name, force_generation=False):
    '''
    generate vulnerability signature
    :param force_generation: force to regenerate signature
    '''
    l.info(
        "\n[*] Run for {},{},{},{}".format(cveid, vul_bin, patched_bin, func_name))

    p_exe = Executor(CVEid=cveid, func_name=func_name)
    patched_signature_saved_path = get_cve_patch_sig_file_path(cveid, func_name)
    vul_signature_saved_path = get_cve_vul_sig_file_path(cveid, func_name)
    try:

        if force_generation or not os.path.exists(patched_signature_saved_path):
            p_flag = p_exe.sig_gen(patched_bin, func_name, patched_signature_saved_path)
        if force_generation or not os.path.exists(vul_signature_saved_path):
            p_exe.sig_gen(vul_bin, func_name, vul_signature_saved_path)
    except KeyboardInterrupt as e:
        l.info("[+] White List {}".format(white_list))
    except FileNotFoundError as e:
        l.error("PoC file not founded for {}".format(e.filename, cveid))

    except Exception as e:
        l.error("[-] Generation Error: {},{},{},{}".format(cveid, vul_bin, patched_bin, func_name))
        l.error(traceback.format_exc())
        return False
    return True

# if __name__ == '__main__':
#     l.addHandler(logging.FileHandler("patch.log"))
#     import memory_access_recorder
#     memory_access_recorder.l.addHandler(logging.FileHandler("patch.log"))
#     import runtime_recorder
#     runtime_recorder.l.addHandler(logging.FileHandler("patch.log"))
#     generate_sigs(force_generation=False)
# batch_main()
