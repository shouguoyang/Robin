'''
Robin main
'''

import datetime
import json
import logging
import math
import os
import traceback
import angr
import sys
import networkx as nx
from sklearn.metrics import roc_auc_score
from Exceptions import StateFileNotExitsException
from cfg_pruning_with_slice import CFG_PS
from important_VALUEs import heap_segment_base, stack_segment_base, reg_gs, CALL_WHITE_LIST
from memory_access_recorder import SimConcretizationStrategyMap
from preparation_for_detection import PreDetection
from runtime_recorder import NullPointerDereference
import csv
import pickle
from collections import defaultdict
import random
import time
from utils import get_cve_state_file_path, \
    get_target_binary_trace_file_path, get_target_cve_flag, \
    get_cve_patch_sig_file_path, \
    get_cve_vul_sig_file_path
rootdir = os.path.dirname(os.path.abspath(__file__))
LOG_LEVEL = logging.DEBUG
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


def set_logger_level(log_level):
    # other loggers
    l.setLevel(log_level)
    logging.getLogger("Memory_Access").setLevel(log_level)
    logging.getLogger("RuntimeRecorder").setLevel(log_level)
    logging.getLogger('preparation').setLevel(log_level)
    logging.getLogger("CFGDiffer").setLevel(log_level)


mute_angr()

l.info("=================={}================".format(time.strftime("%Y-%m-%d %H:%M", time.localtime())))


class SymExePath():
    '''given binaries of vul version and patch version, PoC solvong'''

    def __init__(self, CVEid, func_name):
        '''
        :param CVEid: CVE id
        :param func_name: the vulnerable function
        '''
        self._path_hash_record = [] # record path hash value
        self.cveid = CVEid
        self.func_name = func_name
        self.states_found_for_patch = []  #state after execute feasible paths
        self.CALL_WHITE_LIST = CALL_WHITE_LIST  # functions to step in
        self.callees_and_rets = {}  # (callsite, func_name): ret_val # record function returns
        self._stack_segment_base = stack_segment_base #
        self._heap_segment_base = heap_segment_base #
        self._reg_gs = reg_gs # global section
        self.state_file = get_cve_state_file_path(cve_id=CVEid, function_name=func_name)
        self._loopfinder = None  # from angr
        self.unsat_block_pairs = []  #
        self._length_of_shortest_path = 10
        self._patch_func_addr = None  # function address
        self._program_cfg = None  # program cfg
        self._function_cfg_graph = None  # cfg of function
        self._path_from_check_to_patch = None
        self.patch_project = None  # angr project
        self._patch_func_size = None
        self._cutoff = None

    def _collect_arch_info(self, project: angr.Project):
        self._bits = project.arch.bits
        self._arch_name = project.arch.name
        self._memory_endness = project.arch.memory_endness
        self._byte_width = int(self._bits / 8)  # memory unit width
        self._target_pic_code = project.loader.main_object.pic  # code PIC

    def _hook_libc_functions(self, project):

        # libc function hook
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
        func_sym = p.loader.find_symbol(name) # try fuzzy = True?
        return func_sym.rebased_addr, func_sym.size

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

    def _null_pointer_test_and_sig_generation(self, bin_path, func_name, sig_save_path, bound = 30):
        '''
        1. vulnerability detection
        2. record semantic information
        :param bin_path: binary to be detected
        :param func_name: function in binary
        :param sig_save_path: save semantic information
        :param bound: max loop limitation
        :return:  if vulnerable, returns True
        '''
        p, to_detect_state, callees_and_rets = self._prepare_running_environment_for_detection(bin_path, func_name)
        p._acc_seq = []  # memory access sequece
        # state.options.add(angr.options.CALLLESS)
        sm = p.factory.simgr(to_detect_state, save_unconstrained=True, save_unsat=True)
        # sm.use_technique(angr.exploration_techniques.LoopSeer(cfg=self._function_cfg_graph, bound=30)) #
        func_and_ret = []
        for callsite, callee_func_name in callees_and_rets:
            func_and_ret.append((callee_func_name, self.callees_and_rets[(callsite, callee_func_name)]))

        runtime_recorder = NullPointerDereference(func_and_ret, p, bound = bound)
        sm.use_technique(runtime_recorder)
        l.info("[+] start detection with se in function {} of {}".format(func_name, bin_path))
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
        self.save_other_features(runtime_recorder, sig_save_path)
        return null_dereference

    def save_other_features(self, recorder, mem_acc_seq_file):
        '''
        record other features
        :param recorder:
        :return:
        '''
        file_name = mem_acc_seq_file + ".others"
        dic = {'args': recorder._arguments,
               'arith': recorder._arithmetic_sequence,
               'cmp_constant': recorder._constants_in_cmp_instruction}
        with open(file_name, 'w') as f:
            json.dump(dic, f)

        l.debug("[*] other features saved : {}".format(file_name))

    def save_mem_acc_seq(self, acc_seq, mem_acc_seq_file):
        '''
        record memory access addresses
        :param acc_seq:
        '''
        tdir = os.path.dirname(mem_acc_seq_file)
        if not os.path.exists(tdir):
            os.mkdir(tdir)
        with open(mem_acc_seq_file, 'w') as f:
            json.dump(acc_seq, f)
        l.debug("[*] trace file saved : {}".format(mem_acc_seq_file))

    def get_nodes_from_cfg_by_addrs(self, addrs):
        '''
        :param cfg_graph: program cfg only!
        :param addrs: start block address
        :return: a dic;key is address of block，value is the node of cfg
        '''
        ret_dic = {}

        for addr in addrs:
            block = self.patch_project.factory.block(addr)
            ret_dic[addr] = block.codenode

        return ret_dic

    def _prepare_parameters_and_initilization(self, state):
        # before function execution

        # X86 : cdecl & fastcall
        def _init_stack(state):
            # for 32bit program
            # now only consider cdecl calling convention; supposing that arguments less than 17
            for i in range(16):
                state.memory.store(self.arg_addr + self._byte_width * i,
                                   state.solver.BVS('arg_{}'.format(i), self._bits)
                                   ,endness=state.arch.memory_endness)
            # fast_call_reg = ['eax', 'edx', 'ecx']
            # self._set_reg_by_name(state, fast_call_reg[0], state.solver.BVS('arg_0', self._bits))
            # self._set_reg_by_name(state, fast_call_reg[1], state.solver.BVS('arg_1', self._bits))
            # self._set_reg_by_name(state, fast_call_reg[2], state.solver.BVS('arg_2', self._bits))

        # X64
        def _init_regs(state):
            # push register
            reg_parameter = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
            for i in range(len(reg_parameter)):
                self._set_reg_by_name(
                    state,
                    reg_parameter[i],
                    state.solver.BVS('arg_{}'.format(i), self._bits)
                )
            # push stack
            state.regs.esp = self._stack_segment_base
            for i in range(10):
                state.memory.store(self.arg_addr + self._byte_width * i,
                                   state.solver.BVS('arg_{}'.format(i+6), self._bits),
                                   endness=state.arch.memory_endness)
        state.regs.esp = self._stack_segment_base
        state.regs.gs = self._reg_gs

        if self._arch_name == 'AMD64':
            _init_regs(state)
        elif self._arch_name == 'X86':
            _init_stack(state)
        else:
            raise Exception("arch not supported.")


    def _get_shortest_path(self, func_cfg, program_cfg, source, target, use_program_cfg=False):
        '''
        :param func_cfg: cfg of functions
        :param program_cfg: cfg of binary
        :param source: start address
        :param target:
        :param use_program_cfg: whether using program_cfg
        :return:
        '''
        try:
            return self._find_shortest_paths_in_graph(func_cfg, source, target)
        except Exception as e:
            if use_program_cfg:
                l.warning(
                    "[!] can not calculate shortest path from function cfg, use program cfg instead \n\t {}".format(
                        e.args))
                return self._find_shortest_paths_in_graph(program_cfg, source, target)
            else:
                raise e

    def _find_shortest_paths_in_graph(self, G, source, target):
        '''
        :param source: int: address of start node
        '''
        #
        source_node = None
        target_node = None
        if type(G) is angr.analyses.cfg.CFGFast:
            source_node = G.model.get_node(source)
            target_node = G.model.get_node(target)
            G = G.graph
        else:  # networkx.classes.digraph.DiGraph
            source_node = self.patch_project.factory.block(source).codenode
            target_node = self.patch_project.factory.block(target).codenode

        if target_node not in G.nodes:
            for n in G.nodes:
                if target_node.addr > n.addr and target_node.addr <= n.addr + n.size:
                    target_node = n
                    break
            else:
                l.error("[!] Cound not relocation target node {}".format(hex(target_node.addr)))

        if source_node not in G.nodes:
            for n in G.nodes:
                if source_node.addr > n.addr and source_node.addr <= n.addr + n.size:
                    source_node = n
                    break
            else:
                l.error("[!] Cound not relocation sorce node {}".format(hex(source_node.addr)))

        return list(nx.all_shortest_paths(G, source_node, target_node))

    def _hash_path(self, path: list):
        '''
        :param path:
        :return:
        '''
        x = path[0]
        for y in path[1:]:
            x ^= y
        return x

    def get_state_by_se(self, patch_bin_path, check_addr, patch_addr):
        '''
        '''
        l.debug("[*] starting state generating in get_state_by_se")
        self.patch_project = angr.Project(patch_bin_path,
                                          auto_load_libs="False")  # patched binary angr project
        function_symbol = self.patch_project.loader.find_symbol(self.func_name)
        self._patch_func_addr = function_symbol.rebased_addr
        self._patch_func_size = function_symbol.size
        self._collect_arch_info(self.patch_project)
        self._hook_libc_functions(self.patch_project)
        self.arg_addr = self._stack_segment_base + self._byte_width  # address of first argument
        check_addr = check_addr + 0x400000 if self._target_pic_code else check_addr
        if patch_addr is not None:
            patch_addr = patch_addr + 0x400000 if self._target_pic_code else patch_addr

        cfg_path = patch_bin_path + ".angr_cfg"
        cfg = None
        if os.path.exists(cfg_path):
            cfg = pickle.load(open(cfg_path, 'rb'))
        else:
            l.debug("[*] Constructing CFG for {}. It may take long time.".format(patch_bin_path))
            cfg = self.patch_project.analyses.CFGFast()
            # regions=[(self._patch_func_addr, self._patch_func_addr
            #                                     + self._patch_func_size)])
            # dump cfg
            pickle.dump(cfg, open(cfg_path, 'wb'))
        self._program_cfg = cfg
        # patch_function_instance = cfg.functions[self.func_name] #
        function_cfg_graph = cfg.functions[self.func_name].graph
        l.debug("[p] function size:{}".format(len(function_cfg_graph.nodes)))
        self._function_cfg_graph = function_cfg_graph
        if patch_addr is not None:
            path = \
            list(self._get_shortest_path(function_cfg_graph, cfg, check_addr, patch_addr))[0]
            path.pop(0)
            self._path_from_check_to_patch = path
        l.debug("[*] finding paths from 0x%x To 0x%x" % (self._patch_func_addr, check_addr))
        call_state = self.patch_project.factory.call_state(self._patch_func_addr)
        # self.state.inspect.b('address_concretization', angr.BP_BEFORE, action=self.concretization_symbolic_address)
        call_state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
        call_state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
        call_state.options.add(angr.sim_options.LAZY_SOLVES)
        # self.state.options.add(angr.sim_options.CONSTRAINT_TRACKING_IN_SOLVER) #!!! don't enable. the reason cause invalid dec_ref command
        # self.state.options.remove(angr.sim_options.COMPOSITE_SOLVER)
        self._prepare_parameters_and_initilization(call_state)
        # 首先尝试最短路径
        l.debug("[*] trying the shortest path...\n")
        try:
            #
            # paths = list(nx.all_shortest_paths(function_cfg_graph,
            #                                    nodes_dic[self._patch_func_addr], nodes_dic[self._check_block_addr]))
            paths = self._get_shortest_path(function_cfg_graph, cfg, self._patch_func_addr, check_addr)
            self._cutoff = len(paths[0])
            if patch_addr is not None:  #
                for path in paths:
                    path += self._path_from_check_to_patch
                    self._cutoff = len(path) * 1.5

            state = self._get_state_from_paths(call_state, paths, path_limit=10,
                                               heuristic=True, calibration_time=int(self._cutoff / 4.5))
        except Exception as e:
            # indirect call e.g. CVE-2014-9656
            l.error("[!] error {}".format(e.args))
            l.error(traceback.format_exc())
            state = None

        if state is not None:
            l.debug("[+] state found by shortest paths!")
            return state

        # try to slice CFG and recalculate paths
        l.debug("[*] trying the sliced path...")
        cfgps = CFG_PS(patch_bin_path, self._function_cfg_graph, self._patch_func_addr,
                       check_addr, patch_addr, self.patch_project)
        try:
            cfgps.do_slicing()
            paths = list(cfgps.get_shortest_paths())
            if patch_addr is not None:  #
                for path in paths:
                    path += self._path_from_check_to_patch
            state = self._get_state_from_paths(call_state, paths, path_limit=10,
                                               heuristic=True, calibration_time=int(self._cutoff / 6 / len(paths)))

            if state is not None:
                l.debug("[+] state found by sliced shortest paths!")
                return state
        except Exception as e:
            l.warning("[-] slicing error: {}".format(e.args))

        l.debug("[*] trying all_simple_paths paths, limit path len:{}\n".format(
            self._cutoff))
        paths = cfgps.get_simple_paths(cutoff=self._cutoff)
        found = self._get_state_from_paths(call_state, paths,
                                           path_limit=100, calibration_time=2)
        if found:
            l.debug("[+] state found by simple paths!")
            return found

        # l.warning(
        #     "[!] all simple path failed, try to seek with blind symbolic execution, time consuming")
        # return self._get_state_without_paths(call_state, nodes_dic[check_block], patch_block)

        return None

    def _dfs(self, graph, start_node, end_addr, path_recorder=[], current_depth=0, max_depth=100):
        '''
        深度优先寻找从start_addr 到 end_addr 的路径并返回
        TODO: 1. dfs同时判断循环
            1.1 通过限制路径长度限制循环次数
        :param graph: 函数FastCFG对象.graph
        :param start_node: 开始进行搜索的节点
        :param end_addr:
        :param current_depth: 当前搜索深度
        :param max_depth: 最大搜索深度
        :param path_recorder: 记录从路径节点的地址
        :return: list: 从start_addr 到 end_addr 的路径
        '''
        current_depth += 1
        if current_depth > max_depth:
            return []
        if start_node.addr == end_addr:
            yield path_recorder
        else:
            succs = list(graph.successors(start_node))
            random.shuffle(succs)
            for succ in succs:  #
                if succ in path_recorder:
                    continue

                path_recorder.append(start_node)
                yield from self._dfs(graph, succ, end_addr, path_recorder, current_depth, max_depth)
                path_recorder.pop()

    def _get_all_unreacheable_blocks(self, check_node):
        '''
        :param check_node:
        :param patch_addr:
        :return:
        '''
        cfg = self._program_cfg.graph
        if check_node not in cfg.nodes:
            raise Exception("check node in not in cfg.nodes")

        reacheable_blocks = []  #
        predecessor_queue = [check_node]
        while len(predecessor_queue) > 0:
            current_node = predecessor_queue.pop(0)

            for parentnode in cfg.predecessors(current_node):
                if parentnode.addr not in reacheable_blocks:
                    reacheable_blocks.append(parentnode.addr)
                    predecessor_queue.append(parentnode)

        for node in cfg.nodes:
            if node.addr not in reacheable_blocks:
                yield node

    def _get_state_without_paths(self, init_state, check_node, patch_block, step_time_limit=2000, bound=10):
        '''
        blind symbolic execution
        :param init_state:
        :param patch_block:
        :param step_time_limit:
        :param bound : limitation for loop
        :return: True if path founded
        '''
        # return None
        avoid_blocks = list(self._get_all_unreacheable_blocks(check_node))
        simgr = self.patch_project.factory.simgr(
            init_state)  # veritesting=True  see https://docs.angr.io/core-concepts/pathgroups
        try:
            simgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=self._program_cfg, bound=bound))
            # simgr.use_technique(angr.exploration_techniques.DFS())
            simgr.use_technique(angr.exploration_techniques.LengthLimiter(max_length=step_time_limit))
            # simgr.use_technique(angr.exploration_techniques.Spiller())
            simgr.explore(find=patch_block, avoid=avoid_blocks)
        except Exception as e:
            l.error("[-] simgr.explore failed")

        if len(simgr.found) > 0:
            l.debug("[+] state found by explore!")
            self.states_found_for_patch.append(simgr.found[0])
            return simgr.found[0]
        return None

    def _get_loops(self):
        '''
        :return: the angr.analyses.LOOP instances in the function graph
        '''
        if self._loopfinder is None:
            self._loopfinder = self.patch_project.analyses.LoopFinder(
                functions=(self._program_cfg[self.func_name],))
        return self._loopfinder.loops

    def try_add_loop_to_path(self, path, repeat=1):
        '''
        :param path:
        :param repeat: times the loop path added
        :return: new path which may contain loop
        '''


        def replace_loop(path, loop_entry_node_idx, loop, graph):
            '''
            replace nodes in the path with a loop
            :param loop_entry_node: a node in both loop and path, which is regarded as a stitch point
            :param graph:
            :return: new path which contains a loop
            '''

            loop_nodes_in_order = [loop.entry]
            curr_node = loop.entry
            circled = False  #
            while True:
                tnode = 0
                for node in graph.successors(curr_node):
                    tnode = node.addr
                    if node in loop.body_nodes:
                        if node == loop.entry:
                            circled = True
                        else:
                            loop_nodes_in_order.append(node)
                            curr_node = node
                        break
                else:  #
                    l.warning("[!] the successors of node {} are not in loop, break.".
                              format(hex(tnode)))
                    return []

                if circled:
                    break

            new_list = path[:loop_entry_node_idx] + loop_nodes_in_order + path[loop_entry_node_idx:]
            return new_list

        loops = self._get_loops()
        loop_entries = {}  #
        for idx, loop in enumerate(loops):
            loop_entries[loop.entry.addr] = idx
        l.debug("[*] find {} loop".format(len(loop_entries)))


        for i, node in enumerate(path):
            if node.addr in loop_entries:
                idx = loop_entries[node.addr]
                loop_to_add = loops[idx]
                yield replace_loop(path.copy(), i, loop_to_add, self._program_cfg.graph)
        return []

    def _get_state_from_paths(self, init_state, paths, path_limit=10000, heuristic=False, calibration_time=1):
        '''
        symbolic execution for given paths
        :param init_state: running environment
        :param paths: paths to be executed
        :param path_limit: how many paths are executed
        :param heuristic: whether recalculate paths
        :return: True if a feasible path is found
        '''

        path_i = 0
        for path in paths:

            if path_limit != -1 and path_i > path_limit:
                return None

            path_address = [p.addr for p in path
                            if self._patch_func_addr <= p.addr <= self._patch_func_addr + self._patch_func_size]

            # remove duplicate paths
            path_hash = self._hash_path(path_address)
            if path_hash in self._path_hash_record:
                continue
            else:
                self._path_hash_record.append(path_hash)

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
        :param unsat_state:
        '''

        def analysis_conflict_by_data_flow(check_block_addr, run_trace_addrs, des=0):
            '''

            '''
            check_block = self.patch_project.factory.block(check_block_addr)
            # 定位比较指令 cmp, test, xor...
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

            for bbl in reversed(run_trace_addrs):
                block = self.patch_project.factory.block(bbl)
                for ins in reversed(block.capstone.insns):
                    if ins.insn.mnemonic in ['mov', 'add', 'sub', 'movzx', 'movsx']:  # 指令是数据转移指令
                        if mem_access in ins.insn.op_str.split(',')[des]:
                            return (check_block_addr, bbl)

        l.debug("\t[*] !Conflict state: {}".format(hex(unsat_state.addr)))
        # history_actions = list(unsat_state.history.actions)
        # try:
        #     unsat_cons_list = None
        #     # unsat_cons_list = unsat_state.solver.unsat_core()
        #     if unsat_cons_list is not None and len(unsat_cons_list) > 0:
        #         x = [get_constraint_bb_addr(history_actions, c) for c in unsat_cons_list]
        #         if len(x) == 2:
        #             self.unsat_block_pairs.append(x)
        #         elif len(x) > 2:
        #             self.unsat_block_pairs.append(x[:2])
        #     else:
        #         raise Exception("unsat_core is None")
        # except Exception as e:
        #     l.debug("UNSAT_CORN {}".format(str(e.args)))
        addr_pair = None
        cons = unsat_state.solver.constraints
        if len(cons) > 0 and cons[-1].is_false():
            addr_pair = analysis_conflict_by_data_flow(unsat_state.history.addr, unsat_state.history.bbl_addrs)
        # else:
        #     raise Exception("Z3 unimplemented")

        if addr_pair is not None:
            self.unsat_block_pairs.append(addr_pair)

    def _run_path(self, start_state, path_address, heuristic=False, calibration_time=10):
        '''

        '''

        end_block_addr = path_address[-1]  # end_block_addr:

        sim_strategy = SimConcretizationStrategyMap(self._heap_segment_base, self._heap_segment_base + 0x800000)
        start_state.memory.write_strategies.insert(0, sim_strategy)
        start_state.memory.read_strategies.insert(0, sim_strategy)

        self._length_of_shortest_path = len(path_address)
        if start_state.addr not in path_address:
            return None

        if self._is_contain_conflict_block(path_address):
            l.debug("[!] path contain conflict_block, early stop")
            return None
        l.debug("[*] Try find state by running path(len:{}):\n\t\t{}".format(len(path_address),
                                                                             " ".join([hex(p) for p in path_address])))
        candidate_states = [start_state]  #
        ret = None
        while len(candidate_states) > 0:  #
            state = candidate_states.pop(0)  #
            addr_to_step = path_address.pop(0)
            if state.addr != addr_to_step:
                l.error(
                    "\t[!] the address of state {} mismatch with the path, stop the execution".format(hex(state.addr)))
                break

            l.debug("\t[>]: step in block {} for state generation".format(hex(state.addr)))

            if state.addr == end_block_addr:  # arriving at check block
                ret = state
            else:
                try:
                    succ = state.step()
                except angr.SimMemoryAddressError as e:
                    l.warning('[!] angr.SimMemoryAddressError when concrete symbolic memory address' + str(
                        e))  #
                    break
                if len(succ.successors) > 0:
                    for sstate in succ.all_successors:
                        if sstate.addr == path_address[0]:  #
                            if sstate.satisfiable():
                                candidate_states.append(sstate)
                                continue
                            else:  #
                                try:
                                    self._collect_conflict_blocks(sstate)
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
                            , return a fake(symbolic) value and not execution。
                            '''
                            called_function_name = self.addr_to_func_name(self.patch_project,
                                                                          sstate.addr)
                            new_state = sstate
                            if called_function_name not in self.CALL_WHITE_LIST:  #
                                new_state = self._fake_function_call(sstate, called_function_name)
                                candidate_states.append(new_state)
                            else:
                                succ = new_state.step()
                                candidate_states += succ.successors

                    if len(candidate_states) == 0 and heuristic:

                        for source_state in succ.successors:
                            if source_state.satisfiable():
                                dic = self.get_nodes_from_cfg_by_addrs((source_state.addr, end_block_addr,))
                                return self._path_calibration(source_state,
                                                              source_state.addr,
                                                              end_block_addr, times=calibration_time)



                elif state.block().vex.jumpkind == "Ijk_Call" and \
                        len(succ.unconstrained_successors) > 0:  # call reg
                    nstate = succ.unconstrained_successors[0]
                    nstate.ip = nstate.stack_pop()  # imitate ret instruction
                    function_name = 'indirect_call'
                    call_site = state.block().instruction_addrs[-1]
                    self.callees_and_rets[(call_site, function_name)] = None
                    nstate.regs.eax = nstate.solver.BVS(
                        "fake_ret_" + function_name + "_{}".format(hex(call_site)),
                        32)  #
                    magic_value = 0xdeadbeef
                    nstate.add_constraints(nstate.regs.eax != magic_value)  #
                    candidate_states.append(nstate)
                else:
                    l.warning("[*] state {} has no successors".format(hex(state.addr)))
        return ret

    def _path_calibration(self, interval_state, start_node_addr, end_node_addr, times=1):
        if times < 1:
            return None

        l.debug("[*] Path recalculation from {} to {}".format(hex(start_node_addr), hex(end_node_addr)))
        try:
            paths = self._get_shortest_path(self._function_cfg_graph, self._program_cfg, start_node_addr, end_node_addr)
            return self._get_state_from_paths(interval_state, paths, path_limit=100, heuristic=True,
                                              calibration_time=times - 1)
        except nx.NetworkXNoPath as e:
            l.debug(
                "[!] NexworkXNoPATH between {} and {} in heuristic search".format(hex(start_node_addr),
                                                                                  hex(end_node_addr)))
        return None

    def _fake_function_call(self, state, function_name):
        '''
        :state:
        :param new_pc:

        '''
        new_state = state.copy()
        l.debug("\t[*] faking function call: {}".format(function_name))
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

    def _find_symbolicAST(self, past):
        '''
        '''
        for ast in past.children_asts():
            if len(list(ast.children_asts())) == 0 and ast.symbolic:
                return ast
            if ast.symbolic:
                return self._find_symbolicAST(ast)

    def _find_AST_by_name(self, past, name):
        '''
        '''
        for ast in past.recursive_leaf_asts:
            if ast.shallow_repr() == name:
                return ast

        return None

    def _set_reg_by_name(self, state, reg_name, value):
        reg_number, reg_width = state.arch.registers[reg_name]
        if type(value) is int:
            l.debug("\tReg: {} = {}".format(reg_name, hex(value)))
        state.registers.store(reg_number, value, reg_width)

    def _prepare_running_environment_for_detection(self, to_detect_binary_path, func_name):
        '''

        '''
        l.info("[*] preparing memory layout for detection >>>")
        to_detect_project = angr.Project(to_detect_binary_path, auto_load_libs=False)
        self._collect_arch_info(to_detect_project)
        self.arg_addr = self._stack_segment_base + self._byte_width  #
        self._hook_libc_functions(to_detect_project)
        to_detect_state = to_detect_project.factory.call_state(
            addr=self.func_name_to_addr(to_detect_project, func_name)[0])
        # to_detect_state.options.add(angr.options.FAST_REGISTERS)
        # to_detect_state.options.add(angr.options.FAST_MEMORY)
        self._prepare_parameters_and_initilization(to_detect_state)
        state_found_in_patch = self.states_found_for_patch[0]
        self.print_constraints()
        self.callees_and_rets = state_found_in_patch._call_seq
        constraints_pd = PreDetection(state_found_in_patch, to_detect_state, self.arg_addr, self._arch_name, self.callees_and_rets)
        callees_and_rest = constraints_pd._callees_and_rets
        return to_detect_project, to_detect_state, callees_and_rest

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
        '''
        if os.path.exists(self.state_file):
            state = pickle.load(open(self.state_file, 'rb'))
            self.states_found_for_patch.append(state)
            return True
        return False

    def generate_vul_trigger_input_by_patch(self, patch_bin_path, check_addr, patch_addr, forced=False):
        '''

        '''

        loaded = self._load_state_cache()
        if forced or not loaded:

            state = self.get_state_by_se(patch_bin_path, check_addr, patch_addr)
            if state is None:
                l.error("[-] {} State can not be generated in function {} from {} to {}".format(self.cveid,
                                                                                                self.func_name,
                                                                                hex(self._patch_func_addr),
                                                                                hex(check_addr)))
                return False
            else:
                l.debug("[+] state generation is successful. path len:{}".format(len(state.history.bbl_addrs)))
                pickle.dump(state,
                            open(self.state_file, 'wb'))
                return True

        return loaded

    def sig_gen(self, to_detect_bin, to_detect_func_name, sig_save_path):
        '''

        :return:
        '''
        l.info("[*] start null pointer dereference detection for {} of {} in {}".format(
            to_detect_func_name, self.cveid, to_detect_bin))
        if not self._load_state_cache():
            raise StateFileNotExitsException(self.state_file)
        # self.print_constraints()
        t2 = datetime.now()
        is_vulnerable = self._null_pointer_test_and_sig_generation(to_detect_bin, to_detect_func_name, sig_save_path)
        t3 = datetime.now()
        l.debug("[*] Null pointer detection dereference takes {} microseconds".format((t3 - t2).microseconds))
        return is_vulnerable


def pretty_print_sig(sig):
    for x in sig:
        print(x[0], hex(x[1]))


def PatchDetection(CVE, target_bin, vul_func_name, supplementary_feature=True, force_new=False,
                   to_detect_func_name = None):
    '''

    '''
    if to_detect_func_name is None:
        to_detect_func_name = vul_func_name

    ttrace_file = get_target_binary_trace_file_path(cve_id=CVE, target_binary=target_bin, function_name=to_detect_func_name)
    vul_flag_file = get_target_cve_flag(cve_id=CVE, target_binary=target_bin,
                                        function_name=to_detect_func_name)  #
    '''
    '''
    if os.path.exists(vul_flag_file) and not force_new:
        return -1

    if not os.path.exists(ttrace_file) or force_new:
        sp = SymExePath(CVEid=CVE, func_name=vul_func_name)
        if sp.sig_gen(target_bin, to_detect_func_name=to_detect_func_name,
                      sig_save_path = ttrace_file):  #
            if not os.path.exists(vul_flag_file):
                os.mknod(vul_flag_file)
            return -1

    try:
        sig = "O1" #
        l.info("[*] signature optimization {}".format(sig))
        patch_trace = get_cve_patch_sig_file_path(CVE, vul_func_name, OPT=sig)
        vul_trace = get_cve_vul_sig_file_path(CVE, vul_func_name, OPT=sig)
        ptrace = json.load(open(patch_trace, 'r'))
        vtrace = json.load(open(vul_trace, 'r'))
    except:
        l.error("signature file of {} loaded failed".format(CVE))
        raise FileNotFoundError()

    ttrace = json.load(open(ttrace_file, 'r'))

    t_p = longest_common_subsequence(ptrace, ttrace, element_equal)
    t_v = longest_common_subsequence(ttrace, vtrace, element_equal)
    p_v = longest_common_subsequence(ptrace, vtrace, element_equal)
    Np = len(ptrace)
    Nv = len(vtrace)
    Nt = len(ttrace)
    factor1 = (abs(Nt - Nv) + 1) / (abs(Nt - Np) + 1) #
    factor2 = (t_p + 1) / (t_v + 1) #
    factor3 = (abs(t_p - p_v) + 1) / (abs(t_v - p_v) + 1) #
    p1 = math.tanh(math.log2(factor1))
    p2 = math.tanh(math.log2(factor2))
    p3 = math.tanh(math.log2(factor3))
    prob_patched = p1*0.2 + p2*0.8
    if supplementary_feature:
        supplementary_feature_file = ttrace_file + ".others"
        vul_supple_feature_file = vul_trace + ".others"
        patch_supple_feature_file = patch_trace + ".others"
        try:
            target_sup_feature = json.load(open(supplementary_feature_file, 'r'))
            vul_sup_feature = json.load(open(vul_supple_feature_file, 'r'))
            patch_supple_feature = json.load(open(patch_supple_feature_file, 'r'))
            sup_t_v = supplementary_feature_sim(target_sup_feature, vul_sup_feature)
            sup_t_p = supplementary_feature_sim(target_sup_feature, patch_supple_feature)
            if sup_t_v == 0:
                prob_patched_sup = 1
            else:
                prob_patched_sup = math.tanh(math.log2(sup_t_p / sup_t_v + 0.00000000001))
            l.debug("[>] mem sim:{:f}, supp sim:{:f}".format(prob_patched, prob_patched_sup))
            prob_patched = prob_patched * 0.9 + prob_patched_sup * 0.1
        except FileNotFoundError as e:
            l.error("Supplementary Feature: file not found {}".format(e.filename))
    return prob_patched


def supplementary_feature_sim(supp_dic1: dict, supp_dic2: dict):
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

def input_gen(cveid, patched_bin, func_name, check_addr, patch_addr, force_generation = False):
    cve_entry = [cveid, patched_bin, func_name, str(check_addr), str(patch_addr)]
    l.debug("[*] Gen Input for {}".format(",".join(cve_entry)))
    patched_bin = os.path.join(rootdir, patched_bin)
    p_exe = SymExePath(CVEid=cveid, func_name=func_name)
    try:
        p_exe.generate_vul_trigger_input_by_patch(patched_bin, check_addr, patch_addr, forced=force_generation)
    except Exception as e:
        l.error(traceback.format_exc())

def generate_cve_sig(cveid, vul_bin, patched_bin, func_name, force_generation=False):
    '''
    PoC input Generation
    With PoC input fed, execute function and record semantic information.
    :param force_generation: ignore the cache file
    :return :
    '''
    l.info(
        "\n[*] Run for {},{},{},{}".format(cveid, vul_bin, patched_bin, func_name))

    p_exe = SymExePath(CVEid=cveid, func_name=func_name)
    patched_signature_saved_path = get_cve_patch_sig_file_path(cveid, func_name)
    vul_signature_saved_path = get_cve_vul_sig_file_path(cveid, func_name)
    try:

        if force_generation or not os.path.exists(patched_signature_saved_path):
            p_flag = p_exe.sig_gen(patched_bin,func_name, patched_signature_saved_path)
        if force_generation or not os.path.exists(vul_signature_saved_path):
            p_exe.sig_gen(vul_bin, func_name, vul_signature_saved_path)
    except Exception as e:
        l.error("[-] Generation Error: {},{},{},{}".format(cveid, vul_bin, patched_bin, func_name))
        l.error(traceback.format_exc())
        return False
    return True
if __name__ == '__main__':
    pass
