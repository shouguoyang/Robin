# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     patch_localization.py
   Description :    given two versions of binary file(e.g. openssl 1.0.1a and openssl 1.0.1b)
                 and the patched function A, this script finds out the patched blocks in functionA
                 in openssl 1.0.1b.
   date：          2020/11/21
-------------------------------------------------
    Notice: put the export_cfg.py in the same directory with this file!
-------------------------------------------------
"""
import logging, argparse, os, sys, time
import csv
import json, math
import hashlib
from collections import defaultdict

PROJ_ROOT_DIR = os.path.dirname(os.path.abspath(__file__)) + '/../'
l = logging.getLogger("CFGDiffer")
l.setLevel(logging.INFO)


class BlockDiffing():
    def __init__(self):
        self._index_instruction_hash = \
            ['mov', 'push', 'sub', 'or', 'and', 'pop', 'sar', 'retn', 'shl', 'shr', 'inc', 'dec', 'add', 'lea', 'cmp',
             'test', 'jmp', 'call', 'REG', 'ADDR', 'MEMACC', 'CONSTANT', 'num']
        self._index_dic = {}
        for i in range(len(self._index_instruction_hash)):
            self._index_dic[self._index_instruction_hash[i]] = i
        # CFG = {"nodes":{}, "edges":{}}
        self._m = math.pow(math.e, 2)
        self._jmp_idx_block = -1

    def _reverse_cfg(self, cfg):
        edge = cfg['edges']
        res = defaultdict(list)
        for node in edge:
            for c in edge[node]:
                res[c].append(node)

        for node in cfg['nodes']:
            if node not in res:
                cfg['entry'] = node

        return res

    def _convert_key_to_int(self, cfg_dic):
        nodes_dic = {}
        for node_addr in cfg_dic['nodes']:
            nodes_dic[int(node_addr)] = cfg_dic['nodes'][node_addr]

        edges_dic = {}
        for node_addr in cfg_dic['edges']:
            if len(cfg_dic['edges'][node_addr]) == 0:
                cfg_dic['exit'] = int(node_addr)
            edges_dic[int(node_addr)] = cfg_dic['edges'][node_addr]

        jmp_ins_dic = {}
        for node_addr in cfg_dic['jmp_instruction']:
            jmp_ins_dic[int(node_addr)] = cfg_dic['jmp_instruction'][node_addr]

        cfg_dic['nodes'] = nodes_dic
        cfg_dic['edges'] = edges_dic
        cfg_dic['jmp_instruction'] = jmp_ins_dic

    def find_end_of_continuous_block(self, unmatched_blocks):
        # Given multiple basic blocks, find the largest continuous set of these basic blocks in the CFG, and return the deepest basic block among them
        if len(unmatched_blocks) == 1:
            return unmatched_blocks[0]

        # if self.cfg2['exit'] in unmatched_blocks:
        #     unmatched_blocks.remove(self.cfg2['exit'])

        if self.cfg2['entry'] in unmatched_blocks:
            unmatched_blocks.remove(self.cfg2['entry'])

        #  Use union-search set algorithm to mark continuous basic blocks and their depth
        find_union = [[] for i in range(len(unmatched_blocks))]
        for i, node in enumerate(unmatched_blocks):
            for j, node2 in enumerate(unmatched_blocks):
                if node2 == node:
                    continue
                if node2 in self.cfg2['edges'][node]:
                    find_union[i].append(j)

        node_depth = {}
        for node in unmatched_blocks:
            node_depth[node] = 0
        max_depth = 0

        def update_depth(current_index, visit):
            for child_node_idx in find_union[current_index]:
                if child_node_idx in visit:
                    continue
                node_depth[unmatched_blocks[child_node_idx]] = \
                    max(node_depth[unmatched_blocks[child_node_idx]],
                        node_depth[unmatched_blocks[current_index]] + 1)
                # l.debug("{} to {}".format(hex(unmatched_blocks[current_index]), hex(unmatched_blocks[child_node_idx])))
                visit.append(child_node_idx)
                update_depth(child_node_idx, visit)

        for i in range(len(unmatched_blocks)):
            update_depth(i, [])

        # end of mark
        depth_to_node = defaultdict(list)
        for node in node_depth:
            depth_to_node[node_depth[node]].append(node)
            max_depth = max(max_depth, node_depth[node])

        if len(depth_to_node[max_depth]) == 1:
            return depth_to_node[max_depth][0]

        # else:
        #     return max(depth_to_node[max_depth])
        else:
            simis = []
            if max_depth == 0:
                # If blocks are not adjacent to each other, the basic block with the largest address is returned.
                return max(unmatched_blocks)

            # Calculate the similarities between nodes that are at same depth degree in cfg2 and nodes in cfg1,
            # and take block with the minimum similarity
            for node in depth_to_node[max_depth]:
                node_sim = 0
                for target_node in self.cfg1['nodes']:
                    node_sim = max(node_sim, self.node_sim(node, target_node))
                simis.append(node_sim)
            # find the minimum similarity score
            li = sorted(zip(simis, depth_to_node[max_depth]), key=lambda x: x[0])
            return li[0][1]

    def get_all_changed_pairs(self, cfg1_file, cfg2_file):
        '''
        Compare and diff two cfg files.
        :return a list of tuple. tuple is formatted [(check_block, guard_block)]
        :param cfg1_file: vulnerable cfg
        :param cfg2_file: patch cfg
        '''
        with open(cfg1_file, 'r') as f:
            self.cfg1 = json.load(f)
        with open(cfg2_file, 'r') as f:
            self.cfg2 = json.load(f)
        l.debug("[P] patch function size:{}".format(len(list(self.cfg2['nodes'].keys()))))
        self._convert_key_to_int(self.cfg1)
        self._convert_key_to_int(self.cfg2)
        self.cfg_hash(self.cfg1)
        self.cfg_hash(self.cfg2)
        self._parent_nodes1 = self._reverse_cfg(self.cfg1)
        self._parent_nodes2 = self._reverse_cfg(self.cfg2)
        # calcuates similarity with hash values
        mismatched_blocks = self.match_block(self.cfg1, self.cfg2)
        l.debug("[*] mismatched blocks {}".format([hex(x) for x in mismatched_blocks]))
        if len(mismatched_blocks) == 0:
            l.error("Not found mismatched block")
            return [(0, 0)]

        # if len(mismatched_blocks) == 1:
        #     # If patch changes the comparison operation such as a>=b -> a>b,
        #     # there will be only one block changed.
        #     # the changed block is regarded as check block, and arbitrary child block as guard block.
        #     check_block = mismatched_blocks[0]
        #     patch_block = self.cfg2['edges'][check_block][0]
        #     return [(check_block, patch_block)]

        for check_block in mismatched_blocks:
            for child in self.cfg2['edges'][check_block]:
                yield (check_block, child)


    def diff(self, cfg1_file, cfg2_file):
        '''
        Compare and diff two cfg files.
        :param cfg1_file: vulnerable cfg
        :param cfg2_file: patch cfg
        :return: (check_block, patch_block)
        '''
        with open(cfg1_file, 'r') as f:
            self.cfg1 = json.load(f)
        with open(cfg2_file, 'r') as f:
            self.cfg2 = json.load(f)
        l.debug("[P] patch function size:{}".format(len(list(self.cfg2['nodes'].keys()))))
        self._convert_key_to_int(self.cfg1)
        self._convert_key_to_int(self.cfg2)
        self.cfg_hash(self.cfg1)
        self.cfg_hash(self.cfg2)
        self._parent_nodes1 = self._reverse_cfg(self.cfg1)
        self._parent_nodes2 = self._reverse_cfg(self.cfg2)
        # calcuates similarity with hash values
        mismatched_blocks = self.match_block(self.cfg1, self.cfg2)
        l.debug("[*] mismatched blocks {}".format([hex(x) for x in mismatched_blocks]))
        if len(mismatched_blocks) == 0:
            l.error("Not found mismatched block")
            return 0, 0

        if len(mismatched_blocks) == 1:
            # If patch changes the comparison operation such as a>=b -> a>b,
            # there will be only one block changed.
            # the changed block is regarded as check block, and arbitrary child block as guard block.
            check_block = mismatched_blocks[0]
            patch_block = self.cfg2['edges'][check_block][0]
            return check_block, patch_block

        check_block, patch_block = self.find_new_check_patch(mismatched_blocks)
        if check_block != 0:
            return check_block, patch_block

        patch_block_addr = self.find_end_of_continuous_block(mismatched_blocks)
        # If the algorithm thinks the entry block is the patched block, then return any successive block of it.
        if patch_block_addr == self.cfg2['entry'] and len(self.cfg2['edges'][patch_block_addr]) > 0:
            patch_block_addr = self.cfg2['edges'][patch_block_addr][0]

        error_block_addr = self._error_handle_block(patch_block_addr)

        patch_size = len(self.cfg2['nodes'][patch_block_addr])
        if error_block_addr is not None:
            patch_size += len(self.cfg2['nodes'][error_block_addr])

        l.info("Patch Size is {}".format(patch_size))

        return patch_block_addr, error_block_addr

    def _error_handle_block(self, patch_block_addr):
        '''
        :param patch_block_addr:
        '''
        if patch_block_addr not in self.cfg2['jmp_instruction']:
            return None
        jmp_instruction = self.cfg2['jmp_instruction'][patch_block_addr]
        jmp_target_s = jmp_instruction.split(" ")[-1]
        jmp_target_s = jmp_target_s.replace("loc_", "")
        # jmp_instruction='ja      trunc' ,
        jmp_target = 0
        successors = self.cfg2['edges'][patch_block_addr]
        if len(successors) == 0:  # patch block is the return block
            return patch_block_addr
        try:
            jmp_target = int(jmp_target_s, 16)
        except ValueError as e:
            l.error("[-] Instruction {} jmp target is not a number".format(jmp_instruction))
            jmp_target = 0

        null_branch = successors[0]
        if 'jnz' in jmp_instruction:
            if successors[0] == jmp_target:
                null_branch = successors[1]
        elif 'jz' in jmp_instruction:
            null_branch = jmp_target

        if 'jmp' in self.cfg2['jmp_instruction'][null_branch]:
            return null_branch

        return None

    def find_new_check_patch(self, mismatched_blocks):
        '''
        :param mismatched_blocks: all changed blocks
        :return: (check_block, patch_block)
        '''
        for parent in mismatched_blocks:
            successors = self.cfg2['edges'][parent]
            if len(successors) == 2:
                child1 = successors[0]
                child2 = successors[1]
                if child1 in mismatched_blocks and child2 in mismatched_blocks:
                    jmp_instruction = self.cfg2['jmp_instruction'][parent]
                    jmp_target_s = jmp_instruction.split(" ")[-1]
                    jmp_target_s = jmp_target_s.replace("loc_", "")
                    try:
                        jmp_target = int(jmp_target_s, 16)
                    except ValueError as e:
                        l.error("[-] Instruction {} jmp target is not a number".format(jmp_instruction))
                        jmp_target = 0

                    if jmp_target in [child2, child1]:
                        #
                        if 'jnz' in jmp_instruction:
                            if child1 == jmp_target:
                                jmp_target = child2
                            else:
                                jmp_target = child1
                        else:
                            l.debug("[*] jmp instruction: {}".format(jmp_instruction))
                        l.debug("[+] find error catch block {}".format(hex(jmp_target)))
                        return parent, jmp_target
        return 0, 0

    def match_block(self, cfg1, cfg2):
        '''
        Put all the nodes with the same hash value in cfg1 and cfg2 into one bucket, if the nodes in the bucket are even,
        it means that they match, otherwise return the nodes in cfg2 in the bucket
        '''
        node_hash1 = cfg1['same_hash_nodes'].copy()
        node_hash2 = cfg2['same_hash_nodes'].copy()
        nodes_candidate = []
        nodes_candidate_score = []
        for hash2 in node_hash2:
            if hash2 in node_hash1:
                if len(node_hash2[hash2]) == len(node_hash1[hash2]):
                    continue
                else:
                    for n in self._match_mutiple_blocks(node_hash1[hash2], node_hash2[hash2]):
                        if n is not None and n not in nodes_candidate:
                            nodes_candidate.append(n)
                            # l.debug("Added multiple block {}".format(hex(n)))
            else:
                nodes_candidate += node_hash2[hash2]
                nodes_candidate_score += [0 for i in range(len(node_hash2[hash2]))]

        return nodes_candidate

    def node_sim(self, node_addr_in_cfg2, target_addr_in_cfg1):
        '''
        To further calculate the similarity between two blocks that hold the same hash value
        '''

        def parent_or_child_hashes(node_addr, parent_or_child_dic, hash_dic):
            p = set()
            for pnode in parent_or_child_dic[int(node_addr)]:
                p.add(hash_dic[pnode])
            return p

        t_parent_hashes = parent_or_child_hashes(target_addr_in_cfg1, self._parent_nodes1, self.cfg1['node_hash'])
        n_parent_hashes = parent_or_child_hashes(node_addr_in_cfg2, self._parent_nodes2, self.cfg2['node_hash'])
        p_sim = (len(t_parent_hashes & n_parent_hashes) + 0.1) / (
                len(t_parent_hashes | n_parent_hashes) + 0.1)  # jaccard similarity
        t_child_hashes = parent_or_child_hashes(target_addr_in_cfg1, self.cfg1['edges'], self.cfg1['node_hash'])
        n_child_hashes = parent_or_child_hashes(node_addr_in_cfg2, self.cfg2['edges'], self.cfg2['node_hash'])
        c_sim = (len(t_child_hashes & n_child_hashes) + 0.1) / (
                len(t_child_hashes | n_child_hashes) + 0.1)  # jaccard similarity

        return (p_sim + c_sim) / 2

    @staticmethod
    def longest_common_subsequence(a, b, element_equal):
        m = [[0 for j in range(len(b) + 1)] for i in range(len(a) + 1)]
        for ai, aa in enumerate(a):
            for bi, bb in enumerate(b):
                if element_equal(aa, bb):
                    m[ai + 1][bi + 1] = m[ai][bi] + 1
                else:
                    m[ai + 1][bi + 1] = max(m[ai + 1][bi], m[ai][bi + 1])
        return m[len(a)][len(b)]

    def node_sim_l2(self, node_addr_in_cfg2, target_addr_in_cfg1):
        '''
        To further calculate the similarity between two blocks that hold the same hash value
        '''

        def parent_or_child_hashes(node_addr, parent_or_child_dic, hash_dic):
            p = set()
            for pnode in parent_or_child_dic[int(node_addr)]:
                p.add(hash_dic[pnode])
            return p

        # target_parent_nodes = parent_or_child_hashes(target_addr_in_cfg1, self._parent_nodes1, )
        # detect_parent_nodes = parent_or_child_hashes(node_addr_in_cfg2, self._parent_nodes2, self.cfg2['nodes'])

        # Parent node similarity Use the longest common child sequence
        max_sim = 0
        target_parents = self._parent_nodes1[target_addr_in_cfg1]
        node_parents = self._parent_nodes2[node_addr_in_cfg2]

        for target_parent in target_parents:
            for detect_parent in node_parents:
                target_parent_insts = self.cfg1['nodes'][target_parent]
                detect_parent_insts = self.cfg2['nodes'][detect_parent]
                lcs_len = self.longest_common_subsequence(target_parent_insts, detect_parent_insts, lambda a, b: a == b)
                lcs_sim = lcs_len / min(len(target_parent_insts), len(detect_parent_insts)) - (
                    abs(lcs_len - len(target_parent_insts))) / len(target_parent_insts)
                max_sim = max(max_sim, lcs_sim)
        return max_sim



    def _match_mutiple_blocks(self, nodeaddrs_in_cfg1, nodeaddrs_in_cfg2):
        '''
        If many blocks have the same hash value, we use context information to further distinguish them
        :param nodeaddrs_in_cfg1: list
        :param nodeaddrs_in_cfg2: list
        CVE-2015-0288,binaries/openssl/O0/openssl-1.0.1l,binaries/openssl/O0/openssl-1.0.1m,X509_to_X509_REQ
        '''
        unmatched_block_in_cfg2 = set()
        if len(nodeaddrs_in_cfg2) > len(nodeaddrs_in_cfg1):
            # Pairwise match, return the rest
            block_pair_similarity = []  # pairwise similarity between nodeaddrs_in_cfg1 and nodeaddrs_in_cfg2
            for node_addr in nodeaddrs_in_cfg2:
                for target_addr in nodeaddrs_in_cfg1:
                    node_sim = self.node_sim_l2(node_addr, target_addr)
                    block_pair_similarity.append((node_sim, node_addr, target_addr))
            node_in_cfg1_matched = []
            node_in_cfg2_matched = []
            sorted_pairs = sorted(block_pair_similarity, key=lambda x: x[0], reverse=True)
            for s, n2, n1 in sorted_pairs:
                if n1 not in node_in_cfg1_matched and n2 not in node_in_cfg2_matched:
                    node_in_cfg1_matched.append(n1)
                    node_in_cfg2_matched.append(n2)
            for s, n2, n1 in reversed(sorted_pairs):
                if n2 not in node_in_cfg2_matched:
                    unmatched_block_in_cfg2.add(n2)

        return unmatched_block_in_cfg2

    def cfg_hash(self, cfg):
        '''
        hash every block in cfg
        '''
        cfg['node_hash'] = {}
        cfg['same_hash_nodes'] = defaultdict(list)
        nodes_dic = cfg['nodes']
        for block_addr in nodes_dic:
            block = nodes_dic[block_addr]
            hash = self.block_hash(block)
            cfg['node_hash'][block_addr] = hash
            cfg['same_hash_nodes'][hash].append(block_addr)

    def block_hash(self, block):
        '''
        hash a block
        :param block: list: instructions in block
        :return: self._index_instruction_hash
        jmp includes: jz jnz ja ...
        '''
        m = hashlib.md5()
        m.update("".join(block).encode("utf-8"))
        return m.hexdigest()



class CFGGenerator():
    def __init__(self, ida):
        self._ida = ida
        if not self._ida.endswith('.exe'):  # osx and linux
            self._ida = "TVHEADLESS=1 " + self._ida
        self._script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "export_cfg.py")

    def clear_corrupt_ida_database(self, binary_path):
        # remove files ending with .id0 .id1 .id2 after the ida crashing
        cmd = "rm {}.id0 {}.id1 {}.id2 >/dev/null 2>&1".format(binary_path, binary_path, binary_path)
        os.system(cmd)

    def run(self, binary, function_name, force_generation=False):

        if not os.path.isabs(binary):
            binary = os.path.join(PROJ_ROOT_DIR, binary)

        def is64bit(bin):
            ret = os.popen('file {}'.format(bin))
            if 'x86-64' in ret.read():
                ret.close()
                return True

            ret.close()
            return False

        ida = self._ida
        if is64bit(binary):
            ida = self._ida + "64"

        self._binary = binary
        self._function_name = function_name  # IDA will replace all '.' with '_' in function names
        save_cfg_path = self._binary + "_" + self._function_name + ".idacfg"
        if not force_generation and os.path.exists(save_cfg_path):
            return save_cfg_path

        self.clear_corrupt_ida_database(self._binary)

        cmd = '{}  -Lidaerror.log -A -S"{} {} {}" {}'.format(ida, self._script,
                                                             self._function_name, save_cfg_path, self._binary)
        l.debug("[*] cfg dump: {}".format(cmd))
        res = os.system(cmd)
        if res != 0:
            raise FileNotFoundError("'{}' returns {}".format(cmd, res))
        return save_cfg_path


def diff_main(binary1, binary2, function_name: str, force_new=False, ida="/home/angr/idapro-7.5/idat"):
    '''
    '''

    # function_name = function_name.replace('.', '_')

    cg = CFGGenerator(ida)
    cfg1 = cg.run(binary1, function_name, force_new)
    cfg2 = cg.run(binary2, function_name, force_new)
    bd = BlockDiffing()
    node_addrs = bd.diff(cfg1, cfg2)
    return node_addrs



def one_test():
    e = "CVE-2014-0221,/home/angr/PatchDiff/binaries/openssl/O0/openssl-1.0.1g,/home/angr/PatchDiff/binaries/openssl/O0/openssl-1.0.1h,dtls1_get_message_fragment"

    s = e.split(',')
    vul_bin = os.path.join(PROJ_ROOT_DIR, s[1])
    patch_bin = os.path.join(PROJ_ROOT_DIR, s[2])
    function_name = s[3]
    x = diff_main(vul_bin,
                  patch_bin,
                  function_name=function_name, force_new=False)
    print(hex(x[0]))
    if x[1]:
        print(hex(x[1]))
    exit(0)


if __name__ == '__main__':
    l.addHandler(logging.StreamHandler())
    l.addHandler(logging.FileHandler("patch_diff_by_block.log"))
    l.info("=================== {} ===================\n\t".format(time.strftime("%Y-%m-%d %H:%M", time.localtime())))
    # patch_test()
    one_test()
    ap = argparse.ArgumentParser(__file__)
    ap.add_argument("--ida", type=str, default="/home/angr/idapro-7.5/idat", help="the path to ida")
    ap.add_argument("binary1", type=str, help="the first version of binary")
    ap.add_argument("binary2", type=str, help="the sencond version of binary")
    ap.add_argument("function_name", type=str, help="the patched function name")
    ap.add_argument("--diff", action='store_true', default=True, help='Try to diff function for getting patched block')

    args = ap.parse_args()

    binary1 = args.binary1
    binary2 = args.binary2
    function_name = args.function_name

    if not os.path.exists(binary1) or not os.path.exists(binary1):
        l.error("binary file not exists")
        exit(1)
    ida = args.ida
    l.debug("{} {} {}".format(binary1, binary2, function_name))
    cg = CFGGenerator(ida)

    cfg1 = cg.run(binary1, function_name)
    cfg2 = cg.run(binary2, function_name)


    if args.diff:
        bd = BlockDiffing()
        check_addr, patch_block_addr = bd.diff(cfg1, cfg2)
        l.info("[+] {}:{}:{}:Diff Result {}".format(binary1, binary2, function_name, hex(check_addr)))
        print(hex(check_addr))
