# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     PoC_generation
   Description :   Try to take each changed block as check block, and the most changed block in the
                    successors of check block as guard block.
   Author :
   date：          2021/6/8
-------------------------------------------------
   Change Activity:
                   2021/6/8:
-------------------------------------------------
"""

import logging
import time
import os
import json

from running_setting import ida, TMP_DIR
from patch_detection import Executor
from patch_localization import BlockDiffing, CFGGenerator
from utils import get_PoC_file_path, get_cve_patch_sig_file_path, get_cve_vul_sig_file_path, load_json_data
import angr
from tqdm import tqdm
from datetime import datetime

log = logging.getLogger("PoC_generation")
from utils import LOG_LEVEL
log.setLevel(LOG_LEVEL)


class GeneratePoC:
    # Given two versions of binaries (one is vulnerable version, the other is patched version),
    # this class generates a PoC (function  input) to distinguish different binary version.
    def __init__(self, cveid: str, vul_bin: str, patched_bin: str, function_name: str,
                 new_cfg=False, new_poc=False):
        '''
        :param cveid: e.g., CVE-2014-0160. It is for naming PoC file.
        :param vul_bin: the path to vulnerable version binary.
        :param patched_bin: the path to patched version binary.
        :param function_name: the vulnerable function name.
        :param new_cfg: whether to generate new cfg.
        :param new_poc: whether to generate new poc.
        '''
        log.debug("={},{},{},{}".format(cveid, vul_bin, patched_bin, function_name))
        self._cve_id = cveid
        self._vul_bin = vul_bin
        self._patched_bin = patched_bin
        self._function_name = function_name
        self._new_cfg = new_cfg
        self._new_poc = new_poc
        self._patch_bin_project = None
        self._cg = CFGGenerator(ida)
        self._block_diffing = BlockDiffing()
        self._executor = Executor(cveid, function_name)

    def run(self, new_poc=None):

        self._new_poc = new_poc if new_poc is not None else self._new_poc

        poc_file_path = get_PoC_file_path(self._cve_id, self._function_name)
        if not self._new_poc and os.path.exists(poc_file_path):
            return

        if not os.path.exists(self._patched_bin):
            log.error('file {} not exists'.format(self._patched_bin))
            return

        self._patch_bin_project = angr.Project(self._patched_bin, auto_load_libs="False")

        log.info(f"MFI of {self._cve_id} Generating...")
        try:
            self._pick_patch_block()
        except FileNotFoundError as e:
            log.error("CFG extraction failed. Function name not found.")

    def _get_input_path(self, check, guard):
        tmp_path = '{}/{}_{}_{}_{}.input'.format(TMP_DIR, self._cve_id, self._function_name
                                                 , hex(check), hex(guard))
        return tmp_path

    def _pick_patch_block(self, try_times=20):
        '''
        :param try_times:  the maximum attempt time to generate function input with different patch blocks
        '''
        # the all pairs of (check block, guard block) by diffing binaries.
        cfg_v = self._cg.run(self._vul_bin, self._function_name, force_generation=self._new_cfg)
        cfg_p = self._cg.run(self._patched_bin, self._function_name, force_generation=self._new_cfg)

        num_pairs = 0
        num_inputs = 0

        pair_and_scores = []
        max_score = 0
        ta = datetime.now()
        changed_blocks = self._block_diffing.get_all_changed_pairs(cfg_v, cfg_p)
        tb = datetime.now()
        log.debug('[T] Time of Patch Block Identification: {:f}'.format((tb-ta).total_seconds()))
        t_poc = datetime.now()
        PoC_candidate_selection_times = []
        for (check, guard) in changed_blocks:
            num_pairs += 1
            log.debug("Make a(n) {}th attempt with check {} and guard {}".format(num_pairs, hex(check), hex(guard)))
            if self._input_generation_for_a_pair(check, guard):
                num_inputs += 1
                t1 = datetime.now()
                score = self._scores_for_input(check, guard)
                t2 = datetime.now()
                log.debug('[T] PoC Candidate Selection Time (for one score calculation): {:f}'.format((t2-t1).total_seconds()))
                PoC_candidate_selection_times.append((t2-t1).total_seconds())
                max_score = max(max_score, score)
                pair_and_scores.append((score, (check, guard)))
                log.debug("Function input generation success with score {:f}!".format(score))
                # early stop
                if max_score > 0.5:
                    break
                if max_score > 0 and num_pairs >= try_times:
                    break

        log.debug("{} {} has {} changed blocks, in which {} generate input".format(
            self._cve_id, self._function_name, num_pairs, num_inputs))

        if num_inputs == 0:
            return

        pair_and_scores.sort(reverse=True)
        log.debug(pair_and_scores)
        max_score, (check, guard) = pair_and_scores[0]
        if len(pair_and_scores) > 0 and max_score > 0:
            log.debug('[T] Time of OFFLINE PHASE (consists of Patch Block Selection, Input Solving, PoC Candidate Selection'
                      'CVE Signature Generation): {:f}'.format((datetime.now()-t_poc).total_seconds()))
            self._save_PoC(check, guard)
        else:
            log.warning("PoC generation failed.")

    def _save_PoC(self, check, guard):
        # copy temporary PoC file to specific dir
        tmp_poc_file = self._get_input_path(check, guard)
        poc_file_path = get_PoC_file_path(self._cve_id, self._function_name)
        os.system("cp {} {}".format(tmp_poc_file, poc_file_path))
        log.debug("PoC file {} saved in {}".format(tmp_poc_file, poc_file_path))

        tmp_sig_patch = tmp_poc_file + "patch"
        sig_patch_path = get_cve_patch_sig_file_path(self._cve_id, self._function_name)
        os.system("cp {} {}".format(tmp_sig_patch, sig_patch_path))
        os.system("cp {} {}".format(tmp_sig_patch + ".others", sig_patch_path + ".others"))
        os.system("cp {} {}".format(tmp_sig_patch + ".taint_seqs", sig_patch_path + ".taint_seqs"))
        log.debug("patch signature {} saved in {}".format(tmp_sig_patch, sig_patch_path))

        tmp_sig_vul = tmp_poc_file + "vul"
        sig_vul_path = get_cve_vul_sig_file_path(self._cve_id, self._function_name)
        os.system('cp {} {}'.format(tmp_sig_vul, sig_vul_path))
        os.system('cp {} {}'.format(tmp_sig_vul + ".others", sig_vul_path + ".others"))
        os.system('cp {} {}'.format(tmp_sig_vul + ".taint_seqs", sig_vul_path + ".taint_seqs"))
        log.debug('vul signature {} saved in {}'.format(tmp_sig_vul, sig_vul_path))

    def _input_generation_for_a_pair(self, check, guard):
        # try to generate function input with a pair of check-guard block.
        tmp_input_path = self._get_input_path(check, guard)
        if os.path.exists(tmp_input_path) and not self._new_poc:
            return True
        return self._executor.input_generation(self._patched_bin, check, guard, forced=True,
                                               save=tmp_input_path,
                                               patch_bin_project=self._patch_bin_project)
    def _scores_for_input(self, check, guard):
        # score a function input by how different is in vulnerable and patch function executions.
        # score ranges from 0 to 1.

        input_cache = self._get_input_path(check, guard)

        # signature file is named based on input_cache file
        if self._new_poc or not os.path.exists(input_cache + "vul"):
            if self._executor.sig_gen(self._vul_bin, self._function_name,
                                      sig_save_path=input_cache + "vul",
                                      poc_file=input_cache, NPD=False):
                return 1.0

        if self._new_poc or not os.path.exists(input_cache + 'patch'):
            self._executor.sig_gen(self._patched_bin, self._function_name,
                                   sig_save_path=input_cache + "patch",
                                   poc_file=input_cache, NPD=False)

        # The more different features, the higher scores
        def lcs(a, b, element_equal):
            m = [[0 for j in range(len(b) + 1)] for i in range(len(a) + 1)]
            for ai, aa in enumerate(a):
                for bi, bb in enumerate(b):
                    if element_equal(aa, bb):
                        m[ai + 1][bi + 1] = m[ai][bi] + 1
                    else:
                        m[ai + 1][bi + 1] = max(m[ai + 1][bi], m[ai][bi + 1])
            return m[len(a)][len(b)]

        ptrace = load_json_data(input_cache + 'patch')
        vtrace = load_json_data(input_cache + 'vul')
        trace_lcs = lcs(ptrace, vtrace, lambda x, y: x[0] == y[0] and x[1] == y[1])
        max_len = max(len(ptrace), len(vtrace))
        trace_score = 0 if max_len==0 else (max_len - trace_lcs) * 1.0 / max_len

        p_other = load_json_data(input_cache + 'patch.others')
        v_other = load_json_data(input_cache + 'vul.others')
        flat_p_other = [y for x in p_other.values() for y in x]
        flat_v_other = [y for x in v_other.values() for y in x]
        other_lcs = lcs(flat_p_other, flat_v_other, lambda x, y: x == y)
        max_len2 = max(len(flat_v_other), len(flat_v_other))
        other_score = ((max_len2 - other_lcs) * 1.0) / max_len2

        p_taint = load_json_data(input_cache + 'patch.taint_seqs')
        v_taint = load_json_data(input_cache + 'vul.taint_seqs')
        taint_lcs = lcs(p_taint, v_taint, lambda x, y: x == y)
        max_len3 = max(len(p_taint), len(v_taint))
        if max_len3 == 0:
            taint_score = 0
        else:
            taint_score = ((max_len3 - taint_lcs) * 1.0)/max_len3
        log.debug("Mem Score: {:f}, Other Score: {:f}, Taint Score: {:f}".
                  format(trace_score, other_score, taint_score))
        score = (trace_score + other_score) / 2
        return score


def ttest():
    logging.getLogger("SolvePoC").setLevel(logging.DEBUG)
    logging.getLogger("LoadPoC").setLevel(logging.DEBUG)
    logging.getLogger("RuntimeRecorder").setLevel(logging.DEBUG)
    logging.getLogger("Memory_Access").setLevel(logging.DEBUG)
    logging.getLogger("patch_detection").setLevel(logging.DEBUG)
    # cve_info_with_location = \
    #     'CVE-2014-3470,/home/angr/PatchDiff/binaries/openssl/O0/openssl-1.0.1g,/home/angr/PatchDiff/binaries/openssl/O0/openssl-1.0.1h,ssl3_send_client_key_exchange'
    cve_info_with_location \
        = 'CVE-2014-8176,/home/angr/PatchDiff/binaries/openssl/O0/openssl-1.0.1g,/home/angr/PatchDiff/binaries/openssl/O0/openssl-1.0.1h,dtls1_clear_queues'
    cveid, vul_bin, patched_bin, func_name = cve_info_with_location.split(",")
    gp = GeneratePoC(cveid, vul_bin, patched_bin, func_name)
    gp.run(new_poc=True)


if __name__ == '__main__':
    ttest()
