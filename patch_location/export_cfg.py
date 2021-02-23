#!/usr/bin/env python
# coding=utf-8

'''
IDA Python script for exporting function CFG

CFG: dic:
key:nodes: {'0x12345':[mov eax, ebx; push rbp]}
key:edges: {'0x12345':[0x12356, 0x12367]}
CFG = {"nodes":{}, "edges":{}}
'''

from idc import *
from idautils import *
from idaapi import *
from ida_funcs import *
import json,os
import ida_pro
import ida_auto

def wait_for_analysis_to_finish():
    '''
    等待ida将二进制文件分析完毕再执行其他操作
    :return:
    '''
    ida_auto.auto_wait()

wait_for_analysis_to_finish()


class ExportCFG():
    def __init__(self):
        '''
        key:nodes: {'0x12345':[mov eax, ebx; push rbp]}
        key:edges: {'0x12345':[0x12356, 0x12367]}
        '''
        self._CFG = {"nodes":{}, "edges":{}, "boundary":{}, "jmp_instruction":{}}

    def get_cfg_of(self, func_name, save_path):
        '''
        save the cfg of function
        '''
        func = self.get_func_by_name(func_name)
        if func is None:
            raise Exception("{} is not founded.".format(func_name))
            
        flowchart = FlowChart(func)
        for i in range(flowchart.size):
            bb = flowchart[i]
            self._CFG['edges'][bb.start_ea] = [b.start_ea for b in bb.succs()]
            self._CFG['nodes'][bb.start_ea] = list(self.get_block_asm(func, bb))
            self._CFG['jmp_instruction'][bb.start_ea] = GetDisasm(prev_head(bb.end_ea, 1))
            self._CFG['boundary'][bb.start_ea] = bb.end_ea

        json.dump(self._CFG, open(save_path, 'w'))


    def get_func_by_name(self, func_name):

        for func_start_addr in Functions():
            name = get_func_name(func_start_addr)
            if name == func_name:
                return get_func(func_start_addr)

    def normalize_instruction(self, ea):
        '''
        对指令中的寄存器，常量，内存进行正则化
        保留cmp，test指令中的常量！！！
        '''
        inst_t = DecodeInstruction(ea)
        operands = inst_t.ops
        mnem = inst_t.get_canon_mnem()

        KEEP_CONST = False

        if mnem in ['cmp', 'test', 'lea']:
            KEEP_CONST = True

        ops = [mnem]
        '''
        o_void     =  0, ///< No Operand.
          o_reg      =  1, ///< General Register (al,ax,es,ds...).
          o_mem      =  2, ///< Direct Memory Reference  (DATA).
          o_phrase   =  3, ///< Memory Ref [Base Reg + Index Reg].
          o_displ    =  4, ///< Memory Reg [Base Reg + Index Reg + Displacement].
          o_imm      =  5, ///< Immediate Value.
          o_far      =  6, ///< Immediate Far Address  (CODE).
          o_near     =  7, ///< Immediate Near Address (CODE).
          o_idpspec0 =  8, ///< processor specific type.
          o_idpspec1 =  9, ///< processor specific type.
          o_idpspec2 = 10, ///< processor specific type.
          o_idpspec3 = 11, ///< processor specific type.
          o_idpspec4 = 12, ///< processor specific type.
          o_idpspec5 = 13; ///< processor specific type.
        '''
        for op in operands:
            if op.type == 0:
                continue
            if op.type == 1:
                ops.append("REG")
            elif op.type >= 2 and op.type <=4:
                if op.type == 4 and KEEP_CONST and op.addr >> 31 == 0:
                    ops.append(str(op.addr))
                else:
                    ops.append("MEMACC")
            elif op.type == 5:
                if KEEP_CONST:
                    ops.append(str(op.value))
                else:
                    ops.append('CONSTANT')
            elif op.type == 6 or op.type == 7:
                ops.append("ADDR")
            else:
                ops.append("PROCESS_SPECIFIC")

        return " ".join(ops)

    def get_block_asm(self, func, bb):

        endEA = bb.end_ea
        it_code = func_item_iterator_t(func, bb.start_ea)
        ea = it_code.current()
        while (ea < endEA):
            yield self.normalize_instruction(ea)
            # see if arrive end of the blocks
            if (not it_code.next_code()):
                break
            ea = it_code.current()


if __name__ == "__main__":
    if len(idc.ARGV)<3:
        os.write(1,b'Usage: idat -A -S"{} function_name file_save_cfg" binary_or_idb'.format(os.path.abspath(__file__)))
        ida_pro.qexit(0)
    func_name = idc.ARGV[1]
    path_to_save_cfg = idc.ARGV[2]
    e = ExportCFG()
    e.get_cfg_of(func_name, path_to_save_cfg)
    ida_pro.qexit(0)
