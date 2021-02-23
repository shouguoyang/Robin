from __future__ import print_function
from argparse import ArgumentParser

from future.utils import viewitems, viewvalues

from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.expression.expression import *
from miasm.analysis.data_analysis import intra_block_flow_raw, inter_block_flow
from miasm.core.graph import DiGraph
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.analysis.data_flow import dead_simp
from future.utils import viewitems
from miasm.trackdata.data_analysis_ww_version0 import *

from miasm.trackdata.angr_recovery_cfg import cfg_recovery

import time
import sys
import re

def get_node_name(label, i, n):
    n_name = (label, i, n)
    return n_name

def intra_block_flow_symb(ir_arch, _, flow_graph, irblock, in_nodes, out_nodes):
    symbols_init = ir_arch.arch.regs.regs_init.copy()
    sb = SymbolicExecutionEngine(ir_arch, symbols_init)
    sb.eval_updt_irblock(irblock)

    out = sb.modified(mems=False)
    current_nodes = {}
    # Gen mem arg to mem node links
    for dst, src in out:
        src = sb.eval_expr(dst)
        for n in [dst, src]:

            all_mems = set()
            all_mems.update(get_expr_mem(n))

        for n in all_mems:
            node_n_w = get_node_name(irblock.loc_key, 0, n)
            if not n == src:
                continue
            o_r = n.ptr.get_r(mem_read=False, cst_read=True)
            for i, n_r in enumerate(o_r):
                if n_r in current_nodes:
                    node_n_r = current_nodes[n_r]
                else:
                    node_n_r = get_node_name(irblock.loc_key, i, n_r)
                if not n_r in in_nodes:
                    in_nodes[n_r] = node_n_r
                flow_graph.add_uniq_edge(node_n_r, node_n_w)

    # Gen data flow links
    for dst in out:
        src = sb.eval_expr(dst)
        nodes_r = src.get_r(mem_read=False, cst_read=True)
        nodes_w = set([dst])
        for n_r in nodes_r:
            if n_r in current_nodes:
                node_n_r = current_nodes[n_r]
            else:
                node_n_r = get_node_name(irblock.loc_key, 0, n_r)
            if not n_r in in_nodes:
                in_nodes[n_r] = node_n_r

            flow_graph.add_node(node_n_r)
            for n_w in nodes_w:
                node_n_w = get_node_name(irblock.loc_key, 1, n_w)
                out_nodes[n_w] = node_n_w

                flow_graph.add_node(node_n_w)
                flow_graph.add_uniq_edge(node_n_r, node_n_w)

def node2str(node):
    out = "%s,%s\\l\\\n%s" % node
    return out

def generate_src_arg(src_args_temp,src_arg):
        arg_name=[]
        #print(src_arg)
        for j in src_arg:
            i=j.name
            if(i[0]=='E'):
                i='R'+i[1:]
            if(i[1] in '89' and len(i)==3):
                i=i[:2]
            arg_name.append(i)
        arg_name=list(set(arg_name))
        arg_num=len(arg_name)
        if(arg_num==0):
            src=ExprOp('call_func_ret', src_args_temp)
        elif(arg_num==1):
            src=ExprOp('call_func_ret', src_args_temp,ExprId(arg_name[0], 64))
        elif(arg_num==2):
            src=ExprOp('call_func_ret', src_args_temp,ExprId(arg_name[0], 64),ExprId(arg_name[1], 64))
        elif(arg_num==3):
            src=ExprOp('call_func_ret', src_args_temp,ExprId(arg_name[0], 64),ExprId(arg_name[1], 64),ExprId(arg_name[2], 64))
        elif(arg_num==4):
            src=ExprOp('call_func_ret', src_args_temp,ExprId(arg_name[0], 64),ExprId(arg_name[1], 64),ExprId(arg_name[2], 64),ExprId(arg_name[3], 64))
        elif(arg_num==5):
            src=ExprOp('call_func_ret', src_args_temp,ExprId(arg_name[0], 64),ExprId(arg_name[1], 64),ExprId(arg_name[2], 64),ExprId(arg_name[3], 64),ExprId(arg_name[4], 64))
        elif(arg_num==6):
            src=ExprOp('call_func_ret', src_args_temp,ExprId(arg_name[0], 64),ExprId(arg_name[1], 64),ExprId(arg_name[2], 64),ExprId(arg_name[3], 64),ExprId(arg_name[4], 64),ExprId(arg_name[5], 64))
        #print(src)
        return src

def recovery_call(ircfg):
    #Cannot handle temporarily when the number of passed parameters is greater than 6
    for irblock in viewvalues(ircfg.blocks):
        for line_nb,assignblk in list(enumerate(irblock)):
            if(assignblk.instr.is_subcall()):
                for dst,src in viewitems(assignblk):
                    if(dst.name!="RAX"):
                        continue
                    #print(hex(assignblk.instr.offset))
                    #print(assignblk[dst])
                    src_args_temp=list(src.args)[0]
                    temp_src={}
                    temp_src_1=[]
                    temp_src_2=[]
                    temp_arg=['SI','DI','R8','R9','CX','DX']
                    if(line_nb!=0):
                        for cur_line_nb, assignblk1 in reversed(list(enumerate(irblock[:line_nb]))):
                            if(line_nb-cur_line_nb>15 and assignblk1.instr.is_subcall()):
                                break
                            #Indicates no parameters
                            is_break=False
                            if("MOV" in assignblk1.instr.name or "LEA" in assignblk1.instr.name):
                                for i in temp_arg:
                                    if(hasattr(assignblk1.instr.args[0],'name')):
                                       if(i in assignblk1.instr.args[0].name):
                                           temp_src_2.append(assignblk1.instr.args[0])
                                    else:
                                        is_break=True
                            if(is_break):
                                break
                            if("PUSH" in assignblk1.instr.name):
                                if(assignblk1.instr.args[0].is_int()):
                                    temp_src_2.append(assignblk1.instr.args[0])
                                else:
                                    pass
                    #print(temp_src_2)
                    temp_src_2=list(set(temp_src_2))
                    #temp_src_2.insert(0,src_args_temp)
                    #if(assignblk.instr.offset==0x4a97e):
                    #print(hex(assignblk.instr.offset))
                    #print(temp_src_2)
                    src=generate_src_arg(src_args_temp,temp_src_2)
                    assignblk.set(dst,src)
                    temp_assignblks=list(irblock.assignblks)
                    temp_assignblks[line_nb]=assignblk
                    irblock.set_assignblks(temp_assignblks)

        ircfg.blocks[irblock.loc_key]=irblock

def from_graph_get_dependcy(data):
    #track data
    node=data[0]
    #Which source determines the DST returned
    edge=data[1]

    #There are corresponding dependencies in it
    dependency=[]
    not_track=['IRDst','RBP',"RSP"]

    #Filter operation
    for key in edge.keys():
        node_key=list(node[key])
        if(isinstance(node_key[3],ExprLoc)):
            continue
        if(isinstance(node_key[3],ExprId) and node_key[3].name in not_track):
            continue
        if(isinstance(node_key[3],ExprMem) and isinstance(node_key[3].ptr,ExprOp)):
            judge_change=[]            
            ptr=node_key[3].ptr
            args=list(ptr.args)
            rbp=ExprId('RBP', 64)
            rsp=str(ExprId('RSP', 64))
            if(rsp in str(node_key[3])):
                continue
            if(node_key[3]==ExprId('RBP', 64)):
                continue

        depend=DependencyNode(node_key[0],node_key[1],node_key[2],node_key[3],key,node_key[4],node_key[5])
        if(depend not in dependency):
            dependency.append(depend)
        else:
            depend=dependency[dependency.index(depend)]
        
        for i in edge[key]:
            node_key=list(node[i])
            if(isinstance(node_key[3],ExprLoc)):
                continue
            if(isinstance(node_key[3],ExprId) and node_key[3].name in ['of','zf','nf']):
                continue

            depend_src=DependencyNode(node_key[0],node_key[1],node_key[2],node_key[3],i,node_key[4],node_key[5])
            if(depend_src not in dependency):
                depend.add_dependency(depend_src)
                dependency.append(depend_src)
            else:
                depend_src=dependency[dependency.index(depend_src)]
                depend.add_dependency(depend_src)       
    
    dependency.sort()
    #Filter out unsuitable variables
    for depend in dependency:
        key=depend.loc_key
        line_nb=depend.line_nb
        instr=depend.instr
        temp_dependency=set()
        rbp=ExprId('RBP', 64)
        fs=ExprId('FS', 16)
        temp_dependency.update(depend.dependency)
        if(isinstance(instr,ExprMem) and hasattr(instr,'ptr')):
            #print('instr',str((1,instr)))
            if(not hasattr(instr.ptr,'args')):
                continue
            args=instr.ptr.args
            if(fs in args and len(args)==2):
                temp_dependency=set()
            else:
                depend_instr=set()
                for node in depend.dependency:
                    depend_instr.add(node.instr)
                    if(node.instr==rbp):
                        temp_dependency.remove(node)
                    if(isinstance(node.instr,ExprInt) and node.instr in args):
                        temp_dependency.remove(node)
                depend_instr=list(depend_instr)
                if(len(depend_instr)==2 and len(args)==2 and rbp in depend_instr and depend_instr[0] in args and depend_instr[1] in 
                   args):
                    temp_dependency=set()
        depend.dependency=temp_dependency

    return dependency

def from_graph_get_affected(data):
    #track data
    node=data[0]
    #Which source determines the DST returned
    edge=data[1]

    #There are corresponding dependencies in it
    dependency=[]
    not_track=['IRDst','RBP',"RSP"]

    #Filter operation
    for key in edge.keys():
        node_key=list(node[key])
        if(isinstance(node_key[3],ExprLoc)):
            continue
        if(isinstance(node_key[3],ExprId) and node_key[3].name in not_track):
            continue
        if(isinstance(node_key[3],ExprMem) and isinstance(node_key[3].ptr,ExprOp)):
            judge_change=[]            
            ptr=node_key[3].ptr
            args=list(ptr.args)
            rbp=ExprId('RBP', 64)
            rsp=str(ExprId('RSP', 64))
            if(rsp in str(node_key[3])):
                continue
            if(node_key[3]==ExprId('RBP', 64)):
                continue

        depend=AffectedNodes(node_key[0],node_key[1],node_key[2],node_key[3],key,node_key[4],node_key[5])
        if(depend not in dependency):
            dependency.append(depend)
        else:
            depend=dependency[dependency.index(depend)]
        
        for i in edge[key]:
            node_key=list(node[i])
            if(isinstance(node_key[3],ExprLoc)):
                continue
            if(isinstance(node_key[3],ExprId) and node_key[3].name in ['of','zf','nf']):
                continue

            depend_src=AffectedNodes(node_key[0],node_key[1],node_key[2],node_key[3],i,node_key[4],node_key[5])
            if(depend_src not in dependency):
                depend.add_dependency(depend_src)
                dependency.append(depend_src)
            else:
                depend_src=dependency[dependency.index(depend_src)]
                depend.add_dependency(depend_src)       
    
    dependency.sort()
    #Filter out unsuitable variables
    for depend in dependency:
        key=depend.loc_key
        line_nb=depend.line_nb
        instr=depend.instr
        temp_dependency=set()
        rbp=ExprId('RBP', 64)
        fs=ExprId('FS', 16)
        temp_dependency.update(depend.dependency)
        if(isinstance(instr,ExprMem) and hasattr(instr,'ptr')):
            #print('instr',str((1,instr)))
            if(not hasattr(instr.ptr,'args')):
                continue
            args=instr.ptr.args
            if(fs in args and len(args)==2):
                temp_dependency=set()
            else:
                depend_instr=set()
                for node in depend.dependency:
                    depend_instr.add(node.instr)
                    if(node.instr==rbp):
                        temp_dependency.remove(node)
                    if(isinstance(node.instr,ExprInt) and node.instr in args):
                        temp_dependency.remove(node)
                depend_instr=list(depend_instr)
                if(len(depend_instr)==2 and len(args)==2 and rbp in depend_instr and depend_instr[0] in args and depend_instr[1] in 
                   args):
                    temp_dependency=set()
        depend.dependency=temp_dependency

    return dependency

def from_graph_get_affected2addr(data):
    #track data
    node=data[0]
    #Which source determines the DST returned
    edge=data[1]

    #There are corresponding dependencies in it
    dependency=[]
    not_track=['IRDst','RBP',"RSP"]
    
    #Filter operation
    for key in edge.keys():
        node_key=list(node[key])
        if(isinstance(node_key[3],ExprLoc)):
            continue
        if(isinstance(node_key[3],ExprId) and node_key[3].name in not_track):
            continue
        if(isinstance(node_key[3],ExprMem) and isinstance(node_key[3].ptr,ExprOp)):
            judge_change=[]            
            ptr=node_key[3].ptr
            args=list(ptr.args)
            rbp=ExprId('RBP', 64)
            rsp=str(ExprId('RSP', 64))
            if(rsp in str(node_key[3])):
                continue
            if(node_key[3]==ExprId('RBP', 64)):
                continue

        depend=AffectedNodes2addr(node_key[0],node_key[1],node_key[2],node_key[3],key,node_key[4],node_key[5])
        if(depend not in dependency):
            dependency.append(depend)
        else:
            depend=dependency[dependency.index(depend)]
        
        for i in edge[key]:
            node_key=list(node[i])
            if(isinstance(node_key[3],ExprLoc)):
                continue
            if(isinstance(node_key[3],ExprId) and node_key[3].name in ['of','zf','nf']):
                continue

            depend_src=AffectedNodes2addr(node_key[0],node_key[1],node_key[2],node_key[3],i,node_key[4],node_key[5])
            if(depend_src not in dependency):
                depend.add_dependency(depend_src)
                dependency.append(depend_src)
            else:
                depend_src=dependency[dependency.index(depend_src)]
                depend.add_dependency(depend_src)     
            

    dependency.sort()
    #Filter out unsuitable variables
    for depend in dependency:
        key=depend.loc_key
        line_nb=depend.line_nb
        instr=depend.instr
        temp_dependency=set()
        rbp=ExprId('RBP', 64)
        fs=ExprId('FS', 16)
        temp_dependency.update(depend.dependency)
        if(isinstance(instr,ExprMem) and hasattr(instr,'ptr')):
            #print('instr',str((1,instr)))
            if(not hasattr(instr.ptr,'args')):
                continue
            args=instr.ptr.args
            if(fs in args and len(args)==2):
                temp_dependency=set()
            else:
                depend_instr=set()
                for node in depend.dependency:
                    depend_instr.add(node.instr)
                    if(node.instr==rbp):
                        temp_dependency.remove(node)
                    if(isinstance(node.instr,ExprInt) and node.instr in args):
                        temp_dependency.remove(node)
                depend_instr=list(depend_instr)
                if(len(depend_instr)==2 and len(args)==2 and rbp in depend_instr and depend_instr[0] in args and depend_instr[1] in 
                   args):
                    temp_dependency=set()
        depend.dependency=temp_dependency

    return dependency

def filter_affected2addr(affected):
    #Drop the dependency on integers in the data
    not_track=["RBP","RSP","RIP","cf",'zf','nf']
    for affect in affected:
        temp_dependency=[]
        temp_dependency.extend(affect.dependency)
        #Tracing to [RBP + offset] stops.
        if(len(temp_dependency)==1 and isinstance(temp_dependency[0].instr,ExprInt)):
            affect.dependency=set([])
            continue

        for node in affect.dependency:
            # if(isinstance(affect.instr,ExprMem) and  isinstance(node.instr,ExprInt)):
            #     temp_dependency.remove(node)
            if(type(node.instr)==ExprInt):
                temp_dependency.remove(node)
            if(isinstance(node.instr,ExprId) and node.instr.name in not_track):
                temp_dependency.remove(node)
            exprmem=re.findall(r'\[.+\],',affect.assembly)
            if(len(exprmem)!=0):
                if(affect in temp_dependency):
                    temp_dependency.remove(affect)
                exp=list()
                if(len(exprmem)!=0):
                    exp=exprmem[0]
                    if(isinstance(node.instr,ExprId) and node.instr.name in exp ):
                        temp_dependency.remove(node)
        
        affect.dependency=temp_dependency

def filter_affected_exprmem(affected):
    #Drop the dependency on integers in the data
    not_track=["RBP","RSP","RIP","cf",'zf','nf']
    for affect in affected:
        temp_dependency=[]
        temp_dependency.extend(affect.dependency)
        #Tracing to [RBP + offset] stops.
        if(len(temp_dependency)==1 and isinstance(temp_dependency[0].instr,ExprInt)):
            affect.dependency=set([])
            continue

        for node in affect.dependency:
            if(isinstance(affect.instr,ExprMem) and  isinstance(node.instr,ExprInt)):
                temp_dependency.remove(node)
            if(isinstance(node.instr,ExprId) and node.instr.name in not_track):
                temp_dependency.remove(node)
        affect.dependency=temp_dependency

def filter_affected(affected):
    filter_affected_exprmem(affected)
    affect_exprem=set()
    for affect in affected:
        if(not isinstance(affect.instr,ExprMem)):
            continue
        track_args=['RAX','RBX','RCX','RDX','EAX','EBX','ECX','EDX','AX','BX','CX','DX']
        node_w=affect.instr
        write_w=node_w.ptr.get_r(mem_read=False,cst_read=True)
        write_w=[x for x in write_w if(isinstance(x,ExprId) and x.name in track_args)]
        assembly=affect.assembly
        exprmem=re.findall(r'\[.+\]',assembly)
        exp=list()
        if(len(exprmem)!=0):
            exp=exprmem[0]
        tmep_dependency=set([])
        for node in affect.dependency:
            if(isinstance(node.instr,ExprId) and node.instr.name in track_args 
                and node.instr in write_w):
                tmep_dependency.add(node)
            if(isinstance(node.instr,ExprId) and node.instr.name in exp ):
                tmep_dependency.add(node)
        tmep_dependency.add(affect)
        affect.dependency=tmep_dependency
        affect_exprem.add(affect)
    affect_exprem=list(affect_exprem)
    affect_exprem.sort()
    affect_exprem=set(affect_exprem)
    return affect_exprem

def print_dependency(dependency):
    for depend in dependency:
        print(depend.get_node(),end='')
        print(':')
        for node in depend.dependency:
            print(' '*4,end='')
            print(node.get_node())
        print('')

def print_affected(affected):
    for aff in affected:
        print('aff.get_node:',aff.get_node())
        for temp in aff.depend_separte.keys():
            print(' '*4,end='')
            print(temp)
            for i in aff.depend_separte[temp]:
                print(' '*8,end='')
                print(i)
            print('')
        print('\n')

def print_affected_in_block(affected):
    for affect in affected:
        print(affect.get_node(),end='')
        print(':')
        for key in affect.depend_in_block.keys():
            print(key,end='')
            print(':')
            print(affect.depend_in_block[key])
        print('')

def get_data_affect_separte(affected):
    data={}
    for affect in affected:
        if(len(affect.depend_in_block)!=0):
            if(affect.addr not in data):
                data[affect.addr]=affect.depend_in_block
            else:
                data[affect.addr].update(affect.depend_in_block)
    return data

def print_dependency_in_block(dependency):
    for affect in dependency:
        print(affect.get_node(),end='')
        print(':')
        for key in affect.depend_loc_key_instr.keys():
            print(key,end='')
            print(':')
            temp=list(affect.depend_loc_key_instr[key])
            temp.sort()
            print(temp)
        print('')

def extracte_affect_data(affected):
    #Find backwards in all blocks
    data={}
    #Find backward in current block
    #data_in_block={}
    data_cmp_instr={}
    for affect in affected:
        temp=data.get(affect.addr,set())
        #temp_in_block=data_in_block.get(affect.addr,set())
        for node in affect.depend_line:
            temp.add(node.instr)
        # for node in affect.depend_in_block:
        #     temp_in_block.add(node.addr)
        #temp.add(affect.instr)
        #temp_in_block.add(affect.addr)
        data[affect.addr]=temp
        #data_in_block[affect.addr]=temp_in_block
        if(len(affect.cmp_deal)!=0):
            cmp_data=data_cmp_instr.get(affect.addr,list())
            for nodes in affect.cmp_deal:
                temp_cmp=set()
                for node in nodes:
                    temp_cmp.add(node.instr)
                temp_cmp=list(temp_cmp)
                temp_cmp.sort()
                temp_cmp=set(temp_cmp)
                if(temp_cmp not in cmp_data):
                    cmp_data.append(set(temp_cmp))
            data_cmp_instr[affect.addr]=cmp_data
    
    return [data,data_cmp_instr]

def extracte_affect_data2addr(affected):
    #Find backwards in all blocks
    data={}
    #Find backward in current block
    #data_in_block={}
    data_cmp_instr={}
    for affect in affected:
        # if(affect.addr=='0xa3c2' or affect.addr=='0xa33d'):
        #     print(affect.get_node())
        #     print(':')
        temp=data.get(affect.addr,set())
        for node in affect.depend_line:
            temp.add(node.addr)
            # if(affect.addr=='0xa3c2' or affect.addr=='0xa33d'):
            #     print(node.get_node())
        data[affect.addr]=temp
        if(len(affect.cmp_deal)!=0):
            cmp_data=data_cmp_instr.get(affect.addr,list())
            for nodes in affect.cmp_deal:
                temp_cmp=set()
                for node in nodes:
                    temp_cmp.add(node.addr)
                temp_cmp=list(temp_cmp)
                temp_cmp.sort()
                temp_cmp=set(temp_cmp)
                if(temp_cmp not in cmp_data):
                    cmp_data.append(set(temp_cmp))
            data_cmp_instr[affect.addr]=cmp_data


    
    return [data,data_cmp_instr]

def print_track_affect_data(track_affect_data):
    for key in sorted(track_affect_data):
        print('addr',key)
        for data in track_affect_data[key]:
            print(data)
            for i in data:
                print(' '*4,end='')
                print(i)
            print(' '*4+'-'*4)
        print('')

def print_track_affect_exprmem_data(track_affect_exprem_data):
    for key in sorted(track_affect_exprem_data):
        print('addr:',key)
        temp=track_affect_exprem_data[key]
        for i in temp.keys():
            print(' '*4,end='')
            print(i)
            for j in temp[i]:
                print(' '*8,end='')
                print(j)
        print('')

def data_from_where_separte(dependency):
    data={}
    for node in dependency:
        if(len(node.depend_loc_key_instr)!=0):
            for key in node.depend_loc_key_instr.keys():
                if(key not in data.keys()):
                    data[key]=node.depend_loc_key_instr[key]
                else:
                    data[key].update(node.depend_loc_key_instr[key])
    return data

def data_from_where(dependency):
    data={}
    for node in dependency:
        data_from=data.get(node.addr,set([]))
        for depend in node.depend_loc_key_line:
            depend=list(depend)
            #print('',depend[2])
            data_from.add(depend[2])
        data_from=list(data_from)
        data_from.sort()
        data_from=set(data_from)
        data[node.addr]=data_from
    
    for node in dependency:
        temp_line=data[node.addr]
        for depend in node.depend_loc_key_line:
            pass
    return data

def print_data_pependency(dependency):
    #have been printed
    flag=[ExprId('nf', 1),ExprId('zf', 1),ExprId('of', 1)]
    addr=[]
    for node in dependency:
        if(len(node.depend_loc_key_line)==0):
            continue
        if(node.addr in addr):
            continue
        if(node.instr in flag):
            addr.append(node.addr)
        print(node.addr,node.assembly,end=' ')
        print(':')
        temp_depend=[]
        temp_addr=[]
        for depend in node.depend_loc_key_line:
            depend=list(depend)
            temp_depend.append(depend[2]+'  '+depend[3])
            temp_addr.append(depend[2])
        temp_depend.sort()
        temp=reversed(temp_depend)
        for i in temp:
            print(i)
        temp_addr.sort()
        print(temp_addr)
        print('')

def track_in_block(ircfg,loc_key,line_nb,will_track,
                 affect_data,affect_exprmem_data,addr_to_affect2addr):
    data_to=set()
    block=ircfg.get_block(loc_key)
    #The data that the entire block will track,He must be dealt with first to see if it is rewritten
    track_data=will_track[loc_key]
    track_print=False
    for line,assignblk in enumerate(block[line_nb:]):
        start_addr=assignblk.instr.offset
        break

    is_out_print=False
    for line,assignblk in enumerate(block[line_nb:]):
        addr=str(hex(assignblk.instr.offset))
        # if(line==line_nb):
        #     print(addr)
        #     print(loc_key)
        #     print('')

        # if(addr=='0xabfd' or addr=='0xac24'):
        #     print(addr)
        #     is_out_print=True
        #     print('track_data_before:',track_data)
        #     for i in track_data:
        #         print(" "*4,i)
        #     dict_rw = assignblk.get_rw(cst_read=True)
        #     for node_w, nodes_r in viewitems(dict_rw):
        #         print(('node_w',node_w))
        #         print('     ',nodes_r)
        #     print('')

        #Trace the corresponding register value.
        if(len(track_data)!=0):
            temp_track_data=[]
            dict_rw = assignblk.get_rw(cst_read=True)
            re_assignment=False
            for node_w, nodes_r in viewitems(dict_rw):
                temp_nodes_r=set()
                for i in nodes_r:
                    if(type(i)==ExprMem):
                        temp_nodes_r.update(i.ptr.get_r(mem_read=False,cst_read=True))
                    temp_nodes_r.add(i)
                nodes_r=temp_nodes_r
                re_assignment=True
                #Determines whether the register is rewritten.
                for t_d in track_data:
                    if(node_w not in t_d):
                        temp_track_data.append(t_d)
                #Determines whether the current instruction is affected by the tracked register.
                for t_d in track_data:
                    for t_d_1 in t_d:
                        if(t_d_1 in nodes_r):
                            data_to.add(addr)
                            if(type(node_w)==ExprId and node_w.name in ["RBP","RSP","RIP","cf",'zf','nf','of','IRDst']):
                                continue
                            if(type(node_w)==ExprLoc):
                                continue
                            if(set([node_w]) not in temp_track_data):
                                temp_track_data.append(set([node_w]))
            if(re_assignment):
                track_data=temp_track_data
        
        if(len(track_data)==0):
            break
        
        if(line==line_nb):
            start_addr=assignblk.instr.offset

        if(addr not in affect_data):
            continue
        
        dict_rw=assignblk.get_rw(cst_read=True)
        
        if(addr in addr_to_affect2addr):
            affected=addr_to_affect2addr[addr]
            no_assignment=True
            for node_w,node_r in viewitems(dict_rw):
                for aff in affected:
                    if(aff.instr == node_w and len(aff.dependency)!=0):
                        no_assignment=False
                        break
            if(no_assignment):
                continue

        #The current line is rewritten in the form of [rax + offst], [rbp + offset].
        rewrite_data=set([])
        for node_w,node_r in viewitems(dict_rw):
            if(isinstance(node_w,ExprMem)):
                exprmem_data=affect_exprmem_data[addr]
                for key in exprmem_data.keys():
                    rewrite_data=exprmem_data[key]
                    break

        #The data contained in the current line
        #Determine if you need to stop tracking or if you need to add new tracking variables
        if(len(rewrite_data)!=0):
            temp_track_data=[]
            #The current value to be tracked has been rewritten
            for t_d in track_data:
                count=0
                for r_d1 in rewrite_data:
                    if(r_d1 not in t_d):
                        break
                    count=count+1
                if(count==len(rewrite_data)):
                    delete_y_n=True
                    line_data_seprate=affect_data[addr]
                    for key in line_data_seprate.keys():
                        line_data=line_data_seprate[key]
                        # print(line_data)
                        for t_d1 in track_data:
                            count1=0
                            for t_d11 in t_d1:
                                if(t_d11 in line_data):
                                    count1=count1+1
                            if(count1==len(t_d1)):
                                delete_y_n=False
                                break
                    if(not delete_y_n and t_d not in temp_track_data):
                        temp_track_data.append(t_d)
                else:
                    if(t_d not in temp_track_data):
                        temp_track_data.append(t_d)
    
            #Whether new tracking variables need to be added
            line_data_seprate=affect_data[addr]
            for key in line_data_seprate.keys():
                line_data=line_data_seprate[key]
                # print(line_data)
                for t_d1 in track_data:
                    count1=0
                    for t_d11 in t_d1:
                        if(t_d11 in line_data):
                            count1=count1+1
                    if(count1==len(t_d1)):
                        if(rewrite_data not in temp_track_data):
                            temp_track_data.append(rewrite_data)
                        break
            track_data=temp_track_data

        #Processing of directly using register transfer
        if(len(track_data)!=0):
            temp_track_data=[]
            dict_rw = assignblk.get_rw(cst_read=True)
            re_assignment=False
            for node_w, nodes_r in viewitems(dict_rw):
                temp_nodes_r=set()
                for i in nodes_r:
                    if(type(i)==ExprMem):
                        temp_nodes_r.update(i.ptr.get_r(mem_read=False,cst_read=True))
                    temp_nodes_r.add(i)
                nodes_r=temp_nodes_r
                re_assignment=True
                for t_d in track_data:
                    if(node_w not in t_d):
                        temp_track_data.append(t_d)
                for t_d in track_data:
                    for t_d_1 in t_d:
                        if(t_d_1 in nodes_r ):
                            data_to.add(addr)
                            if(type(node_w)==ExprId and node_w.name in ["RBP","RSP","RIP","cf",'zf','nf','of','IRDst']):
                                continue
                            if(type(node_w)==ExprLoc):
                                continue
                            if(set([node_w]) not in temp_track_data):
                                temp_track_data.append(set([node_w]))
            if(re_assignment):
                track_data=temp_track_data         
        
        if(len(track_data)==0):
            break
       
        line_data_seprate=affect_data[addr]
               
        #Is the current instruction affected
        for key in line_data_seprate.keys():
            line_data=line_data_seprate[key]
            for t_d in track_data:
                count=0
                for t_d1 in t_d:
                    if(t_d1 not in line_data):
                        break
                    count=count+1
                if(count==len(t_d)):
                    data_to.add(addr)
                    break
        
        # if(addr=='0xabfd'):
        #     print(start_addr)
        #     print('test:',track_data)
        #     for i in track_data:
        #         print(" "*4,i)
        #     print('')


    if(is_out_print):
        print(str(hex(start_addr)))
        print('track_data_after:',track_data)
        for i in track_data:
            print(" "*4,i)
        # dict_rw = assignblk.get_rw(cst_read=True)
        # for node_w, nodes_r in viewitems(dict_rw):
        #     print(('node_w',node_w))
        #     print('     ',nodes_r)
        # print('')
    data_to=set(data_to)
    return [data_to,track_data]

def get_is_assignment(affected,target_addr,data_from):
    if(target_addr in data_from):
        return True
    for affect in affected:
        if(affect.addr!=target_addr):
            continue
        #print(affect.dependency)
        for node in affect.dependency:
            if(not isinstance(node.instr,ExprId)):
                continue
            #,print(node.addr)
            if(node.addr in data_from):
                return True
    return False

def from_target_get_track_affect_data(affected):
    data={}
    for aff in affected:
        if('MOV' in aff.assembly or "LEA" in aff.assembly):
            temp=data.get(aff.addr,list())
            if(len(temp)==0):
                depend=set([])
            else:
                depend=temp[0]
            for key in aff.depend_separte.keys():
                depend.update(aff.depend_separte[key])
            if(len(temp)==0 and len(depend)!=0):
                temp.append(depend)
            else:
                if(len(depend)!=0):
                    temp[0]=depend
            if(len(temp)!=0):
                data[aff.addr]=temp
        else:
            temp=data.get(aff.addr,list())
            for key in aff.depend_separte.keys():
                depend=aff.depend_separte[key]
                if(depend not in temp and len(depend)!=0):
                    temp.append(depend)
            if(len(temp)!=0):
                data[aff.addr]=temp
    return data

def from_target_get_track_affect_data1(affected):
    data={}
    for aff in affected:
        if('MOV' in aff.assembly or "LEA" in aff.assembly):
            temp0=data.get(aff.addr,{})
            depend=set()
            if(len(temp0)!=0):
                depend.update(temp0[aff.addr])
            for key in aff.depend_separte.keys():
                depend.update(aff.depend_separte[key])
            temp0[aff.addr]=depend
            data[aff.addr]=temp0
        else:
            temp=data.get(aff.addr,{})
            temp.update(aff.depend_separte)
            data[aff.addr]=temp
    return data

def from_target_get_track_affect_exprmem_data(affected_exprem):
    data={}
    for affect in affected_exprem:
        temp_expr=data.get(affect.addr,{})
        temp={}
        for key in affect.depend_separte.keys():
            temp[key[4]]=affect.depend_separte[key]
        temp_expr.update(temp)
        data[affect.addr]=temp_expr
    return data

def from_affected_exprem_get_backtrack(affect_exprem):
    data={}
    for affect in affect_exprem:
        temp=data.get(affect.addr,set())
        temp.update(affect.depend_line_addr)
        if(len(temp)!=0):
            data[affect.addr]=temp
    return data

#Where will the data go
def get_depend_to(target_addr,data,ircfg):
    #target_addr:Address to analyze
    #data :Nodes and edges
    #data_form_where_separte:Where does the instruction come from? {DST: [], SRC []} is separated
    #data_from_where:wher does the instruction come from

    affected2addr=from_graph_get_affected2addr(data)
    filter_affected2addr(affected2addr)
    #Find out where the data comes from.
    for affect in affected2addr:
        affect.find_dependency()
        #Deal with the situation that a depends on B and B depends on a.
        if(len(affect.dependency)!=0 and len(affect.depend_line)==0):
            for node in affect.dependency:
                affect.depend_line.update(node.depend_line)
                temp=set()
                for i in node.depend_line:
                    temp.add(i.addr)
                if(node.get_node() not in affect.depend_separte):
                    affect.depend_separte[node.get_node()]=temp
                else:
                    affect.depend_separte[node.get_node()].update(temp)

    #print_dependency(affected2addr)
    #Add the current block to the address to be tracked.
    addr_to_affect2addr={}
    for affect in affected2addr:
        temp=addr_to_affect2addr.get(affect.addr,set())
        temp.add(affect)
        addr_to_affect2addr[affect.addr]=temp
    #print_affected(affected2addr)

    #The data source obtained here is in the form of [RBP + offset]
    affected=from_graph_get_affected(data)
    affected_exprmem=filter_affected(affected)
    
    for affect in affected_exprmem:
        affect.find_dependency()

    #What we get is data of type {addr: [addr]}
    track_affect_data=from_target_get_track_affect_data1(affected2addr)
    #What we get is data of type {addr: [exprmem]}
    track_affect_exprmem_data=from_target_get_track_affect_exprmem_data(affected_exprmem)
    
    #[rax + offset] this form needs to trace back where rax comes from. {addr:[exprmem]},in this form
    backtrack_addr=from_affected_exprem_get_backtrack(affected_exprmem)
    
    #Track_effect is the instruction register or memory to trace.
    if(target_addr in track_affect_data):
        track_affect_separge=track_affect_data[target_addr]
        track_affect=[]
        for key in track_affect_separge.keys():
            track_affect.append(track_affect_separge[key])
    else:
        track_affect=list()    
    
    #print_track_affect_data(track_affect_data)

    temp_addr=int(target_addr,0)
    current_loc_key = next(iter(ircfg.getby_offset(temp_addr)))
    current_block = ircfg.get_block(current_loc_key)
    #print(type(current_block))
    #If it is a test, CMP instruction, or the instruction
    #contains operations on memory, the memory needs to be tracked.
    cmp_test_mem=False 
    #First, trace in the block where the destination address is located
    for assignblk_index, assignblk in enumerate(current_block):
        if str(hex(assignblk.instr.offset)) == target_addr:
            current_line=assignblk_index
            #Determine whether the instruction to be tracked is in the form of [RBP + off]
            dict_rw=assignblk.get_rw(cst_read=True)
            for node_w,node_r in viewitems(dict_rw):
                if(isinstance(node_w,ExprMem)):
                    cmp_test_mem=True
                    exprmem_data=track_affect_exprmem_data[target_addr]
                    for key in exprmem_data.keys():
                        track_affect=[exprmem_data[key]]
                        break
            if('TEST' in assignblk.instr.name or 'CMP' in assignblk.instr.name):
                cmp_test_mem=True
            break
    # If not, trace the register directly, such as rax
    if(not cmp_test_mem):
        assignblk=current_block[current_line]
        dict_rw=assignblk.get_rw(cst_read=True)
        track_affect=[]
        for node_w,nodes_r in viewitems(dict_rw):
            if(node_w.name in ["RBP","RSP","RIP","cf",'zf','nf','IRDst']):
                continue
            if(set([node_w]) not in track_affect):
                track_affect.append(set([node_w]))
            if('CDQ' in assignblk.instr.name):
                track_affect.append(nodes_r)
            
        for succs in ircfg.successors_iter(current_loc_key):
            block=ircfg.get_block(succs)
            for assignblk_index, assignblk in enumerate(block):
                if(str(hex(assignblk.instr.offset))==target_addr):
                    current_loc_key=succs
                    current_line=assignblk_index
                    dict_rw=assignblk.get_rw(cst_read=True)
                    track_affect=[]
                    for node_w,nodes_r in viewitems(dict_rw):
                        if(node_w.name in ["RBP","RSP","RIP","cf",'zf','nf','IRDst']):
                            continue
                        if(set([node_w]) not in track_affect):
                            track_affect.append(set([node_w]))
                        if('CDQ' in assignblk.instr.name):
                            track_affect.append(nodes_r)

    if(len(track_affect)==0):
        return set([])
    
    data_to=set([])
    data_to_backtrace=set([])

    #loc_key:[[],[]] this form
    will_track={}
    will_track[current_loc_key]=track_affect
    
    # for i in (track_affect):
    #     print(i)
    # print('')

    #In block tracking, breadth first search is used to transfer tracking results to the next block
    track_block_result=track_in_block(ircfg,current_loc_key,current_line+1,will_track,
                 track_affect_data,track_affect_exprmem_data,addr_to_affect2addr)
    data_to.update(track_block_result[0])
    todo=list()
    for succs in ircfg.successors_iter(current_loc_key):
        todo.append(succs)
        w_r=will_track.get(succs,list())
        for w_t in track_block_result[1]:
            if(w_t not in w_r):
                w_r.append(w_t)
        will_track[succs]=w_r        
    
    if(len(track_block_result[1])==0):
        return data_to

    resolved=set()

    while todo:
        loc_key=todo.pop(0)
        if(loc_key in resolved):
            continue
        resolved.add(loc_key)
        track_data_result=track_in_block(ircfg,loc_key,0,will_track,
                 track_affect_data,track_affect_exprmem_data,addr_to_affect2addr)
        data_to.update(track_data_result[0])
        if(len(track_data_result[1])==0):
            continue
        for succs in ircfg.successors_iter(loc_key):
            todo.append(succs)
            w_r=will_track.get(succs,list())
            for w_t in track_data_result[1]:
                if(w_t not in w_r):
                    w_r.append(w_t)
            will_track[succs]=w_r
        #print(str(succs),succs,type(succs))
    
    data_to=list(data_to)
    data_to.sort()
    
    #Determine whether the current instruction contains registers requiring backtracking, such as [rax + offset]
    for addr in data_to:
        if(addr in backtrack_addr):
            data_to_backtrace.update(backtrack_addr[addr])
    # print('--No backtracking, for debugging------')
    # for i in data_to:
    #     print(i)
    # for i in will_track:
    #     print(i)
    #     print('    ',will_track[i])
    #     print('')

    data_to=set(data_to)
    data_to.add(target_addr)
    data_to.update(data_to_backtrace)
    data_to=list(set(data_to))
    data_to.sort()
    return data_to

def deal_circular_dependencies(dependency):

    for depend in dependency:
        temp_depend=depend.depend_loc_key_line
        temp_depend=list(set(temp_depend))
        temp_node=set([])
        temp_depend.sort()
        for node in depend.dependency:
            temp_node.update(node.depend_loc_key_line)
        temp_node=list(temp_node)
        temp_node.sort()
        if(len(temp_depend)<len(temp_node)):
            depend.depend_loc_key_line=temp_node

#Where does the data come from
def get_depend_from(target_addr,data):
    #target_addr:Address to analyze
    #data: Edge and node data of the entire func

    #Create corresponding data dependency through edge and node.
    dependency=from_graph_get_dependcy(data)
    #print_dependency(dependency)

    #Find the source of the data
    for depend in dependency:
        depend.find_dependency()
   
    #Delete circular data dependency a->b ,b->a
    deal_circular_dependencies(dependency)
    #print_dependency(dependency)

    #The data source is {node1: [], node2: []}
    data_from_separte=data_from_where_separte(dependency)

    #Get the source of data in the form of {addr: set ([])}
    data_from=data_from_where(dependency)

    data1=[]
    if(target_addr in data_from):
        data1=list(data_from[target_addr])
    data1.append(target_addr)
    data1=list(set(data1))
    data1.sort()

    #data1:Data source of destination address instruction
    #The source of the destination address instruction is in the form of {DST: [], SRC: []}
    #Source of all address instructions.
    return [data1,data_from_separte,data_from]

def gen_block_data_flow_graph(ir_arch, ircfg, ad, target_addr):
    
    dead_simp(ir_arch, ircfg)

    #Call register recovery. When the function parameters are 
    #greater than 6, there will be a problem. This problem has not been solved yet
    recovery_call(ircfg)

    # with open('/mnt/sharing/angrforward/ircfg.dot','w') as file:
    #    file.write(ircfg.dot())

    #Determine whether the current block exists
    irblock_0 = None
    for irblock in viewvalues(ircfg.blocks):
        loc_key = irblock.loc_key
        #get the block offset
        offset = ircfg.loc_db.get_location_offset(loc_key)
        if offset == ad:
            irblock_0 = irblock
            break
    assert irblock_0 is not None
    flow_graph = DiGraph()
    flow_graph.node2str = node2str



    irb_in_nodes = {}
    irb_out_nodes = {}
    temp=''
    for label in ircfg.blocks:
        irb_in_nodes[label] = {}
        irb_out_nodes[label] = {}
        if(label.key==1085):
            temp=label
    
    #in_block saves the input of the current block
    #out_block saves the output of the current block
    #Handle every block here
    #Obtain the corresponding first-order dependency
    for label, irblock in viewitems(ircfg.blocks):
        intra_block_flow_raw(ir_arch, ircfg, flow_graph, irblock, irb_in_nodes[label], irb_out_nodes[label])

    #Get the corresponding link relationship
    #Block-to-block tracking, tracking the nearest neighbor node of the data source
    inter_block_flow(ir_arch, ircfg, flow_graph, irblock_0.loc_key, irb_in_nodes, irb_out_nodes)

    # from graph_qt import graph_qt
    #open('E:\\forwardwork\\data.dot', 'w').write(flow_graph.dot())
    
    #Get the corresponding edges and nodes
    data=flow_graph.get_node_and_edge()

    
    data_from=[]
    
    #Backward data source analysis
    data_from=get_depend_from(target_addr,data)

    #Forward data slice analysis
    #data_to=get_depend_to(target_addr,data,ircfg,data_from[1],data_from[2])
    data_to=get_depend_to(target_addr,data,ircfg)

    return [data_from[0],data_to]

def data_analysis(filename,func_addr,target_addr):
    #filename :Binaries waiting to be analyzed
    #Binary function address
    #Instructions to be analyzed for binary functions
    
    ad = func_addr

    cont = Container.from_stream(open(filename, 'rb'))
    machine = Machine(cont.arch)

    mdis = machine.dis_engine(cont.bin_stream, loc_db=cont.loc_db, dont_dis_nulstart_bloc=True)
    
    mdis.follow_call = False

    #block=mdis.dis_block(0xac6f)
    #print([block.loc_key])

    #Get the corresponding disassembly
    asmcfg = mdis.dis_multiblock(ad)
    #print(type(asmcfg))

    indirect_jmp={}
    for block in asmcfg.blocks:
        instr=block.lines[len(block.lines)-1]
        #print(instr)
        if(len(instr.args)>0 and type(instr.args[0])!=ExprLoc):
            #print(instr)
            indirect_jmp[block.lines[0].offset]=instr.offset
            #print(instr.args[0])
            #print('')
    
    #Get the corresponding anti IR
    

    if(len(indirect_jmp)!=0):
        mdis = machine.dis_engine(cont.bin_stream, loc_db=cont.loc_db, dont_dis_nulstart_bloc=True)
    
        mdis.follow_call = False
        recov_cfg=cfg_recovery(filename,func_addr)
        #print(recov_cfg)
        deal_indirect={}
        for in_jmp in indirect_jmp:
            loc_keys=[]
            for addr in recov_cfg[in_jmp]:
                block=mdis.dis_block(addr)
                loc_keys.append(block.loc_key)
            deal_indirect[indirect_jmp[in_jmp]]=loc_keys
        #print('deal_indirect:')
        #print(deal_indirect)
        asmcfg = mdis.dis_multiblock(ad,indirect_jmp=deal_indirect)
        #print(deal_indirect)
        #Get the corresponding anti IR

        ir_arch_analysis = machine.ira(mdis.loc_db)
        ircfg = ir_arch_analysis.new_ircfg_from_asmcfg(asmcfg)
        for block_addr in indirect_jmp.keys():
            current_loc_key = next(iter(ircfg.getby_offset(block_addr)))
            loc_keys=deal_indirect[indirect_jmp[block_addr]]
            for dst in loc_keys:
                ircfg.add_uniq_edge(current_loc_key,dst)

    else:
        ir_arch_analysis = machine.ira(mdis.loc_db)
        ircfg = ir_arch_analysis.new_ircfg_from_asmcfg(asmcfg)    
    #print(block)
    #asmcfg = mdis.dis_multiblock(ad,0)
    #print('ok')

    with open('/mnt/sharing/angrforward/ircfg.dot','w') as file:
       file.write(ircfg.dot())
    with open('/mnt/sharing/angrforward/asmcfg.dot','w') as file:
       file.write(asmcfg.dot())


    #Analyze functions
    data=gen_block_data_flow_graph(ir_arch_analysis, ircfg, ad, str(hex(target_addr)))

    return data

def main_ww():
    time_start=time.time()

    #Obtain the corresponding slice data. Data [0] stores the instruction address of 
    #backward slice, and data [1] stores the instruction address of forward slice
    #data=data_analysis(r'E:\forwardwork\libopenjp2.so.2.2.0_2.2.0.so',0x8388,0x8419)
    data=data_analysis(r'/mnt/sharing/angrforward/opj_decompress_2.2.0.so',0xAA79,0xaba4)
    print('------------data-from--------------')
    for i in data[0]:
        print(i)
    print('-----------------------------------')
    print('------------data--to---------------')
    for i in data[1]:
        print(i)
    print('-----------------------------------')
    time_end=time.time()
    print('total times:',time_end-time_start)

if __name__=='__main__':
    main_ww()
