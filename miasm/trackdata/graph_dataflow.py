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
from miasm.analysis.data_analysis_ww import DependencyNode,AffectedNodes,AffectedNodes2addr

import time
import sys


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

def filter_affected(affected):
    #Drop the dependency on integers in the data
    not_track=["RBP","RSP","RIP","cf",'zf','nf']
    for affect in affected:
        temp_dependency=[]
        temp_dependency.extend(affect.dependency)
        for node in affect.dependency:
            if(isinstance(node.instr,ExprInt)):
                temp_dependency.remove(node)
            if(isinstance(node.instr,ExprId) and node.instr.name in not_track):
                temp_dependency.remove(node)
        affect.dependency=temp_dependency

def print_dependency(dependency):
    for depend in dependency:
        print(depend.get_node(),end='')
        print(':')
        for node in depend.dependency:
            print(node.get_node())
        print('')

def print_affected(affected):
    for affect in affected:
        if(len(affect.depend_line)==0):
            continue
        print(affect.get_node(),end='')
        print(':')
        for node in affect.depend_line:
            print(node.get_node())
        print('')

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
        temp=data.get(affect.addr,set())
        for node in affect.depend_line:
            temp.add(node.addr)
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

def print_track_result(dependency):
    for depend in dependency:
        print(depend.get_node())
        print(depend.depend_loc_key_line)
        print(depend.depend_loc_key_instr)
        print('*'*30)
        print('')
    print('\n\n\n\n')

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

def track_block(ircfg,loc_key,line_nb,data_affected,target_is_cmp,data_from,data_from_cmp,
    data_from_separte,data_affect_sepreat):
    track_data_in_black=set()
    data_to=set()
    block = ircfg.get_block(loc_key)
    affect_key=set()
    for line,assignblk in enumerate(block[line_nb:]):
        if(line==0):
            block_start_address=assignblk.instr.offset
        addr=str(hex(assignblk.instr.offset))
        if(addr in data_affected):
            #Similar to CMP, two registers need special handling
            if(target_is_cmp and addr in data_affect_sepreat.keys()):
                for cmp_data in data_from_cmp:
                    temp_affect=data_affect_sepreat[addr]
                    for key in temp_affect.keys():
                        count=0
                        affect_separte=temp_affect[key]
                        for d_f in cmp_data:
                            if(d_f in affect_separte):
                                count=count+1
                        if(count==len(cmp_data)):
                            data_to.add(addr)
                            if(key in data_from_separte):
                                temp_from=data_from_separte[key]
                                for i in temp_from:
                                    if(block_start_address<=int(i,0) and int(i,0)<=assignblk.instr.offset):
                                        track_data_in_black.add(i)

            elif('MOV' in assignblk.instr.name):
                count=0
                temp_track_data_in_block=set()
                for d_f in data_from:
                    if(d_f in data_affected[addr]):
                        count=count+1
                if(count==len(data_from)):
                    data_to.add(addr)
                    if addr in data_affect_sepreat:
                        temp_key=data_affect_sepreat[addr]
                        for key in temp_key.keys():
                            if(key in data_from_separte ):
                                temp_from=data_from_separte[key]
                                for i in temp_from:
                                    if(block_start_address<=int(i,0) and int(i,0)<=assignblk.instr.offset):
                                        track_data_in_black.add(i)

            elif(addr in data_affect_sepreat.keys()):
                temp_affect=data_affect_sepreat[addr]
                for key in temp_affect.keys():
                    count=0
                    for d_f in data_from:
                        if(d_f in temp_affect[key]):
                            count=count+1
                    if(count==len(data_from)):
                        #print('cmp_data',cmp_data)
                        data_to.add(addr)
                        if(key in data_from_separte ):
                            temp_from=data_from_separte[key]
                            for i in temp_from:
                                if(block_start_address<=int(i,0) and int(i,0)<=assignblk.instr.offset):
                                    track_data_in_black.add(i)




    return [data_to,track_data_in_black]

    # track_data_in_black=set()
    # data_to=set()
    # block = ircfg.get_block(loc_key)
    # for line,assignblk in enumerate(block[line_nb:]):
    #     if(line==0):
    #         block_start_address=assignblk.instr.offset
    #     addr=str(hex(assignblk.instr.offset))
    #     if(addr in data_affected):
    #         if(target_is_cmp):
    #             for cmp_data in data_from_cmp:
    #                 count=0
    #                 temp_track_data_in_block=set()
    #                 for d_f in cmp_data:
    #                     if(d_f in data_affected[addr]):
    #                         count=count+1
    #                     if(block_start_address<int(d_f,0)):
    #                         temp_track_data_in_block.add(d_f)
    #                 if(count==len(cmp_data)):
    #                     data_to.add(addr)
    #                     track_data_in_black.update(temp_track_data_in_block)
    #         else:
    #             count=0
    #             temp_track_data_in_block=set()
    #             for d_f in data_from:
    #                 if(d_f in data_affected[addr]):
    #                     count=count+1
    #                 if(block_start_address<int(d_f,0)):
    #                     temp_track_data_in_block.add(d_f)
    #             if(count==len(data_from)):
    #                 data_to.add(addr)
    #                 track_data_in_black.update(temp_track_data_in_block)
    # return [data_to,track_data_in_black]

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
    
#Where will the data go
def get_depend_to(target_addr,data,ircfg,data_from_where_separte):
    affected2addr=from_graph_get_affected2addr(data)
    filter_affected(affected2addr)
    for affect in affected2addr:
        affect.find_dependency()
        if(len(affect.dependency)!=0 and len(affect.depend_line)==0):
            for node in affect.dependency:
                affect.depend_line.update(node.depend_line)
                temp=set()
                for i in node.depend_line:
                    temp.add(i.addr)
                if(node.get_node() not in affect.depend_in_block):
                    affect.depend_in_block[node.get_node()]=temp
                else:
                    affect.depend_in_block[node.get_node()].update(temp)

    #get affect data        
    data_affect_total=extracte_affect_data2addr(affected2addr)
    #global tracking
    data_affected=data_affect_total[0]

    #in block tracking
    #Instructions similar to CMP need special processing, that is, instructions other than mov instructions need to be processed
    #CMP instruction special handling
    data_cmp=data_affect_total[1]

    
    data_affect_sepreat=get_data_affect_separte(affected2addr)
    #print_dependency(affected2addr)
    #print_affected(affected2addr)

    data_from=data_affected[target_addr]

    no_assignment=get_is_assignment(affected2addr,target_addr,data_from)
    
    #print('no_assignment:',no_assignment)
    if(no_assignment):
        affected2addr=from_graph_get_affected(data)
        filter_affected(affected2addr)
        affected2addr.sort()
        for affect in affected2addr:
            affect.find_dependency()
        data_affect_total=extracte_affect_data(affected2addr)
        data_affected=data_affect_total[0]
        data_cmp=data_affect_total[1]
        data_affect_sepreat=get_data_affect_separte(affected2addr)
        data_from=data_affected[target_addr]


    temp_addr=int(target_addr,0)
    current_loc_key = next(iter(ircfg.getby_offset(temp_addr)))
    current_block = ircfg.get_block(current_loc_key)
    data_to=set()
    if(target_addr not in data_affected):
        return data_to
    data_from_cmp=set()
    if(target_addr in data_cmp):
        target_is_cmp=True
        data_from_cmp=data_cmp[target_addr]
    else:
        target_is_cmp=False

    for assignblk_index, assignblk in enumerate(current_block):
        if str(hex(assignblk.instr.offset)) == target_addr:
            currend_line=assignblk_index
            if('CALL' in assignblk.instr.name):
                is_call=True
            else:
                is_call=False
            break
    if(is_call):
        data_from=[target_addr]

    track_data_in_black=set()

    #print('target_is_cmp',target_is_cmp)
    data_from=list(data_from)
    data_from.sort()
    a=list(reversed(data_from))
    
    #print('data_from',a)
    #print('data_from_cmp',data_from_cmp)
    #Get instructions affected by current block
    
    track_data=track_block(ircfg,current_loc_key,assignblk_index,data_affected,target_is_cmp,data_from,
                        data_from_cmp,data_from_where_separte,data_affect_sepreat)
    data_to.update(track_data[0])
    track_data_in_black.update(track_data[1])
    todo=set()
    for succs in ircfg.successors_iter(current_loc_key):
        todo.add(succs)

    resolved=set()

    #Breadth first traversal for processing
    while todo:
        loc_key=todo.pop()
        #print(loc_key)
        if(loc_key in resolved):
            continue
        resolved.add(loc_key)
        #track data in block
        track_data=track_block(ircfg,loc_key,0,data_affected,target_is_cmp,data_from,data_from_cmp,
                        data_from_where_separte,data_affect_sepreat)
        data_to.update(track_data[0])
        track_data_in_black.update(track_data[1])
        for succs in ircfg.successors_iter(loc_key):
            if(succs not in resolved):
                todo.add(succs)    
    #Looking for affected instructions in the current block
    a=list(data_to)
    a.sort()
    print('------------data_to_no_recall:---------')
    for i in a:
        print(i)
    data_to.update(track_data_in_black)
    data_to.add(target_addr)
    data_to=list(set(data_to))
    data_to.sort()
    track_data_in_black=list(track_data_in_black)
    track_data_in_black.sort()
    #print('track_data_in_block:',track_data_in_black)
    return data_to

def deal_circular_dependencies(dependency):

    for depend in dependency:
        temp_depend=depend.depend_loc_key_line
        temp_depend=list(set(temp_depend))
        temp_node=set([])
        #print(type(depend))
        #print(('depend:',depend))
        temp_depend.sort()
        for node in depend.dependency:
            temp_node.update(node.depend_loc_key_line)
        temp_node=list(temp_node)
        temp_node.sort()
        if(len(temp_depend)<len(temp_node)):
            depend.depend_loc_key_line=temp_node

#Where does the data come from
def get_depend_from(target_addr,data):
    dependency=from_graph_get_dependcy(data)

    for depend in dependency:
        depend.find_dependency()
   
    deal_circular_dependencies(dependency)
    #print_dependency(dependency)
    data_from_separte=data_from_where_separte(dependency)

    data_from=data_from_where(dependency)


    data1=[]
    if(target_addr in data_from):
        data1=list(data_from[target_addr])
    data1.append(target_addr)
    data1=list(set(data1))
    data1.sort()
    return [data1,data_from_separte]

#where will the data go version2
def get_data_to_2(target_addr,data,ircfg,data_from_separte):
    affected=from_graph_get_affected2(data)
    filter_affected(affected)

    for affect in affected:
        pass

def gen_block_data_flow_graph(ir_arch, ircfg, ad, target_addr):
    

    dead_simp(ir_arch, ircfg)

    recovery_call(ircfg)

    #with open('E:\\forwardwork\\ircfg.dot','w') as file:
    #    file.write(ircfg.dot())

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
    for label in ircfg.blocks:
        irb_in_nodes[label] = {}
        irb_out_nodes[label] = {}
    #Handle every block here
    #Obtain the corresponding first-order dependency
    for label, irblock in viewitems(ircfg.blocks):
        intra_block_flow_raw(ir_arch, ircfg, flow_graph, irblock, irb_in_nodes[label], irb_out_nodes[label])
        # print('in',irb_in_nodes)
        # print('out',irb_out_nodes)

    #Get the corresponding link relationship
    inter_block_flow(ir_arch, ircfg, flow_graph, irblock_0.loc_key, irb_in_nodes, irb_out_nodes)

    # from graph_qt import graph_qt
    #open('E:\\forwardwork\\data.dot', 'w').write(flow_graph.dot())
    
    #Get the corresponding first-order dependence
    data=flow_graph.dot_data()

    
    data_from=[]
    data_from=get_depend_from(target_addr,data)
    data_to=get_depend_to(target_addr,data,ircfg,data_from[1])

    return [data_from[0],data_to]

def data_analysis(filename,func_addr,target_addr):

    ad = func_addr

    #print('disasm...')
    cont = Container.from_stream(open(filename, 'rb'))
    machine = Machine(cont.arch)

    mdis = machine.dis_engine(cont.bin_stream, loc_db=cont.loc_db, dont_dis_nulstart_bloc=True)
    
    mdis.follow_call = True
    asmcfg = mdis.dis_multiblock(ad)
    #asmcfg = mdis.dis_multiblock(ad,0)
    #print('ok')


    #print('generating dataflow graph for:')
    ir_arch_analysis = machine.ira(mdis.loc_db)
    ircfg = ir_arch_analysis.new_ircfg_from_asmcfg(asmcfg)

    #with open('E:\\forwardwork\\ircfg.dot','w') as file:
    #    file.write(ircfg.dot())
    #with open('E:\\forwardwork\\asmcfg.dot','w') as file:
    #    file.write(asmcfg.dot())


    
    data=gen_block_data_flow_graph(ir_arch_analysis, ircfg, ad, str(hex(target_addr)))

    return data
    #print('*' * 40)

def main_ww():
    time_start=time.time()
    #data=data_analysis(r'E:\forwardwork\data_analysis.so',0x82f,0x8e0)
    #data=data_analysis(r'D:\ustc\singapore_project2\procedure\libfreetype_253.so',0xa4f40,0xa4fed)
    #data=data_analysis(r'D:\ustc\singapore_project2\procedure\curl_7.19.5.so',0x4F178,0x4F378)
    #data=data_analysis(r'E:\forwardwork\libopenjp2.so.2.2.0_2.2.0.so',0x33E11,0x33Fb1)
    data=data_analysis(r'E:\share\test.so',0x692,0x6be)
    
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
