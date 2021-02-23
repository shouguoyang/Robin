from __future__ import print_function
from builtins import range
from argparse import ArgumentParser
from pdb import pm
import json
import time
import sys
from future.utils import viewitems

from miasm.analysis.machine import Machine
from miasm.analysis.binary import Container
from miasm.analysis.depgraph import DependencyGraph
from miasm.expression.expression import ExprMem, ExprId, ExprInt,ExprLoc
from miasm.arch.x86.arch import mn_x86
from miasm.core.locationdb import LocationDB




def filter_register(reg):
    if(reg[0]=='E'):
        reg='R'+reg[1:]
    if(len(reg)==2 and reg[0]!='R'):
        reg='R'+reg
    if(reg[-1]=='L'):
        reg=reg[:-1]+'X'
    if(reg[-1]=='W' or reg[-1]=='B' or reg[-1]=='D'):
        reg=reg[:-1]
    return reg

def depgraph(filename,func_addr,target_addr):
    with open(filename, "rb") as fstream:
        cont = Container.from_stream(fstream)
    is_memory=0
    #contain the arch
    #fielname='D:\\ustc\\singapore_project2\\bincode_similarity\\revlent_instruction\\libfree_241.so'
    #save_filename=filename+'_'+str(func_addr)+'_'+str(target_addr)+'_'+element[0].lower()
    save_filename=filename+'_'+str(func_addr)+'_'+str(target_addr)
    arch =  cont.arch
    machine = Machine(arch)

    # Check elements
    elements =[]
    regs = machine.mn.regs.all_regs_ids_byname

    mdis = machine.dis_engine(cont.bin_stream, dont_dis_nulstart_bloc=True)
    ir_arch = machine.ira(mdis.loc_db)

    # Common argument forms

    asmcfg = mdis.dis_multiblock(int(str(func_addr), 0))
    count=0
    for i in asmcfg.blocks:
        if(count==0):
            i.lines[1].args[1]=ExprId('RBP', 64)
            #for j in i.lines:
            #    print(j)
        count=count+1
    # Generate IR
    #with open('asmcfg.dot','w') as file:
    #    file.write(asmcfg.dot())
    ircfg = ir_arch.new_ircfg_from_asmcfg(asmcfg)
    #with open('asmcfg.dot','w') as file:
    #    file.write(ircfg.dot())
    assignblks_sim=[]
    index=-1
    for block in ircfg.blocks.keys():
        #print(ircfg.blocks[block])
        for i in ircfg.blocks[block]:
            index=index+1
            if(index==0 or index==1 or index==2):
                continue
            assignblks_sim.append(i)
            #print(i)
            #print('-----\n')
        #for item in block.items:
        #    print(item)
    #print(assignblks_sim)
    #Symbolic_simulation(ir_arch,assignblks_sim)
    dg = DependencyGraph(
        ircfg
    )



    # Build information
    target_addr = int(target_addr, 0)
    try:
        current_loc_key = next(iter(ircfg.getby_offset(target_addr)))
    except StopIteration:
        return []
    assignblk_index = 0
    current_block = ircfg.get_block(current_loc_key)

    #get instruction operand
    for assignblk_index, assignblk in enumerate(current_block):
        if assignblk.instr.offset == target_addr:
            elements.extend(assignblk.instr.args)
            if assignblk.instr.is_subcall():
                assignblk_index=assignblk_index-1
            else:
                assignblk_index=assignblk_index+1
            break
    
    #replace eax to rax et.filter the reg
    temp_arg=[]
    for arg in elements:
        if(isinstance(arg,ExprId) and arg.size!=64):
            reg=filter_register(arg.name)
            reg=ExprId(reg,64)
            temp_arg.append(reg)
        elif(isinstance(arg,ExprInt) or isinstance(arg,ExprLoc)):
            continue
        else:
            temp_arg.append(arg)

    elements=set(temp_arg)

    json_solutions = []
    instr_save=open(r'E:\forwardwork\test'+'.instr','w')

    instr_relevant=[]
    loop_count=0
    result_dict={}
    #if(len(temp_arg)!=0):
    #    print(type(temp_arg[0]))
    #get the relevant instuctions
    for sol_nb, sol in enumerate(dg.get(current_block.loc_key, elements, assignblk_index, set())):
        loc_key_instr={}
        has_loop=[]
        fname = "\n\nsol_%d.dot\n" % sol_nb
        #print(sol.links)
        instr_save.write(fname)
        #get relevant lock_id---line_nb
        for i in sol.relevant_nodes:
            instr=loc_key_instr.get(i.loc_key,list())
            instr.append(i.line_nb)
            loc_key_instr[i.loc_key]=instr
        for i in loc_key_instr.keys():
            loc_key_instr[i]=list(set(loc_key_instr[i]))
        #list block from the head
        #loc_key_instr reserve block_number   line_number
        save_addr=[]
        save_disasm=[]
        for i in asmcfg.blocks:
            if(loc_key_instr.get(i.loc_key)!=None):
                for a in range(len(i.lines)):
                    if(a in loc_key_instr[i.loc_key]):
                        if ((i.lines[a].to_string()).lower()=='push       rbp' or (i.lines[a].to_string()).lower()=='mov        rbp, rsp' or 'sub        rsp' in (i.lines[a].to_string()).lower()):
                            continue
                        #if(i.lines[a].is_subcall()):
                        #    if(a==1 and len(i.lines[a-1].args)>1 and 'DI' in i.lines[a-1].args[0].name):
                        #        has_loop.append(str(hex(i.lines[a-1].offset)))
                        #        save_addr.append(str(hex(i.lines[a-1].offset))+'\t')
                        #        save_disasm.append(i.lines[a-1].to_string())
                        #    elif(a>1 and len(i.lines[a-2].args)>1 and 'SI' in i.lines[a-2].args[0].name):
                        #        has_loop.append(str(hex(i.lines[a-2].offset)))
                        #        save_addr.append(str(hex(i.lines[a-2].offset))+'\t')
                        #        save_disasm.append(i.lines[a-2].to_string())
                        #        has_loop.append(str(hex(i.lines[a-1].offset)))
                        #    elif(a>1 and len(i.lines[a-1].args)>1 and 'DI' in i.lines[a-1].args[0].name):
                        #        has_loop.append(str(hex(i.lines[a-1].offset)))
                        #        save_addr.append(str(hex(i.lines[a-1].offset))+'\t')
                        #        save_disasm.append(i.lines[a-1].to_string())

                        has_loop.append(str(hex(i.lines[a].offset)))
                        save_addr.append(str(hex(i.lines[a].offset))+'\t')
                        save_disasm.append(i.lines[a].to_string())
        
        #Determine whether there is a cycle
        count=0
        for i in has_loop:
            if(i in instr_relevant):
                count=count+1
        if(count==len(has_loop)):
            loop_count=loop_count+1
            if(loop_count==1000):
                break
        else:
            for i in range(len(save_addr)):
                instr_save.write(save_addr[i])
                instr_save.write(save_disasm[i])
                instr_save.write('\n')
        instr_relevant.extend(has_loop)
        
        #use symbolic execution get results
        results = sol.emul(ir_arch)
        tokens = {str(k): str(v) for k, v in viewitems(results)}
        for v,x in viewitems(tokens):
            temp=result_dict.get(v,list())
            if x not in temp:
                temp.append(x)
                result_dict[v]=temp
        #print(result)

    #instr_save.close()
    instr_relevant.append(str(hex(target_addr)))
    instr_relevant=list(set(instr_relevant))
    a=sorted(instr_relevant)
    b={}
    b[str(hex(target_addr))]=result_dict
    instr_save.close()
    return [a,b]

def main_ww():
    result=[]
    for i in range(1):
        start=time.time()
        #aa=depgraph(r'D:\ustc\singapore_project2\freetype_idapro6.8\libfreetype_27.so','0x3d14c','0x3d4ad', ['RDX'])
        #aa=depgraph(r'D:\ustc\singapore_project2\freetype_idapro6.8\libfreetype_241.so','0x55eff','0x5616e', ['RAX'])
        #aa=depgraph(r'D:\ustc\singapore_project2\freetype_idapro6.8\libfreetype_2411.so','0x17351','0x5616e', ['RAX'])
        #aa=depgraph(r'D:\ustc\singapore_project2\procedure\curl_7.51.0.bin','0x539a2','0x54081')
        #aa=depgraph(r'E:\share\code\test1','0x809','0x8c9')
        #aa=depgraph(r'D:\ustc\singapore_project2\procedure\curl_7.50.0','0x39C6E','0x39D3B')
        #aa=depgraph(r'D:\ustc\singapore_project2\procedure\libfreetype_253.so','0x64CCB','0x64D2D')
        target_addr=sys.argv[1]
        aa=depgraph(r'E:\forwardwork\data_analysis.so','0x82f',target_addr)
        print(aa[0])
        temp=aa[1]
        #print(temp)
        #print(len(cc))


def main_xy():
    filename = sys.argv[1]
    func_addr = sys.argv[2]
    target_addr = sys.argv[3]
    element = sys.argv[4]
    elements = [element]
    res = depgraph(filename, func_addr, target_addr)
    res.append(target_addr)
    print (res)

if __name__=="__main__":
    main_ww()
    #main_xy()