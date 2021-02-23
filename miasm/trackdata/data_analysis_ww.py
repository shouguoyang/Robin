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



class DependencyNode(object):
    def __init__(self,loc_key,line_nb,dst_or_src,instr,node_id,addr,assembly):
        self.loc_key=loc_key
        self.line_nb=line_nb
        self.dst_or_src=dst_or_src
        self.node_id=node_id
        self.dependency=set()
        self.instr=instr
        self.tracked=False
        self.addr=str(hex(addr))
        self.assembly=assembly
        #The corresponding path passed
        self.depend_line=set()
        self.depend_loc_key_line=set()
        #The form of the intermediate expression of the final result
        self.depend_loc_key_instr={}

    def __lt__(self, other):
        if(self.loc_key<other.loc_key):
            return True
        elif(self.loc_key==other.loc_key):
            return self.line_nb<other.line_nb
        else:
            return False
    def __eq__(self,other):
        return (self.loc_key==other.loc_key and self.line_nb==other.line_nb and 
                self.dst_or_src==other.dst_or_src and self.instr==other.instr)

    def get_addr_assembly(self):
        return (self.addr,self.assembly)

    def __contains__(self,node):
        return node==self

    def get_node(self):
        return (self.loc_key,self.line_nb,self.dst_or_src,self.addr,self.instr)

    def add_dependency(self,node):
        self.dependency.add(node)

    def remove_dependency(self,node):
        self.dependency.remove(node)
        

    #Internal tracking to get the real source of data
    def find_dependency(self):
        not_track=["RBP","RSP","RIP"]
        if(not self.tracked):
            self.tracked=True
            for node in self.dependency:
                if(len(node.dependency)==0):
                    self.depend_loc_key_line.add((node.loc_key,node.line_nb,node.addr,node.assembly))
                    if (node.get_node() not in self.depend_loc_key_instr):
                        self.depend_loc_key_instr[node.get_node()]=set([node.addr])
                    else:
                        self.depend_loc_key_instr[node.get_node()].add(node.addr)
                    continue
                if(node.tracked):
                    self.depend_loc_key_line.update(node.depend_loc_key_line)
                    self.depend_loc_key_line.add((node.loc_key,node.line_nb,node.addr,node.assembly))
                    temp=set()
                    for i in node.depend_loc_key_line:
                        i=list(i)
                        temp.add(i[2])
                    temp.add(node.addr)
                    if(node.get_node() not in self.depend_loc_key_instr):
                        self.depend_loc_key_instr[node.get_node()]=temp
                    else:
                        self.depend_loc_key_instr[node.get_node()].update(temp)
                    continue 
                if(isinstance(node.instr,ExprId) and node.instr.name in not_track):
                    continue
                if(isinstance(node.instr,ExprInt)):
                    self.depend_loc_key_line.add((node.loc_key,node.line_nb,node.addr,node.assembly))
                    temp=set()
                    for i in node.depend_loc_key_line:
                        i=list(i)
                        temp.add(i[2])
                    temp.add(node.addr)
                    if(node.get_node() not in self.depend_loc_key_instr):
                        self.depend_loc_key_instr[node.get_node()]=temp
                    else:
                        self.depend_loc_key_instr[node.get_node()].update(temp)
                    continue

                node.find_dependency()
                self.depend_loc_key_line.update(node.depend_loc_key_line)
                self.depend_loc_key_line.add((node.loc_key,node.line_nb,node.addr,node.assembly))
                temp=set()
                for i in node.depend_loc_key_line:
                    i=list(i)
                    temp.add(i[2])
                temp.add(node.addr)
                if(node.get_node() not in self.depend_loc_key_instr):
                    self.depend_loc_key_instr[node.get_node()]=temp
                else:
                    self.depend_loc_key_instr[node.get_node()].update(temp)
       

class AffectedNodes(object):

    def __init__(self,loc_key,line_nb,dst_or_src,instr,node_id,addr,assembly):
        self.loc_key=loc_key
        self.line_nb=line_nb
        self.dst_or_src=dst_or_src
        self.node_id=node_id
        self.dependency=set()
        self.instr=instr
        self.tracked=False
        self.tracked_in_block=False
        self.addr=str(hex(addr))
        self.assembly=assembly
        #The corresponding path passed
        self.depend_line=set()
        self.depend_in_block={}
        self.cmp_deal=[]

    def __lt__(self, other):
        if(self.loc_key<other.loc_key):
            return True
        elif(self.loc_key==other.loc_key):
            return self.line_nb<other.line_nb
        else:
            return False
    def __eq__(self,other):
        return (self.loc_key==other.loc_key and self.line_nb==other.line_nb and 
                self.dst_or_src==other.dst_or_src and self.instr==other.instr)

    def get_addr_assembly(self):
        return (self.addr,self.assembly)

    def __contains__(self,node):
        return node==self

    def get_node(self):
        return (self.loc_key,self.line_nb,self.dst_or_src,self.addr,self.instr)

    def add_dependency(self,node):
        self.dependency.add(node)

    def remove_dependency(self,node):
        self.dependency.remove(node)

  

    #Internal tracking to get the real source of data
    def find_dependency(self):
        not_track=["RBP","RSP","RIP"]
        cmp_data=['zf','of','nf']
        if(not self.tracked and len(self.dependency)!=0):
            self.tracked=True
            for node in self.dependency:
                #CMP instructions need special handling
                # if(isinstance(self.instr,ExprId) and self.instr.name in cmp_data):
                #     if(not node.tracked):
                #         node.find_dependency()
                #     temp=list(set(node.depend_line))
                #     temp.sort()
                #     if temp not in self.cmp_deal:
                #         self.cmp_deal.append(temp)
                
                #Not mov instructions need special handling
                if("MOV" not in self.assembly):
                    if(not node.tracked):
                        node.find_dependency()
                    temp=list(set(node.depend_line))
                    temp.sort()
                    if temp not in self.cmp_deal:
                        self.cmp_deal.append(temp)

                if(len(node.dependency)==0):
                    self.depend_line.add(node)
                    if(node.get_node() not in self.depend_in_block):
                        self.depend_in_block[node.get_node()]=set([node.instr])
                    else:
                        self.depend_in_block[node.get_node()].add(node.instr)
                    continue
                if(node.tracked):
                    self.depend_line.update(node.depend_line)
                    temp=set()
                    for i in node.depend_line:
                        temp.add(i.instr)
                    if(node.get_node() not in self.depend_in_block):
                        self.depend_in_block[node.get_node()]=temp
                    else:
                        self.depend_in_block[node.get_node()].update(temp)
                    continue
                if(isinstance(node.instr,ExprId) and node.instr.name in not_track):
                    continue

                node.find_dependency()
                self.depend_line.update(node.depend_line)
                temp=set()
                for i in node.depend_line:
                    temp.add(i.instr)
                if(node.get_node() not in self.depend_in_block):
                    self.depend_in_block[node.get_node()]=temp
                else:
                    self.depend_in_block[node.get_node()].update(temp)
                

class AffectedNodes2addr(object):

    def __init__(self,loc_key,line_nb,dst_or_src,instr,node_id,addr,assembly):
        self.loc_key=loc_key
        self.line_nb=line_nb
        self.dst_or_src=dst_or_src
        self.node_id=node_id
        self.dependency=set([])
        self.instr=instr
        self.tracked=False
        self.tracked_in_block=False
        self.addr=str(hex(addr))
        self.assembly=assembly
        #The corresponding path passed
        self.depend_line=set([])
        self.depend_in_block={}
        self.cmp_deal=[]

    def __lt__(self, other):
        if(self.loc_key<other.loc_key):
            return True
        elif(self.loc_key==other.loc_key):
            return self.line_nb<other.line_nb
        else:
            return False
    
    def __eq__(self,other):
        return (self.loc_key==other.loc_key and self.line_nb==other.line_nb and 
                self.dst_or_src==other.dst_or_src and self.instr==other.instr)

    def get_addr_assembly(self):
        return (self.addr,self.assembly)

    def __contains__(self,node):
        return node==self

    def get_node(self):
        return (self.loc_key,self.line_nb,self.dst_or_src,self.addr,self.instr)

    def add_dependency(self,node):
        self.dependency.add(node)

    def remove_dependency(self,node):
        self.dependency.remove(node)

    #Internal tracking to get the real source of data
    def find_dependency(self):
        not_track=["RBP","RSP","RIP"]
        cmp_data=['zf','of','nf']
        # if(self.addr=='0xa3ba' and isinstance(self.instr,ExprMem)):
        #     print('\n'+'1'*20)
        #     print('self:',self)
        #     print('self.tracked:',self.tracked)
        #     print('self.get_node:',self.get_node())
        #     print('sefl.depend_line:',self.depend_line)
        #     print('1'*20)
        #     print('')

        # if(self.addr=='0xa33d'): 
        #     print('2'*20)
        #     print('self.tracked:',self.tracked)
        #     print(self.get_node(),end='')
        #     print(':')
        #     print('self.depend_line')
        #     print(self.depend_line)
        #     for j in self.depend_line:
        #         print(j.get_node())     
        #     print('-'*20)
        #     for i in self.dependency:
        #         print('i:',i)
        #         print('i.tracked:',i.tracked)
        #         print('i.depend_line:',i.depend_line)
        #         print('i.get_node:',i.get_node(),end='')
        #         print(':')
        #         for j in i.depend_line:
        #             print(j.get_node())
        #         print('^'*10)
        #     print('2'*20)
        #     print(' ')


        if(not self.tracked):
            self.tracked=True
            for node in self.dependency:
                # if("MOV" not in self.assembly):                     
                #     if(not node.tracked):
                #         node.find_dependency()
                #     #self.depend_line.update(node.depend_line)
                #     temp=list(set(node.depend_line))
                #     temp.sort()
                #     if temp not in self.cmp_deal:
                #         self.cmp_deal.append(temp)
                if(len(node.dependency)==0):
                    # depend_line 保存的是对应的节点node 对象
                    self.depend_line.add(node)
                    if(node.get_node() not in self.depend_in_block):
                        self.depend_in_block[node.get_node()]=set([node.addr])
                        # print(node.get_node(),node.addr)
                    else:
                        self.depend_in_block[node.get_node()].add(node.addr)
                    continue
                if(node.tracked):
                    self.depend_line.update(node.depend_line)
                    temp=set()
                    for i in node.depend_line:
                        temp.add(i.addr)
                    if(node.get_node() not in self.depend_in_block):
                        self.depend_in_block[node.get_node()]=temp
                    else:
                        self.depend_in_block[node.get_node()].update(temp)
                    # print(node.get_node(),temp)
                    
                    if("MOV" not in self.assembly):                     
                        if(not node.tracked):
                            node.find_dependency()
                        temp=list(set(node.depend_line))
                        temp.sort()
                        if temp not in self.cmp_deal:
                            self.cmp_deal.append(temp)
                    continue
                if(isinstance(node.instr,ExprId) and node.instr.name in not_track):
                    continue
                node.find_dependency()
                self.depend_line.update(node.depend_line)
                temp=set()
                for i in node.depend_line:
                    temp.add(i.addr)
                if(node.get_node() not in self.depend_in_block):
                    self.depend_in_block[node.get_node()]=temp
                else:
                    self.depend_in_block[node.get_node()].update(temp)
                print(node.get_node(),temp)
                if("MOV" not in self.assembly):      
                    temp=list(set(node.depend_line))
                    temp.sort()
                    if temp not in self.cmp_deal:
                        self.cmp_deal.append(temp)


        # if(self.addr=='0xa3ba' and isinstance(self.instr,ExprMem)):
        #     print('\n'+'1'*20)
        #     print('self:',self)
        #     print('self.tracked:',self.tracked)
        #     print('self.get_node:',self.get_node())
        #     print('sefl.depend_line:',self.depend_line)
        #     print('1'*20)
        #     print('')


class TrackResult(object):
    def __init__(self,func_addr,track_addr):
        self.func_addr=func_addr
        self.track_addr=track_addr
    
    def __eq__(self,other):
        return(self.track_addr==other.track_addr)

    def __it__(self,other):
        if(self.track_addr<other.track_addr):
            return True
        else:
            return False
    
    def set_data_from(self,data_from):
        self.data_from=data_from

    def set_data_to(self,data_to):
        self.data_to=data_to

    def print_track_result(self):
        print('func_addr :',str(hex(self.func_addr)))
        print('track_addr:',self.track_addr)
        print('data_from :',self.data_from)
        print('data_to   :',self.data_to)
        print('')