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
    '''#This class mainly stores the content of the data forward slice'''
    def __init__(self,loc_key,line_nb,dst_or_src,instr,node_id,addr,assembly):
        self.loc_key=loc_key
        self.line_nb=line_nb
        self.dst_or_src=dst_or_src
        self.node_id=node_id
        self.dependency=set([])
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

    def __hash__(self):
        return hash(self.loc_key+str(self.line_nb)+str(self.dst_or_src))

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
        
    #The main function of this function is to take a recursive
    #backtracking method to view the dependence of the corresponding instruction
    #Internal tracking to get the real source of data
    #Here we mainly look up the dependent address
    def find_dependency(self):
        not_track=["RBP","RSP","RIP"]
        if(not self.tracked):
            self.tracked=True
            for node in self.dependency:
                # if(self.addr=='0x1347d'):
                #     print(self.assembly)
                #     print(node.assembly)
                #     print('')
                #The current instruction has no use for backward dependencies
                if(len(node.dependency)==0):
                    self.depend_loc_key_line.add((node.loc_key,node.line_nb,node.addr,node.assembly))
                    if (node.get_node() not in self.depend_loc_key_instr):
                        self.depend_loc_key_instr[node.get_node()]=set([node.addr])
                    else:
                        self.depend_loc_key_instr[node.get_node()].add(node.addr)
                    continue
                
                #If the backward dependent items have been processed,
                #they will be added directly and will not be processed accordingly.
                if(node.tracked):
                    self.depend_loc_key_line.update(node.depend_loc_key_line)
                    if(self.assembly!=node.assembly):
                        self.depend_loc_key_line.add((node.loc_key,node.line_nb,node.addr,node.assembly))
                    temp=set()
                    for i in node.depend_loc_key_line:
                        i=list(i)
                        temp.add(i[2])
                    if(self.assembly!=node.assembly):
                        temp.add(node.addr)
                    if(node.get_node() not in self.depend_loc_key_instr):
                        self.depend_loc_key_instr[node.get_node()]=temp
                        #This is stored as a dictionary
                    else:
                        self.depend_loc_key_instr[node.get_node()].update(temp)
                    continue 

                #
                if(isinstance(node.instr,ExprId) and node.instr.name in not_track):
                    continue


                if(isinstance(node.instr,ExprInt)):
                    self.depend_loc_key_line.add((node.loc_key,node.line_nb,node.addr,node.assembly))
                    temp=set()
                    for i in node.depend_loc_key_line:
                        i=list(i)
                        temp.add(i[2])
                    if(self.assembly!=node.assembly):
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
                if(self.assembly!=node.assembly):
                    temp.add(node.addr)
                if(node.get_node() not in self.depend_loc_key_instr):
                    self.depend_loc_key_instr[node.get_node()]=temp
                else:
                    self.depend_loc_key_instr[node.get_node()].update(temp)


class AffectedNodes(object):
    """[这个结构保存对应的指令的依赖关系，这里只需要跟踪到对应的 [rbp+offset] 这种类似的结构就可以了
        或者跟踪到没有跟踪的地方就可以了，反正对应的指令要么依赖于 [rbp+offset] 这种形式，要么就只依赖于特定的寄存器的形式]
    """
    '''This class mainly refers to the data structure used in forward slicing, the backward 
    tracking of advanced row data, and stopping tracking when tracking to [RBP + offset]'''
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
        self.depend_separte={}  # 保存对应的依赖节点的指令
        self.depend_line_addr=set([]) # 这里保存对应的依赖的节点
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
    def __hash__(self):
        return hash(self.loc_key+str(self.line_nb)+str(self.dst_or_src))

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
    #This function is mainly used to search the instruction 
    #source recursively and find the form of [RBP + offset] to stop
    def find_dependency(self):
        not_track=["RBP","RSP","RIP"]
        cmp_data=['zf','of','nf']
        if(not self.tracked):
            self.tracked=True 
            for node in self.dependency:
                if(isinstance(self.instr,ExprId) and self.instr.name in not_track):
                    break
                if(isinstance(node.instr,ExprId) and node.instr.name in not_track):
                    continue
                if(len(node.dependency)==0 and isinstance(node.instr,ExprInt)):
                    continue

                #这里追踪到对应的指令依赖于 [rbp+offset] 的时候停止，对应的指令没有依赖的时候停止跟踪
                if(isinstance(node.instr,ExprMem) or len(node.dependency)==0):
                    self.depend_line.add(node)    # 这里保存依赖的node节点,只需要保存对应依赖的node就可以了。
                    #self.depend_line_addr.add(node.addr)
                    if(node.get_node() not in self.depend_separte):
                        self.depend_separte[node.get_node()]=set([node.instr])   # 保存对应的依赖的指令
                    else:
                        self.depend_separte[node.get_node()].add(node.instr)
                    continue
                if(node.tracked):
                    self.depend_line.update(node.depend_line)
                    self.depend_line_addr.update(node.depend_line_addr)
                    self.depend_line_addr.add(node.addr)
                    temp=set()
                    for i in node.depend_line:
                        temp.add(i.instr)
                    if(node.get_node() not in self.depend_separte):
                        self.depend_separte[node.get_node()]=temp
                    else:
                        self.depend_separte[node.get_node()].update(temp)
                    continue

                if(isinstance(node.instr,ExprId) and node.instr.name in not_track):
                    continue
                node.find_dependency()
                self.depend_line.update(node.depend_line)
                self.depend_line_addr.update(node.depend_line_addr)
                self.depend_line_addr.add(node.addr)
                temp=set()
                for i in node.depend_line:
                    temp.add(i.instr)
                if(node.get_node() not in self.depend_separte):
                    self.depend_separte[node.get_node()]=temp
                else:
                    self.depend_separte[node.get_node()].update(temp)
            

            if(not isinstance(self.instr,ExprInt) and len(self.dependency)==0):
                self.depend_separte[self.get_node()]=set([self.instr])
                if(isinstance(self.instr,ExprId) and self.instr.name in not_track):
                    self.depend_separte={}

            #CMP instruction and lea instruction do not need to be considered separately
            # cmp 指令需要分开考虑，不是cmp 合并跟踪就可以了
            if('CMP' not in self.assembly):
                if(not isinstance(self.instr,ExprInt)):
                    temp=set([])
                    for key in self.depend_separte.keys():
                        temp.update(self.depend_separte[key])
                    self.depend_separte={}
                    self.depend_separte[self.get_node()]=temp
                

class AffectedNodes2addr(object):
    """[summary]
    这个结构保存的是每条指令最终的define结构，跟踪出每个节点的最总define关系
    """
    #This class is mainly used for forward slicing, but it mainly saves sh
    def __init__(self,loc_key,line_nb,dst_or_src,instr,node_id,addr,assembly):
        self.loc_key=loc_key
        self.line_nb=line_nb
        self.dst_or_src=dst_or_src
        self.node_id=node_id
        self.dependency=set([])
        self.instr=instr
        self.tracked=False
        self.addr=str(hex(addr))
        self.assembly=assembly
        #The corresponding path passed
        self.depend_line=set([])  # 这里保存的是依赖的节点
        self.depend_separte={}   # 这里保存的是对应的依赖的指令
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

    def __hash__(self):
        return hash(self.loc_key+str(self.line_nb)+str(self.dst_or_src))
        
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
        if(not self.tracked):
            self.tracked=True 
            #这里跟踪对应的指令，保存依赖的所有依赖的对象和依赖的指令
            for node in self.dependency:
                if(isinstance(self.instr,ExprId) and self.instr.name in not_track):
                    break
                if(isinstance(node.instr,ExprId) and node.instr.name in not_track):
                    continue
                if(len(node.dependency)==0 and isinstance(node.instr,ExprInt)):
                    continue
                if(isinstance(node.instr,ExprMem) or len(node.dependency)==0):
                    self.depend_line.add(node)
                    if(node.get_node() not in self.depend_separte):
                        self.depend_separte[node.get_node()]=set([node.instr])
                    else:
                        self.depend_separte[node.get_node()].add(node.instr)
                    continue
                if(node.tracked):
                    self.depend_line.update(node.depend_line)
                    temp=set()
                    for i in node.depend_line:
                        temp.add(i.instr)
                    if(node.get_node() not in self.depend_separte):
                        self.depend_separte[node.get_node()]=temp    #这里保存的是对应的指令，一条指令分开保存，保存对应的操作寄存器的依赖关系
                    else:
                        self.depend_separte[node.get_node()].update(temp)   #这里把保存对应的指令依赖关系

                    continue

                if(isinstance(node.instr,ExprId) and node.instr.name in not_track):
                    continue
                node.find_dependency()
                self.depend_line.update(node.depend_line)
                temp=set()
                for i in node.depend_line:
                    temp.add(i.instr)
                if(node.get_node() not in self.depend_separte):
                    self.depend_separte[node.get_node()]=temp
                else:
                    self.depend_separte[node.get_node()].update(temp)
            

            #如果不是常数，则当前指令也依赖自己
            if(not isinstance(self.instr,ExprInt) and len(self.dependency)==0):
                self.depend_separte[self.get_node()]=set([self.instr])
                if(isinstance(self.instr,ExprId) and self.instr.name in not_track):
                    self.depend_separte={}

            #CMP instruction and instruction do not need to be considered separately
            #不是cmp 指令需要分开考虑
            if('CMP' not in self.assembly):
                if(not isinstance(self.instr,ExprInt)):
                    temp=set([])
                    for key in self.depend_separte.keys():
                        temp.update(self.depend_separte[key])
                    self.depend_separte={}
                    self.depend_separte[self.get_node()]=temp
            

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

    def print_data_from(self):
        print('func_addr :',str(hex(self.func_addr)))
        print('track_addr:',self.track_addr)
        print('data_from :',self.data_from)
        print('')
    
    def print_data_to(self):
        print('func_addr :',str(hex(self.func_addr)))
        print('track_addr:',self.track_addr)
        print('data_to   :',self.data_to)
        print('')

    def print_track_result(self):
        print('func_addr :',str(hex(self.func_addr)))
        print('track_addr:',self.track_addr)
        print('data_from :',self.data_from)
        print('data_to   :',self.data_to)
        print('')