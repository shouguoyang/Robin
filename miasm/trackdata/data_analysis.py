from __future__ import print_function

from future.utils import viewitems

from builtins import object
from functools import cmp_to_key
from miasm.expression.expression \
    import get_expr_mem, ExprId, ExprInt, \
    compare_exprs
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.expression.expression import *

def get_node_name(label, i,r_or_w, n,addr,instruction):
    #0: read
    #1: write
    n_name = (str(label), i,r_or_w, n,addr,instruction)
    return n_name

def filter_node(n_r):
    if(isinstance(n_r,ExprMem) and hasattr(n_r,'ptr') and isinstance(n_r.ptr,ExprOp)):
        op=n_r.ptr
        args=op.args
        replace_arg=['RCX','RBX']
        if(len(args)==2):
            arg0=args[0]
            arg1=args[1]
            if(isinstance(arg0,ExprId) and arg0.name in replace_arg):
                arg0=ExprId('RAX',64)
            if(isinstance(arg1,ExprId) and arg1.name in replace_arg):
                arg1=ExprId('RAX',64)
            n_r1=ExprMem(ExprOp(op.op,arg0,arg1),n_r.size)
            #print(n_r1)
            return n_r1
    return n_r

def intra_block_flow_raw(ir_arch, ircfg, flow_graph, irb, in_nodes, out_nodes):
    """
    Create data flow for an irbloc using raw IR expressions
    """
    current_nodes = {}
    have_print={}
    for i, assignblk in enumerate(irb):
        if(assignblk.instr==None):
            continue
        dict_rw = assignblk.get_rw(cst_read=True)
        current_nodes.update(out_nodes)
        # gen mem arg to mem node links
        all_mems = set()
        for node_w, nodes_r in viewitems(dict_rw):
            if('MOV' in assignblk.instr.name or "LEA" in assignblk.instr.name):
                break
            for n in nodes_r.union([node_w]):
                all_mems.update(get_expr_mem(n))
            if not all_mems:
                continue
            for n in all_mems:
                node_n_w = get_node_name(irb.loc_key, i,1, n,assignblk.instr.offset,str(assignblk.instr))
                if not n in nodes_r:
                    continue
                o_r = n.ptr.get_r(mem_read=False, cst_read=True)
                for n_r in o_r:
                    if n_r in current_nodes:
                        node_n_r = current_nodes[n_r]
                    else:
                        node_n_r = get_node_name(irb.loc_key, i,0, n_r,assignblk.instr.offset,str(assignblk.instr))
                        current_nodes[n_r] = node_n_r
                        in_nodes[n_r] = node_n_r
                    flow_graph.add_uniq_edge(node_n_r, node_n_w)


        # gen data flow links
        for node_w, nodes_r in viewitems(dict_rw):
            for n_r in nodes_r:
                temp_n_r=filter_node(n_r)
                #temp_n_r=n_r
                if temp_n_r in current_nodes:
                    node_n_r = current_nodes[temp_n_r]
                else:
                    if(isinstance(n_r,ExprMem)):
                        node_n_r = get_node_name(irb.loc_key, i,1, temp_n_r,assignblk.instr.offset,str(assignblk.instr))
                    else:
                        node_n_r = get_node_name(irb.loc_key, i,0, temp_n_r,assignblk.instr.offset,str(assignblk.instr))
                    #node_n_r = get_node_name(irb.loc_key, i,0, n_r)
                    current_nodes[temp_n_r] = node_n_r
                    in_nodes[temp_n_r] = node_n_r
                
                flow_graph.add_node(node_n_r)
                temp_node_w=filter_node(node_w)
                node_n_w = get_node_name(irb.loc_key, i ,1, node_w,assignblk.instr.offset,str(assignblk.instr))
                out_nodes[temp_node_w] = node_n_w
                # if(assignblk.instr.offset==0xa33d):
                #    print('n_r',(1,temp_n_r))
                #    print('node_n_r',node_n_r)
                #    print('node_w',(1,temp_node_w))
                #    print('node_n_w',node_n_w)
                #    print('current_nodes[n_r])',(1,current_nodes[temp_n_r])) 
                flow_graph.add_node(node_n_w)
                flow_graph.add_uniq_edge(node_n_r, node_n_w)
            
            #deal  mem node_w
            if(isinstance(node_w,ExprMem)):
                track_args=['RAX','RBX','RCX']
                write_w=node_w.ptr.get_r(mem_read=False,cst_read=True)
                write_w=[x for x in write_w if(isinstance(x,ExprId) and x.name in track_args)]
                node_n_w = get_node_name(irb.loc_key, i ,1, node_w,assignblk.instr.offset,str(assignblk.instr))
                for temp in write_w:
                    if(temp in current_nodes):
                        node_n_r=current_nodes[temp]
                        flow_graph.add_uniq_edge(node_n_r, node_n_w)
                if(assignblk.instr.offset==0x8dc or assignblk.instr.offset==0x8f3):
                   print(write_w)
                   for temp in write_w:
                       node_n_r=current_nodes[temp]
                       flow_graph.add_uniq_edge(node_n_r, node_n_w)
                       print(' ',(1,current_nodes[temp]))
                   print('')
            
            ## deal mem node_r
            if('MOV' in assignblk.instr.name or "LEA" in assignblk.instr.name):
                for n_r in nodes_r:
                    if(isinstance(n_r,ExprMem)):
                        track_args=['RAX','RBX','RCX']
                        read_r=n_r.ptr.get_r(mem_read=False,cst_read=True)
                        read_r=[x for x in read_r if(isinstance(x,ExprId) and x.name in track_args)]
                        node_n_w = get_node_name(irb.loc_key, i ,1, node_w,assignblk.instr.offset,str(assignblk.instr))
                        for temp in read_r:
                            if temp in current_nodes:
                                node_n_r=current_nodes[temp]
                                flow_graph.add_uniq_edge(node_n_r, node_n_w)
        





def inter_block_flow_link(ir_arch, ircfg, flow_graph, irb_in_nodes, irb_out_nodes, todo, link_exec_to_data):
    lbl, current_nodes, exec_nodes = todo
    current_nodes = dict(current_nodes)

    # print('lbl:',lbl)
    # print('current_nodes:',current_nodes)
    # print('exec_nodes:',exec_nodes)
    # print('link_exec_to_data:',link_exec_to_data)
    # link current nodes to block in_nodes
    if not lbl in ircfg.blocks:
        print("cannot find block!!", lbl)
        return set()
    irb = ircfg.blocks[lbl]
    to_del = set()
    for n_r, node_n_r in viewitems(irb_in_nodes[irb.loc_key]):
        if not n_r in current_nodes:
            continue
        flow_graph.add_uniq_edge(current_nodes[n_r], node_n_r)
        to_del.add(n_r)

    # if link exec to data, all nodes depends on exec nodes
    if link_exec_to_data:
        for n_x_r in exec_nodes:
            for n_r, node_n_r in viewitems(irb_in_nodes[irb.loc_key]):
                if not n_x_r in current_nodes:
                    continue
                if isinstance(n_r, ExprInt):
                    continue
                flow_graph.add_uniq_edge(current_nodes[n_x_r], node_n_r)

    # update current nodes using block out_nodes
    for n_w, node_n_w in viewitems(irb_out_nodes[irb.loc_key]):
        current_nodes[n_w] = node_n_w

    # get nodes involved in exec flow
    x_nodes = tuple(sorted(irb.dst.get_r(), key=cmp_to_key(compare_exprs)))

    todo = set()
    for lbl_dst in ircfg.successors(irb.loc_key):
        todo.add((lbl_dst, tuple(viewitems(current_nodes)), x_nodes))

    return todo


def create_implicit_flow(ir_arch, flow_graph, irb_in_nodes, irb_out_ndes):

    # first fix IN/OUT
    # If a son read a node which in not in OUT, add it
    todo = set(ir_arch.blocks.keys())
    while todo:
        lbl = todo.pop()
        irb = ir_arch.blocks[lbl]
        for lbl_son in ir_arch.graph.successors(irb.loc_key):
            if not lbl_son in ir_arch.blocks:
                print("cannot find block!!", lbl)
                continue
            irb_son = ir_arch.blocks[lbl_son]
            for n_r in irb_in_nodes[irb_son.loc_key]:
                if n_r in irb_out_nodes[irb.loc_key]:
                    continue
                if not isinstance(n_r, ExprId):
                    continue

                node_n_w = irb.loc_key, len(irb), n_r
                irb_out_nodes[irb.loc_key][n_r] = node_n_w
                if not n_r in irb_in_nodes[irb.loc_key]:
                    irb_in_nodes[irb.loc_key][n_r] = irb.loc_key, 0, n_r
                node_n_r = irb_in_nodes[irb.loc_key][n_r]
                for lbl_p in ir_arch.graph.predecessors(irb.loc_key):
                    todo.add(lbl_p)

                flow_graph.add_uniq_edge(node_n_r, node_n_w)


def inter_block_flow(ir_arch, ircfg, flow_graph, irb_0, irb_in_nodes, irb_out_nodes, link_exec_to_data=True):

    todo = set()
    done = set()
    todo.add((irb_0, (), ()))

    while todo:
        state = todo.pop()
        if state in done:
            continue
        done.add(state)
        out = inter_block_flow_link(ir_arch, ircfg, flow_graph, irb_in_nodes, irb_out_nodes, state, link_exec_to_data)
        todo.update(out)


class symb_exec_func(object):

    """
    This algorithm will do symbolic execution on a function, trying to propagate
    states between basic blocks in order to extract inter-blocks dataflow. The
    algorithm tries to merge states from blocks with multiple parents.

    There is no real magic here, loops and complex merging will certainly fail.
    """

    def __init__(self, ir_arch):
        self.todo = set()
        self.stateby_ad = {}
        self.cpt = {}
        self.states_var_done = set()
        self.states_done = set()
        self.total_done = 0
        self.ir_arch = ir_arch

    def add_state(self, parent, ad, state):
        variables = dict(state.symbols)

        # get block dead, and remove from state
        b = self.ir_arch.get_block(ad)
        if b is None:
            raise ValueError("unknown block! %s" % ad)
        s = parent, ad, tuple(sorted(viewitems(variables)))
        self.todo.add(s)

    def get_next_state(self):
        state = self.todo.pop()
        return state

    def do_step(self):
        if len(self.todo) == 0:
            return None
        if self.total_done > 600:
            print("symbexec watchdog!")
            return None
        self.total_done += 1
        print('CPT', self.total_done)
        while self.todo:
            state = self.get_next_state()
            parent, ad, s = state
            self.states_done.add(state)
            self.states_var_done.add(state)

            sb = SymbolicExecutionEngine(self.ir_arch, dict(s))

            return parent, ad, sb
        return None
