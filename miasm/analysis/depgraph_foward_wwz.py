"""Provide dependency graph"""

from functools import total_ordering

from future.utils import viewitems

from miasm.expression.expression import *
from miasm.core.graph import DiGraph
from miasm.core.locationdb import LocationDB
from miasm.expression.simplifications import expr_simp_explicit
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.ir.ir import IRBlock, AssignBlock
from miasm.ir.translators import Translator
from miasm.expression.expression_helper import possible_values

try:
    import z3
except:
    pass

@total_ordering
class DependencyNode(object):

    """Node elements of a DependencyGraph

    A dependency node stands for the dependency on the @element at line number
    @line_nb in the IRblock named @loc_key, *before* the evaluation of this
    line.
    """

    #__slots__ = ["_loc_key", "_element", "_line_nb", "_hash","loc_key", "element", "line_nb"]

    def __init__(self, loc_key, element, line_nb):
        """Create a dependency node with:
        @loc_key: LocKey instance
        @element: Expr instance
        @line_nb: int
        """
        
        self._loc_key = loc_key
        self._element = element
        self._line_nb = line_nb
        self._hash = hash(
            (self._loc_key, self._element, self._line_nb))
        
        self.element_forward = element
        self.loc_key_forward = loc_key
        self.line_nb_forward = line_nb

    def __hash__(self):
        """Returns a hash of @self to uniquely identify @self"""
        return self._hash

    def __eq__(self, depnode):
        """Returns True if @self and @depnode are equals."""
        if not isinstance(depnode, self.__class__):
            return False
        return (self.loc_key == depnode.loc_key and
                self.element == depnode.element and
                self.line_nb == depnode.line_nb)

    def __ne__(self, depnode):
        # required Python 2.7.14
        return not self == depnode

    def __lt__(self, node):
        """Compares @self with @node."""
        if not isinstance(node, self.__class__):
            return NotImplemented

        return ((self.loc_key, self.element, self.line_nb) <
                (node.loc_key, node.element, node.line_nb))

    def __str__(self):
        """Returns a string representation of DependencyNode"""
        return "<%s %s %s %s>" % (self.__class__.__name__,
                                  self.loc_key, self.element,
                                  self.line_nb)

    def __repr__(self):
        """Returns a string representation of DependencyNode"""
        return self.__str__()

    @property
    def loc_key(self):
        "Name of the current IRBlock"
        return self._loc_key

    @property
    def element(self):
        "Current tracked Expr"
        return self._element

    @property
    def line_nb(self):
        "Line in the current IRBlock"
        return self._line_nb


class DependencyState(object):

    """
    Store intermediate depnodes states during dependencygraph analysis
    """

    def __init__(self, loc_key, pending=None,forward_pending=None, line_nb=None,):
        self.loc_key = loc_key
        self.history = [loc_key]
        if(pending!=None):
            self.pending = {k: set(v) for k, v in viewitems(pending)}
        self.line_nb = line_nb
        self.links = set()
        self.pending_forward=set()

        # Init lazy elements
        self._graph = None

    def __repr__(self):
        return "<State: %r (%r) (%r)>" % (
            self.loc_key,
            self.pending,
            self.links
        )

    def extend(self, loc_key):
        """Return a copy of itself, with itself in history
        @loc_key: LocKey instance for the new DependencyState's loc_key
        """
        #Create an instance object of the current class
        new_state = self.__class__(loc_key, self.pending,self.pending_forward)
        new_state.links = set(self.links)
        new_state.history = self.history + [loc_key]
        return new_state

    def get_done_state(self):
        """Returns immutable object representing current state"""
        return (self.loc_key, frozenset(self.pending_forward))

    def as_graph(self):
        """Generates a Digraph of dependencies"""
        graph = DiGraph()
        for node_a, node_b in self.links:
            if not node_b:
                graph.add_node(node_a)
            else:
                graph.add_edge(node_a, node_b)
        for parent, sons in viewitems(self.pending):
            for son in sons:
                graph.add_edge(parent, son)
        return graph

    @property
    def graph(self):
        """Returns a DiGraph instance representing the DependencyGraph"""
        if self._graph is None:
            self._graph = self.as_graph()
        return self._graph

    def remove_pendings(self, nodes):
        """Remove resolved @nodes"""
        for node in nodes:
            del self.pending[node]

    def add_pendings(self, future_pending):
        """Add @future_pending to the state"""
        for node, depnodes in viewitems(future_pending):
            if node not in self.pending:
                self.pending[node] = depnodes
            else:
                self.pending[node].update(depnodes)

    def link_element(self, element, line_nb):
        """Link element to its dependencies
        @element: the element to link
        @line_nb: the element's line
        """

        depnode = DependencyNode(self.loc_key, element, line_nb)
        # print(',',element)
        # print(self.pending)
        if not self.pending[element]:
            # Create start node
            self.links.add((depnode, None))
        else:
            # Link element to its known dependencies
            for node_son in self.pending[element]:
                self.links.add((depnode, node_son))
        #print('self.pending',self.pending)
        #print('self.links',self.links)
    def link_dependencies_forward(self, element, line_nb, dependencies,
                          future_pending):
        """Link unfollowed dependencies and create remaining pending elements.
        @element: the element to link
        @line_nb: the element's line
        @dependencies: the element's dependencies
        @future_pending: the future dependencies
        """

        #this is a parent
        #src,Determined value
        parent = DependencyNode(self.loc_key, element, line_nb)

        # Update pending, add link to unfollowed nodes
        #dst
        for dependency in dependencies:
            #dst
            depnode = DependencyNode(
                    self.loc_key, dependency.element, line_nb)
            if not dependency.follow:
                #If it's not traceable
                # Add non followed dependencies to the dependency graph
                #dst
                self.links.add((parent, depnode))
                continue
            # Create future pending between new dependency and the current
            # element
            future_pending.setdefault(parent.element, set()).add(depnode)

    def link_dependencies(self, element, line_nb, dependencies,
                          future_pending):
        """Link unfollowed dependencies and create remaining pending elements.
        @element: the element to link
        @line_nb: the element's line
        @dependencies: the element's dependencies
        @future_pending: the future dependencies
        """

        depnode = DependencyNode(self.loc_key, element, line_nb)

        # Update pending, add link to unfollowed nodes
        for dependency in dependencies:
            if not dependency.follow:
                # Add non followed dependencies to the dependency graph
                parent = DependencyNode(
                    self.loc_key, dependency.element, line_nb)
                self.links.add((parent, depnode))
                continue
            # Create future pending between new dependency and the current
            # element
            future_pending.setdefault(dependency.element, set()).add(depnode)


class DependencyResult(DependencyState):

    """Container and methods for DependencyGraph results"""

    def __init__(self, ircfg, initial_state, state, inputs):

        super(DependencyResult, self).__init__(state.loc_key, state.pending)
        self.initial_state = initial_state
        self.history = state.history
        self.pending = state.pending
        self.line_nb = state.line_nb
        self.inputs = inputs
        self.links = state.links
        self._ircfg = ircfg

        # Init lazy elements
        self._has_loop = None

    @property
    def unresolved(self):
        """Set of nodes whose dependencies weren't found"""
        return set(element for element in self.pending
                   if element != self._ircfg.IRDst)

    @property
    def relevant_nodes(self):
        """Set of nodes directly and indirectly influencing inputs"""
        output = set()
        for node_a, node_b in self.links:
            if(node_a is not None):
                output.add(node_a)
            if node_b is not None:
                output.add(node_b)
        return output

    @property
    def relevant_loc_keys(self):
        """List of loc_keys containing nodes influencing inputs.
        The history order is preserved."""
        # Get used loc_keys
        used_loc_keys = set(depnode.loc_key for depnode in self.relevant_nodes)
        # Keep history order
        output = []
        for loc_key in self.history:
            if loc_key in used_loc_keys:
                output.append(loc_key)
        return output

    @property
    def has_loop(self):
        """True iff there is at least one data dependencies cycle (regarding
        the associated depgraph)"""
        if self._has_loop is None:
            self._has_loop = self.graph.has_loop()
        return self._has_loop

    def irblock_slice(self, irb, max_line=None):
        """Slice of the dependency nodes on the irblock @irb
        @irb: irbloc instance
        """

        assignblks = []
        line2elements = {}
        for depnode in self.relevant_nodes:
            if depnode.loc_key != irb.loc_key:
                continue
            line2elements.setdefault(depnode.line_nb,
                                     set()).add(depnode.element)

        for line_nb, elements in sorted(viewitems(line2elements)):
            if max_line is not None and line_nb >= max_line:
                break
            assignmnts = {}
            for element in elements:
                if element in irb[line_nb]:
                    # constants, loc_key, ... are not in destination
                    assignmnts[element] = irb[line_nb][element]
            assignblks.append(AssignBlock(assignmnts))

        return IRBlock(irb.loc_key, assignblks)

    def emul(self, ir_arch, ctx=None, step=False):
        """Symbolic execution of relevant nodes according to the history
        Return the values of inputs nodes' elements
        @ir_arch: IntermediateRepresentation instance
        @ctx: (optional) Initial context as dictionary
        @step: (optional) Verbose execution
        Warning: The emulation is not sound if the inputs nodes depend on loop
        variant.
        """
        # Init
        ctx_init = {}
        if ctx is not None:
            ctx_init.update(ctx)
        assignblks = []

        # Build a single assignment block according to history
        last_index = len(self.relevant_loc_keys)
        #last_index=2
        for index, loc_key in enumerate(reversed(self.relevant_loc_keys), 1):
            if index == last_index and loc_key == self.initial_state.loc_key:
                line_nb = self.initial_state.line_nb
            else:
                line_nb = None
            a=self._ircfg.blocks[loc_key],line_nb
            assignblks += self.irblock_slice(self._ircfg.blocks[loc_key],
                                             line_nb).assignblks
        # Eval the block
        #for i in assignblks:
        #    print(i)
        #temp_assignblks=[]
        #for i in assignblks:
        #    temp=i.to_string()
        #    temp=temp.replace(' ','')
        #    if(temp=='RSP=RSP+-0x8\n'):
        #        continue
        #    if(temp=='RBP=RSP\n'):
        #        continue
        #    temp_assignblks.append(i)
        ##assignblks=assignblks
        #assignblks=temp_assignblks
        loc_db = LocationDB()
        temp_loc = loc_db.get_or_create_name_location("Temp")
        symb_exec = SymbolicExecutionEngine(ir_arch, ctx_init)
        #print(IRBlock(temp_loc,assignblks))
        symb_exec.eval_updt_irblock(IRBlock(temp_loc, assignblks), step=step)

        # Return only inputs values (others could be wrongs)
        return {element: symb_exec.symbols[element]
                for element in self.inputs}
    
    def emul_wwz(self, ir_arch, trace,ctx=None, step=False):
        """Symbolic execution of relevant nodes according to the history
        Return the values of inputs nodes' elements
        @ir_arch: IntermediateRepresentation instance
        @ctx: (optional) Initial context as dictionary
        @step: (optional) Verbose execution
        Warning: The emulation is not sound if the inputs nodes depend on loop
        variant.
        """
        # Init
        ctx_init = {}
        if ctx is not None:
            ctx_init.update(ctx)
        assignblks = []

        # Build a single assignment block according to history
        last_index = len(self.relevant_loc_keys)
        #last_index=2
        for index, loc_key in enumerate(reversed(self.relevant_loc_keys), 1):
            if index == last_index and loc_key == self.initial_state.loc_key:
                line_nb = self.initial_state.line_nb
            else:
                line_nb = None
            a=self._ircfg.blocks[loc_key],line_nb
            assignblks += self.irblock_slice(self._ircfg.blocks[loc_key],
                                             line_nb).assignblks
        # Eval the block
        #for i in assignblks:
        #    print(i)
        temp_assignblks=[]
        for i in assignblks:
            temp=i.to_string()
            temp=temp.replace(' ','')
            if(temp=='RSP=RSP+-0x8\n'):
                continue
            if(temp=='RBP=RSP\n'):
                continue
            temp_assignblks.append(i)
        #assignblks=assignblks
        assignblks=temp_assignblks
        loc_db = LocationDB()
        temp_loc = loc_db.get_or_create_name_location("Temp")
        symb_exec = SymbolicExecutionEngine(ir_arch, ctx_init)
        #print(IRBlock(temp_loc,assignblks))
        symb_exec.eval_updt_irblock_wwz(IRBlock(temp_loc, assignblks), trace,step=step)

        return {element: symb_exec.symbols[element]
                for element in self.inputs}


class DependencyResultImplicit(DependencyResult):

    """Stand for a result of a DependencyGraph with implicit option

    Provide path constraints using the z3 solver"""
    # Z3 Solver instance
    _solver = None

    unsat_expr = ExprAssign(ExprInt(0, 1), ExprInt(1, 1))

    def _gen_path_constraints(self, translator, expr, expected):
        """Generate path constraint from @expr. Handle special case with
        generated loc_keys
        """
        out = []
        expected = self._ircfg.loc_db.canonize_to_exprloc(expected)
        expected_is_loc_key = expected.is_loc()
        for consval in possible_values(expr):
            value = self._ircfg.loc_db.canonize_to_exprloc(consval.value)
            if expected_is_loc_key and value != expected:
                continue
            if not expected_is_loc_key and value.is_loc_key():
                continue

            conds = z3.And(*[translator.from_expr(cond.to_constraint())
                             for cond in consval.constraints])
            if expected != value:
                conds = z3.And(
                    conds,
                    translator.from_expr(
                        ExprAssign(value,
                                expected))
                )
            out.append(conds)

        if out:
            conds = z3.Or(*out)
        else:
            # Ex: expr: lblgen1, expected: 0x1234
            # -> Avoid inconsistent solution lblgen1 = 0x1234
            conds = translator.from_expr(self.unsat_expr)
        return conds

    def emul(self, ir_arch, ctx=None, step=False):
        # Init
        ctx_init = {}
        if ctx is not None:
            ctx_init.update(ctx)
        solver = z3.Solver()
        symb_exec = SymbolicExecutionEngine(ir_arch, ctx_init)
        history = self.history[::-1]
        history_size = len(history)
        translator = Translator.to_language("z3")
        size = self._ircfg.IRDst.size

        for hist_nb, loc_key in enumerate(history, 1):
            if hist_nb == history_size and loc_key == self.initial_state.loc_key:
                line_nb = self.initial_state.line_nb
            else:
                line_nb = None
            irb = self.irblock_slice(self._ircfg.blocks[loc_key], line_nb)

            # Emul the block and get back destination
            dst = symb_exec.eval_updt_irblock(irb, step=step)

            # Add constraint
            if hist_nb < history_size:
                next_loc_key = history[hist_nb]
                expected = symb_exec.eval_expr(ExprLoc(next_loc_key, size))
                solver.add(self._gen_path_constraints(translator, dst, expected))
        # Save the solver
        self._solver = solver

        # Return only inputs values (others could be wrongs)
        return {
            element: symb_exec.eval_expr(element)
            for element in self.inputs
        }

    @property
    def is_satisfiable(self):
        """Return True iff the solution path admits at least one solution
        PRE: 'emul'
        """
        return self._solver.check() == z3.sat

    @property
    def constraints(self):
        """If satisfiable, return a valid solution as a Z3 Model instance"""
        if not self.is_satisfiable:
            raise ValueError("Unsatisfiable")
        return self._solver.model()


class FollowExpr(object):

    "Stand for an element (expression, depnode, ...) to follow or not"
    __slots__ = ["follow", "element"]

    def __init__(self, follow, element):
        self.follow = follow
        self.element = element

    def __repr__(self):
        return '%s(%r, %r)' % (self.__class__.__name__, self.follow, self.element)

    @staticmethod
    def to_depnodes(follow_exprs, loc_key, line):
        """Build a set of FollowExpr(DependencyNode) from the @follow_exprs set
        of FollowExpr
        @follow_exprs: set of FollowExpr
        @loc_key: LocKey instance
        @line: integer
        """
        dependencies = set()
        for follow_expr in follow_exprs:
            dependencies.add(FollowExpr(follow_expr.follow,
                                        DependencyNode(loc_key,
                                                       follow_expr.element,
                                                       line)))
        return dependencies

    @staticmethod
    def extract_depnodes(follow_exprs, only_follow=False):
        """Extract depnodes from a set of FollowExpr(Depnodes)
        @only_follow: (optional) extract only elements to follow"""
        return set(follow_expr.element
                   for follow_expr in follow_exprs
                   if not(only_follow) or follow_expr.follow)


class DependencyGraph(object):

    """Implementation of a dependency graph

    A dependency graph contains DependencyNode as nodes. The oriented edges
    stand for a dependency.
    The dependency graph is made of the lines of a group of IRblock
    *explicitly* or *implicitly* involved in the equation of given element.
    """

    def __init__(self, ircfg,
                 implicit=False, apply_simp=True, follow_mem=True,
                 follow_call=True):
        """Create a DependencyGraph linked to @ircfg

        @ircfg: IRCFG instance
        @implicit: (optional) Track IRDst for each block in the resulting path

        Following arguments define filters used to generate dependencies
        @apply_simp: (optional) Apply expr_simp_explicit
        @follow_mem: (optional) Track memory syntactically
        @follow_call: (optional) Track through "call"
        """
        # Init
        self._ircfg = ircfg
        self._implicit = implicit
        self.forward=set()

        # Create callback filters. The order is relevant.
        self._cb_follow = []
        if apply_simp:
            self._cb_follow.append(self._follow_simp_expr)
        self._cb_follow.append(lambda exprs: self._follow_exprs(exprs,
                                                                follow_mem,
                                                                follow_call))
        self._cb_follow.append(self._follow_no_loc_key)

    @staticmethod
    def _follow_simp_expr(exprs):
        """Simplify expression so avoid tracking useless elements,
        as: XOR EAX, EAX
        """
        follow = set()
        for expr in exprs:
            follow.add(expr_simp_explicit(expr))
        return follow, set()

    @staticmethod
    def get_expr(expr, follow, nofollow):
        """Update @follow/@nofollow according to insteresting nodes
        Returns same expression (non modifier visitor).

        @expr: expression to handle
        @follow: set of nodes to follow
        @nofollow: set of nodes not to follow
        """
        if expr.is_id():
            follow.add(expr)
        elif expr.is_int():
            nofollow.add(expr)
        elif expr.is_mem():
            follow.add(expr)
        return expr

    @staticmethod
    def follow_expr(expr, _, nofollow, follow_mem=False, follow_call=False):
        """Returns True if we must visit sub expressions.
        @expr: expression to browse
        @follow: set of nodes to follow
        @nofollow: set of nodes not to follow
        @follow_mem: force the visit of memory sub expressions
        @follow_call: force the visit of call sub expressions
        """
        if not follow_mem and expr.is_mem():
            nofollow.add(expr)
            return False
        if not follow_call and expr.is_function_call():
            nofollow.add(expr)
            return False
        return True

    @classmethod
    def _follow_exprs(cls, exprs, follow_mem=False, follow_call=False):
        """Extracts subnodes from exprs and returns followed/non followed
        expressions according to @follow_mem/@follow_call

        """
        follow, nofollow = set(), set()
        for expr in exprs:
            expr.visit(lambda x: cls.get_expr(x, follow, nofollow),
                       lambda x: cls.follow_expr(x, follow, nofollow,
                                                 follow_mem, follow_call))
        return follow, nofollow

    @staticmethod
    def _follow_no_loc_key(exprs):
        """Do not follow loc_keys"""
        follow = set()
        for expr in exprs:
            if expr.is_int() or expr.is_loc():
                continue
            follow.add(expr)

        return follow, set()

    def _follow_apply_cb(self, expr):
        """Apply callback functions to @expr
        @expr : FollowExpr instance"""
        follow = set([expr])
        nofollow = set()

        for callback in self._cb_follow:
            follow, nofollow_tmp = callback(follow)
            nofollow.update(nofollow_tmp)

        out = set(FollowExpr(True, expr) for expr in follow)
        out.update(set(FollowExpr(False, expr) for expr in nofollow))
        return out

    def _track_exprs(self, state, assignblk, line_nb,irb):
        """Track pending expression in an assignblock"""
        future_pending = {}
        node_resolved = set()
        #print(state.pending[self._ircfg.IRDst])
        for dst, src in viewitems(assignblk):
            # Only track pending

            if(isinstance(dst,ExprMem) and hasattr(dst,'ptr') and isinstance(dst.ptr,ExprId)):
                dst=ExprMem(ExprId(dst.ptr.name,dst.ptr.size),64)
            if dst not in state.pending:
                continue
            # Track IRDst in implicit mode only
            if dst == self._ircfg.IRDst and not self._implicit:
                continue
            
            assert dst not in node_resolved

            #We're dealing with [rax] here
            if(isinstance(dst,ExprMem) and hasattr(dst,'ptr') and isinstance(dst.ptr,ExprId)):
                temp_dependency=list(state.pending[dst])[0];
                temp_irb0 = self._ircfg.blocks[temp_dependency.loc_key]
                temp_line_nb0=temp_dependency.line_nb
                track=dst.ptr
                for l_nb0, ass0 in reversed(list(enumerate(temp_irb0[:temp_line_nb0]))):
                    if("MOV" in ass0.instr.name or "LEA" in ass0.instr.name):
                        #Track only one instruction up
                        if(hasattr(ass0.instr.args[0],'name') and ass0.instr.args[0]==track):
                            track_result0=ass0.instr.args[1]
                            break
                for l_nb1, ass1 in reversed(list(enumerate(irb[:line_nb]))):
                    if("MOV" in ass1.instr.name or "LEA" in ass1.instr.name):
                        #Track only one instruction up
                        if(hasattr(ass1.instr.args[0],'name') and ass1.instr.args[0]==track):
                            track_result1=ass1.instr.args[1]
                            break
                if(track_result0!=track_result1):
                    continue

            node_resolved.add(dst)

            if(assignblk.instr.is_subcall()):
                src_args_temp=list(src.args)[0]
                temp_src={}
                temp_src_1=[]
                temp_src_2=[]
                temp_arg=['SI','DI','R8','R9','CX','DX']
                if(line_nb!=0):
                    for cur_line_nb, assignblk1 in reversed(list(enumerate(irb[:line_nb]))):
                        if(line_nb-cur_line_nb>25 and assignblk1.instr.is_subcall()):
                            break
                        #Indicates no parameters
                        if("MOV" not in assignblk1.instr.name or "LEA" not in assignblk1.instr.name):
                            break
                        if(not hasattr(assignblk1.instr.args[0],'name')):
                            break
                        if(hasattr(assignblk1.instr.args[0],'name') and "DI" not in assignblk1.instr.args[0].name):
                            break
                        if("MOV" in assignblk1.instr.name or "LEA" in assignblk1.instr.name):
                            for i in temp_arg:
                                if(hasattr(assignblk1.instr.args[0],'name') and i in assignblk1.instr.args[0].name):
                                    temp_src[str(hex(assignblk1.instr.offset))]=(assignblk1.instr.args[0])
                                    #temp_src_1.append(assignblk.instr.args[0])
                                    temp_src_2.append(assignblk1.instr.args[0])
                        if("PUSH" in assignblk1.instr.name):
                            #Create a link to yourself
                            depnode1 = DependencyNode(state.loc_key,assignblk1.instr.args[0] , cur_line_nb)
                            state.links.add((depnode1,None))
                            if(assignblk1.instr.args[0].is_int()):
                                temp_src[str(hex(assignblk1.instr.offset))]=(assignblk1.instr.args[0])
                                #temp_src_1.append(assignblk.instr.args[0])
                                temp_src_2.append(assignblk1.instr.args[0])
                            else:
                                for cur_line_nb_ph, assignblk_push in reversed(list(enumerate(irb[:cur_line_nb]))):
                                    if(assignblk_push.instr.is_subcall()):
                                        break
                                    for dst_push, src_push in viewitems(assignblk_push):
                                        if((hasattr(dst_push,'name') and "MOV" in assignblk_push.instr.name and dst_push.name==assignblk1.instr.args[0].name) or 
                                           (hasattr(dst_push,'name') and "LEA" in assignblk_push.instr.name and dst_push.name==assignblk1.instr.args[0].name)):
                                            #print(str(hex(assignblk_push.instr.offset)),dst_push.name,assignblk1.instr.args[0].name)
                                            #print('src_push',src_push)
                                            temp_src[str(hex(assignblk_push.instr.offset))]=(assignblk_push.instr.args[1])
                                            temp_src_1.append(src_push)
                                            #Create link to call
                                            depnode2 = DependencyNode(state.loc_key,assignblk_push.instr.args[0] , cur_line_nb_ph)
                                            state.links.add((depnode2,None))
                                            dependencies_push = self._follow_apply_cb(src_push)
                                            state.link_dependencies(dst, line_nb,dependencies_push, future_pending)
                a=temp_src.keys()
                a.sort()
                a.reverse()
                #print('\ntemp_src')
                #for i in a:
                #    print(i,temp_src[i])
                temp_src_2.insert(0,src_args_temp)
                src=self._generate_src_arg(temp_src_2)
                
         
            dependencies = self._follow_apply_cb(src)
            #print('offset',str(hex(assignblk.instr.offset)))
            state.link_element(dst, line_nb)
            state.link_dependencies(dst, line_nb,
                                    dependencies, future_pending)

        # Update pending nodes
        if(future_pending.has_key(ExprId('RBP', 64))):
            future_pending.pop(ExprId('RBP', 64))
        state.remove_pendings(node_resolved)
        state.add_pendings(future_pending)

        #Deal with [eax] this situation
        for key in state.pending.keys():
            if(isinstance(key,ExprMem) and hasattr(key,'ptr') and isinstance(key.ptr,ExprId)):
                temp_key=ExprMem(ExprId(key.ptr.name,key.ptr.size),64)
                key_value=state.pending[key]
                state.pending.pop(key)
                state.pending[temp_key]=key_value

    def _generate_src_arg(self,src_arg):
        arg_name=[]
        for j in src_arg[1:]:
            i=j.name
            if(i[0]=='E'):
                i='R'+i[1:]
            if(i[1] in '89' and len(i)==3):
                i=i[:2]
            arg_name.append(i)
        arg_name=list(set(arg_name))
        arg_num=len(arg_name)
        if(arg_num==0):
            src=ExprOp('call_func_ret', src_arg[0])
        elif(arg_num==1):
            src=ExprOp('call_func_ret', src_arg[0],ExprId(arg_name[0], 64))
        elif(arg_num==2):
            src=ExprOp('call_func_ret', src_arg[0],ExprId(arg_name[0], 64),ExprId(arg_name[1], 64))
        elif(arg_num==3):
            src=ExprOp('call_func_ret', src_arg[0],ExprId(arg_name[0], 64),ExprId(arg_name[1], 64),ExprId(arg_name[2], 64))
        elif(arg_num==4):
            src=ExprOp('call_func_ret', src_arg[0],ExprId(arg_name[0], 64),ExprId(arg_name[1], 64),ExprId(arg_name[2], 64),ExprId(arg_name[3], 64))
        elif(arg_num==5):
            src=ExprOp('call_func_ret', src_arg[0],ExprId(arg_name[0], 64),ExprId(arg_name[1], 64),ExprId(arg_name[2], 64),ExprId(arg_name[3], 64),ExprId(arg_name[4], 64))
        elif(arg_num==6):
            src=ExprOp('call_func_ret', src_arg[0],ExprId(arg_name[0], 64),ExprId(arg_name[1], 64),ExprId(arg_name[2], 64),ExprId(arg_name[3], 64),ExprId(arg_name[4], 64),ExprId(arg_name[5], 64))

        return src


    def _compute_intrablock(self, state):
        """Follow dependencies tracked in @state in the current irbloc
        @state: instance of DependencyState"""

        irb = self._ircfg.blocks[state.loc_key]
        line_nb = len(irb) if state.line_nb is None else state.line_nb
        
        #irb,current block instuction
        #line_nb:current instuction patch_location in block
        for cur_line_nb, assignblk in reversed(list(enumerate(irb[:line_nb]))):
            #print(dir(assignblk.instr))
            #if(assignblk.instr.offset==0x268bd):
            #    print(assignblk.instr.to_string())
            self._track_exprs(state, assignblk, cur_line_nb,irb)

    def get(self, loc_key, elements, line_nb, heads):
        """Compute the dependencies of @elements at line number @line_nb in
        the block named @loc_key in the current IRCFG, before the execution of
        this line. Dependency check stop if one of @heads is reached
        @loc_key: LocKey instance
        @element: set of Expr instances
        @line_nb: int
        @heads: set of LocKey instances
        Return an iterator on DiGraph(DependencyNode)
        """
        # Init the algorithm
        inputs = {element: set() for element in elements}
        initial_state = DependencyState(loc_key, inputs, line_nb)
        todo = set([initial_state])
        done = set()
        dpResultcls = DependencyResultImplicit if self._implicit else DependencyResult
        while todo:
            state = todo.pop()
            self._compute_intrablock(state)
            done_state = state.get_done_state()
            if done_state in done:
                continue
            done.add(done_state)
            if (not state.pending or
                    state.loc_key in heads or
                    not self._ircfg.predecessors(state.loc_key)):
                yield dpResultcls(self._ircfg, initial_state, state, elements)
                if not state.pending:
                    continue

            if self._implicit:
                # Force IRDst to be tracked, except in the input block
                state.pending[self._ircfg.IRDst] = set()

            # Propagate state to parents
            for pred in self._ircfg.predecessors_iter(state.loc_key):
                todo.add(state.extend(pred))

    def get_from_depnodes(self, depnodes, heads):
        """Alias for the get() method. Use the attributes of @depnodes as
        argument.
        PRE: Loc_Keys and lines of depnodes have to be equals
        @depnodes: set of DependencyNode instances
        @heads: set of LocKey instances
        """
        lead = list(depnodes)[0]
        elements = set(depnode.element for depnode in depnodes)
        return self.get(lead.loc_key, elements, lead.line_nb, heads)

    def _track_exprs_forward(self,state,assignblk,line_nb,irb):
        """track spread expression in an assignblock"""
        future_pending={}
        node_resolved=set()
        for dst,src in viewitems(assignblk):
            print('%'*20)
            print('state.pending before')
            print(state.pending_forward)
            if(isinstance(dst,ExprMem) and hasattr(dst,'ptr') and isinstance(dst.ptr,ExprId)):
                dst=ExprMem(ExprId(dst.ptr.name,dst.ptr.size),64)
            if(isinstance(src,ExprMem) and hasattr(src,'ptr') and isinstance(src.ptr,ExprId)):
                src=ExprMem(ExprId(src.ptr.name,src.ptr.size),64)
            
            ##Processing function parameters
            call_args=[]
            if(assignblk.instr.is_subcall()):
                if(dst==ExprId('RSP', 64)):
                    continue
                #src_args_temp=list(src.args)[0]
                temp_src={}
                temp_src_1=[]
                temp_src_2=[]
                temp_arg=['SI','DI','R8','R9','CX','DX']
                if(line_nb!=0):
                    for cur_line_nb, assignblk1 in reversed(list(enumerate(irb[:line_nb]))):
                        if(line_nb-cur_line_nb>25 and assignblk1.instr.is_subcall()):
                            break
                        #Indicates no parameters
                        if("MOV" not in assignblk1.instr.name or "LEA" not in assignblk1.instr.name):
                            break
                        if(not hasattr(assignblk1.instr.args[0],'name')):
                            break
                        if(hasattr(assignblk1.instr.args[0],'name') and "DI" not in assignblk1.instr.args[0].name):
                            break
                        if("MOV" in assignblk1.instr.name or "LEA" in assignblk1.instr.name):
                            for i in temp_arg:
                                if(hasattr(assignblk1.instr.args[0],'name') and i in assignblk1.instr.args[0].name):
                                    temp_src[str(hex(assignblk1.instr.offset))]=(assignblk1.instr.args[0])
                                    #temp_src_1.append(assignblk.instr.args[0])
                                    temp_src_2.append(assignblk1.instr.args[0])
                        if("PUSH" in assignblk1.instr.name):
                            #Create a link to yourself
                            depnode1 = DependencyNode(state.loc_key,assignblk1.instr.args[0] , cur_line_nb)
                            state.links.add((depnode1,None))
                            if(assignblk1.instr.args[0].is_int()):
                                temp_src[str(hex(assignblk1.instr.offset))]=(assignblk1.instr.args[0])
                                #temp_src_1.append(assignblk.instr.args[0])
                                temp_src_2.append(assignblk1.instr.args[0])
                            else:
                                for cur_line_nb_ph, assignblk_push in reversed(list(enumerate(irb[:cur_line_nb]))):
                                    if(assignblk_push.instr.is_subcall()):
                                        break
                                    for dst_push, src_push in viewitems(assignblk_push):
                                        if((hasattr(dst_push,'name') and "MOV" in assignblk_push.instr.name and dst_push.name==assignblk1.instr.args[0].name) or 
                                           (hasattr(dst_push,'name') and "LEA" in assignblk_push.instr.name and dst_push.name==assignblk1.instr.args[0].name)):
                                            #print(str(hex(assignblk_push.instr.offset)),dst_push.name,assignblk1.instr.args[0].name)
                                            #print('src_push',src_push)
                                            temp_src[str(hex(assignblk_push.instr.offset))]=(assignblk_push.instr.args[1])
                                            temp_src_1.append(src_push)
                                            #Create link to call
                                            depnode2 = DependencyNode(state.loc_key,assignblk_push.instr.args[0] , cur_line_nb_ph)
                                            state.links.add((depnode2,None))
                                            dependencies_push = self._follow_apply_cb(src_push)
                                            state.link_dependencies(dst, line_nb,dependencies_push, future_pending)   
                a=temp_src.keys()
                a.sort()
                a.reverse()
                #temp_src_2.insert(0,src_args_temp)
                #src=self._generate_src_arg(temp_src_2)
                print(temp_src_2)
                call_args=temp_src_2

            
            #Get the corresponding variables and track them
            dependencies_dst=self._follow_apply_cb(dst)
            dependencies_src=self._follow_apply_cb(src)
            #mov eax,rdi    delete eax,if eax in state.penging_forward
            dst_pending=[]
            for dependency in dependencies_dst:
                if dependency.follow:
                    element=dependency.element
                    if((hasattr(element,'name'))):
                       if(element.name=="RBP"):
                            continue
                    if(isinstance(element,ExprMem) and hasattr(element,'ptr') and isinstance(element.ptr,ExprId)):
                        element=ExprMem(ExprId(element.ptr.name,element.ptr.size),64)
                    dst_pending.append(element)
            for temp_dst in dst_pending:
                if(temp_dst in state.pending_forward):
                    if("MOV" in assignblk.instr.name):
                        state.pending_forward.remove(temp_dst)
            
            src_pending=[]
            for dependency in dependencies_src:
                if dependency.follow:
                    element=dependency.element
                    if(hasattr(element,'name')):
                       if(element.name=="RBP"):
                           continue
                    if(isinstance(element,ExprMem) and hasattr(element,'ptr') and isinstance(element.ptr,ExprId)):
                        element=ExprMem(ExprId(element.ptr.name,element.ptr.size),64)
                    src_pending.append(element)
            print('src',src_pending)
            print('dst',dst_pending)
            #Determine whether there are traceable variables
            count=0
            for dependency in dependencies_src:
                if dependency.follow:
                    if(dependency.element in state.pending_forward):
                        count=count+1
            if(count==0):
                continue



            if(assignblk.instr.is_subcall()):
                dst_pending.append(ExprId('RAX', 64))
                src_pending.extend(call_args)
            #print('src',src_pending)
            #print('dst',dst_pending)

            #print(state.pending_forward)
            
            not_following=['af','pf','zf','of','nf','cf']
            for temp_src in src_pending:
                if((temp_src in state.pending_forward)):
                    node=DependencyNode(state.loc_key, assignblk, line_nb)
                    #reserve the relevant values
                    self.forward.add(node)
                    state.pending_forward.add(temp_src)
                    for temp_dst in dst_pending:
                        if(isinstance(temp_dst,ExprId) and hasattr(temp_dst,'name') and (temp_dst.name in not_following)):
                            continue
                        else:
                            state.pending_forward.add(temp_dst)
            
            node_resolved.update(src_pending)
            print('after')
            print(state.pending_forward)
            #print('-'*80)
        #print('\n')


    def _compute_intrablock_forward(self,state):
        """ follow spread tracked in @state in the current irbloc
        @state : instance of DependencyState"""

        # get the ir block
        irb=self._ircfg.blocks[state.loc_key]
        line_nb=0 if state.line_nb is None else state.line_nb
        #Here to be determined
        # line_nb+=1
        print('state.pending before')
        print(state.pending_forward)
        i=0
        for cur_line_nb,assignblk in list(enumerate(irb[line_nb:])):
            print(str(hex(assignblk.instr.offset))),
            print(assignblk.instr)
            self._track_exprs_forward(state,assignblk,line_nb,irb)
            if(i==0):
                addr=str(hex(assignblk.instr.offset))
            i=i+1
        print('state.pending after')
        print(state.pending_forward)
        print(addr)
        print('_________________________\n\n\n')


    def get_forward(self,loc_key,elements,line_nb,heads):
        """Compute the spread of @elements at line number @line_nb in
        the block named @loc_key in the current IRCFG, before the execution of
        this line. Dependency check stop if one of @heads is reached
        @loc_key: LocKey instance
        @element: set of Expr instances
        @line_nb: int
        @heads: set of LocKey instances
        Return an iterator on DiGraph(DependencyNode)
        """
        inputs={element:set() for element in elements}
        initial_state=DependencyState(loc_key,inputs,set(elements),line_nb+1)
        initial_state.pending_forward=elements
        todo=set([initial_state])
        done=set()
        done_forward={}

        irb=self._ircfg.blocks[loc_key]
        assignblk=irb[line_nb]
        dpResultcls=DependencyResult
        node=DependencyNode(loc_key,assignblk,line_nb)
        self.forward.add(node)
        while todo:
            state=todo.pop()
            self._compute_intrablock_forward(state)
            done_state=state.get_done_state()
            done_forward[state.loc_key]=state
            if done_state in done:
                continue
            done.add(done_state)
            if(not state.pending_forward):
                done_forward.pop(state.loc_key)
            #propagate state to child
            for succs in self._ircfg.successors_iter(state.loc_key):
                temp_state=DependencyState(succs)
                for parent in self._ircfg.predecessors_iter(succs):
                    if(done_forward.has_key(parent)):
                        temp_state.pending_forward.update(done_forward[parent].pending_forward)
                todo.add(temp_state)

        #print('result')
        #print('*'*40)
        result={}
        for temp in self.forward:
            loc_key=temp.loc_key_forward
            element=temp.element_forward
            result[str(hex(element.instr.offset))]=element.instr.to_string()
        
        #print(result)
        #print('*'*40)
        return result
