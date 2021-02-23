"""Provide dependency graph"""

from functools import total_ordering

from future.utils import viewitems

from miasm.expression.expression import ExprInt, ExprLoc, ExprAssign
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


def Symbolic_simulation(ir_arch,assignblks,step=False):
    loc_db = LocationDB()
    temp_loc = loc_db.get_or_create_name_location("Temp")
    ctx_init={}
    symb_exec = SymbolicExecutionEngine(ir_arch, ctx_init)
    symb_exec.eval_updt_irblock(IRBlock(temp_loc, assignblks), step=step)
    print(symb_exec.symbols)
    print(symb_exec.dump())
