#
# Primitives for taint propagation.
#

from qiling.const import *

def set_taint_range(ql, begin, end, taint):
    # Decide if we should taint or un-taint memory.
    verb = 'Tainting' if taint else 'Untainting'
    ql.dprint(D_INFO, f'{verb} range 0x{begin:x}-0x{end:x}')

    # Apply taint for the entire memory range.
    taint_func = ql.triton_ctx.taintMemory if taint else ql.triton_ctx.untaintMemory
    for addr in range(begin, end):
        taint_func(addr)

def get_taint_range(ql, begin, end):
    return [ql.triton_ctx.isMemoryTainted(addr) for addr in range(begin, end)]

def copy_taint(ql, source, destination, length):
    for i in range(length):
        if ql.triton_ctx.isMemoryTainted(source + i):
            ql.triton_ctx.taintMemory(destination + i)
        else:
            ql.triton_ctx.untaintMemory(destination + i)

def is_range_tainted(ql, begin, end):
    return any(get_taint_range(ql, begin, end))
