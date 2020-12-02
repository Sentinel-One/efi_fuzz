#
# Keeps track of uninitialized memory via memory tainting.
#

from .uninitialized_memory_tainter import uninitialized_memory_tainter
import capstone
from capstone.x86_const import *
import triton
from taint.uefi import *

cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
cs.detail = True



def enable_uninitialized_memory_tracker(ql):
    
    u = uninitialized_memory_tainter()
    u.register(ql)

    def hook_opcode(ql, address, size):
        global cs

        # Read instruction.
        buf = ql.mem.read(address, size)
        instruction = next(cs.disasm(buf, address))

        for tainter in ql.tainters.values():
            tainter.instruction_hook(ql, instruction)

            # Sync Triton and Qiling.
            tainter.sync(ql)

            # Process instruction, propagate taint.
            inst = triton.Instruction()
            inst.setAddress(address)
            inst.setOpcode(bytes(buf))
            tainter.triton_ctx.processing(inst)

    # Hook every opcode.
    ql.hook_code(hook_opcode)