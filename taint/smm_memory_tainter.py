from .base_tainter import base_tainter
from qiling.const import *
import capstone
import os

def ReadSaveState_propagate_taint(ql, address, params):
    begin = params['Buffer']
    end = begin + params['Width']
    ql.tainters['smm'].set_taint_range(begin, end, True)

class smm_memory_tainter(base_tainter):

    NAME = 'smm'

    def __init__(self):
        super().__init__()

    def register(self, ql):
        super().register(ql, self.NAME)

        ql.set_api("SMM_CPU_ReadSaveState", ReadSaveState_propagate_taint, QL_INTERCEPT.EXIT)

    @staticmethod
    def compute_effective_address(ql, operand):
        
        assert operand.type == capstone.CS_OP_MEM
        assert operand.access == capstone.CS_AC_WRITE

        base = ql.reg.read(ql.reg.reverse_mapping[operand.mem.base])

        if operand.mem.index == 0:
            index = 0
        else:
            index = ql.reg.read(ql.reg.reverse_mapping[operand.mem.index])
        
        # [base + index * scale + disp]
        return base + index * operand.mem.scale + operand.mem.disp

    def instruction_hook(self, ql, instruction):
        # Not enough operands
        if len(instruction.operands) < 1:
            return

        # Destination is not a memory location
        destination = instruction.operands[0]
        if destination.type != capstone.CS_OP_MEM or destination.access != capstone.CS_AC_WRITE:
            return

        address = self.compute_effective_address(ql, destination)
        
        if address < ql.os.smm.smbase or address > ql.os.smm.smbase + ql.os.smm.smram_size:
            # Outside SMRAM
            return

        # If we got here, it means a write to SMRAM has occured.
        # Check if the base register is tainted, which means an attacker can control the memory
        # address being written.
        base_reg = ql.reg.reverse_mapping[destination.mem.base]
        triton_base_reg = getattr(self.triton_ctx.registers, base_reg)
        if self.triton_ctx.isRegisterTainted(triton_base_reg):
            ql.dprint(D_INFO, "***")
            ql.dprint(D_INFO, "Detected a write to SMRAM with attacker-controllable address!")
            ql.dprint(D_INFO, "***")
            ql.os.emu_error()
            os.abort()
            