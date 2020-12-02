from .base_tainter import base_tainter
from qiling.const import *
import os
from qiling.os.uefi.utils import read_int64

import capstone
from capstone.x86_const import *

def SetMem_propagate_taint(ql, address, params):
    """
    Taint propagation for SetMem(). We taint or untaint the target buffer based on the taint status
    'UINT8 Value' argument.
    """
    begin = params['Buffer']
    end = begin + params['Size']
    # r8b corresponds to the 'UINT8 Value' parameter.
    taint = ql.tainters['uninitialized'].triton_ctx.isRegisterTainted(ql.tainters['uninitialized'].triton_ctx.registers.r8b)
    ql.tainters['uninitialized'].set_taint_range(begin, end, taint)

def CopyMem_propagate_taint(ql, address, params):
    """
    Taint propagation for CopyMem(). The taint is copied on a byte-by-byte basis from the source
    buffer to the destination buffer.
    """
    ql.tainters['uninitialized'].copy_taint(params['Source'], params['Destination'], params['Length'])

def AllocatePool_propagate_taint(ql, address, params):
    """
    Taint propagation for Alloca
    tePool().
    We know that all pool memory is initially uninitialized, so we taint it.
    """
    begin = read_int64(ql, params['Buffer'])
    end = begin + params['Size']
    ql.tainters['uninitialized'].set_taint_range(begin, end, True)

def GetVariable_propagate_taint(ql, address, params):
    """
    Taint propagation for GetVariable(). We initially assume that all NVRAM variables are fully
    initialized, so the target buffer becomes untainted.
    """
    begin = params['Data']
    end = begin + read_int64(ql, params['DataSize'])
    ql.tainters['uninitialized'].set_taint_range(begin, end, False)

def SetVariable_propagate_taint(ql, address, params):
    """
    Taint propagation of SetVariable(). If the data that was written to NVRAM contains some tainted
    bytes, that means a potential infoleak has occurred and we can abort the process and report that.
    """
    begin = params["Data"]
    end = params["Data"] + params["DataSize"]
    if ql.tainters['uninitialized'].is_range_tainted(begin, end):
        ql.dprint(D_INFO, f"Detected potential info leak in SetVariable({params})")
        ql.os.emu_error()
        os.abort()

class uninitialized_memory_tainter(base_tainter):

    NAME = 'uninitialized'

    def __init__(self):
        super().__init__()

    def register(self, ql):
        super().register(ql, self.NAME)

        ql.set_api("SetMem", SetMem_propagate_taint, QL_INTERCEPT.EXIT)
        ql.set_api("CopyMem", CopyMem_propagate_taint, QL_INTERCEPT.EXIT)
        ql.set_api("SetVariable", SetVariable_propagate_taint, QL_INTERCEPT.EXIT)
        ql.set_api("GetVariable", GetVariable_propagate_taint, QL_INTERCEPT.EXIT)
        ql.set_api("AllocatePool", AllocatePool_propagate_taint, QL_INTERCEPT.EXIT)

    @staticmethod
    def is_stack_pointer_decrement(inst):
        # sub rsp, x
        if inst.id == X86_INS_SUB and \
        inst.operands[0].type == capstone.CS_OP_REG and inst.operands[0].reg == X86_REG_RSP:
            assert inst.operands[1].type == capstone.CS_OP_IMM
            decrement = inst.operands[1].imm
            return True, decrement

        # add rsp, -x
        if inst.id == X86_INS_ADD and \
        inst.operands[0].type == capstone.CS_OP_REG and inst.operands[0].reg == X86_REG_RSP:
            assert inst.operands[1].type == capstone.CS_OP_IMM
            increment = inst.operands[1].imm
            if increment < 0:
                return True, -increment

        return False, 0

    def instruction_hook(self, ql, instruction):
        # We are looking for instructions which decrement the stack pointer.
        (should_taint, decrement) = self.is_stack_pointer_decrement(instruction)
        if should_taint:
            # Taint all stack memory from current rsp to new rsp.
            self.set_taint_range(ql.reg.arch_sp - decrement, ql.reg.arch_sp, True)