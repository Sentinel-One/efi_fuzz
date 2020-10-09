#
# Keeps track of uninitialized memory via memory tainting.
#

import capstone
from capstone.x86_const import *
import triton
from taint.uefi import *

cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
cs.detail = True

def is_rsp_decrement(inst):
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

def sync_triton_ctx(ql):
    from unicorn.x86_const import UC_X86_REG_EFLAGS

    ql.triton_ctx.setConcreteRegisterValue(ql.triton_ctx.registers.rax, ql.reg.rax)
    ql.triton_ctx.setConcreteRegisterValue(ql.triton_ctx.registers.rbx, ql.reg.rbx)
    ql.triton_ctx.setConcreteRegisterValue(ql.triton_ctx.registers.rcx, ql.reg.rcx)
    ql.triton_ctx.setConcreteRegisterValue(ql.triton_ctx.registers.rdx, ql.reg.rdx)
    ql.triton_ctx.setConcreteRegisterValue(ql.triton_ctx.registers.rdi, ql.reg.rdi)
    ql.triton_ctx.setConcreteRegisterValue(ql.triton_ctx.registers.rsi, ql.reg.rsi)
    ql.triton_ctx.setConcreteRegisterValue(ql.triton_ctx.registers.rbp, ql.reg.rbp)
    ql.triton_ctx.setConcreteRegisterValue(ql.triton_ctx.registers.rsp, ql.reg.rsp)
    ql.triton_ctx.setConcreteRegisterValue(ql.triton_ctx.registers.rip, ql.reg.rip)
    ql.triton_ctx.setConcreteRegisterValue(ql.triton_ctx.registers.r8, ql.reg.r8)
    ql.triton_ctx.setConcreteRegisterValue(ql.triton_ctx.registers.r9, ql.reg.r9)
    ql.triton_ctx.setConcreteRegisterValue(ql.triton_ctx.registers.r10, ql.reg.r10)
    ql.triton_ctx.setConcreteRegisterValue(ql.triton_ctx.registers.r11, ql.reg.r11)
    ql.triton_ctx.setConcreteRegisterValue(ql.triton_ctx.registers.r12, ql.reg.r12)
    ql.triton_ctx.setConcreteRegisterValue(ql.triton_ctx.registers.r13, ql.reg.r13)
    ql.triton_ctx.setConcreteRegisterValue(ql.triton_ctx.registers.r14, ql.reg.r14)
    ql.triton_ctx.setConcreteRegisterValue(ql.triton_ctx.registers.r15, ql.reg.r15)
    ql.triton_ctx.setConcreteRegisterValue(ql.triton_ctx.registers.eflags, ql.reg.read(UC_X86_REG_EFLAGS))
    ql.triton_ctx.setConcreteRegisterValue(ql.triton_ctx.registers.fs, ql.reg.fs)
    ql.triton_ctx.setConcreteRegisterValue(ql.triton_ctx.registers.gs, ql.reg.gs)

def enable_uninitialized_memory_tracker(ql):
    # Build and initialize a TritonContext.
    ql.triton_ctx = triton.TritonContext()
    ql.triton_ctx.setArchitecture(triton.ARCH.X86_64)
    ql.triton_ctx.setMode(triton.MODE.ALIGNED_MEMORY, True)
    ql.triton_ctx.setAstRepresentationMode(triton.AST_REPRESENTATION.PYTHON)

    ql.set_api("SetMem", SetMem_propagate_taint, QL_INTERCEPT.EXIT)
    ql.set_api("CopyMem", CopyMem_propagate_taint, QL_INTERCEPT.EXIT)
    ql.set_api("SetVariable", SetVariable_propagate_taint, QL_INTERCEPT.EXIT)
    ql.set_api("GetVariable", GetVariable_propagate_taint, QL_INTERCEPT.EXIT)
    ql.set_api("AllocatePool", AllocatePool_propagate_taint, QL_INTERCEPT.EXIT)

    def hook_opcode(ql, address, size):
        global cs

        # Read instruction.
        buf = ql.mem.read(address, size)
        instruction = next(cs.disasm(buf, address))

        # We are looking for instructions which decrement the stack pointer.
        (should_taint, decrement) = is_rsp_decrement(instruction)
        if should_taint:
            # Taint all stack memory from current rsp to new rsp.
            set_taint_range(ql, ql.reg.arch_sp - decrement, ql.reg.arch_sp, True)

        # Sync Triton and Qiling.
        sync_triton_ctx(ql)

        # Process instruction, propagate taint.
        inst = triton.Instruction()
        inst.setAddress(address)
        inst.setOpcode(bytes(buf))
        ql.triton_ctx.processing(inst)

    # Hook every opcode.
    ql.hook_code(hook_opcode)