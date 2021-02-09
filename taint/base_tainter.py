import triton
from abc import ABC, abstractmethod

class base_tainter(ABC):

    def __init__(self):
        # Build and initialize a TritonContext.
        self.triton_ctx = triton.TritonContext()
        self.triton_ctx.setArchitecture(triton.ARCH.X86_64)
        self.triton_ctx.setMode(triton.MODE.ALIGNED_MEMORY, True)
        self.triton_ctx.setAstRepresentationMode(triton.AST_REPRESENTATION.PYTHON)

    @property
    @staticmethod
    @abstractmethod
    def NAME():
        raise NotImplementedError

    def register(self, ql, name):
        if not hasattr(ql, 'tainters'):
            ql.tainters = {}

        ql.tainters[name] = self

    def sync(self, ql):
        from unicorn.x86_const import UC_X86_REG_EFLAGS

        self.triton_ctx.setConcreteRegisterValue(self.triton_ctx.registers.rax, ql.reg.rax)
        self.triton_ctx.setConcreteRegisterValue(self.triton_ctx.registers.rbx, ql.reg.rbx)
        self.triton_ctx.setConcreteRegisterValue(self.triton_ctx.registers.rcx, ql.reg.rcx)
        self.triton_ctx.setConcreteRegisterValue(self.triton_ctx.registers.rdx, ql.reg.rdx)
        self.triton_ctx.setConcreteRegisterValue(self.triton_ctx.registers.rdi, ql.reg.rdi)
        self.triton_ctx.setConcreteRegisterValue(self.triton_ctx.registers.rsi, ql.reg.rsi)
        self.triton_ctx.setConcreteRegisterValue(self.triton_ctx.registers.rbp, ql.reg.rbp)
        self.triton_ctx.setConcreteRegisterValue(self.triton_ctx.registers.rsp, ql.reg.rsp)
        self.triton_ctx.setConcreteRegisterValue(self.triton_ctx.registers.rip, ql.reg.rip)
        self.triton_ctx.setConcreteRegisterValue(self.triton_ctx.registers.r8, ql.reg.r8)
        self.triton_ctx.setConcreteRegisterValue(self.triton_ctx.registers.r9, ql.reg.r9)
        self.triton_ctx.setConcreteRegisterValue(self.triton_ctx.registers.r10, ql.reg.r10)
        self.triton_ctx.setConcreteRegisterValue(self.triton_ctx.registers.r11, ql.reg.r11)
        self.triton_ctx.setConcreteRegisterValue(self.triton_ctx.registers.r12, ql.reg.r12)
        self.triton_ctx.setConcreteRegisterValue(self.triton_ctx.registers.r13, ql.reg.r13)
        self.triton_ctx.setConcreteRegisterValue(self.triton_ctx.registers.r14, ql.reg.r14)
        self.triton_ctx.setConcreteRegisterValue(self.triton_ctx.registers.r15, ql.reg.r15)
        self.triton_ctx.setConcreteRegisterValue(self.triton_ctx.registers.eflags, ql.reg.read(UC_X86_REG_EFLAGS))
        self.triton_ctx.setConcreteRegisterValue(self.triton_ctx.registers.fs, ql.reg.fs)
        self.triton_ctx.setConcreteRegisterValue(self.triton_ctx.registers.gs, ql.reg.gs)

    @abstractmethod
    def instruction_hook(self, ql, instruction):
        raise NotImplementedError()

    #
    # Taint utilities
    #

    def set_taint_range(self, begin, end, taint):
        # Apply taint for the entire memory range.
        taint_func = self.triton_ctx.taintMemory if taint else self.triton_ctx.untaintMemory
        for addr in range(begin, end + 1):
            taint_func(addr)

    def get_taint_range(self, begin, end):
        return [self.triton_ctx.isMemoryTainted(addr) for addr in range(begin, end + 1)]

    def copy_taint(self, source, destination, length):
        for i in range(length):
            if self.triton_ctx.isMemoryTainted(source + i):
                self.triton_ctx.taintMemory(destination + i)
            else:
                self.triton_ctx.untaintMemory(destination + i)

    def is_range_tainted(self, begin, end):
        return any(self.get_taint_range(begin, end))
