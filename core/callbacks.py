import capstone
from unicorn import *
from unicorn.x86_const import *

def after_module_execution_callback(ql, number_of_modules_left):
    ret = False
    for callback in ql.os.after_module_execution_callbacks:
        if callback(ql, number_of_modules_left):
            ret = True
    return ret

# We need to hook the `in` instruction to support ACPI Power Management Timer.
PM_TMR_PORT = 0x1808
def hook_in(uc, port, size, ql):
    if port == PM_TMR_PORT:
        ql.count += 10000
        return ql.count
    return 0

def init_callbacks(ql):
    ql.os.after_module_execution_callbacks = []
    ql.os.notify_after_module_execution = after_module_execution_callback
    
    ql.count = 0
    ql.uc.hook_add(UC_HOOK_INSN, hook_in, ql, 1, 0, UC_X86_INS_IN)

def end_of_execution_callback(ql):
    after_module_execution_callback(ql, 0)

def set_end_of_execution_callback(ql, address):

    def next_instruction_address(ql, address):
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        buf = ql.mem.read(address, 16)
        insn = next(cs.disasm(buf, address))
        return address + insn.size

    end_address = next_instruction_address(ql, address)
    ql.hook_address(callback=end_of_execution_callback, address=address)
    return end_address