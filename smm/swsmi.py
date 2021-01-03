from .save_state_area import create_smm_save_state
from qiling.os.uefi.ProcessorBind import STRUCT
from qiling.const import D_INFO
import ctypes


class EFI_SMM_SW_CONTEXT(STRUCT):
    _fields_ = [
        ('SwSmiCpuIndex', ctypes.c_uint64),
        ('CommandPort', ctypes.c_uint8),
        ('DataPort', ctypes.c_uint8)
    ]

def trigger_next_smi_handler(ql):
    (dispatch_handle, smi_num, smi_params) = ql.os.smm.swsmi_handlers.pop(0)
    ql.nprint(f"Executing SMI 0x{smi_num:x} with params {smi_params}")
    
    # IN EFI_HANDLE  DispatchHandle
    ql.reg.rcx = dispatch_handle

    # IN CONST VOID  *Context         OPTIONAL
    ql.mem.write(ql.os.smm.context_buffer, convert_struct_to_bytes(smi_params["RegisterContext"]))
    ql.reg.rdx = ql.os.smm.context_buffer

    # The CommandPort should correspond to the SMI's number.
    # See https://github.com/tianocore/edk2/blob/master/MdePkg/Include/Protocol/SmmSwDispatch2.h for more details
    
    smm_sw_context = EFI_SMM_SW_CONTEXT(0, smi_num, 0)
    smm_sw_context.saveTo(ql.os.smm.comm_buffer)

    ql.reg.r8 = ql.os.smm.comm_buffer  # OUT VOID    *CommBuffer
    ql.reg.r9 = ql.os.smm.comm_buffer_size # OUT UINTN   *CommBufferSize
    ql.reg.rip = smi_params["DispatchFunction"]
    ql.stack_push(ql.loader.end_of_execution_ptr)
    return True

def trigger_swsmi(ql, user_data=None):
    if len(ql.os.smm.swsmi_handlers) < 1:
        # No SMI handlers
        return False

    saved_regs = ql.reg.save()

    # Apply fuzzed registers
    for (reg, value) in ql.os.smm.swsmi_args.items():
        ql.reg.write(reg, int.from_bytes(value, 'little'))
        
    create_smm_save_state(ql)

    # Restore the saved registers, we only want them to be manifested in the SMRAM save state area.
    ql.reg.restore(saved_regs)

    # Call the dispatcher
    return trigger_next_smi_handler(ql)

def fuzzable_registers():
    GP_REGISTERS = (
        "rax",
        "rbx",
        "rcx",
        "rdx",
        "rsi",
        "rdi",
        "rbp",
        "rsp",
        "r8",
        "r9",
        "r10",
        "r11",
        "r12",
        "r13",
        "r14",
        "r15",
        "ef",
    )

    return GP_REGISTERS
