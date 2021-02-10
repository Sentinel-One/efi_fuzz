
import binascii

from .save_state_area import create_smm_save_state
from qiling.os.uefi.ProcessorBind import STRUCT, PAGE_SIZE
import ctypes
from qiling.os.uefi.utils import ptr_write64


def trigger_next_smi_handler(ql):
    (dispatch_handle, smi_params) = ql.os.smm.swsmi_handlers.popitem()
    ql.log.info(f"Executing SMI with params {smi_params}")
    
    # IN EFI_HANDLE  DispatchHandle
    ql.reg.rcx = dispatch_handle

    # IN CONST VOID  *Context         OPTIONAL
    register_context = smi_params['RegisterContext']
    register_context.saveTo(ql, ql.os.smm.context_buffer)
    ql.reg.rdx = ql.os.smm.context_buffer

    comm_buffer = smi_params['CommunicationBuffer']
    if comm_buffer:
        # IN OUT VOID    *CommBuffer      OPTIONAL
        comm_buffer.saveTo(ql, ql.os.smm.comm_buffer)
        ql.reg.r8 = ql.os.smm.comm_buffer

        # IN OUT UINTN   *CommBufferSize  OPTIONAL
        size_ptr = ql.os.smm.comm_buffer + comm_buffer.sizeof()
        ptr_write64(ql, size_ptr, comm_buffer.sizeof())
        ql.reg.r9 = size_ptr

    ql.reg.rip = smi_params["DispatchFunction"]
    ql.stack_push(ql.loader.end_of_execution_ptr)
    return True

def trigger_swsmi(ql, user_data=None):
    if len(ql.os.smm.swsmi_handlers) < 1:
        # No SMI handlers
        return False

    saved_regs = ql.reg.save()

    # Apply registers
    if ql.os.smm.swsmi_args.get('registers'):
        for (reg, value) in ql.os.smm.swsmi_args['registers'].items():
            ql.reg.write(reg, int(value, 0))
        
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
