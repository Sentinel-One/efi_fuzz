
import binascii

from .save_state_area import create_smm_save_state
from qiling.os.uefi.ProcessorBind import STRUCT, PAGE_SIZE
import ctypes
from qiling.os.uefi.utils import ptr_write64

def register_sw_smi(ql, DispatchFunction, RegisterContext, CommunicationBuffer):
    # Allocate a unique handle for this SMI.
    dh = ql.os.heap.alloc(1)
    
    smi_params = {
        "DispatchFunction": DispatchFunction,
        "RegisterContext": RegisterContext,
        "CommunicationBuffer": CommunicationBuffer,
    }

    # Let's save the dispatch params, so they can be triggered if needed.
    ql.os.smm.swsmi_handlers[dh] = smi_params
    return dh

def unregister_sw_smi(ql, DispatchHandle):
    try:
        del ql.os.smm.swsmi_handlers[DispatchHandle]
        ql.os.heap.free(DispatchHandle)
    except:
        return EFI_INVALID_PARAMETER
    else:
        return EFI_SUCCESS

def trigger_next_smi_handler(ql):
    (dispatch_handle, smi_params) = ql.os.smm.swsmi_handlers.popitem()
    ql.log.info(f"Executing SMI with params {smi_params}")
    
    # IN EFI_HANDLE  DispatchHandle
    ql.reg.rcx = dispatch_handle

    # IN CONST VOID  *Context         OPTIONAL
    register_context = smi_params['RegisterContext']
    if register_context:
        register_context.saveTo(ql, ql.os.smm.context_buffer)
    ql.reg.rdx = ql.os.smm.context_buffer

    comm_buffer = smi_params['CommunicationBuffer'] or ql.os.smm.comm_buffer_fuzz_data
    if comm_buffer:
        # IN OUT VOID    *CommBuffer      OPTIONAL
        if type(comm_buffer) == bytes:
            if len(comm_buffer) > ql.os.smm.comm_buffer_size:
                comm_buffer = comm_buffer[:ql.os.smm.comm_buffer_size]
            ql.mem.write(ql.os.smm.comm_buffer, comm_buffer)
            comm_buffer_size = len(comm_buffer)
            if hasattr(ql, 'tainters') and 'smm' in ql.tainters:
                ql.tainters['smm'].set_taint_range(ql.os.smm.comm_buffer, ql.os.smm.comm_buffer + comm_buffer_size, True)
        else:
            if comm_buffer.sizeof() > ql.os.smm.comm_buffer_size:
                ql.log.error("Structure too big, can't write command buffer")
                return False
            comm_buffer.saveTo(ql, ql.os.smm.comm_buffer)
            comm_buffer_size = comm_buffer.sizeof()
        ql.reg.r8 = ql.os.smm.comm_buffer

        # IN OUT UINTN   *CommBufferSize  OPTIONAL
        ptr_write64(ql, ql.os.smm.comm_buffer_size_ptr, comm_buffer_size)
        ql.reg.r9 = ql.os.smm.comm_buffer_size_ptr

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
