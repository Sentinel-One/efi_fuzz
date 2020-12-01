from .save_state_area import create_smm_save_state
from qiling.os.uefi.utils import convert_struct_to_bytes
from qiling.const import D_INFO
import ctypes

def after_module_execution_callback(ql, number_of_modules_left):
    if number_of_modules_left == 0:
        return trigger_swsmi(ql)
    return False

class EFI_SMM_SW_CONTEXT(ctypes.Structure):
    _fields_ = [
        ('SwSmiCpuIndex', ctypes.c_uint64),
        ('CommandPort', ctypes.c_uint8),
        ('DataPort', ctypes.c_uint8)
    ]

def trigger_next_smi_handler(ql):
    pointer_size = 8

    (smi_num, smi_params) = ql.os.smm.swsmi_handlers.pop(0)
    ql.dprint(D_INFO, f"Executing SMI 0x{smi_num:x} with params {smi_params}")
    
    ql.reg.rcx = smi_params["DispatchHandle"]
    ql.reg.rdx = smi_params["RegisterContext"]

    # The CommandPort should correspond to the SMI's number.
    # See https://github.com/tianocore/edk2/blob/master/MdePkg/Include/Protocol/SmmSwDispatch2.h for more details
    smm_sw_context = EFI_SMM_SW_CONTEXT(0, smi_num, 0)

    ql.mem.write(ql.os.smm.comm_buffer, convert_struct_to_bytes(smm_sw_context))
    ql.reg.r8 = ql.os.smm.comm_buffer  # OUT VOID    *CommBuffer
    ql.reg.r9 = ql.os.smm.comm_buffer_size # OUT UINTN   *CommBufferSize
    ql.reg.rip = smi_params["DispatchFunction"]
    ql.stack_push(ql.loader.end_of_execution_ptr)
    return True

def trigger_swsmi(ql, user_data=None):
    if len(ql.os.smm.swsmi_handlers) < 1:
        # No SMI handlers
        return False

    # Apply fuzzed registers
    for (reg, value) in ql.os.smm.swsmi_args.items():
        ql.reg.write(reg, int.from_bytes(value, 'little'))
        
    create_smm_save_state(ql)

    # Call the dispatcher
    return trigger_next_smi_handler(ql)
