from .smm_sw_dispatch_protocol import install_EFI_SMM_SW_DISPATCH_PROTOCOL
from .smm_sw_dispatch2_protocol import install_EFI_SMM_SW_DISPATCH2_PROTOCOL
from .smm_sx_dispatch_protocol import install_EFI_SMM_SX_DISPATCH_PROTOCOL
from .smm_base_protocol import install_EFI_SMM_BASE_PROTOCOL
from .smm_variable_protocol import install_EFI_SMM_VARIABLE_PROTOCOL
from .smm_access_protocol import install_EFI_SMM_ACCESS_PROTOCOL
from .guids import *
from qiling.os.uefi.const import *
from ..swsmi import EFI_SMM_SW_CONTEXT, trigger_swsmi
import ctypes
import random

class SmmState(object):
    def __init__(self, ql):
        self.swsmi_handlers = []
        self.smbase = int(ql.os.profile.get("SMM", "smbase"), 0)
        self.smram_size = int(ql.os.profile.get("SMM", "smram_size"), 0)
        self.swsmi_args = {}
        
        # Communication buffer
        self.comm_buffer = ql.os.heap.alloc(ctypes.sizeof(EFI_SMM_SW_CONTEXT))
        self.comm_buffer_size = ql.os.heap.alloc(ctypes.sizeof(ctypes.c_void_p))
        ql.mem.write(self.comm_buffer_size, ctypes.sizeof(EFI_SMM_SW_CONTEXT).to_bytes(ctypes.sizeof(ctypes.c_void_p), 'little'))
        
        # Reserve SMRAM
        ql.mem.map(self.smbase, self.smram_size)

def init(ql, in_smm=False):
    install_EFI_SMM_SW_DISPATCH_PROTOCOL(ql)
    install_EFI_SMM_SW_DISPATCH2_PROTOCOL(ql)
    install_EFI_SMM_SX_DISPATCH_PROTOCOL(ql)
    install_EFI_SMM_BASE_PROTOCOL(ql)
    install_EFI_SMM_VARIABLE_PROTOCOL(ql)

    ql.os.smm = SmmState(ql)

    def hook_InSmm(ql, address, params):
        nonlocal in_smm
        write_int64(ql, params["InSmram"], in_smm)

    # Replace 'InSmm' to correctly report whether or not we're executing an SMM module.
    ql.set_api("InSmm", hook_InSmm)

    def after_module_execution_callback(ql, number_of_modules_left):
        if number_of_modules_left == 0:
            return trigger_swsmi(ql)
        return False

    ql.os.after_module_execution_callbacks.append(after_module_execution_callback)
    
    init_GetCapabilities(ql)

    def hook_mm_interrupt_register(ql, address, params):
        smi_num = 0
        params['RegisterContext'] = 0
        params['DispatchFunction'] = params["Handler"]
        DispatchHandle = random.getrandbits(64)
        ql.os.smm.swsmi_handlers.append((DispatchHandle, smi_num, params))
        write_int64(ql, params["DispatchHandle"], DispatchHandle)
        return EFI_SUCCESS
    
    def hook_efi_mm_interrupt_unregister(ql, address, params):
        dh = read_int64(ql, params["DispatchHandle"])
        ql.os.smm.swsmi_handlers[:] = [tup for tup in ql.os.smm.swsmi_handlers if tup[0] != dh]
        return EFI_SUCCESS

    ql.set_api("mm_interrupt_register", hook_mm_interrupt_register)
    ql.set_api("efi_mm_interrupt_unregister", hook_efi_mm_interrupt_unregister)
