from .smm_sw_dispatch_protocol import install_EFI_SMM_SW_DISPATCH_PROTOCOL
from .smm_sw_dispatch2_protocol import install_EFI_SMM_SW_DISPATCH2_PROTOCOL
from .smm_sx_dispatch_protocol import install_EFI_SMM_SX_DISPATCH_PROTOCOL
from .smm_base_protocol import install_EFI_SMM_BASE_PROTOCOL
from .smm_variable_protocol import install_EFI_SMM_VARIABLE_PROTOCOL
from .smm_cpu_protocol import init_EFI_SMM_CPU_PROTOCOL
from .smm_access_protocol import install_EFI_SMM_ACCESS_PROTOCOL
from .guids import *
from qiling.os.uefi.const import *
from qiling.os.uefi.utils import ptr_write64, ptr_read64
from ..swsmi import trigger_swsmi
import ctypes
import random

def install(ql, in_smm=False):
    install_EFI_SMM_SW_DISPATCH_PROTOCOL(ql)
    install_EFI_SMM_SW_DISPATCH2_PROTOCOL(ql)
    install_EFI_SMM_SX_DISPATCH_PROTOCOL(ql)
    install_EFI_SMM_BASE_PROTOCOL(ql)
    install_EFI_SMM_VARIABLE_PROTOCOL(ql)
    init_EFI_SMM_CPU_PROTOCOL(ql)
    install_EFI_SMM_ACCESS_PROTOCOL(ql)

    def hook_mm_interrupt_register(ql, address, params):
        smi_num = 0
        params['RegisterContext'] = 0
        params['DispatchFunction'] = params["Handler"]
        DispatchHandle = random.getrandbits(64)
        ql.os.smm.swsmi_handlers.append((DispatchHandle, smi_num, params))
        ptr_write64(ql, params["DispatchHandle"], DispatchHandle)
        return EFI_SUCCESS
    
    def hook_efi_mm_interrupt_unregister(ql, address, params):
        dh = ptr_read64(ql, params["DispatchHandle"])
        ql.os.smm.swsmi_handlers[:] = [tup for tup in ql.os.smm.swsmi_handlers if tup[0] != dh]
        return EFI_SUCCESS

    ql.set_api("mm_interrupt_register", hook_mm_interrupt_register)
    ql.set_api("efi_mm_interrupt_unregister", hook_efi_mm_interrupt_unregister)
