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
from ..swsmi import trigger_swsmi, register_sw_smi, unregister_sw_smi
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
        dh = register_sw_smi(ql, params["Handler"], 0, 0)
        if dh:
            ptr_write64(ql, params["DispatchHandle"], dh)
            return EFI_SUCCESS
        else:
            return EFI_OUT_OF_RESOURCES
    
    def hook_efi_mm_interrupt_unregister(ql, address, params):
        return unregister_sw_smi(ql, params["DispatchHandle"])

    ql.set_api("mm_interrupt_register", hook_mm_interrupt_register)
    ql.set_api("efi_mm_interrupt_unregister", hook_efi_mm_interrupt_unregister)

    # For now we don't have anyting diffrent to do for SMMCs, so let's use the same hook functions.
    ql.set_api("SmiHandlerRegister", hook_mm_interrupt_register)
    ql.set_api("SmiHandlerUnRegister", hook_efi_mm_interrupt_unregister)