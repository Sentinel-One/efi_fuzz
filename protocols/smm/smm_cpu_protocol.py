from .smm_cpu_type import EFI_SMM_CPU_PROTOCOL
from qiling.os.uefi.fncc import *
from qiling.os.const import *
from qiling.os.uefi.const import *
import ctypes

@dxeapi(params={
    "This": POINTER, #POINTER_T(struct__EFI_SMM_SW_DISPATCH2_PROTOCOL)
    "Width": POINTER, #POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), POINTER_T(None), POINTER_T(None), POINTER_T(ctypes.c_uint64)))
    "Register": POINTER, #POINTER_T(struct_EFI_SMM_SW_REGISTER_CONTEXT)
    "CpuIndex": POINTER, #POINTER_T(POINTER_T(None))
    "Buffer": POINTER,
})
def hook_SMM_CPU_ReadSaveState(ql, address, params):
    return EFI_UNSUPPORTED

@dxeapi(params={
    "This": POINTER, #POINTER_T(struct__EFI_SMM_SW_DISPATCH2_PROTOCOL)
    "Width": UINT, #POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), POINTER_T(None), POINTER_T(None), POINTER_T(ctypes.c_uint64)))
    "Register": UINT, #POINTER_T(struct_EFI_SMM_SW_REGISTER_CONTEXT)
    "CpuIndex": UINT, #POINTER_T(POINTER_T(None))
    "Buffer": POINTER,
})
def hook_SMM_CPU_WriteSaveState(ql, address, params):
    # Since we are not really in smm mode, we can just call the function from here
    return EFI_UNSUPPORTED


def install_EFI_SMM_CPU_PROTOCOL(ql, start_ptr):
    efi_smm_cpu_protocol = EFI_SMM_CPU_PROTOCOL()
    ptr = start_ptr + ctypes.sizeof(EFI_SMM_CPU_PROTOCOL)
    pointer_size = 8

    efi_smm_cpu_protocol.ReadSaveState = ptr
    ql.hook_address(hook_SMM_CPU_ReadSaveState, ptr)
    ptr += pointer_size

    efi_smm_cpu_protocol.WriteSaveState = ptr
    ql.hook_address(hook_SMM_CPU_WriteSaveState, ptr)
    ptr += pointer_size

    return (ptr, efi_smm_cpu_protocol)