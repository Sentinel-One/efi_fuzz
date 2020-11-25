from .smm_cpu_type import EFI_SMM_CPU_PROTOCOL
from qiling.os.uefi.fncc import *
from qiling.os.const import *
from qiling.os.uefi.const import *
from qiling.const import *
import ctypes

from ..save_state_area import read_smm_save_state, write_smm_save_state

@dxeapi(params={
    "This": POINTER, #POINTER_T(struct__EFI_SMM_SW_DISPATCH2_PROTOCOL)
    "Width": POINTER, #POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), POINTER_T(None), POINTER_T(None), POINTER_T(ctypes.c_uint64)))
    "Register": POINTER, #POINTER_T(struct_EFI_SMM_SW_REGISTER_CONTEXT)
    "CpuIndex": POINTER, #POINTER_T(POINTER_T(None))
    "Buffer": POINTER,
})
def hook_SMM_CPU_ReadSaveState(ql, address, params):
    try:
        data = read_smm_save_state(ql, params['Register'], params['Width'])
    except KeyError:
        ql.dprint(D_INFO, f"Unsupported register id {params['Register']}")
        return EFI_UNSUPPORTED

    ql.mem.write(params['Buffer'], data)
    return EFI_SUCCESS

@dxeapi(params={
    "This": POINTER, #POINTER_T(struct__EFI_SMM_SW_DISPATCH2_PROTOCOL)
    "Width": UINT, #POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), POINTER_T(None), POINTER_T(None), POINTER_T(ctypes.c_uint64)))
    "Register": UINT, #POINTER_T(struct_EFI_SMM_SW_REGISTER_CONTEXT)
    "CpuIndex": UINT, #POINTER_T(POINTER_T(None))
    "Buffer": POINTER,
})
def hook_SMM_CPU_WriteSaveState(ql, address, params):
    data = ql.mem.read(params['Buffer'], params['Width'])
    try:
        write_smm_save_state(ql, params['Register'], data)
    except KeyError as e:
        ql.dprint(D_INFO, f"Unsupported register id {params['Register']}")
        return EFI_UNSUPPORTED

    return EFI_SUCCESS


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