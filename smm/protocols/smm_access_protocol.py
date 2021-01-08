from .smm_access_type import EFI_MMRAM_DESCRIPTOR, EFI_SMM_ACCESS_PROTOCOL, EFI_SMRAM_STATE
from qiling.os.uefi.fncc import *
from qiling.os.const import *
from qiling.os.uefi.const import *
from qiling.os.uefi.utils import *
# from qiling.const import *
from ctypes import Structure, c_uint64, sizeof

@dxeapi(params={
    "This": POINTER, #POINTER_T(struct__EFI_MM_ACCESS_PROTOCOL)
})
def hook_Open(ql, address, params):
    return EFI_UNSUPPORTED

@dxeapi(params={
    "This": POINTER, #POINTER_T(struct__EFI_MM_ACCESS_PROTOCOL)
})
def hook_Close(ql, address, params):
    return EFI_UNSUPPORTED

@dxeapi(params={
    "This": POINTER, #POINTER_T(struct__EFI_MM_ACCESS_PROTOCOL)
})
def hook_Lock(ql, address, params):
    return EFI_UNSUPPORTED

@dxeapi(params={
    "This": POINTER, #POINTER_T(struct__EFI_MM_ACCESS_PROTOCOL)
    "MmramMapSize": POINTER, #POINTER_T(ctypes.c_uint64)
    "MmramMap": POINTER, #POINTER_T(struct_EFI_MMRAM_DESCRIPTOR)
})
def hook_GetCapabilities(ql, address, params):
    write_int64(ql, params["MmramMapSize"], ql.os.smm.get_capabilities_info_size)
    if params['MmramMap'] != 0:
        write_int64(ql, params['MmramMap'], ql.os.smm.get_capabilities_info)
        return EFI_SUCCESS
    return EFI_BUFFER_TOO_SMALL

def install_EFI_SMM_ACCESS_PROTOCOL(ql, start_ptr):

    def init_GetCapabilities(ql):
        number_of_map_info_entries = 2 # We only support two SMRAM region
        struct_size = sizeof(EFI_MMRAM_DESCRIPTOR)
        ql.os.smm.get_capabilities_info_size = number_of_map_info_entries * struct_size
        ql.os.smm.get_capabilities_info  = ql.os.heap.alloc(ql.os.smm.get_capabilities_info_size)

        efi_mmram_descriptor = (EFI_MMRAM_DESCRIPTOR * number_of_map_info_entries)()
        # CSEG
        efi_mmram_descriptor[0].PhysicalStart = ql.os.smm.cseg_base
        efi_mmram_descriptor[0].CpuStart = ql.os.smm.cseg_base
        efi_mmram_descriptor[0].PhysicalSize = ql.os.smm.cseg_size
        efi_mmram_descriptor[0].RegionState = EFI_SMRAM_STATE.EFI_ALLOCATED
        # TSEG
        efi_mmram_descriptor[1].PhysicalStart = ql.os.smm.tseg_base
        efi_mmram_descriptor[1].CpuStart = ql.os.smm.tseg_base
        efi_mmram_descriptor[1].PhysicalSize = ql.os.smm.tseg_size
        efi_mmram_descriptor[1].RegionState = EFI_SMRAM_STATE.EFI_ALLOCATED
        
        ql.mem.write(ql.os.smm.get_capabilities_info, convert_struct_to_bytes(efi_mmram_descriptor))

    efi_smm_access_protocol = EFI_SMM_ACCESS_PROTOCOL()
    ptr = start_ptr
    pointer_size = 8

    efi_smm_access_protocol.Open = ptr
    ql.hook_address(hook_Open, ptr)
    ptr += pointer_size

    efi_smm_access_protocol.Close = ptr
    ql.hook_address(hook_Close, ptr)
    ptr += pointer_size

    efi_smm_access_protocol.Lock = ptr
    ql.hook_address(hook_Lock, ptr)
    ptr += pointer_size

    init_GetCapabilities(ql)
    efi_smm_access_protocol.GetCapabilities = ptr
    ql.hook_address(hook_GetCapabilities, ptr)
    ptr += pointer_size

    return (ptr, efi_smm_access_protocol)


