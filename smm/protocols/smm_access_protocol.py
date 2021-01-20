from smm.protocols.guids import EFI_SMM_ACCESS_PROTOCOL_GUID
from qiling.os.uefi.fncc import *
from qiling.os.const import *
from qiling.os.uefi.const import *
from qiling.os.uefi.utils import *
from ctypes import Structure, c_uint64, sizeof
from qiling.os.uefi.ProcessorBind import *
from qiling.os.uefi.UefiBaseType import *
from enum import IntEnum

class EFI_SMRAM_STATE(IntEnum):
    EFI_MMRAM_OPEN               = 0x00000001
    EFI_MMRAM_CLOSED             = 0x00000002
    EFI_MMRAM_LOCKED             = 0x00000004
    EFI_CACHEABLE                = 0x00000008
    EFI_ALLOCATED                = 0x00000010
    EFI_NEEDS_TESTING            = 0x00000020
    EFI_NEEDS_ECC_INITIALIZATION = 0x00000040


class EFI_MMRAM_DESCRIPTOR(STRUCT):
    EFI_MMRAM_DESCRIPTOR = STRUCT
    # @TODO: should be UINTN?
    _fields_ = [
        ('PhysicalStart', UINT64),
        ('CpuStart', UINT64),
        ('PhysicalSize', UINT64),
        ('RegionState', UINT64),
    ]

class EFI_SMM_ACCESS_PROTOCOL(STRUCT):
    EFI_SMM_ACCESS_PROTOCOL = STRUCT
    _fields_ = [
        ('Open', FUNCPTR(EFI_STATUS, PTR(EFI_SMM_ACCESS_PROTOCOL), UINTN)),
        ('Close', FUNCPTR(EFI_STATUS, PTR(EFI_SMM_ACCESS_PROTOCOL), UINTN)),
        ('Lock', FUNCPTR(EFI_STATUS, PTR(EFI_SMM_ACCESS_PROTOCOL), UINTN)),
        ('GetCapabilities', FUNCPTR(EFI_STATUS, PTR(EFI_SMM_ACCESS_PROTOCOL), PTR(UINTN), PTR(VOID))),
        ('LockState', BOOLEAN),
        ('OpenState', BOOLEAN),
    ]

def EFI_MMRAM_DESCRIPTOR_ARRAY(num_descriptors):
    class _EFI_MMRAM_DESCRIPTOR_ARRAY(STRUCT):
        EFI_MMRAM_DESCRIPTOR_ARRAY = STRUCT
        _fields_ = [
            ('Descriptors', (EFI_MMRAM_DESCRIPTOR * num_descriptors))
        ]

    return _EFI_MMRAM_DESCRIPTOR_ARRAY()

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

def install_EFI_SMM_ACCESS_PROTOCOL(ql):

    def init_GetCapabilities(ql):
        number_of_map_info_entries = 2 # We only support two SMRAM region
        struct_size = sizeof(EFI_MMRAM_DESCRIPTOR)
        ql.os.smm.get_capabilities_info_size = number_of_map_info_entries * struct_size
        ql.os.smm.get_capabilities_info  = ql.os.heap.alloc(ql.os.smm.get_capabilities_info_size)

        efi_mmram_descriptor = EFI_MMRAM_DESCRIPTOR_ARRAY(number_of_map_info_entries)
        # CSEG
        efi_mmram_descriptor.Descriptors[0].PhysicalStart = ql.os.smm.cseg.base
        efi_mmram_descriptor.Descriptors[0].CpuStart = ql.os.smm.cseg.base
        efi_mmram_descriptor.Descriptors[0].PhysicalSize = ql.os.smm.cseg.size
        efi_mmram_descriptor.Descriptors[0].RegionState = EFI_SMRAM_STATE.EFI_ALLOCATED
        # TSEG
        efi_mmram_descriptor.Descriptors[1].PhysicalStart = ql.os.smm.tseg.base
        efi_mmram_descriptor.Descriptors[1].CpuStart = ql.os.smm.tseg.base
        efi_mmram_descriptor.Descriptors[1].PhysicalSize = ql.os.smm.tseg.size
        efi_mmram_descriptor.Descriptors[1].RegionState = EFI_SMRAM_STATE.EFI_ALLOCATED

        efi_mmram_descriptor.saveTo(ql, ql.os.smm.get_capabilities_info)        

    descriptor = {
        'guid': EFI_SMM_ACCESS_PROTOCOL_GUID,
        'struct' : EFI_SMM_ACCESS_PROTOCOL,
        'fields' : (
            ('Open', hook_Open),
            ('Close', hook_Close),
            ('Lock', hook_Lock),
            ('GetCapabilities', hook_GetCapabilities)
        )
    }
    ql.loader.smm_context.install_protocol(descriptor, 1)

    init_GetCapabilities(ql)
