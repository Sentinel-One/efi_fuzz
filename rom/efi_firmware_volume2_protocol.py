from qiling.os.uefi.ProcessorBind import FUNCPTR, STRUCT, VOID, PTR, UINT8, UINTN, UINT32
from qiling.os.uefi.const import EFI_BUFFER_TOO_SMALL, EFI_NOT_FOUND, EFI_SUCCESS, EFI_UNSUPPORTED
from qiling.os.uefi.UefiBaseType import EFI_STATUS, EFI_HANDLE
import ctypes
from qiling.os.uefi.fncc import *
from qiling.os.uefi.utils import read_int64, write_int64
from qiling.os.const import *
import uefi_firmware
from enum import Enum

EFI_FIRMWARE_VOLUME2_PROTOCOL_GUID = '220e73b6-6bdb-4413-8405-b974b108619a'

class EFI_SECTION_TYPE(Enum):
    PE32                  = 0x10
    PIC                   = 0x11
    TE                    = 0x12
    DXE_DEPEX             = 0x13
    VERSION               = 0x14
    USER_INTERFACE        = 0x15
    COMPATIBILITY16       = 0x16
    FIRMWARE_VOLUME_IMAGE = 0x17
    FREEFORM_SUBTYPE_GUID = 0x18
    RAW                   = 0x19
    PEI_DEPEX             = 0x1B
    SMM_DEPEX             = 0x1C

class EFI_FIRMWARE_VOLUME2_PROTOCOL(STRUCT):
    EFI_FIRMWARE_VOLUME2_PROTOCOL = STRUCT
    _fields_ = [
        ('GetVolumeAttributes', FUNCPTR(EFI_STATUS, PTR(EFI_FIRMWARE_VOLUME2_PROTOCOL), PTR(VOID))),
        ('SetVolumeAttributes', FUNCPTR(EFI_STATUS, PTR(EFI_FIRMWARE_VOLUME2_PROTOCOL), PTR(VOID))),
        ('ReadFile',            FUNCPTR(EFI_STATUS, PTR(EFI_FIRMWARE_VOLUME2_PROTOCOL), PTR(VOID), PTR(VOID), PTR(VOID), PTR(VOID), PTR(VOID), PTR(VOID))),
        ('ReadSection',         FUNCPTR(EFI_STATUS,  PTR(EFI_FIRMWARE_VOLUME2_PROTOCOL), PTR(VOID), UINT8, UINTN, PTR(VOID), PTR(VOID), PTR(VOID))),
        ('WriteFile',           FUNCPTR(EFI_STATUS, PTR(EFI_FIRMWARE_VOLUME2_PROTOCOL), UINT32, UINT32, UINTN, PTR(VOID))),
        ('GetNextFile',         FUNCPTR(EFI_STATUS, PTR(EFI_FIRMWARE_VOLUME2_PROTOCOL), PTR(VOID), PTR(VOID), PTR(VOID), PTR(VOID), PTR(VOID))),
        ('KeySize',             UINT32),
        ('ParentHandle',        EFI_HANDLE),
        ('GetInfo',             FUNCPTR(EFI_STATUS, PTR(EFI_FIRMWARE_VOLUME2_PROTOCOL), PTR(VOID), PTR(VOID), PTR(VOID))),
        ('SetInfo',             FUNCPTR(EFI_STATUS, PTR(EFI_FIRMWARE_VOLUME2_PROTOCOL), PTR(VOID), UINTN, PTR(VOID))),
]

@dxeapi(params={
    "This": POINTER, #POINTER_T(struct__EFI_SMM_SW_DISPATCH2_PROTOCOL)
    "FvAttributes": POINTER, #POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, PTR(VOID), PTR(VOID), PTR(VOID), POINTER_T(ctypes.c_uint64)))
})
def hook_GetVolumeAttributes(ql, address, params):
    return EFI_UNSUPPORTED

@dxeapi(params={
    "This": POINTER, #POINTER_T(struct__EFI_SMM_SW_DISPATCH2_PROTOCOL)
    "FvAttributes": POINTER, #POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, PTR(VOID), PTR(VOID), PTR(VOID), POINTER_T(ctypes.c_uint64)))
})
def hook_SetVolumeAttributes(ql, address, params):
    return EFI_UNSUPPORTED

@dxeapi(params={
    "This": POINTER, #POINTER_T(struct__EFI_SMM_SW_DISPATCH2_PROTOCOL)
    "NameGuid": POINTER, #POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, PTR(VOID), PTR(VOID), PTR(VOID), POINTER_T(ctypes.c_uint64)))
    "Buffer": POINTER,
    "BufferSize": POINTER,
    "FoundType": POINTER,
    "FileAttributes": POINTER,
    "AuthenticationStatus": POINTER,
})
def hook_ReadFile(ql, address, params):
    return EFI_UNSUPPORTED

def get_firmware_file(ql, guid):
    for volume in ql.os.firmware_volumes:
        objects = uefi_firmware.utils.flatten_firmware_objects(volume.iterate_objects())
        for obj in objects:
            if obj['guid'] == guid:
                return obj['_self']

def get_section(fw_file, section_type, section_instance):
    counter = -1
    for section in fw_file.sections:
        if section.type == section_type:
            counter += 1
            if counter == section_instance:
                return section

@dxeapi(params={
    "This": POINTER, #POINTER_T(struct__EFI_SMM_SW_DISPATCH2_PROTOCOL)
    "NameGuid": POINTER, #POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, PTR(VOID), PTR(VOID), PTR(VOID), POINTER_T(ctypes.c_uint64)))
    "SectionType": INT,
    "SectionInstance": INT,
    "Buffer": POINTER,
    "BufferSize": POINTER,
    "AuthenticationStatus": POINTER,
})
def hook_ReadSection(ql, address, params):
    guid = str(ql.os.read_guid(params["NameGuid"]))
    section_type = params["SectionType"] & 0xFF
    
    fw_file = get_firmware_file(ql, guid)
    if not fw_file:
        return EFI_NOT_FOUND

    section = get_section(fw_file, section_type, params["SectionInstance"])
    if not section:
        return EFI_NOT_FOUND

    buffer = read_int64(ql, params["Buffer"])
    if buffer == 0:
        # The output buffer is to be allocated by ReadSection()
        buffer = ql.os.heap.alloc(len(section.data))
        ql.mem.write(buffer, section.data)
        write_int64(ql, params["BufferSize"], len(section.data))    
        write_int64(ql, params["Buffer"], buffer)
        return EFI_SUCCESS

    # The output buffer is caller allocated, ...
    buffer_size = read_int64(ql, params["BufferSize"])
    if buffer_size < len(section.data):
        # But is not big enough
        write_int64(ql, params["BufferSize"], len(section.data))
        return EFI_BUFFER_TOO_SMALL

    # And is big enough
    write_int64(ql, params["BufferSize"], len(section.data))
    ql.mem.write(buffer, section.data)
    return EFI_SUCCESS

@dxeapi(params={
    "This": POINTER, #POINTER_T(struct__EFI_SMM_SW_DISPATCH2_PROTOCOL)
    "NumberOfFiles": INT, #POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, PTR(VOID), PTR(VOID), PTR(VOID), POINTER_T(ctypes.c_uint64)))
    "WritePolicy": INT,
    "FileData": POINTER,
})
def hook_WriteFile(ql, address, params):
    return EFI_UNSUPPORTED

@dxeapi(params={
    "This": POINTER, #POINTER_T(struct__EFI_SMM_SW_DISPATCH2_PROTOCOL)
    "Key": POINTER, #POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, PTR(VOID), PTR(VOID), PTR(VOID), POINTER_T(ctypes.c_uint64)))
    "FileType": POINTER,
    "NameGuid": POINTER,
    "Attributes": POINTER,
    "Size": POINTER,
})
def hook_GetNextFile(ql, address, params):
    return EFI_UNSUPPORTED

@dxeapi(params={
    "This": POINTER, #POINTER_T(struct__EFI_SMM_SW_DISPATCH2_PROTOCOL)
    "InformationType": POINTER, #POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, PTR(VOID), PTR(VOID), PTR(VOID), POINTER_T(ctypes.c_uint64)))
    "BufferSize": POINTER,
    "Buffer": POINTER,
})
def hook_GetInfo(ql, address, params):
    return EFI_UNSUPPORTED

@dxeapi(params={
    "This": POINTER, #POINTER_T(struct__EFI_SMM_SW_DISPATCH2_PROTOCOL)
    "InformationType": POINTER, #POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, PTR(VOID), PTR(VOID), PTR(VOID), POINTER_T(ctypes.c_uint64)))
    "BufferSize": INT,
    "Buffer": POINTER,
})
def hook_SetInfo(ql, address, params):
    return EFI_UNSUPPORTED

def install_EFI_FIRMWARE_VOLUME2_PROTOCOL(ql):
    descriptor = {
        'guid'   : EFI_FIRMWARE_VOLUME2_PROTOCOL_GUID,
        'struct' : EFI_FIRMWARE_VOLUME2_PROTOCOL,
        'fields' : (
            ('GetVolumeAttributes', hook_GetVolumeAttributes),
            ('SetVolumeAttributes', hook_SetVolumeAttributes),
            ('ReadFile',            hook_ReadFile),
            ('ReadSection',         hook_ReadSection),
            ('WriteFile',           hook_WriteFile),
            ('GetNextFile',         hook_GetNextFile),
            # ('KeySize',             
            # ('ParentHandle',       
            ('GetInfo',             hook_GetInfo),
            ('SetInfo',             hook_SetInfo),
        )
    }
    ql.loader.dxe_context.install_protocol(descriptor, 1)
