from qiling.const import *
from qiling.os.const import *
from qiling.os.uefi.const import *
from qiling.os.uefi.utils import *
from qiling.os.uefi.fncc import *
from .guids import EFI_SMM_BASE_PROTOCOL_GUID
from qiling.os.uefi.ProcessorBind import *
from qiling.os.uefi.UefiBaseType import *

class EFI_SMM_BASE_PROTOCOL(STRUCT):
    EFI_SMM_BASE_PROTOCOL = STRUCT
    _fields_ = [
        ('Register', FUNCPTR(EFI_STATUS, PTR(EFI_SMM_BASE_PROTOCOL), PTR(VOID), PTR(VOID), PTR(VOID), PTR(VOID), PTR(VOID))),
        ('UnRegister', FUNCPTR(EFI_STATUS, PTR(EFI_SMM_BASE_PROTOCOL), PTR(VOID), PTR(VOID), PTR(VOID))),
        ('Communicate', FUNCPTR(EFI_STATUS, PTR(EFI_SMM_BASE_PROTOCOL), PTR(VOID), PTR(VOID), PTR(VOID))),
        ('RegisterCallback', FUNCPTR(EFI_STATUS, PTR(EFI_SMM_BASE_PROTOCOL), PTR(VOID), PTR(VOID), UINT64, UINT64)),
        ('InSmm', FUNCPTR(EFI_STATUS, PTR(EFI_SMM_BASE_PROTOCOL), PTR(VOID))),
        ('SmmAllocatePool', FUNCPTR(EFI_STATUS, PTR(EFI_SMM_BASE_PROTOCOL), UINT64, UINT64, PTR(VOID))),
        ('SmmFreePool', FUNCPTR(EFI_STATUS, PTR(EFI_SMM_BASE_PROTOCOL), PTR(VOID))),
        ('GetSmstLocation', FUNCPTR(EFI_STATUS, PTR(EFI_SMM_BASE_PROTOCOL), PTR(VOID))),
    ]


@dxeapi(params={
    "This": POINTER, #POINTER_T(struct__EFI_SMM_BASE2_PROTOCOL)
    "InSmram": POINTER, #POINTER_T(ctypes.c_ubyte)
})
def hook_InSmm(ql, address, params):
    ptr_write64(ql, params["InSmram"], 1)
    return EFI_SUCCESS

@dxeapi(params={
    "This": POINTER, #POINTER_T(struct__EFI_SMM_BASE2_PROTOCOL)
    "Smst": POINTER, #POINTER_T(POINTER_T(struct__EFI_SMM_SYSTEM_TABLE2))
})
def hook_GetSmstLocation(ql, address, params):
    if params["Smst"] == 0:
        return EFI_INVALID_PARAMETER
    ptr_write64(ql, params["Smst"], ql.loader.mm_system_table_ptr)
    return EFI_SUCCESS


# mm_system_table functions

@dxeapi(params={
    "This": POINTER,
    "Buffer": POINTER,
})
def hook_SmmFreePool(ql, address, params):
    return EFI_INVALID_PARAMETER

@dxeapi(params={
    "This": POINTER,
    "PoolType": INT,
    "Size": INT,
    "Buffer": POINTER,
})
def hook_SmmAllocatePool(ql, address, params):
    address = ql.os.smm.heap_alloc(params["Size"])
    write_int64(ql, params["Buffer"], address)
    return EFI_SUCCESS if address else EFI_OUT_OF_RESOURCES

@dxeapi(params={
    "This": POINTER,
    "SmmImageHandle": POINTER,
    "CallbackAddress": POINTER,
    "MakeLast": INT,
    "FloatingPointSave": INT,
})
def hook_RegisterCallback(ql, address, params):
    return EFI_INVALID_PARAMETER

@dxeapi(params={
    "This": GUID, 
    "ImageHandle": POINTER, 
    "CommunicationBuffer": POINTER, 
    "SourceSize": POINTER, 
})
def hook_Communicate(ql, address, params):
    return EFI_SUCCESS

@dxeapi(params={
    "This": POINTER, 
    "ImageHandle": POINTER, 
})
def hook_UnRegister(ql, address, params):
    return EFI_SUCCESS

@dxeapi(params={
    "This": POINTER, 
    "FilePath": POINTER,
    "SourceBuffer": POINTER,
    "SourceSize": POINTER,
    "ImageHandle": POINTER,
    "LegacyIA32Binary": POINTER,
})
def hook_Register(ql, address, params):
    return EFI_SUCCESS

def install_EFI_SMM_BASE_PROTOCOL(ql):
    descriptor = {
        'guid'   : EFI_SMM_BASE_PROTOCOL_GUID,
        'struct' : EFI_SMM_BASE_PROTOCOL,
        'fields' : (
            ('Register',            hook_Register),
            ('UnRegister',          hook_UnRegister),
            ('Communicate',         hook_Communicate),
            ('RegisterCallback',    hook_RegisterCallback),
            ('InSmm',               hook_InSmm),
            ('SmmAllocatePool',     hook_SmmAllocatePool),
            ('SmmFreePool',         hook_SmmFreePool),
            ('GetSmstLocation',     hook_GetSmstLocation)
        )
    }
    ql.loader.smm_context.install_protocol(descriptor, 1)


