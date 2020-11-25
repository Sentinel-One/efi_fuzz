from qiling.const import *
from qiling.os.const import *
from qiling.os.uefi.const import *
from qiling.os.uefi.utils import *
from .smm_base_type import *
from qiling.os.uefi.fncc import *
import ctypes


@dxeapi(params={
    "This": POINTER, #POINTER_T(struct__EFI_SMM_BASE2_PROTOCOL)
    "InSmram": POINTER, #POINTER_T(ctypes.c_ubyte)
})
def hook_InSmm(ql, address, params):
    write_int64(ql, params["InSmram"], 1)
    return EFI_SUCCESS

@dxeapi(params={
    "This": POINTER, #POINTER_T(struct__EFI_SMM_BASE2_PROTOCOL)
    "Smst": POINTER, #POINTER_T(POINTER_T(struct__EFI_SMM_SYSTEM_TABLE2))
})
def hook_GetSmstLocation(ql, address, params):
    if params["Smst"] == 0:
        return EFI_INVALID_PARAMETER
    write_int64(ql, params["Smst"], ql.loader.mm_system_table_ptr)
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
    return EFI_INVALID_PARAMETER

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

def install_EFI_SMM_BASE_PROTOCOL(ql, start_ptr):
    efi_smm_base_protocol = EFI_SMM_BASE_PROTOCOL()
    ptr = start_ptr + ctypes.sizeof(EFI_SMM_BASE_PROTOCOL)
    pointer_size = 8
    
    efi_smm_base_protocol.Register = ptr
    ql.hook_address(hook_Register, ptr)
    ptr += pointer_size

    efi_smm_base_protocol.UnRegister = ptr
    ql.hook_address(hook_UnRegister, ptr)
    ptr += pointer_size

    efi_smm_base_protocol.Communicate = ptr
    ql.hook_address(hook_Communicate, ptr)
    ptr += pointer_size

    efi_smm_base_protocol.RegisterCallback = ptr
    ql.hook_address(hook_RegisterCallback, ptr)
    ptr += pointer_size

    efi_smm_base_protocol.InSmm = ptr
    ql.hook_address(hook_InSmm, ptr)
    ptr += pointer_size

    efi_smm_base_protocol.SmmAllocatePool = ptr
    ql.hook_address(hook_SmmAllocatePool, ptr)
    ptr += pointer_size

    efi_smm_base_protocol.SmmFreePool = ptr
    ql.hook_address(hook_SmmFreePool, ptr)
    ptr += pointer_size

    efi_smm_base_protocol.GetSmstLocation = ptr
    ql.hook_address(hook_GetSmstLocation, ptr)
    ptr += pointer_size

    # mm_system_table functions
    # efi_mm_system_table.MmStartupThisAp = ptr
    # ql.hook_address(hook_mm_startup_this_ap, ptr)
    # ptr += pointer_size
    # efi_mm_system_table.MmiManage = ptr
    # ql.hook_address(hook_mm_interrupt_manage, ptr)
    # ptr += pointer_size
    # efi_mm_system_table.MmiHandlerRegister = ptr
    # ql.hook_address(hook_mm_interrupt_register, ptr)
    # ptr += pointer_size
    # efi_mm_system_table.MmiHandlerUnRegister = ptr
    # ql.hook_address(hook_efi_mm_interrupt_unregister, ptr)
    # ptr += pointer_size

    return (ptr, efi_smm_base_protocol)

