from qiling.const import *
from qiling.os.const import *
from qiling.os.uefi.const import *
from qiling.os.uefi.fncc import *
from .guids import EFI_SMM_SX_DISPATCH_PROTOCOL_GUID
from qiling.os.uefi.ProcessorBind import *
from qiling.os.uefi.UefiBaseType import *

class EFI_SMM_SX_DISPATCH_PROTOCOL(STRUCT):
    EFI_SMM_SX_DISPATCH_PROTOCOL = STRUCT
    _fields_ = [
        ('Register', FUNCPTR(EFI_STATUS, PTR(EFI_SMM_SX_DISPATCH_PROTOCOL), PTR(VOID), PTR(VOID), PTR(EFI_HANDLE))),
        ('UnRegister', FUNCPTR(EFI_STATUS, PTR(EFI_SMM_SX_DISPATCH_PROTOCOL), EFI_HANDLE))
    ]


@dxeapi(params={
    "This": POINTER, #POINTER_T(struct__EFI_SMM_SX_DISPATCH2_PROTOCOL)
    "DispatchFunction": POINTER, #POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), POINTER_T(None), POINTER_T(None), POINTER_T(ctypes.c_uint64)))
    "RegisterContext": POINTER, #POINTER_T(struct_EFI_SMM_SX_REGISTER_CONTEXT)
    "DispatchHandle": POINTER, #POINTER_T(POINTER_T(None))
})
def hook_SMM_SX_DISPATCH_Register(ql, address, params):
    return EFI_SUCCESS
    
@dxeapi(params={
    "This": POINTER, #POINTER_T(struct__EFI_SMM_SX_DISPATCH2_PROTOCOL)
    "DispatchHandle": POINTER, #POINTER_T(None)
})
def hook_SMM_SX_DISPATCH_UnRegister(ql, address, params):
    return EFI_UNSUPPORTED

def install_EFI_SMM_SX_DISPATCH_PROTOCOL(ql):
    descriptor = {
        'guid'   : EFI_SMM_SX_DISPATCH_PROTOCOL_GUID,
        'struct' : EFI_SMM_SX_DISPATCH_PROTOCOL,
        'fields' : (
            ('Register',        hook_SMM_SX_DISPATCH_Register),
            ('UnRegister',      hook_SMM_SX_DISPATCH_UnRegister)
        )
    }
    ql.loader.smm_context.install_protocol(descriptor, 1)

