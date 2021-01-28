from qiling.const import *
from qiling.os.const import *
from qiling.os.uefi.const import *
from qiling.os.uefi.fncc import *
from .guids import EFI_SMM_SW_DISPATCH_PROTOCOL_GUID
from qiling.os.uefi.ProcessorBind import *
from qiling.os.uefi.UefiBaseType import *
from qiling.os.uefi.utils import ptr_write64, ptr_read64

class EFI_SMM_SW_DISPATCH_PROTOCOL(STRUCT):
    EFI_SMM_SW_DISPATCH_PROTOCOL = STRUCT
    _fields_ = [
        ('Register', FUNCPTR(EFI_STATUS, PTR(EFI_SMM_SW_DISPATCH_PROTOCOL), PTR(VOID), PTR(VOID), PTR(VOID))),
        ('UnRegister', FUNCPTR(EFI_STATUS, PTR(EFI_SMM_SW_DISPATCH_PROTOCOL), PTR(VOID))),
        ('MaximumSwiValue', UINT64)
    ]

@dxeapi(params={
    "This": POINTER, #POINTER_T(struct__EFI_SMM_SW_DISPATCH2_PROTOCOL)
    "DispatchFunction": POINTER, #POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), POINTER_T(None), POINTER_T(None), POINTER_T(ctypes.c_uint64)))
    "RegisterContext": POINTER, #POINTER_T(struct_EFI_SMM_SW_REGISTER_CONTEXT)
    "DispatchHandle": POINTER, #POINTER_T(POINTER_T(None))
})
def hook_SMM_SW_DISPATCH_Register(ql, address, params):
    smi_num = int.from_bytes(ql.mem.read(params['RegisterContext'], 8), 'little')
    DispatchHandle = random.getrandbits(64)
    ql.os.smm.swsmi_handlers.append((DispatchHandle, smi_num, params))
    ptr_write64(ql, params["DispatchHandle"], DispatchHandle)
    return EFI_SUCCESS
    
@dxeapi(params={
    "This": POINTER, #POINTER_T(struct__EFI_SMM_SW_DISPATCH2_PROTOCOL)
    "DispatchHandle": POINTER, #POINTER_T(None)
})
def hook_SMM_SW_DISPATCH_UnRegister(ql, address, params):
    dh = ptr_read64(ql, params["DispatchHandle"])
    ql.os.smm.swsmi_handlers[:] = [tup for tup in ql.os.smm.swsmi_handlers if tup[0] != dh]
    return EFI_UNSUPPORTED

def install_EFI_SMM_SW_DISPATCH_PROTOCOL(ql):
    descriptor = {
        'guid'   : EFI_SMM_SW_DISPATCH_PROTOCOL_GUID,
        'struct' : EFI_SMM_SW_DISPATCH_PROTOCOL,
        'fields' : (
            ('Register',        hook_SMM_SW_DISPATCH_Register),
            ('UnRegister',      hook_SMM_SW_DISPATCH_UnRegister),
            ('MaximumSwiValue', None)
        )
    }
    ql.loader.dxe_context.install_protocol(descriptor, 1)