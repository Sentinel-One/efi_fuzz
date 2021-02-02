from qiling.const import *
from qiling.os.const import *
from qiling.os.uefi.const import *
from qiling.os.uefi.fncc import *
from .guids import EFI_SMM_SW_DISPATCH_PROTOCOL_GUID
from qiling.os.uefi.ProcessorBind import *
from qiling.os.uefi.UefiBaseType import *
from qiling.os.uefi.utils import ptr_write64, ptr_read64
import random

class EFI_SMM_SW_DISPATCH_CONTEXT(STRUCT):
    EFI_SMM_SW_DISPATCH_CONTEXT = STRUCT
    _fields_ = [
        ('SwSmiInputValue', UINTN),
    ]

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
    "DispatchContext": POINTER, #POINTER_T(struct_EFI_SMM_SW_REGISTER_CONTEXT)
    "DispatchHandle": POINTER, #POINTER_T(POINTER_T(None))
})
def hook_SMM_SW_DISPATCH_Register(ql, address, params):
    # Read 'this' pointer.
    this = EFI_SMM_SW_DISPATCH_PROTOCOL.loadFrom(ql, params['This'])

    # Read dispatch context.
    smm_sw_dispatch_context = EFI_SMM_SW_DISPATCH_CONTEXT.loadFrom(ql, params['DispatchContext'])

    if smm_sw_dispatch_context.SwSmiInputValue == 0xFFFFFFFF_FFFFFFFF:
        raise NotImplementedError("SwSmiInputValue == 0xFFFFFFFF_FFFFFFFF")
    else:
        registered = [handler['RegisterContext'].SwSmiInputValue for handler in ql.os.smm.swsmi_handlers.values()]
        if smm_sw_dispatch_context.SwSmiInputValue in registered:
            # SMI# is already registered.
            return EFI_INVALID_PARAMETER

        if smm_sw_dispatch_context.SwSmiInputValue > this.MaximumSwiValue:
            # SMI# is too big.
            return EFI_INVALID_PARAMETER

    # Allocate a unique handle for this SMI.
    dh = ql.os.heap.alloc(1)
    ptr_write64(ql, params["DispatchHandle"], dh)
    
    smi_params = {
        "DispatchFunction": params["DispatchFunction"],
        "RegisterContext": smm_sw_dispatch_context,
        "CommunicationBuffer": None,
    }

    # Let's save the dispatch params, so they can be triggered if needed.
    ql.os.smm.swsmi_handlers[dh] = smi_params
    return EFI_SUCCESS
    
@dxeapi(params={
    "This": POINTER, #POINTER_T(struct__EFI_SMM_SW_DISPATCH2_PROTOCOL)
    "DispatchHandle": POINTER, #POINTER_T(None)
})
def hook_SMM_SW_DISPATCH_UnRegister(ql, address, params):
    dh = params['DispatchHandle']
    try:
        del ql.os.smm.swsmi_handlers[dh]
        ql.os.heap.free(dh)
    except:
        return EFI_INVALID_PARAMETER
    else:
        return EFI_SUCCESS

def install_EFI_SMM_SW_DISPATCH_PROTOCOL(ql):
    descriptor = {
        'guid'   : EFI_SMM_SW_DISPATCH_PROTOCOL_GUID,
        'struct' : EFI_SMM_SW_DISPATCH_PROTOCOL,
        'fields' : (
            ('Register',        hook_SMM_SW_DISPATCH_Register),
            ('UnRegister',      hook_SMM_SW_DISPATCH_UnRegister),
            ('MaximumSwiValue', 0xff)
        )
    }
    ql.loader.dxe_context.install_protocol(descriptor, 1)