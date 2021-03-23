import random
from qiling.const import *
from qiling.os.const import *
from qiling.os.uefi.fncc import *
from .guids import EFI_SMM_SW_DISPATCH2_PROTOCOL_GUID
from qiling.os.uefi.ProcessorBind import *
from qiling.os.uefi.UefiBaseType import *
from qiling.os.uefi.const import *
from qiling.os.uefi.utils import ptr_write64, ptr_read64

class EFI_SMM_SW_REGISTER_CONTEXT(STRUCT):
    EFI_SMM_SW_REGISTER_CONTEXT = STRUCT
    _fields_ = [
        ('SwSmiInputValue', UINTN),
    ]

class EFI_SMM_SW_CONTEXT(STRUCT):
    EFI_SMM_SW_CONTEXT = STRUCT
    _fields_ = [
        ('SwSmiCpuIndex', UINTN),
        ('CommandPort', UINT8),
        ('DataPort', UINT8)
    ]

class EFI_SMM_SW_DISPATCH2_PROTOCOL(STRUCT):
    EFI_SMM_SW_DISPATCH2_PROTOCOL = STRUCT
    _fields_ = [
        ('Register', FUNCPTR(EFI_STATUS, PTR(EFI_SMM_SW_DISPATCH2_PROTOCOL), PTR(VOID), PTR(VOID), PTR(VOID))),
        ('UnRegister', FUNCPTR(EFI_STATUS, PTR(EFI_SMM_SW_DISPATCH2_PROTOCOL), PTR(VOID))),
        ('MaximumSwiValue', UINT64)
    ]



@dxeapi(params={
    "This": POINTER, #POINTER_T(struct__EFI_SMM_SW_DISPATCH2_PROTOCOL)
    "DispatchFunction": POINTER, #POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), POINTER_T(None), POINTER_T(None), POINTER_T(ctypes.c_uint64)))
    "RegisterContext": POINTER, #POINTER_T(struct_EFI_SMM_SW_REGISTER_CONTEXT)
    "DispatchHandle": POINTER, #POINTER_T(POINTER_T(None))
})
def hook_SMM_SW_DISPATCH2_Register(ql, address, params):
    # Read 'this' pointer.
    this = EFI_SMM_SW_DISPATCH2_PROTOCOL.loadFrom(ql, params['This'])

    # Read registration context.
    smm_sw_register_context = EFI_SMM_SW_REGISTER_CONTEXT.loadFrom(ql, params['RegisterContext'])

    if smm_sw_register_context.SwSmiInputValue == 0xFFFFFFFF_FFFFFFFF:
        raise NotImplementedError("SwSmiInputValue == 0xFFFFFFFF_FFFFFFFF")
    else:
        registered = [handler['RegisterContext'].SwSmiInputValue for handler in ql.os.smm.swsmi_handlers.values()]
        if smm_sw_register_context.SwSmiInputValue in registered:
            # SMI# is already registered.
            return EFI_INVALID_PARAMETER

        if smm_sw_register_context.SwSmiInputValue > this.MaximumSwiValue:
            # SMI# is too big.
            return EFI_INVALID_PARAMETER

    smm_sw_context = EFI_SMM_SW_CONTEXT()
    # For now we only support 1 CPU.
    smm_sw_context.SwSmiCpuIndex = 0
    # CommandPort is the value that was written to the APM I/O port 0xB2.
    # For software SMIs, it is used to signal which SMI handler is to be invoked.
    smm_sw_context.CommandPort = smm_sw_register_context.SwSmiInputValue
    # DataPort is the value that was written to the APM I/O port 0xB3.
    # This is a scratchpad register used to pass additional data to the SMI handler.
    # Currently we don't support it and always pass a zero value for it.
    smm_sw_context.DataPort = 0

    dh = register_sw_smi(ql, params["DispatchFunction"], smm_sw_context)
    if dh:
        ptr_write64(ql, params["DispatchHandle"], dh)
        return EFI_SUCCESS
    else:
        return EFI_OUT_OF_RESOURCES
    
@dxeapi(params={
    "This": POINTER, #POINTER_T(struct__EFI_SMM_SW_DISPATCH2_PROTOCOL)
    "DispatchHandle": POINTER, #POINTER_T(None)
})
def hook_SMM_SW_DISPATCH2_UnRegister(ql, address, params):
    return unregister_sw_smi(ql, params["DispatchHandle"])

def install_EFI_SMM_SW_DISPATCH2_PROTOCOL(ql):
    descriptor = {
        'guid'   : EFI_SMM_SW_DISPATCH2_PROTOCOL_GUID,
        'struct' : EFI_SMM_SW_DISPATCH2_PROTOCOL,
        'fields' : (
            ('Register',        hook_SMM_SW_DISPATCH2_Register),
            ('UnRegister',      hook_SMM_SW_DISPATCH2_UnRegister),
            ('MaximumSwiValue', 0xFF)
        )
    }
    ql.loader.smm_context.install_protocol(descriptor, 1)

