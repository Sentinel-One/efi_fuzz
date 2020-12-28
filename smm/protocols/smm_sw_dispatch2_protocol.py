from qiling.const import *
from qiling.os.const import *
from qiling.os.uefi.utils import *
from .smm_sw_dispatch2_type import *
from qiling.os.uefi.fncc import *

pointer_size = ctypes.sizeof(ctypes.c_void_p)

class EFI_SMM_SW_REGISTER_CONTEXT(ctypes.Structure):
    _fields_ = [
        ('SwSmiInputValue', UINTN)
    ]

class EFI_SMM_SW_CONTEXT(ctypes.Structure):
    _fields_ = [
        ('SwSmiCpuIndex', UINTN),
        ('CommandPort', UINT8),
        ('DataPort', UINT8)
    ]

@dxeapi(params={
    "This": POINTER, #POINTER_T(struct__EFI_SMM_SW_DISPATCH2_PROTOCOL)
    "DispatchFunction": POINTER, #POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), POINTER_T(None), POINTER_T(None), POINTER_T(ctypes.c_uint64)))
    "RegisterContext": POINTER, #POINTER_T(struct_EFI_SMM_SW_REGISTER_CONTEXT)
    "DispatchHandle": POINTER, #POINTER_T(POINTER_T(None))
})
def hook_SMM_SW_DISPATCH2_Register(ql, address, params):
    this = EFI_SMM_SW_DISPATCH2_PROTOCOL.from_buffer(
        ql.mem.read(params["This"], ctypes.sizeof(EFI_SMM_SW_DISPATCH2_PROTOCOL)))

    register_context = EFI_SMM_SW_REGISTER_CONTEXT.from_buffer(
        ql.mem.read(params['RegisterContext'], ctypes.sizeof(EFI_SMM_SW_REGISTER_CONTEXT)))

    if register_context.SwSmiInputValue == 0xFFFFFFFF_FFFFFFFF:
        breakpoint()
    else:
        registered_smis = [handler['RegisterContext'].SwSmiInputValue for handler in ql.os.smm.swsmi_handlers.values()]
        if (register_context.SwSmiInputValue in registered_smis) or (register_context.SwSmiInputValue > this.MaximumSwiValue):
            return EFI_INVALID_PARAMETER

    sw_context = EFI_SMM_SW_CONTEXT()
    # For now we only 1 CPU
    sw_context.SwSmiCpuIndex = 0
    # CommandPort is the value that was written to the APM I/O port 0xB2.
    # For software SMIs, it is used to signal which SMI handler is to be invoked.
    sw_context.CommandPort = register_context.SwSmiInputValue
    # DataPort is the value that was written to the APM I/O port 0xB3.
    # This is a scratchpad register used to pass additional data to the SMI handler.
    # Currently we don't support it and always pass a zero value for it.
    sw_context.DataPort = 0

    # Allocate a unique handle for this SMI.
    dispatch_handle = ql.os.heap.alloc(1)
    write_int64(ql, params["DispatchHandle"], dispatch_handle)
    
    smi_params = {
        "DispatchFunction": params["DispatchFunction"],
        "RegisterContext": register_context,
        "CommunicationBuffer": sw_context,
    }

    # Let's save the dispatch params, so they can be triggered if needed.
    ql.os.smm.swsmi_handlers[dispatch_handle] = smi_params
    return EFI_SUCCESS
    
@dxeapi(params={
    "This": POINTER, #POINTER_T(struct__EFI_SMM_SW_DISPATCH2_PROTOCOL)
    "DispatchHandle": POINTER, #POINTER_T(None)
})
def hook_SMM_SW_DISPATCH2_UnRegister(ql, address, params):
    try:
        del ql.os.smm.swsmi_handlers[params['DispatchHandle']]
        ql.os.heap.free(params['DispatchHandle'])
    except:
        return EFI_INVALID_PARAMETER
    else:
        return EFI_SUCCESS

def install_EFI_SMM_SW_DISPATCH2_PROTOCOL(ql, start_ptr):
    efi_smm_sw_dispatch2_protocol = EFI_SMM_SW_DISPATCH2_PROTOCOL()
    ptr = start_ptr
    pointer_size = 8

    efi_smm_sw_dispatch2_protocol.Register = ptr
    ql.hook_address(hook_SMM_SW_DISPATCH2_Register, ptr)
    ptr += pointer_size

    efi_smm_sw_dispatch2_protocol.UnRegister = ptr
    ql.hook_address(hook_SMM_SW_DISPATCH2_UnRegister, ptr)
    ptr += pointer_size

    efi_smm_sw_dispatch2_protocol.MaximumSwiValue = 0xFF
    ptr += pointer_size

    return (ptr, efi_smm_sw_dispatch2_protocol)

