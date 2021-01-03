import random
from qiling.const import *
from qiling.os.const import *
from qiling.os.uefi.fncc import *
from .guids import EFI_SMM_SW_DISPATCH2_PROTOCOL_GUID
from qiling.os.uefi.ProcessorBind import *
from qiling.os.uefi.UefiBaseType import *

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
    this = EFI_SMM_SW_DISPATCH2_PROTOCOL.from_buffer(
        ql.mem.read(params["This"], ctypes.sizeof(EFI_SMM_SW_DISPATCH2_PROTOCOL)))

    # Read registration context.
    smm_sw_register_context = EFI_SMM_SW_REGISTER_CONTEXT.from_buffer(
        ql.mem.read(params['RegisterContext'], ctypes.sizeof(EFI_SMM_SW_REGISTER_CONTEXT)))

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

    # Allocate a unique handle for this SMI.
    dispatch_handle = ql.os.heap.alloc(1)
    write_int64(ql, params["DispatchHandle"], dispatch_handle)
    
    smi_params = {
        "DispatchFunction": params["DispatchFunction"],
        "RegisterContext": smm_sw_register_context,
        "CommunicationBuffer": smm_sw_context,
    }

    # Let's save the dispatch params, so they can be triggered if needed.
    smi_num = int.from_bytes(ql.mem.read(params['RegisterContext'], 8), 'little')
    DispatchHandle = random.getrandbits(64)
    ql.os.smm.swsmi_handlers.append((DispatchHandle, smi_num, params))
    write_int64(ql, params["DispatchHandle"], DispatchHandle)
    return EFI_SUCCESS
    
@dxeapi(params={
    "This": POINTER, #POINTER_T(struct__EFI_SMM_SW_DISPATCH2_PROTOCOL)
    "DispatchHandle": POINTER, #POINTER_T(None)
})
def hook_SMM_SW_DISPATCH2_UnRegister(ql, address, params):
    dh = read_int64(ql, params["DispatchHandle"])
    ql.os.smm.swsmi_handlers[:] = [tup for tup in ql.os.smm.swsmi_handlers if tup[0] != dh]
    return EFI_SUCCESS

<<<<<<< HEAD
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
=======
def install_EFI_SMM_SW_DISPATCH2_PROTOCOL(ql):
    descriptor = {
        'guid'   : EFI_SMM_SW_DISPATCH2_PROTOCOL_GUID,
        'struct' : EFI_SMM_SW_DISPATCH2_PROTOCOL,
        'fields' : (
            ('Register',        hook_SMM_SW_DISPATCH2_Register),
            ('UnRegister',      hook_SMM_SW_DISPATCH2_UnRegister),
            ('MaximumSwiValue', None)
        )
    }
    ql.loader.smm_context.install_protocol(descriptor, 1)
>>>>>>> 199539f (Initial version, not everything is tested yet.)

