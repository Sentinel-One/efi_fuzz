import random
from qiling.const import *
from qiling.os.const import *
from qiling.os.uefi.utils import *
from .smm_sw_dispatch2_type import *
from qiling.os.uefi.fncc import *

pointer_size = ctypes.sizeof(ctypes.c_void_p)

@dxeapi(params={
    "This": POINTER, #POINTER_T(struct__EFI_SMM_SW_DISPATCH2_PROTOCOL)
    "DispatchFunction": POINTER, #POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), POINTER_T(None), POINTER_T(None), POINTER_T(ctypes.c_uint64)))
    "RegisterContext": POINTER, #POINTER_T(struct_EFI_SMM_SW_REGISTER_CONTEXT)
    "DispatchHandle": POINTER, #POINTER_T(POINTER_T(None))
})
def hook_SMM_SW_DISPATCH2_Register(ql, address, params):
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

    return (ptr, efi_smm_sw_dispatch2_protocol)

