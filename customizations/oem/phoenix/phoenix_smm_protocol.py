from .phoenix_smm_type import PHOENIX_SMM_PROTOCOL
from qiling.os.uefi.const import *
from qiling.os.uefi.fncc import *
from qiling.os.const import *
import ctypes

@dxeapi(params={
    "Arg1": POINTER, #POINTER_T(None)
    "Arg2": POINTER, #POINTER_T(None)
})
def hook_Func1(ql, address, params):
    return EFI_SUCCESS

def install_PHOENIX_SMM_PROTOCOL(ql, start_ptr):
    phoenix_smm_protocol = PHOENIX_SMM_PROTOCOL()
    ptr = start_ptr + ctypes.sizeof(PHOENIX_SMM_PROTOCOL)
    pointer_size = 8

    phoenix_smm_protocol.Func1 = ptr
    ql.hook_address(hook_Func1, ptr)
    ptr += pointer_size

    return (ptr, phoenix_smm_protocol)