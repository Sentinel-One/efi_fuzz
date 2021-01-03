from qiling.os.uefi.const import *
from qiling.os.uefi.fncc import *
from qiling.os.const import *
from qiling.os.uefi.ProcessorBind import *
from qiling.os.uefi.UefiBaseType import *

class PHOENIX_SMM_PROTOCOL(STRUCT):
    PHOENIX_SMM_PROTOCOL = STRUCT
    _fields_ = [
        ('Func1', FUNCPTR(EFI_STATUS, PTR(PHOENIX_SMM_PROTOCOL), PTR(VOID)))
    ]

@dxeapi(params={
    "Arg1": POINTER, #POINTER_T(None)
    "Arg2": POINTER, #POINTER_T(None)
})
def hook_Func1(ql, address, params):
    return EFI_SUCCESS

PHOENIX_SMM_PROTOCOL_GUID =  "ff052503-1af9-4aeb-83c4-c2d4ceb10ca3"

def install_PHOENIX_SMM_PROTOCOL(ql):
    descriptor = {
        "guid" : PHOENIX_SMM_PROTOCOL_GUID,
        'struct' : PHOENIX_SMM_PROTOCOL,
        'fields' : (
            ('Func1', hook_Func1),
        )
    }
    ql.loader.smm_context.install_protocol(descriptor, 1)