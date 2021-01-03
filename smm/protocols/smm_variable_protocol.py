from qiling.os.uefi.UefiSpec import EFI_GET_VARIABLE, EFI_GET_NEXT_VARIABLE_NAME, EFI_SET_VARIABLE, EFI_QUERY_VARIABLE_INFO
from qiling.os.uefi.rt import hook_GetVariable, hook_GetNextVariableName, hook_SetVariable, hook_QueryVariableInfo
from .guids import EFI_SMM_VARIABLE_PROTOCOL_GUID
from qiling.os.uefi.ProcessorBind import *



class EFI_SMM_VARIABLE_PROTOCOL(STRUCT):
    EFI_SMM_VARIABLE_PROTOCOL = STRUCT
    _fields_ = [
        ('SmmGetVariable', EFI_GET_VARIABLE),
        ('SmmGetNextVariableName', EFI_GET_NEXT_VARIABLE_NAME),
        ('SmmSetVariable', EFI_SET_VARIABLE),
        ('SmmQueryVariableInfo', EFI_QUERY_VARIABLE_INFO)
    ]



def install_EFI_SMM_VARIABLE_PROTOCOL(ql):
    descriptor = {
        'guid': EFI_SMM_VARIABLE_PROTOCOL_GUID,
        'struct' : EFI_SMM_VARIABLE_PROTOCOL,
        'fields' : (
            ('SmmGetVariable', hook_GetVariable),
            ('SmmGetNextVariableName', hook_GetNextVariableName),
            ('SmmSetVariable', hook_SetVariable),
            ('SmmQueryVariableInfo', hook_QueryVariableInfo)
        )
    }
    ql.loader.smm_context.install_protocol(descriptor, 1)

