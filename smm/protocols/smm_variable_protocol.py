from .smm_variable_type import EFI_SMM_VARIABLE_PROTOCOL
from qiling.os.uefi.runtime import hook_GetVariable, hook_GetNextVariableName, hook_SetVariable, \
    hook_QueryVariableInfo
import ctypes


def install_EFI_SMM_VARIABLE_PROTOCOL(ql, start_ptr):
    efi_smm_variable_protocol = EFI_SMM_VARIABLE_PROTOCOL()
    ptr = start_ptr + ctypes.sizeof(EFI_SMM_VARIABLE_PROTOCOL)
    pointer_size = 8

    efi_smm_variable_protocol.SmmGetVariable = ptr
    ql.hook_address(hook_GetVariable, ptr)
    ptr += pointer_size

    efi_smm_variable_protocol.SmmGetNextVariableName = ptr
    ql.hook_address(hook_GetNextVariableName, ptr)
    ptr += pointer_size

    efi_smm_variable_protocol.SmmSetVariable = ptr
    ql.hook_address(hook_SetVariable, ptr)
    ptr += pointer_size

    efi_smm_variable_protocol.SmmQueryVariableInfo = ptr
    ql.hook_address(hook_QueryVariableInfo, ptr)
    ptr += pointer_size

    return (ptr, efi_smm_variable_protocol)