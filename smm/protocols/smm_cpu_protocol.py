from qiling.os.uefi.fncc import *
from qiling.os.const import *
from qiling.os.uefi.const import *
from qiling.const import *
import ctypes

from ..save_state_area import read_smm_save_state, write_smm_save_state

def hook_SMM_CPU_ReadSaveState(ql, address, params):
    try:
        data = read_smm_save_state(ql, params['Register'], params['Width'])
    except KeyError:
        ql.dprint(D_INFO, f"Unsupported register id {params['Register']}")
        return EFI_UNSUPPORTED

    ql.mem.write(params['Buffer'], data)
    return EFI_SUCCESS

def hook_SMM_CPU_WriteSaveState(ql, address, params):
    data = ql.mem.read(params['Buffer'], params['Width'])
    try:
        write_smm_save_state(ql, params['Register'], data)
    except KeyError as e:
        ql.dprint(D_INFO, f"Unsupported register id {params['Register']}")
        return EFI_UNSUPPORTED

    return EFI_SUCCESS


def init_EFI_SMM_CPU_PROTOCOL(ql):
    ql.set_api("SmmReadSaveState", hook_SMM_CPU_ReadSaveState)
    ql.set_api("SmmWriteSaveState", hook_SMM_CPU_WriteSaveState)
