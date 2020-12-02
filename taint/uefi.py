#
# Contains taint propagation for some of the more commonly used UEFI services.
# In the context of this module, tainting is used to keep track of uninitialized memory.
#

from qiling.os.uefi.utils import read_int64
from taint.primitives import *
import os

def SetMem_propagate_taint(ql, address, params):
    """
    Taint propagation for SetMem(). We taint or untaint the target buffer based on the taint status
    'UINT8 Value' argument.
    """
    begin = params['Buffer']
    end = begin + params['Size']
    # r8b corresponds to the 'UINT8 Value' parameter.
    taint = ql.triton_ctx.isRegisterTainted(ql.triton_ctx.registers.r8b)
    set_taint_range(ql, begin, end, taint)

def CopyMem_propagate_taint(ql, address, params):
    """
    Taint propagation for CopyMem(). The taint is copied on a byte-by-byte basis from the source
    buffer to the destination buffer.
    """
    copy_taint(ql, params['Source'], params['Destination'], params['Length'])

def AllocatePool_propagate_taint(ql, address, params):
    """
    Taint propagation for Alloca
    tePool().
    We know that all pool memory is initially uninitialized, so we taint it.
    """
    import ipdb; ipdb.set_trace()
    begin = read_int64(ql, params['Buffer'])
    end = begin + params['Size']
    set_taint_range(ql, begin, end, True)

def GetVariable_propagate_taint(ql, address, params):
    """
    Taint propagation for GetVariable(). We initially assume that all NVRAM variables are fully
    initialized, so the target buffer becomes untainted.
    """
    begin = params['Data']
    end = begin + read_int64(ql, params['DataSize'])
    set_taint_range(ql, begin, end, False)

def SetVariable_propagate_taint(ql, address, params):
    """
    Taint propagation of SetVariable(). If the data that was written to NVRAM contains some tainted
    bytes, that means a potential infoleak has occurred and we can abort the process and report that.
    """
    begin = params["Data"]
    end = params["Data"] + params["DataSize"]
    if is_range_tainted(ql, begin, end):
        ql.dprint(D_INFO, f"Detected potential info leak in SetVariable({params})")
        ql.os.emu_error()
        os.abort()

