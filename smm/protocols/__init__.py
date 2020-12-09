from .smm_cpu_protocol import install_EFI_SMM_CPU_PROTOCOL
from .smm_sw_dispatch_protocol import install_EFI_SMM_SW_DISPATCH_PROTOCOL
from .smm_sw_dispatch2_protocol import install_EFI_SMM_SW_DISPATCH2_PROTOCOL
from .smm_sx_dispatch_protocol import install_EFI_SMM_SX_DISPATCH_PROTOCOL
from .smm_base_protocol import install_EFI_SMM_BASE_PROTOCOL
from .smm_variable_protocol import install_EFI_SMM_VARIABLE_PROTOCOL
from .mm_access_protocol import init_GetCapabilities
from .guids import *
from qiling.os.uefi.utils import convert_struct_to_bytes, write_int64
from qiling.os.memory import QlMemoryHeap
from ..swsmi import EFI_SMM_SW_CONTEXT, trigger_swsmi
import ctypes

class SmmState(object):
    def __init__(self, ql):
        self.swsmi_handlers = []
        self.smbase = int(ql.os.profile.get("SMM", "smbase"), 0)
        self.smram_size = int(ql.os.profile.get("SMM", "smram_size"), 0)
        self.heap_size = int(ql.os.profile.get("SMM", "heap_size"), 0)
        self.swsmi_args = {}
        
        # Communication buffer
        self.comm_buffer = ql.os.heap.alloc(ctypes.sizeof(EFI_SMM_SW_CONTEXT))
        self.comm_buffer_size = ql.os.heap.alloc(ctypes.sizeof(ctypes.c_void_p))
        ql.mem.write(self.comm_buffer_size, ctypes.sizeof(EFI_SMM_SW_CONTEXT).to_bytes(ctypes.sizeof(ctypes.c_void_p), 'little'))
        
        if self.smram_size - self.heap_size < 0x10000:
            raise RuntimeError(f"SMRAM must be at least 64kb in size")

        if ql.mem.is_available(self.smbase, self.smram_size):
            # Reserve SMRAM and create the SMM heap. The SMM heap will occupy the upper portion of SMRAM.
            ql.mem.map(self.smbase, self.smram_size - self.heap_size)
            self.heap = QlMemoryHeap(ql, self.smbase + self.smram_size - self.heap_size, self.smbase + self.smram_size)
        else:
            raise RuntimeError(f"Can't allocate SMRAM at 0x{self.smbase:x}-0x{self.smbase+self.smram_size:x}, \
region is already occupied")

def init(ql, in_smm=False):
    # Allocate and initialize the protocols buffer
    protocol_buf_size = 0x1000
    ptr = ql.os.heap.alloc(protocol_buf_size)
    ql.mem.write(ptr, b'\x90' * protocol_buf_size)

    # EFI_SMM_CPU_PROTOCOL
    smm_cpu_protocol_ptr = ptr
    (ptr, efi_smm_cpu_protocol) = install_EFI_SMM_CPU_PROTOCOL(ql, ptr)
    ql.loader.handle_dict[1][EFI_SMM_CPU_PROTOCOL_GUID] = smm_cpu_protocol_ptr

    # EFI_SMM_SW_DISPATCH_PROTOCOL
    smm_sw_dispatch_protocol_ptr = ptr
    (ptr, smm_sw_dispatch_protocol) = install_EFI_SMM_SW_DISPATCH_PROTOCOL(ql, ptr)
    ql.loader.handle_dict[1][EFI_SMM_SW_DISPATCH_PROTOCOL_GUID] = smm_sw_dispatch_protocol_ptr

    # EFI_SMM_SW_DISPATCH2_PROTOCOL
    smm_sw_dispatch2_protocol_ptr = ptr
    (ptr, smm_sw_dispatch2_protocol) = install_EFI_SMM_SW_DISPATCH2_PROTOCOL(ql, ptr)
    ql.loader.handle_dict[1][EFI_SMM_SW_DISPATCH2_PROTOCOL_GUID] = smm_sw_dispatch2_protocol_ptr

    # EFI_SMM_SX_DISPATCH_PROTOCOL
    smm_sx_dispatch_protocol_ptr = ptr
    (ptr, smm_sx_dispatch_protocol) = install_EFI_SMM_SX_DISPATCH_PROTOCOL(ql, ptr)
    ql.loader.handle_dict[1][EFI_SMM_SX_DISPATCH_PROTOCOL_GUID] = smm_sx_dispatch_protocol_ptr

    # EFI_SMM_BASE_PROTOCOL
    smm_base_protocol_ptr = ptr
    (ptr, smm_base_protocol) = install_EFI_SMM_BASE_PROTOCOL(ql, ptr)
    ql.loader.handle_dict[1][EFI_SMM_BASE_PROTOCOL_GUID] = smm_base_protocol_ptr

    # EFI_SMM_VARIABLE_PROTOCOL
    smm_variable_protocol_ptr = ptr
    (ptr, smm_variable_protocol) = install_EFI_SMM_VARIABLE_PROTOCOL(ql, ptr)
    ql.loader.handle_dict[1][EFI_SMM_VARIABLE_PROTOCOL_GUID] = smm_variable_protocol_ptr

    # Serialize all protocols to memory
    ql.mem.write(smm_cpu_protocol_ptr, convert_struct_to_bytes(efi_smm_cpu_protocol))
    ql.mem.write(smm_sw_dispatch_protocol_ptr, convert_struct_to_bytes(smm_sw_dispatch_protocol))
    ql.mem.write(smm_sw_dispatch2_protocol_ptr, convert_struct_to_bytes(smm_sw_dispatch2_protocol))
    ql.mem.write(smm_sx_dispatch_protocol_ptr, convert_struct_to_bytes(smm_sx_dispatch_protocol))
    ql.mem.write(smm_base_protocol_ptr, convert_struct_to_bytes(smm_base_protocol))
    ql.mem.write(smm_variable_protocol_ptr, convert_struct_to_bytes(smm_variable_protocol))

    ql.os.smm = SmmState(ql)

    def hook_InSmm(ql, address, params):
        nonlocal in_smm
        write_int64(ql, params["InSmram"], in_smm)

    # Replace 'InSmm' to correctly report whether or not we're executing an SMM module.
    ql.set_api("InSmm", hook_InSmm)

    def after_module_execution_callback(ql, number_of_modules_left):
        if number_of_modules_left == 0:
            return trigger_swsmi(ql)
        return False

    ql.os.after_module_execution_callbacks.append(after_module_execution_callback)
    
    init_GetCapabilities(ql)
