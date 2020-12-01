from .phoenix_smm_protocol import install_PHOENIX_SMM_PROTOCOL
from qiling.os.uefi.utils import convert_struct_to_bytes

PHOENIX_SMM_PROTOCOL_GUID =  "ff052503-1af9-4aeb-83c4-c2d4ceb10ca3"

def run(ql):
    protocol_buf_size = 0x1000
    ptr = ql.os.heap.alloc(protocol_buf_size)
    ql.mem.write(ptr, b'\x90' * protocol_buf_size)

    phoenix_smm_protocol_ptr = ptr
    (ptr, phoenix_smm_protocol) = install_PHOENIX_SMM_PROTOCOL(ql, ptr)
    ql.loader.handle_dict[1][PHOENIX_SMM_PROTOCOL_GUID] = phoenix_smm_protocol_ptr

    ql.mem.write(phoenix_smm_protocol_ptr, convert_struct_to_bytes(phoenix_smm_protocol))