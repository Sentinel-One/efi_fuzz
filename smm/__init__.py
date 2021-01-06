from . import protocols
from qiling.os.uefi.utils import convert_struct_to_bytes, write_int64
from qiling.os.memory import QlMemoryHeap
from .swsmi import trigger_swsmi

class SmmState(object):

    PAGE_SIZE = 0x1000

    def __init__(self, ql):
        self.swsmi_handlers = {}
        self.smbase = int(ql.os.profile.get("SMM", "smbase"), 0)
        self.smram_size = int(ql.os.profile.get("SMM", "smram_size"), 0)
        self.heap_size = int(ql.os.profile.get("SMM", "heap_size"), 0)
        self.swsmi_args = {}
        
        if self.smram_size - self.heap_size < 0x10000:
            raise RuntimeError(f"SMRAM must be at least 64kb in size")

        if ql.mem.is_available(self.smbase, self.smram_size):
            # Reserve SMRAM.
            ql.mem.map(self.smbase, self.smram_size - self.heap_size)
            # Create the SMM heap, which will occupy the upper portion of SMRAM.
            self.heap = QlMemoryHeap(ql, self.smbase + self.smram_size - self.heap_size, self.smbase + self.smram_size)
        else:
            raise RuntimeError(f"Can't allocate SMRAM at 0x{self.smbase:x}-0x{self.smbase+self.smram_size:x}, \
region is already occupied")

        # Points to an optional handler context which was specified when the
        # handler was registered.
        self.context_buffer = self.heap.alloc(self.PAGE_SIZE)

        # A pointer to a collection of data in memory that will
        # be conveyed from a non-MM environment into an MM environment.
        self.comm_buffer = self.heap.alloc(self.PAGE_SIZE)

def init(ql, in_smm=False):
    ql.os.smm = SmmState(ql)
    protocols.install(ql)

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
