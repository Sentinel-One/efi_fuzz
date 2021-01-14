from . import protocols
from qiling.os.uefi.utils import convert_struct_to_bytes, write_int64
from qiling.os.memory import QlMemoryHeap
from .swsmi import trigger_swsmi

class SmmSegment:
    def __init__(self, ql, name):
        self.base = int(ql.os.profile.get(name, "base"), 0)
        self.size = int(ql.os.profile.get(name, "size"), 0)
        if ql.os.profile.has_option(name, "heap_size"):
            self.heap_size = int(ql.os.profile.get(name, "heap_size"), 0)
        else:
            self.heap_size = 0
        
        ql.mem.map(self.base, self.size - self.heap_size, info=f"[SMM {name.upper()}]")
        
        # Create the SMM heap, which will occupy the upper portion of the segment.
        if self.heap_size > 0:
            heap_base = self.base + self.size - self.heap_size
            heap_end = self.base + self.size
            self.heap = QlMemoryHeap(ql, heap_base, heap_end)
        else:
            self.heap = None

    def heap_alloc(self, size):
        if self.heap:
            return self.heap.alloc(size)
        return 0

    def overlaps(self, address):
        return (address >= self.base) and (address < self.base + self.size)

class SmmState(object):

    PAGE_SIZE = 0x1000

    def __init__(self, ql):
        self.swsmi_handlers = {}
        self.smbase = int(ql.os.profile.get("smm", "smbase"), 0)
        self.swsmi_args = {}

        # Init CSEG and TSEG.
        self.cseg = SmmSegment(ql, "cseg")
        self.tseg = SmmSegment(ql, "tseg")
        
        # Points to an optional handler context which was specified when the
        # handler was registered.
        self.context_buffer = self.heap_alloc(self.PAGE_SIZE)

        # A pointer to a collection of data in memory that will
        # be conveyed from a non-MM environment into an MM environment.
        self.comm_buffer = self.heap_alloc(self.PAGE_SIZE)

    def heap_alloc(self, size):
        # Prefer allocating from TSEG.
        p = self.tseg.heap_alloc(size)
        if p != 0:
            return p

        # Fallback to allocating from CSEG.
        p = self.cseg.heap_alloc(size)
        return p

    def overlaps(self, address):
        if self.tseg.overlaps(address):
            # Address overlaps with TSEG.
            return True

        if self.cseg.overlaps(address):
            # Address overlaps with CSEG.
            return True

        # Address doesn't overlap SMRAM.
        return False

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
