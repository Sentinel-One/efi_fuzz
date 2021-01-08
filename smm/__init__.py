from . import protocols
from qiling.os.uefi.utils import convert_struct_to_bytes, write_int64
from qiling.os.memory import QlMemoryHeap
from .swsmi import trigger_swsmi

class SmmState(object):

    PAGE_SIZE = 0x1000

    def __init__(self, ql):
        self.swsmi_handlers = {}
        self.smbase = int(ql.os.profile.get("smm", "smbase"), 0)
        self.heap_size = int(ql.os.profile.get("smm", "heap_size"), 0)
        self.swsmi_args = {}

        # Init CSEG.
        self.cseg_base = int(ql.os.profile.get("cseg", "base"), 0)
        self.cseg_size = int(ql.os.profile.get("cseg", "size"), 0)
        ql.mem.map(self.cseg_base, self.cseg_size, info="[SMM CSEG]")

        # Init TSEG.
        self.tseg_base = int(ql.os.profile.get("tseg", "base"), 0)
        self.tseg_size = int(ql.os.profile.get("tseg", "size"), 0)
        ql.mem.map(self.tseg_base, self.tseg_size - self.heap_size, info="[SMM TSEG]")
        
        # Create the SMM heap, which will occupy the upper portion of TSEG.
        heap_base = self.tseg_base + self.tseg_size - self.heap_size
        heap_end = self.tseg_base + self.tseg_size
        self.heap = QlMemoryHeap(ql, heap_base, heap_end)
        
        # Points to an optional handler context which was specified when the
        # handler was registered.
        self.context_buffer = self.heap.alloc(self.PAGE_SIZE)

        # A pointer to a collection of data in memory that will
        # be conveyed from a non-MM environment into an MM environment.
        self.comm_buffer = self.heap.alloc(self.PAGE_SIZE)

    def in_smram(self, address):
        if address >= self.cseg_base and address < self.cseg_base + self.cseg_size:
            # Address overlaps CSEG.
            return True

        if address >= self.tseg_base and address < self.tseg_base + self.tseg_size:
            # Address overlaps TSEG.
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
