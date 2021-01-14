from qiling.os.memory import QlMemoryHeap

def enable_low_heap(ql):
    """
    The low heap is guaranteed to allocate memory below the 4GB boundary.
    """
    heap_base = ql.mem.find_free_space(size = 0x1024 ** 2, max_addr = 0xffffffff)
    ql.os.low_heap = QlMemoryHeap(ql, heap_base, heap_base + 0x1024 ** 2)