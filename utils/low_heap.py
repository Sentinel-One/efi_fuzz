from qiling.os.memory import QlMemoryHeap

def enable_low_heap(ql, size = 0x1024 ** 2):
    # A heap which guarantees that all allocation are below 4GB.
    heap_base = ql.mem.find_free_space(size = size, max_addr = 0xffffffff)
    ql.os.low_heap = QlMemoryHeap(ql, heap_base, heap_base + size)