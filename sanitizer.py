import os

from qiling.const import *
from qiling.extensions.sanitizers.heap import QlSanitizedMemoryHeap


def verbose_abort(ql):
    ql.os.emu_error()
    os.abort()

def enable_sanitized_heap(ql, fault_rate=0):
    """
    Enables the sanitized heap, currently capable of detecting:
    - pool overflows
    - pool underflows
    - pool OOB read ahead
    - pool OOB read behind
    - pool double frees
    - pool invalid frees
    - pool use-after-free
    """
    def bo_handler(ql, access, addr, size, value):
        ql.dprint(D_INFO, "***")
        ql.dprint(D_INFO, f'bo_handler - {access}, {addr}, {size}, {value}')
        ql.dprint(D_INFO, "***")

        verbose_abort(ql)

    def oob_handler(ql, access, addr, size, value):
        ql.dprint(D_INFO, "***")
        ql.dprint(D_INFO, f'oob_handler - {access}, {addr}, {size}, {value}')
        ql.dprint(D_INFO, "***")

        verbose_abort(ql)

    def uaf_handler(ql, access, addr, size, value):
        ql.dprint(D_INFO, "***")
        ql.dprint(D_INFO, f'uaf_handler - {access}, {addr}, {size}, {value}')
        ql.dprint(D_INFO, "***")

        verbose_abort(ql)

    def bad_free_handler(ql, addr):
        ql.dprint(D_INFO, "***")
        ql.dprint(D_INFO, f'bad_free_handler - {addr}')
        ql.dprint(D_INFO, "***")

        verbose_abort(ql)

    ql.os.heap = QlSanitizedMemoryHeap(ql, ql.os.heap, fault_rate=fault_rate)
    ql.os.heap.oob_handler = oob_handler
    ql.os.heap.bo_handler = bo_handler
    ql.os.heap.bad_free_handler = bad_free_handler
    ql.os.heap.uaf_handler = uaf_handler

def enable_sanitized_CopyMem(ql):
    """
    Replaces the emulated CopyMem() service with an inline assembly implementation.
    This implementation will trigger hooks placed on the Destination and Source buffers.
    """

    # typedef VOID(EFIAPI * EFI_COPY_MEM) (IN VOID *Destination, IN VOID *Source, IN UINTN Length)
    code = """
        push rsi
        push rdi
        mov rsi, rdx
        mov rdi, rcx
        mov rcx, r8            
        rep movsb
        pop rdi
        pop rsi
        """
    runcode = ql.compile(ql.archtype, code)
    ptr = ql.os.heap.alloc(len(runcode))
    ql.mem.write(ptr, runcode)

    def my_CopyMem(ql, address, params):
        ql.os.exec_arbitrary(ptr, ptr+len(runcode))
        return 0

    ql.set_api("CopyMem", my_CopyMem)

def enable_sanitized_SetMem(ql):
    """
    Replaces the emulated SetMem() service with an inline assembly implementation.
    This implementation will trigger hooks placed on the Buffer argument.
    """

    # typedef VOID(EFIAPI * EFI_SET_MEM) (IN VOID *Buffer, IN UINTN Size, IN UINT8 Value)
    code = """
        push rdi
        mov rdi, rcx
        mov rcx, rdx
        mov al, r8b            
        rep stosb
        pop rdi
        """
    runcode = ql.compile(ql.archtype, code)
    ptr = ql.os.heap.alloc(len(runcode))
    ql.mem.write(ptr, runcode)

    def my_SetMem(ql, address, params):
        ql.os.exec_arbitrary(ptr, ptr+len(runcode))
        return 0

    ql.set_api("SetMem", my_SetMem)