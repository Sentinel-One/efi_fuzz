import os
from qiling.const import D_INFO

def enable_smm_sanitizer(ql):
    ql.os.smm.sanitize = True

def activate_smm_sanitizer(ql):

    def invoke_bs_rt_service(ql, access, addr, size, value):
        ql.dprint(D_INFO, "***")
        ql.dprint(D_INFO, f'read_from_system - {access}, 0x{addr:x}, {size}, {value}')
        ql.dprint(D_INFO, "SMI handler tried to call a boot/runtime service")
        ql.dprint(D_INFO, "***")
        ql.os.emu_error()
        os.abort()

    begin = min(ql.loader.runtime_services_ptr, ql.loader.boot_services_end_ptr)
    end   = max(ql.loader.runtime_services_ptr, ql.loader.boot_services_end_ptr)
    ql.hook_mem_read(invoke_bs_rt_service, begin=begin, end=end)
