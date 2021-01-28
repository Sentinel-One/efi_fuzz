import os
from .base_sanitizer import base_sanitizer

class smm_sanitizer(base_sanitizer):

    NAME = "smm"

    def __init__(self, ql):
        super().__init__(ql)

    @staticmethod
    def _activate_smm_sanitizer(ql):

        def invoke_bs_rt_service(ql, access, addr, size, value):
            ql.log.error("***")
            ql.log.error(f'invoke_bs_rt_service - {access}, 0x{addr:x}, {size}, {value}')
            ql.log.error("SMI handler tried to call a boot/runtime service")
            ql.log.error("***")

            ql.os.emu_error()
            os.abort()

        begin = min(ql.loader.runtime_services_ptr, ql.loader.boot_services_end_ptr)
        end   = max(ql.loader.runtime_services_ptr, ql.loader.boot_services_end_ptr)
        ql.hook_mem_read(invoke_bs_rt_service, begin=begin, end=end)

    @staticmethod
    def _after_module_execution_callback(ql, number_of_modules_left):
        if number_of_modules_left == 0:
            smm_sanitizer._activate_smm_sanitizer(ql)

    def enable(self):
        self.ql.os.after_module_execution_callbacks.insert(0, smm_sanitizer._after_module_execution_callback)

