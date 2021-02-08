import os
from .base_sanitizer import base_sanitizer
from qiling.os.uefi.UefiSpec import EFI_SYSTEM_TABLE, EFI_BOOT_SERVICES, EFI_RUNTIME_SERVICES

class smm_callout_sanitizer(base_sanitizer):

    NAME = "smm_callout"

    def __init__(self, ql):
        super().__init__(ql)

    @staticmethod
    def memberat(cls, offset):
        for field in cls._fields_:
            if cls.offsetof(field[0]) == offset:
                return field[0]

    @staticmethod
    def boot_service_callout_handler(ql, access, addr, size, value):

        st = EFI_SYSTEM_TABLE.loadFrom(ql, ql.loader.gST) 
        offset = addr - st.BootServices.value
        member = smm_callout_sanitizer.memberat(EFI_BOOT_SERVICES, offset)

        ql.log.error("***")
        ql.log.error(f'invoke_boot_service - {access}, 0x{addr:x}, {size}, {value}')
        ql.log.error(f"SMI handler tried to call a boot service gBS->{member}")
        ql.log.error("***")

        ql.os.emu_error()
        ql.os.fault_handler()

    @staticmethod
    def runtime_service_callout_handler(ql, access, addr, size, value):

        st = EFI_SYSTEM_TABLE.loadFrom(ql, ql.loader.gST) 
        offset = addr - st.RuntimeServices.value
        member = smm_callout_sanitizer.memberat(EFI_RUNTIME_SERVICES, offset)

        ql.log.error("***")
        ql.log.error(f'invoke_runtime_service - {access}, 0x{addr:x}, {size}, {value}')
        ql.log.error(f"SMI handler tried to call a runtime service gRT->{member}")
        ql.log.error("***")

        ql.os.emu_error()

    @staticmethod
    def _activate_smm_sanitizer(ql):

        st = EFI_SYSTEM_TABLE.loadFrom(ql, ql.loader.gST) 
        begin = st.BootServices.value
        end = st.BootServices.value + EFI_BOOT_SERVICES.sizeof()
        ql.hook_mem_read(smm_callout_sanitizer.boot_service_callout_handler, begin=begin, end=end)

        begin = st.RuntimeServices.value
        end = st.RuntimeServices.value + EFI_RUNTIME_SERVICES.sizeof()
        ql.hook_mem_read(smm_callout_sanitizer.runtime_service_callout_handler, begin=begin, end=end)

    @staticmethod
    def _after_module_execution_callback(ql, number_of_modules_left):
        if number_of_modules_left == 0:
            smm_callout_sanitizer._activate_smm_sanitizer(ql)

    def enable(self):
        self.ql.os.after_module_execution_callbacks.insert(0, smm_callout_sanitizer._after_module_execution_callback)

