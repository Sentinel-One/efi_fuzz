import pickle
import rom
from qiling import Qiling
from . import callbacks
import sanitizers
import smm
from qiling.extensions.coverage import utils as cov_utils
import json
import dummy_protocol
from . import fault
import os
import binascii
from qiling.os.uefi.ProcessorBind import STRUCT, PAGE_SIZE
import capstone
from unicorn.x86_const import *
from conditional import conditional

class EmulationManager:

    DEFAULT_SANITIZERS = ['smm_callout', 'smm', 'uninitialized'] # @TODO: add 'memory' sanitizer as default

    def __init__(self, target_module, extra_modules=None):

        if extra_modules is None:
            extra_modules = []

        self.ql = Qiling(extra_modules + [target_module],
                         ".",                                        # rootfs
                         output="trace")

        callbacks.init_callbacks(self.ql)

        self.coverage_file = None
        
        self.sanitizers = EmulationManager.DEFAULT_SANITIZERS
        self.fault_handler = 'exit' # By default we prefer to exit the emulation cleanly

    def load_nvram(self, nvram_file):
        # Load NVRAM environment.
        with open(nvram_file, 'rb') as nvram:
            self.ql.env.update(pickle.load(nvram))

    def load_rom(self, rom_file):
        # Init firmware volumes from the provided ROM file.
        rom.install(self.ql, rom_file)

    def _enable_sanitizers(self):
        # Enable sanitizers.
        self.ql.log.info(f'Enabling sanitizers {self.sanitizers}')
        for sanitizer in self.sanitizers:
            sanitizers.get(sanitizer)(self.ql).enable()

    def enable_smm(self):
        profile = os.path.join(os.path.dirname(__file__), os.path.pardir, 'smm', 'smm.ini')
        self.ql.profile.read(profile)
        # Init SMM related protocols.
        smm.init(self.ql, True)

    @property
    def coverage_file(self):
        return self._coverage_file

    @coverage_file.setter
    def coverage_file(self, cov):
        self._coverage_file = cov

    def apply(self, json_conf):
        if not json_conf:
            return

        with open(json_conf, 'r') as f:
            conf = json.load(f)
        
        # Install protocols
        if conf.get('protocols'):
            for proto in conf['protocols']:
                descriptor = dummy_protocol.make_descriptor(proto['guid'])
                self.ql.loader.dxe_context.install_protocol(descriptor, 1)

        if conf.get('registers'):
            self.ql.os.smm.swsmi_args['registers'] = conf['registers']

        if conf.get('memory'):
            # Apply memory.
            for (address, data) in conf['memory'].items():
                address = int(address, 0)
                data = binascii.unhexlify(data.replace(' ', ''))
                if not self.ql.mem.is_mapped(address, len(data)):
                    if address % PAGE_SIZE == 0:
                        page = address
                    else:
                        page = self.ql.mem.align(address) - PAGE_SIZE
                    size = self.ql.mem.align(len(data))
                    self.ql.mem.map(page, size)
                self.ql.mem.write(address, data)
            
    @property
    def fault_handler(self):
        return self._fault_handler

    @fault_handler.setter
    def fault_handler(self, value):
        self._fault_handler = value

        if value == 'exit':
            self.ql.os.fault_handler = fault.exit
        elif value == 'abort':
            self.ql.os.fault_handler = fault.abort
        elif value == 'ignore':
            self.ql.os.fault_handler = fault.ignore
        elif value == 'break':
            self.ql.os.fault_handler = fault._break

    def run(self, end=None, timeout=0, **kwargs):

        if end:
            end = callbacks.set_end_of_execution_callback(self.ql, end)

        self._enable_sanitizers()

        try:
            # Don't collect coverage information unless explicitly requested by the user.
            with conditional(self.coverage_file, cov_utils.collect_coverage(self.ql, 'drcov_exact', self.coverage_file)):
                self.ql.run(end=end, timeout=timeout)
        except fault.ExitEmulation:
            # Exit cleanly.
            pass
