import pickle
import rom
from qiling import Qiling
import callbacks
import sanitizers
import smm
import taint
from qiling.extensions.coverage import utils as cov_utils
import json
import dummy_protocol
import fault
import os

class EmulationManager:

    def __init__(self, target_module, extra_modules=None):

        if extra_modules is None:
            extra_modules = []

        self.ql = Qiling(extra_modules + [target_module],
                         ".",                                        # rootfs
                         output="trace")

        self.ql.os.fault_handler = fault.stop # default
        callbacks.set_after_module_execution_callback(self.ql)

    def load_nvram(self, nvram_file):
        # Load NVRAM environment.
        if nvram_file:
            with open(nvram_file, 'rb') as nvram:
                self.env = pickle.load(nvram)
        else:
            self.env = {}

    def load_rom(self, rom_file):
        # Init firmware volumes from the provided ROM file.
        if rom_file:
            rom.install(self.ql, rom_file)

    def enable_sanitizer(self, sanitizer_name):
        # Enable sanitizers.
        sanitizers.get(sanitizer_name)(self.ql).enable()

    def enable_taint(self, taint_name):
        taint.tracker.enable(self.ql, taint_name)

    def enable_smm(self):
        
        # Init SMM related protocols
        profile = os.path.join(os.path.dirname(__file__), 'smm', 'smm.ini')
        self.ql.profile.read(profile)
        smm.init(self.ql, True) #args.mode == 'swsmi')

        self.enable_sanitizer('smm_callout')
        self.enable_taint(['smm'])

    def enable_coverage(self, coverage_file):
        self.coverage_file = coverage_file

    def apply(self, json_conf):
        if not json_conf:
            return

        with open(json_conf, 'r') as f:
            conf = json.load(f)
        
        # Install protocols
        for proto in conf['protocols']:
            descriptor = dummy_protocol.make_descriptor(proto['guid'])
            self.ql.loader.dxe_context.install_protocol(descriptor, 1)

        self.ql.os.smm.swsmi_args['registers'] = conf['registers']
            
    def set_fault_handler(self, verb):
        if verb == 'stop':
            self.ql.os.fault_handler = fault.stop
        elif verb == 'crash':
            self.ql.os.fault_handler = fault.crash
        elif verb == 'ignore':
            self.ql.os.fault_handler = fault.ignore
        elif verb == 'break':
            self.ql.os.fault_handler = fault._break

    def run(self, end=None, timeout=0):

        if end:
            end = callbacks.set_end_of_execution_callback(self.ql, end)

        # okay, ready to roll.
        try:
            with cov_utils.collect_coverage(self.ql, 'drcov_exact', self.coverage_file):
                self.ql.run(end=end, timeout=timeout)
        except fault.StopEmulation:
            pass
        except:
            # Probable Unicorn memory error. Treat as crash.
            # verbose_abort(ql)
            raise