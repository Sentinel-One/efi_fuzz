# Make sure Qiling uses our patched Unicorn instead of it's own.
from unicorn.x86_const import UC_X86_INS_CPUID, UC_X86_INS_RDMSR
import unicornafl
unicornafl.monkeypatch()

from unicorn import *

import pefile
from core.EmulationManager import EmulationManager
from qiling import Qiling
import os
import core.fault

def start_afl(_ql: Qiling, user_data):
    """
    Callback from inside
    """

    (varname, infile) = user_data

    def place_input_callback_nvram(uc, _input, _, data):
        """
        Injects the mutated variable to the emulated NVRAM environment.
        """
        _ql.env[varname] = _input

    def validate_crash(uc, err, _input, persistent_round, user_data):
        """
        Informs AFL that a certain condition should be treated as a crash.
        """
        if hasattr(_ql.os.heap, "validate"):
            if not _ql.os.heap.validate():
                # Canary was corrupted.
                verbose_abort(_ql)
                return True

        crash = (_ql.internal_exception is not None) or (err.errno != UC_ERR_OK)
        return crash

    # Choose the function to inject the mutated input to the emulation environment,
    # based on the fuzzing mode.
    place_input_callback = place_input_callback_nvram

    # We start our AFL forkserver or run once if AFL is not available.
    # This will only return after the fuzzing stopped.
    try:
        if not _ql.uc.afl_fuzz(input_file=infile,
                               place_input_callback=place_input_callback,
                               exits=[_ql.os.exit_point],
                               always_validate=True,
                               validate_crash_callback=validate_crash):
            print("Dry run completed successfully without AFL attached.")
            os._exit(0)  # that's a looot faster than tidying up.
    except unicornafl.UcAflError as ex:
        if ex != unicornafl.UC_AFL_RET_CALLED_TWICE:
            raise

class FuzzingManager(EmulationManager):
    
    # Tainting significantly slows down the fuzzing process.
    # Therefore, we won't enable them unless explicitly requested by the user.
    DEFAULT_TAINTERS = []

    DEFAULT_SANITIZERS = ['smm_callout'] # @TODO: maybe enable 'memory' sanitizer as well?

    def __init__(self, target_module, extra_modules=None):
        super().__init__(target_module, extra_modules)

        self.tainters = FuzzingManager.DEFAULT_TAINTERS
        self.sanitizers = FuzzingManager.DEFAULT_SANITIZERS
        self.fault_handler = 'abort' # By default we prefer to abort to notify AFL of potential crashes.

    @EmulationManager.coverage_file.setter
    def coverage_file(self, cov):
        # The default behaviour of the fuzzer is to 'abort()' upon encoutering a fault.
        # Since no termination handlers will be called, the coverage collector won't be
        # able to dump the collected coverage entries to a file.
        self.ql.log.warn('Coverage collection is incompatible with fuzzing')
        self._coverage_file = None

    def fuzz(self, end=None, timeout=0, **kwargs):
        # The last loaded image is the main module we're interested in fuzzing
        target = self.ql.loader.images[-1].path
        pe = pefile.PE(target, fast_load=True)
        image_base = self.ql.loader.images[-1].base
        entry_point = image_base + pe.OPTIONAL_HEADER.AddressOfEntryPoint

        # We want AFL's forkserver to spawn new copies starting from the main module's entrypoint.
        self.ql.hook_address(callback=start_afl, address=entry_point, user_data=(kwargs['varname'], kwargs['infile']))

        super().run(end, timeout)