#!/usr/bin/env python3

"""
A simple UEFI NVRAM fuzzer, based on Qiling framework and AFLplusplus.

After building afl++, make sure you install `unicorn_mode/setup_unicorn.sh`

Then, to fuzz a UEFI module, perform the following steps:

1. Dump the UEFI firmware to a file. For more details, please consult:
   https://labs.sentinelone.com/moving-from-common-sense-knowledge-about-uefi-to-actually-dumping-uefi-firmware/

2. Prepare a pickled dictionary for the NVRAM variables:
   python scripts/prepare_nvram rom.bin nvram.pickle

3. Prepare the initial corpus for fuzzing:
   python scripts/prepare_afl_corpus.py rom.bin afl_inputs

4. Perform a dry-run for running the target UEFI module in the emulation environment:
   python ./efi_fuzz.py nvram.pickle <var_name> afl_inputs/<var_name>/<var_name>_0

5. If successful, you can move on to a full fuzzing session:
   afl-fuzz -i afl_inputs/<var_name>/ -o afl_outputs -U -- python ./efi_fuzz.py <target> nvram.pickle <var_name> @@
"""

# Make sure Qiling uses our patched Unicorn instead of it's own.
import unicornafl
unicornafl.monkeypatch()

import io
import pickle
import pefile
import argparse
import os
import functools
import importlib

try:
    import monkeyhex
except ImportError:
    pass

from qiling import arch
from qiling import Qiling
from unicorn import *
from sanitizers.memory import *
from sanitizers.smm import *
import taint
import taint.tracker
import smm.protocols
import smm.swsmi

# for argparse
auto_int = functools.partial(int, base=0)

def start_afl(_ql: Qiling, user_data):
    """
    Callback from inside
    """

    args = user_data

    def place_input_callback_nvram(uc, _input, _, data):
        """
        Injects the mutated variable to the emulated NVRAM environment.
        """
        try:
            _ql.env[args.varname] = _input
        except Exception as e:
            verbose_abort(_ql)

    def place_input_callback_swsmi(uc, _input, _, data):
        """
        Injects the mutated variable to the emulated NVRAM environment.
        """
        total_size = len(args.registers) * 8
        _input = _input.ljust(total_size, b'\x00') # zero padding

        stream = io.BytesIO(_input)
        for reg in args.registers:
            _ql.os.smm.swsmi_args[reg] = stream.read(8)

    def validate_crash(uc, err, _input, persistent_round, user_data):
        """
        Informs AFL that a certain condition should be treated as a crash.
        """
        if args.sanitize and not _ql.os.heap.validate():
            # Canary was corrupted.
            verbose_abort(_ql)
            return True

        # Some other internal exception.
        crash = (_ql.internal_exception is not None) or (err.errno != UC_ERR_OK)
        if crash and args.output == 'debug':
            _ql.os.emu_error()
        return crash

    # Choose the function to inject the mutated input to the emulation environment,
    # based on the fuzzing mode.
    if args.mode == 'nvram':
        place_input_callback = place_input_callback_nvram
    elif args.mode == 'swsmi':
        place_input_callback = place_input_callback_swsmi
    else:
        assert False, "Bad fuzzing mode"

    # We start our AFL forkserver or run once if AFL is not available.
    # This will only return after the fuzzing stopped.
    try:
        if not _ql.uc.afl_fuzz(input_file=args.infile,
                               place_input_callback=place_input_callback,
                               exits=[_ql.os.exit_point],
                               always_validate=True,
                               validate_crash_callback=validate_crash):
            print("Dry run completed successfully without AFL attached.")
            os._exit(0)  # that's a looot faster than tidying up.
    except unicornafl.UcAflError as ex:
        if ex != unicornafl.UC_AFL_RET_CALLED_TWICE:
            raise

def main(args):
    enable_trace = args.output != 'off'

    # Listify extra modules.
    if args.extra_modules is None:
        extra_modules = []

    ql = Qiling(extra_modules + [args.target],
                ".",                                        # rootfs
                console=True if enable_trace else False,
                stdout=1 if enable_trace else None,
                stderr=1 if enable_trace else None,
                output=args.output,
                profile="smm/smm.ini")

    ql.os.notify_after_module_execution = smm.swsmi.after_module_execution_callback

    # Load NVRAM environment.
    if args.nvram_file:
        with open(args.nvram_file, 'rb') as f:
            ql.env = pickle.load(f)

    # The last loaded image is the main module we're interested in fuzzing
    pe = pefile.PE(args.target, fast_load=True)
    image_base = ql.loader.images[-1].base
    entry_point = image_base + pe.OPTIONAL_HEADER.AddressOfEntryPoint

    # Not passing the fuzzing mode argument results in a dry run, without AFL's involvement.
    if args.mode:
        # We want AFL's forkserver to spawn new copies starting from the main module's entrypoint.
        ql.hook_address(callback=start_afl, address=entry_point, user_data=args)

    if args.taint:
        taint.tracker.enable(ql, args.taint)

    # Init SMM related protocols
    smm.protocols.init(ql, args.mode == 'swsmi')

    # Run custom initialization script.
    if args.load_package:
        mod = importlib.import_module(args.load_package)
        if hasattr(mod, 'run'):
            mod.run(ql)

    if args.sanitize:
        enable_sanitized_heap(ql)
        enable_sanitized_CopyMem(ql)
        enable_sanitized_SetMem(ql)
        enable_smm_sanitizer(ql)

    # okay, ready to roll.
    try:
        ql.run(end=args.end, timeout=args.timeout)
    except Exception as ex:
        # Probable Unicorn memory error. Treat as crash.
        verbose_abort(ql)

    os._exit(0)  # that's a looot faster than tidying up.



if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    # Positional arguments
    parser.add_argument("target", help="Path to the target binary to fuzz")

    # Optional arguments
    parser.add_argument("-e", "--end", help="End address for emulation", type=auto_int)
    parser.add_argument("-t", "--timeout", help="Emulation timeout in ms", type=int, default=60*100000)
    parser.add_argument("-o", "--output", help="Trace execution for debugging purposes", choices=['trace', 'disasm', 'debug', 'off'], default='off')
    parser.add_argument("-s", "--sanitize", help="Enable memory sanitizer", action='store_true')
    parser.add_argument("--taint", help="Track uninitialized memory (experimental!)", choices=taint.get_available_tainters().keys(), nargs='+')
    parser.add_argument("-l", "--load-package", help="Load a package to further customize the environment")
    parser.add_argument("-v", "--nvram-file", help="Pickled dictionary containing the NVRAM environment variables")
    parser.add_argument("-x", "--extra-modules", help="Extra modules to load", nargs='+')

    subparsers = parser.add_subparsers(help="Fuzzing modes", dest="mode")

    # NVRAM sub-command
    nvram_subparser = subparsers.add_parser("nvram", help="Fuzz contents of NVRAM variables")
    nvram_subparser.add_argument("varname", help="Name of the NVRAM variable to mutate")
    nvram_subparser.add_argument("infile", help="Mutated input buffer. Set to @@ when running under afl-fuzz")
    
    # SWSMI sub-command
    swsmi_subparser = subparsers.add_parser("swsmi", help="Fuzz arguments of SWSMI handlers")
    swsmi_subparser.add_argument("registers", help="List of registers to fuzz", choices=['rax','rbx','rcx','rdx','rsi','rdi'], nargs='+')
    swsmi_subparser.add_argument("infile", help="Mutated input buffer. Set to @@ when running under afl-fuzz")

    main(parser.parse_args())
