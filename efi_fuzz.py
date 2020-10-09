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

import pickle
import pefile
import argparse
import os
import functools

try:
    import monkeyhex
except ImportError:
    pass

from qiling import Qiling
from unicorn import *
from sanitizer import *
from taint.tracker import enable_uninitialized_memory_tracker

# for argparse
auto_int = functools.partial(int, base=0)

def start_afl(_ql: Qiling, user_data):
    """
    Callback from inside
    """

    (infile, varname, sanitize) = user_data

    def place_input_callback(uc, _input, _, data):
        """
        Injects the mutated variable to the emulated NVRAM environment.
        """
        try:
            _ql.env[varname] = _input
        except Exception as e:
            verbose_abort(_ql)

    def validate_crash(uc, err, _input, persistent_round, user_data):
        """
        Informs AFL that a certain condition should be treated as a crash.
        """
        if sanitize and not _ql.os.heap.validate():
            # Canary was corrupted.
            verbose_abort(_ql)
            return True

        # Some other internal exception.
        return (_ql.internal_exception is not None) or (err.errno != UC_ERR_OK)

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

def main(target_binary, nvram_file, var_name, input_file, output, end, timeout, sanitize, track_uninitialized, extra_modules):
    enable_trace = output != 'off'

    # Listify extra modules.
    if extra_modules is None:
        extra_modules = []

    ql = Qiling(extra_modules + [target_binary],
                ".",                                        # rootfs
                console=True if enable_trace else False,
                stdout=1 if enable_trace else None,
                stderr=1 if enable_trace else None,
                output=output)

    # Load NVRAM environment.
    with open(nvram_file, 'rb') as f:
        ql.env = pickle.load(f)

    # The last loaded image is the main module we're interested in fuzzing
    pe = pefile.PE(target_binary, fast_load=True)
    image_base = ql.loader.images[-1].base
    entry_point = image_base + pe.OPTIONAL_HEADER.AddressOfEntryPoint

    # We want AFL's forkserver to spawn new copies starting from the main module's entrypoint.
    ql.hook_address(callback=start_afl, address=entry_point, user_data=(input_file, var_name, sanitize))

    if sanitize:
        enable_sanitized_heap(ql)
        enable_sanitized_CopyMem(ql)
        enable_sanitized_SetMem(ql)

    if track_uninitialized:
        enable_uninitialized_memory_tracker(ql)

    # okay, ready to roll.
    try:
        ql.run(end=end, timeout=timeout)
    except Exception as ex:
        # Probable Unicorn memory error. Treat as crash.
        verbose_abort(ql)

    os._exit(0)  # that's a looot faster than tidying up.


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    # Positional arguments
    parser.add_argument("target", help="Path to the target binary to fuzz")
    parser.add_argument("nvram", help="Pickled dictionary containing the NVRAM environment variables")
    parser.add_argument("varname", help="Name of the NVRAM variable to mutate")
    parser.add_argument("infile", help="Mutated input buffer. Set to @@ when running under afl-fuzz")

    # Optional arguments
    parser.add_argument("-e", "--end", help="End address for emulation", type=auto_int)
    parser.add_argument("-t", "--timeout", help="Emulation timeout in ms", type=int, default=60*100000)
    parser.add_argument("-o", "--output", help="Trace execution for debugging purposes", choices=['trace', 'disasm', 'debug', 'off'], default='off')
    parser.add_argument("-n", "--no-sanitize", help="Disable memory sanitizer", action='store_true', default=False)
    parser.add_argument("-u", "--track-uninitialized", help="Track uninitialized memory (experimental!)", action='store_true', default=False)
    parser.add_argument("-x", "--extra-modules", help="Extra modules to load", nargs='+')

    args = parser.parse_args()

    sanitize = not args.no_sanitize
    main(args.target, args.nvram, args.varname, args.infile, args.output, args.end, args.timeout, sanitize, args.track_uninitialized, args.extra_modules)
