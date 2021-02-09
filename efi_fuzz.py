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
from FuzzingManager import FuzzingManager

import argparse
import os
import functools

try:
    import monkeyhex
except ImportError:
    pass

from unicorn import *
import sanitizers
import taint
import taint.tracker
from EmulationManager import EmulationManager

# for argparse
auto_int = functools.partial(int, base=0)

def emulate(args):
    e = EmulationManager(args.target, args.extra_modules)
    e.load_nvram(args.nvram_file)
    e.enable_smm()
    e.enable_taint(['uninitialized'])
    e.enable_coverage(args.coverage_file)
    e.apply(args.json_conf)
    e.set_fault_handler(args.fault)
    e.run()

def fuzz(args):
    e = FuzzingManager(args.target, args.extra_modules)
    e.load_nvram(args.nvram_file)
    e.enable_smm()
    e.enable_taint(['uninitialized'])
    e.enable_coverage(args.coverage_file)
    e.apply(args.json_conf)
    e.set_fault_handler(args.fault)
    e.run(args.end, args.timeout, args.varname, args.infile)

def main(args):
    enable_trace = args.output != 'off'

    if args.command == 'run':
        emulate(args)
    elif args.command == 'fuzz':
        fuzz(args)
    # assert(False)
    return

    os._exit(0)  # that's a looot faster than tidying up.

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    # Positional arguments
    parser.add_argument("command", help="What should I do?", choices=['run', 'fuzz'])
    parser.add_argument("target", help="Path to the target binary to fuzz")

    # Optional arguments
    parser.add_argument("-c", "--coverage-file", help="Path to code coverage file")
    parser.add_argument("-f", "--fault", help="What to do when encountering a fault?", choices=['crash', 'stop', 'ignore', 'break'])
    parser.add_argument("-e", "--end", help="End address for emulation", type=auto_int)
    parser.add_argument("-t", "--timeout", help="Emulation timeout in ms", type=int, default=60*100000)
    parser.add_argument("-o", "--output", help="Trace execution for debugging purposes", choices=['trace', 'disasm', 'debug', 'off'], default='off')
    parser.add_argument("-s", "--sanitize", help="Enable memory sanitizer", choices=sanitizers.get_available_sanitizers().keys(), nargs='+')
    parser.add_argument("--taint", help="Track uninitialized memory (experimental!)", choices=taint.get_available_tainters().keys(), nargs='+')
    parser.add_argument("-j", "--json-conf", help="Specify a JSON file to further customize the environment")
    parser.add_argument("-v", "--nvram-file", help="Pickled dictionary containing the NVRAM environment variables")
    parser.add_argument("-r", "--rom-file", help="Path to the UEFI ROM file")
    parser.add_argument("-x", "--extra-modules", help="Extra modules to load", nargs='+')

    subparsers = parser.add_subparsers(help="Fuzzing modes", dest="mode")

    # NVRAM sub-command
    nvram_subparser = subparsers.add_parser("nvram", help="Fuzz contents of NVRAM variables")
    nvram_subparser.add_argument("varname", help="Name of the NVRAM variable to mutate")
    nvram_subparser.add_argument("infile", help="Mutated input buffer. Set to @@ when running under afl-fuzz")
    
    main(parser.parse_args())
