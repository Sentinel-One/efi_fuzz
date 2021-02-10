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

import argparse
import os
import functools

try:
    import monkeyhex
except ImportError:
    pass

from unicorn import *
import sanitizers
import taint.tracker
from EmulationManager import EmulationManager
from FuzzingManager import FuzzingManager

# for argparse
auto_int = functools.partial(int, base=0)

def create_emulator(cls, args):
    emu = cls(args.target, args.extra_modules)
    
    # Load NVRAM environment from the provided Pickle.
    if args.nvram_file:
        emu.load_nvram(args.nvram_file)

    # Load firmware volumes from the provided ROM file.
    if args.rom_file:
        emu.load_rom(args.rom_file)

    # Set the fault handling policy.
    if args.fault_handler:
        emu.fault_handler = args.fault_handler

    # Enable collection of code coverage.
    if args.coverage_file:
        emu.coverage_file = args.coverage_file

    # Initialize SMRAM and some SMM-related protocols.
    emu.enable_smm()

    # Enable sanitizers.
    if args.sanitize:
        emu.sanitizers = args.sanitize

    # Override default output mode.
    if args.output:
        emu.ql.output = args.output

    emu.apply(args.json_conf)
    return emu

def run(args):
    emu = create_emulator(EmulationManager, args)
    emu.run(args.end, args.timeout)

def fuzz(args):
    emu = create_emulator(FuzzingManager, args)
    emu.run(args.end, args.timeout, varname=args.varname, infile=args.infile)

def main(args):
    if args.command == 'run':
        run(args)
    elif args.command == 'fuzz':
        fuzz(args)

    os._exit(0)  # that's a looot faster than tidying up.

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    # Positional arguments
    parser.add_argument("command", help="What should I do?", choices=['run', 'fuzz'])
    parser.add_argument("target", help="Path to the target binary to fuzz")

    # Optional arguments
    parser.add_argument("-c", "--coverage-file", help="Path to code coverage file")
    parser.add_argument("-f", "--fault-handler", help="What to do when encountering a fault?", choices=['crash', 'stop', 'ignore', 'break'])
    parser.add_argument("-e", "--end", help="End address for emulation", type=auto_int)
    parser.add_argument("-t", "--timeout", help="Emulation timeout in ms", type=int, default=60*100000)
    parser.add_argument("-o", "--output", help="Trace execution for debugging purposes", choices=['trace', 'disasm', 'debug', 'dump', 'off'])
    parser.add_argument("-s", "--sanitize", help="Enable memory sanitizer", choices=sanitizers.get_available_sanitizers().keys(), nargs='+')
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
