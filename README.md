# efi_fuzz
A simple, coverage-guided fuzzer for UEFI NVRAM variables.
Based on [Qiling](https://github.com/qilingframework/qiling) and [AFL++](https://github.com/AFLplusplus/AFLplusplus).\
Written by Itai Liba ([@liba2k](https://twitter.com/liba2k)) and Assaf Carlsbad ([@assaf_carlsbad](https://twitter.com/assaf_carlsbad)).

## Usage
1. If running on Windows, install WSL. We recommend WSL2 as opposed to the original WSL, which tends to be slow sometimes. The full installation instructions for Windows 10 can be found here: https://docs.microsoft.com/en-us/windows/wsl/install-win10

2. Inside the WSL distribution, install some necessary packages that will allow us to compile C source code:\
`sudo apt install build-essential automake`

3. Install AFL++ with Unicorn mode support. \
    3.1. Clone the repository: \
    `git clone https://github.com/AFLplusplus/AFLplusplus` \
    3.2. Build core AFL++ binaries: \
    `make` \
    3.3. Build the Unicorn support feature: \
    `cd unicorn_mode` \
    `./build_unicorn_support.sh` \
    3.4. Install everything: \
    `make install`
    
4. Acquire and unpack the UEFI firmware you wish to fuzz.  For the full technical details on how this is done is practice, see [here](https://labs.sentinelone.com/moving-from-common-sense-knowledge-about-uefi-to-actually-dumping-uefi-firmware/) or [here](https://www.amazon.com/Rootkits-Bootkits-Reversing-Malware-Generation/dp/1593277164).

5. Clone the fuzzer and install required dependencies: \
`git clone https://github.com/Sentinel-One/efi_fuzz` \
`pip install -r efi_fuzz/requirements.txt`

6. Prepare the emulated NVRAM environment: \
`python scripts/prepare_nvram.py ron.bin nvram.pickle`

7. Prepare the initial corpus for the NVRAM variables: \
`python scripts/prepare_afl_corpus.py rom.bin afl_inputs`

8. Perform a dry run of the fuzzer: \
`python efi_fuzz.py <target> <nvram> <varname> <seed>`

9. If successful, move on to full-fledged fuzzing: \
`afl-fuzz -i afl_inputs/<varname> -o afl_outputs/ -U -- python efi_fuzz.py <target> <nvram> <varname> @@`

## Command-line options
* `-e, --end`: Specify an end address for the emulation.
* `-t, --timeout`: Specify a new timeout value for the emulation, in ms.
* `-o, --output`: Specify output format for debugging purposes. Valid values are: `trace`, `disasm`, `debug` and `off` (defaults to `off`).
* `-n, --no-sanitize`: Disable the memory sanitizer (defaults to `False`).
* `-x, --extra-modules`: A list of extra modules to load to satisfy the dependencies of the target. 
