import uefi_firmware
import argparse
import sys
import os
from contextlib import contextmanager
import shutil
import filecmp
import subprocess
import glob
import uuid
from pathlib import Path

@contextmanager
def chdir(new_dir):
    cwd = os.getcwd()
    try:
        os.chdir(new_dir)
        yield
    finally:
        os.chdir(cwd)

def get_uefiextract():
    if sys.platform == "linux":
        platform = "linux"
        uefiextract = "UEFIExtract"
    elif sys.platform == "darwin":
        platform = "mac"
        uefiextract = "UEFIExtract"
    elif sys.platform == "win32":
        platform = "windows"
        uefiextract = "UEFIExtract.exe"

    return os.path.join(Path(__file__).parent.parent, 'bin', platform, uefiextract)

def main(rom_file, corpus_directory):
    UEFI_EXTRACT_PATH = get_uefiextract()
    subprocess.run([UEFI_EXTRACT_PATH, rom_file], stdout=subprocess.DEVNULL)

    nvram_dir = f"{rom_file}.dump"
    variables = glob.glob(os.path.join(nvram_dir, "**/*VSS*/**/body.bin"), recursive=True)

    if os.path.isdir(corpus_directory):
        shutil.rmtree(corpus_directory)
    os.mkdir(corpus_directory)

    for var_filename in variables:
        parent = Path(var_filename)
        parent_name = str(parent.parent)
        variable_name = parent_name.split(" ")[-1]

        var_binary = open(var_filename, "rb").read()
        print(f"Writing {variable_name}.")

        with chdir(corpus_directory):
            open(variable_name + "_0", 'wb').write(var_binary)
        

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('rom_file', help='ROM file obtained by dumping the SPI flash')
    parser.add_argument('corpus_directory', help='Name of the corpus directory to generate', nargs='?', default='afl_inputs')
    args = parser.parse_args()

    main(args.rom_file, args.corpus_directory)
