import os
import pickle
import subprocess
import sys
import argparse
import glob

def main(rom_file, nvram_file):
    UEFI_EXTRACT_PATH = os.path.join(os.path.dirname(__file__), 'UEFIExtract')
    subprocess.run([UEFI_EXTRACT_PATH, rom_file], stdout=subprocess.DEVNULL)

    nvram_dict = {}

    nvram_dir = f"{rom_file}.nvram.dir"
    variables = glob.glob(os.path.join(nvram_dir, "*.bin"))
    for var_filename in variables:
        # Trim directory prefix.
        var_name = var_filename[len(nvram_dir) + 1:]
        # UEFIExtract generates files based on the following pattern: <varname>_<guid>_<attrs>_<num>.bin
        var_name = "_".join(var_name.split("_")[:-3])   
        # Update variables dictionary
        nvram_dict[var_name] = open(var_filename, "rb").read()
        print(f'[*] Pickled variable {var_name}')
    
    # Serialize everything.
    with open(nvram_file, 'wb') as nvram_pickle:
        pickle.dump(nvram_dict, nvram_pickle)

    print('[!] Done!')
    print(f'The complete pickled NVRAM environment can be found here: {nvram_file}')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('rom_file', help='ROM file obtained by dumping the SPI flash')
    parser.add_argument('nvram_file', help='pickled NVRAM dictionary to create')
    args = parser.parse_args()

    main(args.rom_file, args.nvram_file)
