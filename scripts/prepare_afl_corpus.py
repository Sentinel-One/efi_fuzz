import uefi_firmware
import argparse
import sys
import os
from contextlib import contextmanager
import shutil
import filecmp

@contextmanager
def chdir(new_dir):
    cwd = os.getcwd()
    try:
        os.chdir(new_dir)
        yield
    finally:
        os.chdir(cwd)

def main(rom_filename, corpus_directory):
    data = open(rom_filename, 'rb').read()
    parser = uefi_firmware.AutoParser(data)
    fd = parser.parse()
    for region in fd.regions:
        if region.name == 'bios':
            break
    else:
        print('BIOS region could not be found')
        sys.exit(1)

    # Make clean directory.
    if os.path.isdir(corpus_directory):
        shutil.rmtree(corpus_directory)
    os.mkdir(corpus_directory)
    os.chdir(corpus_directory)

    for volume in region.objects:
        for fs in volume.firmware_filesystems:
            for file in fs.files:
                for obj in file.objects:
                    if obj.type_label == 'NVARVariableStore':
                        for var in obj.variables:
                            if not var.name:
                                # Invalid variable.
                                continue

                            if not os.path.isdir(var.name):
                                os.mkdir(var.name)

                            seeds = os.listdir(var.name)
                            no = len(seeds)

                            with chdir(var.name):
                                fname = var.name + f'_{no}'
                                var_data = var.data[var.data_offset:]
                                open(fname, 'wb').write(var_data)

                                duplicate = any([filecmp.cmp(fname, seed) for seed in seeds])
                                if duplicate:
                                    os.remove(fname)
                                else:
                                    print(f'[*] Wrote {var.name}/{fname}')
    print('[!] Done!')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('rom_file', help='ROM file obtained by dumping the SPI flash')
    parser.add_argument('corpus_directory', help='Name of the corpus directory to generate', nargs='?', default='afl_inputs')
    args = parser.parse_args()

    main(args.rom_file, args.corpus_directory)
