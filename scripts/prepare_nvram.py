import pickle
import uefi_firmware
import sys
import argparse

def main(rom_file, nvram_file):
    data = open(rom_file, 'rb').read()
    parser = uefi_firmware.AutoParser(data)
    fd = parser.parse()
    for region in fd.regions:
        if region.name == 'bios':
            break
    else:
        print('BIOS region could not be found')
        sys.exit(1)

    nvram_dict = {}
    for volume in region.objects:
        for fs in volume.firmware_filesystems:
            for file in fs.files:
                for obj in file.objects:
                    if obj.type_label == 'NVARVariableStore':
                        for var in obj.variables:
                            if not var.name:
                                # Invalid variable.
                                continue

                            if nvram_dict.get(var.name):
                                # Redundant copy of a variable we already have.
                                continue

                            var_data = var.data[var.data_offset:]
                            nvram_dict[var.name] = var_data
                            print(f'[*] Pickled variable {var.name}')

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
