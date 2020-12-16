import os
import uefi_firmware
from uefi_firmware.utils import sguid
from enum import Enum
import csv

GUIDS_DB = {}

APRIORI_DXE_GUID = b'\xe7\x0eQ\xfc\xdc\xff\xd4\x11\xbdA\x00\x80\xc7<\x88\x81'

class EfiSectionType(Enum):
    GuidDefined = 0x02
    PE32 = 0x10
    Dependency = 0x13
    Version = 0x14

LZMA_CUSTOM_DECOMPRESS_GUID = 'ee4e5898-3914-4259-9d6e-dc7bd79403cf'

modules_to_avoid =  [
    'd6a2cb7f-6a18-4e2f-b43b-9920a733700a', # DxeCore
]
def get_bios_region(rom_file):
    data = open(rom_file, "rb").read()
    parser = uefi_firmware.AutoParser(data)
    if parser.type() == 'unknown':
        return None
    firmware = parser.parse()
    for region in firmware.regions:
        if region.name == 'bios':
            return region

def get_firmware_volume(bios_region, guid):
    for volume in bios_region.objects:
        if sguid(volume.fvname) == guid:
            return volume

def read_apriori_file(ap):
    apriori_guids = []
    assert len(ap.sections) == 1
    data = ap.sections[0].data
    assert len(data) % 16 == 0
    for i in range(len(data) // 16):
        guid = data[i*16:(i+1)*16]
        apriori_guids.append(guid)
    return apriori_guids

def get_all_files(volume, apriori_guid):
    all_files = []

    for ffs in volume.objects:
        for file in ffs.files:
            if file.guid == apriori_guid:
                apriori_guids = read_apriori_file(file)
            else:
                all_files.append(file)

    apriori_files = [f for f in all_files if f.guid in apriori_guids]
    # Make sure the apriori files are correctly sorted
    apriori_files = sorted(apriori_files, key=lambda f: apriori_guids.index(f.guid))
    none_apriori_files = [f for f in all_files if f.guid not in apriori_guids]

    return apriori_files, none_apriori_files

def build_guid_db(guids_filename='guids.csv'):
    global GUIDS_DB
    reader = csv.reader(open(guids_filename, 'r'))
    for row in reader:
        (guid, name) = row
        GUIDS_DB[guid] = name

def dump_pe(file, rootfs):
    # check if in blacklist
    if file.guid_label in modules_to_avoid:
        return None

    # check if already exists
    try:
        friendly_name = GUIDS_DB[file.guid_label.upper()]
    except KeyError:
        friendly_name = file.guid_label

    fname = os.path.join(rootfs, friendly_name)
    if os.path.exists(fname):
        return os.path.join(fname, 'section0.pe')

    for section in file.sections:
        if section.type == EfiSectionType.GuidDefined.value:
            assert len(section.objects) == 1
            encapsulated = section.objects[0]
            if encapsulated.guid_label == LZMA_CUSTOM_DECOMPRESS_GUID:
                # LZMA compressed
                for subsection in encapsulated.subsections:
                    if subsection.type == EfiSectionType.PE32.value:
                        subsection.dump(fname)
                        return subsection.path
            else:
                raise ValueError(f"Unrecognized GUID defined section {encapsulated.guid_label}")