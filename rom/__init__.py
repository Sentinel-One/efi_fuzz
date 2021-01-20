import ctypes
from qiling.os.uefi.protocols.EfiLoadedImageProtocol import EFI_LOADED_IMAGE_PROTOCOL
from qiling.os.uefi.utils import convert_struct_to_bytes
from .efi_firmware_volume2_protocol import install_EFI_FIRMWARE_VOLUME2_PROTOCOL
import uefi_firmware

def _patch_device_handle(ql, device_handle):
    # Patch the DeviceHandle member
    for img in ql.loader.images:
        loaded_image_protocol_ptr = ql.loader.handle_dict[img.base]['5b1b31a1-9562-11d2-8e3f-00a0c969723b']
        loaded_image_protocol = EFI_LOADED_IMAGE_PROTOCOL.from_buffer(
            ql.mem.read(loaded_image_protocol_ptr, ctypes.sizeof(EFI_LOADED_IMAGE_PROTOCOL)))
        # Patch the DeviceHandle member to refer to the volume driver
        loaded_image_protocol.DeviceHandle = device_handle
        # Write back to memory
        ql.mem.write(loaded_image_protocol_ptr, convert_struct_to_bytes(loaded_image_protocol))

def install(ql, rom_file):
    
    def bios_region(rom_file):
        """
        Returns the BIOS region of the given UEFI image.
        """
        data = open(rom_file, 'rb').read()
        parser = uefi_firmware.AutoParser(data)
        fd = parser.parse()
        for region in fd.regions:
            if region.name == 'bios':
                return region

    # Allocate and initialize the protocols buffer
    protocol_buf_size = 0x1000
    ptr = ql.os.heap.alloc(protocol_buf_size)
    ql.mem.write(ptr, b'\x90' * protocol_buf_size)

    # EFI_FIRMWARE_VOLUME2_PROTOCOL
    efi_firmware_voluem2_protocol_ptr = ptr
    (ptr, efi_firmware_voluem2_protocol) = install_EFI_FIRMWARE_VOLUME2_PROTOCOL(ql, ptr)
    ql.loader.handle_dict[1]['220e73b6-6bdb-4413-8405-b974b108619a'] = efi_firmware_voluem2_protocol_ptr

    # Serialize all protocols to memory
    ql.mem.write(efi_firmware_voluem2_protocol_ptr, convert_struct_to_bytes(efi_firmware_voluem2_protocol))

    _patch_device_handle(ql, 1)

    try:
        ql.os.firmware_volumes = bios_region(rom_file).objects
    except:
        ql.os.firmware_volumes = []
