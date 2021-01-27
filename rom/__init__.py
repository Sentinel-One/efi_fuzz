import ctypes
from qiling.os.uefi.protocols.EfiLoadedImageProtocol import EFI_LOADED_IMAGE_PROTOCOL
from .efi_firmware_volume2_protocol import install_EFI_FIRMWARE_VOLUME2_PROTOCOL
import uefi_firmware

def _patch_device_handle(ql, device_handle):
    # Patch the DeviceHandle member
    for img in ql.loader.images:
        loaded_image_protocol_ptr = ql.loader.dxe_context.protocols[img.base]['5b1b31a1-9562-11d2-8e3f-00a0c969723b']
        loaded_image_protocol = EFI_LOADED_IMAGE_PROTOCOL.loadFrom(ql, loaded_image_protocol_ptr)
        # Patch the DeviceHandle member to refer to the volume driver
        loaded_image_protocol.DeviceHandle = device_handle
        # Write back to memory
        loaded_image_protocol.saveTo(ql, loaded_image_protocol_ptr)

def install(ql, rom_file):
    
    def bios_region(fd):
        """
        Returns the BIOS region of the given UEFI image.
        """
        assert fd.type_label == 'FlashDescriptor'
        for region in fd.regions:
            if region.name == 'bios':
                return region

    # EFI_FIRMWARE_VOLUME2_PROTOCOL
    install_EFI_FIRMWARE_VOLUME2_PROTOCOL(ql)

    _patch_device_handle(ql, 1)

    data = open(rom_file, 'rb').read()
    parser = uefi_firmware.AutoParser(data)
    fd = parser.parse()
    if fd.type_label == 'FlashDescriptor':
        ql.os.firmware_volumes = bios_region(fd).objects
    elif fd.type_label == 'FirmwareCapsule':
        ql.os.firmware_volumes = fd.objects
    else:
        ql.os.firmware_volumes = []