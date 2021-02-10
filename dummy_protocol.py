from qiling.os.uefi.ProcessorBind import *
from qiling.os.uefi.UefiBaseType import *
from qiling.os.uefi.UefiSpec import EFI_SYSTEM_TABLE, EFI_DEVICE_PATH_PROTOCOL, EFI_IMAGE_UNLOAD
from qiling.os.uefi.UefiMultiPhase import EFI_MEMORY_TYPE

class EFI_FAKE_PROTOCOL(STRUCT):
	_fields_ = [
		('Revision',		UINT32),
	]

def make_descriptor(guid):
	descriptor = {
		"guid" : guid,
		"struct" : EFI_FAKE_PROTOCOL,
		"fields" : (
			('Revision',		0x1000),
		)
	}

	return descriptor

__all__ = [
	'EFI_FAKE_PROTOCOL',
	'make_descriptor'
]