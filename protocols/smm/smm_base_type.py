# -*- coding: utf-8 -*-
#
# TARGET arch is: ['-IMdePkg/Include', '-IIntelFrameworkPkg/Include']
# WORD_SIZE is: 8
# POINTER_SIZE is: 8
# LONGDOUBLE_SIZE is: 16
#
import ctypes


c_int128 = ctypes.c_ubyte*16
c_uint128 = c_int128
void = None
if ctypes.sizeof(ctypes.c_longdouble) == 16:
    c_long_double_t = ctypes.c_longdouble
else:
    c_long_double_t = ctypes.c_ubyte*16

# if local wordsize is same as target, keep ctypes pointer function.

# required to access _ctypes
import _ctypes
# Emulate a pointer class using the approriate c_int32/c_int64 type
# The new class should have :
# ['__module__', 'from_param', '_type_', '__dict__', '__weakref__', '__doc__']
# but the class should be submitted to a unique instance for each base type
# to that if A == B, POINTER_T(A) == POINTER_T(B)
ctypes._pointer_t_type_cache = {}
def POINTER_T(pointee):
    # a pointer should have the same length as LONG
    fake_ptr_base_type = ctypes.c_uint64 
    # specific case for c_void_p
    if pointee is None: # VOID pointer type. c_void_p.
        pointee = type(None) # ctypes.c_void_p # ctypes.c_ulong
        clsname = 'c_void'
    else:
        clsname = pointee.__name__
    if clsname in ctypes._pointer_t_type_cache:
        return ctypes._pointer_t_type_cache[clsname]
    # make template
    class _T(_ctypes._SimpleCData,):
        _type_ = 'L'
        _subtype_ = pointee
        def _sub_addr_(self):
            return self.value
        def __repr__(self):
            return '%s(%d)'%(clsname, self.value)
        def contents(self):
            raise TypeError('This is not a ctypes pointer.')
        def __init__(self, **args):
            raise TypeError('This is not a ctypes pointer. It is not instanciable.')
    _class = type('LP_%d_%s'%(8, clsname), (_T,),{}) 
    ctypes._pointer_t_type_cache[clsname] = _class
    return _class



class struct_c__SA_EFI_SMI_CPU_SAVE_STATE(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('Reserved1', ctypes.c_ubyte * 248),
    ('SMBASE', ctypes.c_uint32),
    ('SMMRevId', ctypes.c_uint32),
    ('IORestart', ctypes.c_uint16),
    ('AutoHALTRestart', ctypes.c_uint16),
    ('Reserved2', ctypes.c_ubyte * 164),
    ('ES', ctypes.c_uint32),
    ('CS', ctypes.c_uint32),
    ('SS', ctypes.c_uint32),
    ('DS', ctypes.c_uint32),
    ('FS', ctypes.c_uint32),
    ('GS', ctypes.c_uint32),
    ('LDTBase', ctypes.c_uint32),
    ('TR', ctypes.c_uint32),
    ('DR7', ctypes.c_uint32),
    ('DR6', ctypes.c_uint32),
    ('EAX', ctypes.c_uint32),
    ('ECX', ctypes.c_uint32),
    ('EDX', ctypes.c_uint32),
    ('EBX', ctypes.c_uint32),
    ('ESP', ctypes.c_uint32),
    ('EBP', ctypes.c_uint32),
    ('ESI', ctypes.c_uint32),
    ('EDI', ctypes.c_uint32),
    ('EIP', ctypes.c_uint32),
    ('EFLAGS', ctypes.c_uint32),
    ('CR3', ctypes.c_uint32),
    ('CR0', ctypes.c_uint32),
     ]

class union_c__UA_EFI_SMM_CPU_SAVE_STATE(ctypes.Union):
    _pack_ = True # source:False
    _fields_ = [
    ('Ia32SaveState', struct_c__SA_EFI_SMI_CPU_SAVE_STATE),
     ]

class struct_c__SA_EFI_SMI_OPTIONAL_FPSAVE_STATE(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('Fcw', ctypes.c_uint16),
    ('Fsw', ctypes.c_uint16),
    ('Ftw', ctypes.c_uint16),
    ('Opcode', ctypes.c_uint16),
    ('Eip', ctypes.c_uint32),
    ('Cs', ctypes.c_uint16),
    ('Rsvd1', ctypes.c_uint16),
    ('DataOffset', ctypes.c_uint32),
    ('Ds', ctypes.c_uint16),
    ('Rsvd2', ctypes.c_ubyte * 10),
    ('St0Mm0', ctypes.c_ubyte * 10),
    ('Rsvd3', ctypes.c_ubyte * 6),
    ('St0Mm1', ctypes.c_ubyte * 10),
    ('Rsvd4', ctypes.c_ubyte * 6),
    ('St0Mm2', ctypes.c_ubyte * 10),
    ('Rsvd5', ctypes.c_ubyte * 6),
    ('St0Mm3', ctypes.c_ubyte * 10),
    ('Rsvd6', ctypes.c_ubyte * 6),
    ('St0Mm4', ctypes.c_ubyte * 10),
    ('Rsvd7', ctypes.c_ubyte * 6),
    ('St0Mm5', ctypes.c_ubyte * 10),
    ('Rsvd8', ctypes.c_ubyte * 6),
    ('St0Mm6', ctypes.c_ubyte * 10),
    ('Rsvd9', ctypes.c_ubyte * 6),
    ('St0Mm7', ctypes.c_ubyte * 10),
    ('Rsvd10', ctypes.c_ubyte * 6),
    ('Rsvd11', ctypes.c_ubyte * 352),
     ]

class struct_c__SA_EFI_PMI_OPTIONAL_FLOATING_POINT_CONTEXT(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('f2', ctypes.c_uint64 * 2),
    ('f3', ctypes.c_uint64 * 2),
    ('f4', ctypes.c_uint64 * 2),
    ('f5', ctypes.c_uint64 * 2),
    ('f6', ctypes.c_uint64 * 2),
    ('f7', ctypes.c_uint64 * 2),
    ('f8', ctypes.c_uint64 * 2),
    ('f9', ctypes.c_uint64 * 2),
    ('f10', ctypes.c_uint64 * 2),
    ('f11', ctypes.c_uint64 * 2),
    ('f12', ctypes.c_uint64 * 2),
    ('f13', ctypes.c_uint64 * 2),
    ('f14', ctypes.c_uint64 * 2),
    ('f15', ctypes.c_uint64 * 2),
    ('f16', ctypes.c_uint64 * 2),
    ('f17', ctypes.c_uint64 * 2),
    ('f18', ctypes.c_uint64 * 2),
    ('f19', ctypes.c_uint64 * 2),
    ('f20', ctypes.c_uint64 * 2),
    ('f21', ctypes.c_uint64 * 2),
    ('f22', ctypes.c_uint64 * 2),
    ('f23', ctypes.c_uint64 * 2),
    ('f24', ctypes.c_uint64 * 2),
    ('f25', ctypes.c_uint64 * 2),
    ('f26', ctypes.c_uint64 * 2),
    ('f27', ctypes.c_uint64 * 2),
    ('f28', ctypes.c_uint64 * 2),
    ('f29', ctypes.c_uint64 * 2),
    ('f30', ctypes.c_uint64 * 2),
    ('f31', ctypes.c_uint64 * 2),
     ]

class union_c__UA_EFI_SMM_FLOATING_POINT_SAVE_STATE(ctypes.Union):
    _pack_ = True # source:False
    _fields_ = [
    ('Ia32FpSave', struct_c__SA_EFI_SMI_OPTIONAL_FPSAVE_STATE),
    ('ItaniumFpSave', struct_c__SA_EFI_PMI_OPTIONAL_FLOATING_POINT_CONTEXT),
    ('PADDING_0', ctypes.c_ubyte * 32),
     ]

class struct__EFI_SMM_SYSTEM_TABLE(ctypes.Structure):
    pass


# values for enumeration 'enum_16'
enum_16__enumvalues = {
    10: 'EfiACPIMemoryNVS',
    9: 'EfiACPIReclaimMemory',
    3: 'EfiBootServicesCode',
    4: 'EfiBootServicesData',
    7: 'EfiConventionalMemory',
    1: 'EfiLoaderCode',
    2: 'EfiLoaderData',
    15: 'EfiMaxMemoryType',
    11: 'EfiMemoryMappedIO',
    12: 'EfiMemoryMappedIOPortSpace',
    13: 'EfiPalCode',
    14: 'EfiPersistentMemory',
    0: 'EfiReservedMemoryType',
    5: 'EfiRuntimeServicesCode',
    6: 'EfiRuntimeServicesData',
    8: 'EfiUnusableMemory',
}
EfiACPIMemoryNVS = 10
EfiACPIReclaimMemory = 9
EfiBootServicesCode = 3
EfiBootServicesData = 4
EfiConventionalMemory = 7
EfiLoaderCode = 1
EfiLoaderData = 2
EfiMaxMemoryType = 15
EfiMemoryMappedIO = 11
EfiMemoryMappedIOPortSpace = 12
EfiPalCode = 13
EfiPersistentMemory = 14
EfiReservedMemoryType = 0
EfiRuntimeServicesCode = 5
EfiRuntimeServicesData = 6
EfiUnusableMemory = 8
enum_16 = ctypes.c_int # enum
class struct_GUID(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('Data1', ctypes.c_uint32),
    ('Data2', ctypes.c_uint16),
    ('Data3', ctypes.c_uint16),
    ('Data4', ctypes.c_ubyte * 8),
     ]

class struct__EFI_SMM_CPU_IO_INTERFACE(ctypes.Structure):
    pass

class struct_c__SA_EFI_SMM_IO_ACCESS(ctypes.Structure):
    pass


# values for enumeration 'c__EA_EFI_SMM_IO_WIDTH'
c__EA_EFI_SMM_IO_WIDTH__enumvalues = {
    0: 'SMM_IO_UINT8',
    1: 'SMM_IO_UINT16',
    2: 'SMM_IO_UINT32',
    3: 'SMM_IO_UINT64',
}
SMM_IO_UINT8 = 0
SMM_IO_UINT16 = 1
SMM_IO_UINT32 = 2
SMM_IO_UINT64 = 3
c__EA_EFI_SMM_IO_WIDTH = ctypes.c_int # enum
struct_c__SA_EFI_SMM_IO_ACCESS._pack_ = True # source:False
struct_c__SA_EFI_SMM_IO_ACCESS._fields_ = [
    ('Read', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_SMM_CPU_IO_INTERFACE), c__EA_EFI_SMM_IO_WIDTH, ctypes.c_uint64, ctypes.c_uint64, POINTER_T(None)))),
    ('Write', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_SMM_CPU_IO_INTERFACE), c__EA_EFI_SMM_IO_WIDTH, ctypes.c_uint64, ctypes.c_uint64, POINTER_T(None)))),
]

struct__EFI_SMM_CPU_IO_INTERFACE._pack_ = True # source:False
struct__EFI_SMM_CPU_IO_INTERFACE._fields_ = [
    ('Mem', struct_c__SA_EFI_SMM_IO_ACCESS),
    ('Io', struct_c__SA_EFI_SMM_IO_ACCESS),
]

class struct_EFI_TABLE_HEADER(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('Signature', ctypes.c_uint64),
    ('Revision', ctypes.c_uint32),
    ('HeaderSize', ctypes.c_uint32),
    ('CRC32', ctypes.c_uint32),
    ('Reserved', ctypes.c_uint32),
     ]


# values for enumeration 'enum_494'
enum_494__enumvalues = {
    2: 'AllocateAddress',
    0: 'AllocateAnyPages',
    1: 'AllocateMaxAddress',
    3: 'MaxAllocateType',
}
AllocateAddress = 2
AllocateAnyPages = 0
AllocateMaxAddress = 1
MaxAllocateType = 3
enum_494 = ctypes.c_int # enum
class struct_EFI_CONFIGURATION_TABLE(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('VendorGuid', struct_GUID),
    ('VendorTable', POINTER_T(None)),
     ]

struct__EFI_SMM_SYSTEM_TABLE._pack_ = True # source:False
struct__EFI_SMM_SYSTEM_TABLE._fields_ = [
    ('Hdr', struct_EFI_TABLE_HEADER),
    ('SmmFirmwareVendor', POINTER_T(ctypes.c_uint16)),
    ('SmmFirmwareRevision', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('SmmInstallConfigurationTable', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_SMM_SYSTEM_TABLE), POINTER_T(struct_GUID), POINTER_T(None), ctypes.c_uint64))),
    ('EfiSmmCpuIoGuid', struct_GUID),
    ('SmmIo', struct__EFI_SMM_CPU_IO_INTERFACE),
    ('SmmAllocatePool', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, enum_16, ctypes.c_uint64, POINTER_T(POINTER_T(None))))),
    ('SmmFreePool', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None)))),
    ('SmmAllocatePages', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, enum_494, enum_16, ctypes.c_uint64, POINTER_T(ctypes.c_uint64)))),
    ('SmmFreePages', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64))),
    ('SmmStartupThisAp', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(ctypes.CFUNCTYPE(None, POINTER_T(None))), ctypes.c_uint64, POINTER_T(None)))),
    ('CurrentlyExecutingCpu', ctypes.c_uint64),
    ('NumberOfCpus', ctypes.c_uint64),
    ('CpuSaveState', POINTER_T(union_c__UA_EFI_SMM_CPU_SAVE_STATE)),
    ('CpuOptionalFloatingPointState', POINTER_T(union_c__UA_EFI_SMM_FLOATING_POINT_SAVE_STATE)),
    ('NumberOfTableEntries', ctypes.c_uint64),
    ('SmmConfigurationTable', POINTER_T(struct_EFI_CONFIGURATION_TABLE)),
]

class struct__EFI_SMM_BASE_PROTOCOL(ctypes.Structure):
    pass

class struct__EFI_DEVICE_PATH_PROTOCOL(ctypes.Structure):
    pass

struct__EFI_SMM_BASE_PROTOCOL._pack_ = True # source:False
struct__EFI_SMM_BASE_PROTOCOL._functions_ = []
struct__EFI_SMM_BASE_PROTOCOL._fields_ = [
    ('Register', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_SMM_BASE_PROTOCOL), POINTER_T(struct__EFI_DEVICE_PATH_PROTOCOL), POINTER_T(None), ctypes.c_uint64, POINTER_T(POINTER_T(None)), ctypes.c_ubyte))),
    ('UnRegister', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_SMM_BASE_PROTOCOL), POINTER_T(None)))),
    ('Communicate', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_SMM_BASE_PROTOCOL), POINTER_T(None), POINTER_T(None), POINTER_T(ctypes.c_uint64)))),
    ('RegisterCallback', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_SMM_BASE_PROTOCOL), POINTER_T(None), POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), POINTER_T(None), POINTER_T(ctypes.c_uint64))), ctypes.c_ubyte, ctypes.c_ubyte))),
    ('InSmm', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_SMM_BASE_PROTOCOL), POINTER_T(ctypes.c_ubyte)))),
    ('SmmAllocatePool', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_SMM_BASE_PROTOCOL), enum_16, ctypes.c_uint64, POINTER_T(POINTER_T(None))))),
    ('SmmFreePool', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_SMM_BASE_PROTOCOL), POINTER_T(None)))),
    ('GetSmstLocation', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_SMM_BASE_PROTOCOL), POINTER_T(POINTER_T(struct__EFI_SMM_SYSTEM_TABLE))))),
]
struct__EFI_SMM_BASE_PROTOCOL._functions_.append(("Register", ['ctypes.c_uint64', 'POINTER_T(struct__EFI_SMM_BASE_PROTOCOL)', 'POINTER_T(struct__EFI_DEVICE_PATH_PROTOCOL)', 'POINTER_T(None)', 'ctypes.c_uint64', 'POINTER_T(POINTER_T(None))', 'ctypes.c_ubyte']))

EFI_SMM_BASE_PROTOCOL = struct__EFI_SMM_BASE_PROTOCOL
EFI_SMM_CALLBACK_ENTRY_POINT = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), POINTER_T(None), POINTER_T(ctypes.c_uint64)))
EFI_SMM_REGISTER_HANDLER = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_SMM_BASE_PROTOCOL), POINTER_T(struct__EFI_DEVICE_PATH_PROTOCOL), POINTER_T(None), ctypes.c_uint64, POINTER_T(POINTER_T(None)), ctypes.c_ubyte))
EFI_SMM_UNREGISTER_HANDLER = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_SMM_BASE_PROTOCOL), POINTER_T(None)))
EFI_SMM_COMMUNICATE = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_SMM_BASE_PROTOCOL), POINTER_T(None), POINTER_T(None), POINTER_T(ctypes.c_uint64)))
EFI_SMM_CALLBACK_SERVICE = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_SMM_BASE_PROTOCOL), POINTER_T(None), POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(None), POINTER_T(None), POINTER_T(ctypes.c_uint64))), ctypes.c_ubyte, ctypes.c_ubyte))
EFI_SMM_ALLOCATE_POOL = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_SMM_BASE_PROTOCOL), enum_16, ctypes.c_uint64, POINTER_T(POINTER_T(None))))
EFI_SMM_FREE_POOL = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_SMM_BASE_PROTOCOL), POINTER_T(None)))
EFI_SMM_INSIDE_OUT = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_SMM_BASE_PROTOCOL), POINTER_T(ctypes.c_ubyte)))
EFI_SMM_GET_SMST_LOCATION = POINTER_T(ctypes.CFUNCTYPE(ctypes.c_uint64, POINTER_T(struct__EFI_SMM_BASE_PROTOCOL), POINTER_T(POINTER_T(struct__EFI_SMM_SYSTEM_TABLE))))
gEfiSmmBaseProtocolGuid = struct_GUID # Variable struct_GUID
struct__EFI_DEVICE_PATH_PROTOCOL._pack_ = True # source:False
struct__EFI_DEVICE_PATH_PROTOCOL._fields_ = [
    ('Type', ctypes.c_ubyte),
    ('SubType', ctypes.c_ubyte),
    ('Length', ctypes.c_ubyte * 2),
]

__all__ = \
    ['AllocateAddress', 'AllocateAnyPages', 'AllocateMaxAddress',
    'EFI_SMM_ALLOCATE_POOL', 'EFI_SMM_BASE_PROTOCOL',
    'EFI_SMM_CALLBACK_ENTRY_POINT', 'EFI_SMM_CALLBACK_SERVICE',
    'EFI_SMM_COMMUNICATE', 'EFI_SMM_FREE_POOL',
    'EFI_SMM_GET_SMST_LOCATION', 'EFI_SMM_INSIDE_OUT',
    'EFI_SMM_REGISTER_HANDLER', 'EFI_SMM_UNREGISTER_HANDLER',
    'EfiACPIMemoryNVS', 'EfiACPIReclaimMemory', 'EfiBootServicesCode',
    'EfiBootServicesData', 'EfiConventionalMemory', 'EfiLoaderCode',
    'EfiLoaderData', 'EfiMaxMemoryType', 'EfiMemoryMappedIO',
    'EfiMemoryMappedIOPortSpace', 'EfiPalCode', 'EfiPersistentMemory',
    'EfiReservedMemoryType', 'EfiRuntimeServicesCode',
    'EfiRuntimeServicesData', 'EfiUnusableMemory', 'MaxAllocateType',
    'SMM_IO_UINT16', 'SMM_IO_UINT32', 'SMM_IO_UINT64', 'SMM_IO_UINT8',
    'c__EA_EFI_SMM_IO_WIDTH', 'enum_16', 'enum_494',
    'gEfiSmmBaseProtocolGuid', 'struct_EFI_CONFIGURATION_TABLE',
    'struct_EFI_TABLE_HEADER', 'struct_GUID',
    'struct__EFI_DEVICE_PATH_PROTOCOL',
    'struct__EFI_SMM_BASE_PROTOCOL',
    'struct__EFI_SMM_CPU_IO_INTERFACE',
    'struct__EFI_SMM_SYSTEM_TABLE',
    'struct_c__SA_EFI_PMI_OPTIONAL_FLOATING_POINT_CONTEXT',
    'struct_c__SA_EFI_SMI_CPU_SAVE_STATE',
    'struct_c__SA_EFI_SMI_OPTIONAL_FPSAVE_STATE',
    'struct_c__SA_EFI_SMM_IO_ACCESS',
    'union_c__UA_EFI_SMM_CPU_SAVE_STATE',
    'union_c__UA_EFI_SMM_FLOATING_POINT_SAVE_STATE']
