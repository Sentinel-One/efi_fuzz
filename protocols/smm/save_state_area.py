from enum import Enum

# See https://github.com/tianocore/edk2/blob/3806e1fd139775610d8f2e7541a916c3a91ad989/MdePkg/Include/Protocol/MmCpu.h
class EFI_MM_SAVE_STATE_REGISTER(Enum):

    #
    # x86/X64 standard registers
    #

    GDTBASE       = 4
    IDTBASE       = 5
    LDTBASE       = 6
    GDTLIMIT      = 7
    IDTLIMIT      = 8
    LDTLIMIT      = 9
    LDTINFO       = 10
    ES            = 20
    CS            = 21
    SS            = 22
    DS            = 23
    FS            = 24
    GS            = 25
    LDTR_SEL      = 26
    TR_SEL        = 27
    DR7           = 28
    DR6           = 29
    R8            = 30
    R9            = 31
    R10           = 32
    R11           = 33
    R12           = 34
    R13           = 35
    R14           = 36
    R15           = 37
    RAX           = 38
    RBX           = 39
    RCX           = 40
    RDX           = 41
    RSP           = 42
    RBP           = 43
    RSI           = 44
    RDI           = 45
    RIP           = 46
    RFLAGS        = 51
    CR0           = 52
    CR3           = 53
    CR4           = 54
    FCW           = 25
    FSW           = 25
    FTW           = 25
    OPCODE        = 25
    FP_EIP        = 26
    FP_CS         = 26
    DATAOFFSET    = 26
    FP_DS         = 26
    MM0           = 26
    MM1           = 26
    MM2           = 26
    MM3           = 26
    MM4           = 26
    MM5           = 26
    MM6           = 27
    MM7           = 27
    XMM0          = 27
    XMM1          = 27
    XMM2          = 27
    XMM3          = 27
    XMM4          = 27
    XMM5          = 27
    XMM6          = 27
    XMM7          = 27
    XMM8          = 28
    XMM9          = 28
    XMM10         = 28
    XMM11         = 28
    XMM12         = 28
    XMM13         = 28
    XMM14         = 28
    XMM15         = 28

    #
    # Pseudo-Registers
    #

    IO            = 51
    LMA           = 51
    PROCESSOR_ID  = 514

save_state_offsets = {
   EFI_MM_SAVE_STATE_REGISTER.ES.value:      0x7FA8,
   EFI_MM_SAVE_STATE_REGISTER.CS.value:      0x7FAC,
   EFI_MM_SAVE_STATE_REGISTER.SS.value:      0x7FB0,
   EFI_MM_SAVE_STATE_REGISTER.DS.value:      0x7FB4,
   EFI_MM_SAVE_STATE_REGISTER.FS.value:      0x7FB8,
   EFI_MM_SAVE_STATE_REGISTER.GS.value:      0x7FBC,
   EFI_MM_SAVE_STATE_REGISTER.DR7.value:     0x7FC8,
   EFI_MM_SAVE_STATE_REGISTER.DR6.value:     0x7FD0,
   EFI_MM_SAVE_STATE_REGISTER.R8.value:      0x7F54,
   EFI_MM_SAVE_STATE_REGISTER.R9.value:      0x7F4C,
   EFI_MM_SAVE_STATE_REGISTER.R10.value:     0x7F44,
   EFI_MM_SAVE_STATE_REGISTER.R11.value:     0x7F3C,
   EFI_MM_SAVE_STATE_REGISTER.R12.value:     0x7F34,
   EFI_MM_SAVE_STATE_REGISTER.R13.value:     0x7F2C,
   EFI_MM_SAVE_STATE_REGISTER.R14.value:     0x7F24,
   EFI_MM_SAVE_STATE_REGISTER.R15.value:     0x7F1C,
   EFI_MM_SAVE_STATE_REGISTER.RAX.value:     0x7F5C,
   EFI_MM_SAVE_STATE_REGISTER.RBX.value:     0x7F74,
   EFI_MM_SAVE_STATE_REGISTER.RCX.value:     0x7F64,
   EFI_MM_SAVE_STATE_REGISTER.RDX.value:     0x7F6C,
   EFI_MM_SAVE_STATE_REGISTER.RSP.value:     0x7F7C,
   EFI_MM_SAVE_STATE_REGISTER.RBP.value:     0x7F84,
   EFI_MM_SAVE_STATE_REGISTER.RSI.value:     0x7F8C,
   EFI_MM_SAVE_STATE_REGISTER.RDI.value:     0x7F94,
   EFI_MM_SAVE_STATE_REGISTER.RIP.value:     0x7FD8,
   EFI_MM_SAVE_STATE_REGISTER.RFLAGS.value:  0x7FE8,
   EFI_MM_SAVE_STATE_REGISTER.CR0.value:     0x7FF8,
   EFI_MM_SAVE_STATE_REGISTER.CR3.value:     0x7FF0,
   EFI_MM_SAVE_STATE_REGISTER.CR4.value:     0x7E40,
}

def read_smm_save_state(ql, reg_id, width):
    save_state_base = ql.os.smm.smbase + 0x8000
    address = save_state_base + save_state_offsets[reg_id]
    return bytes(ql.mem.read(address, width))

def create_smm_save_state(ql):
    save_state_base = ql.os.smm.smbase + 0x8000
    offset = 0x7C00

    def _write_field(value, size):
        nonlocal offset
        ql.mem.write(save_state_base + offset, value.to_bytes(size, 'little'))
        offset += size

    #
    # See Intel Software Developers Manual, Volume 3C:
    # https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-3c-part-3-manual.pdf
    #

    _write_field(0, 464)         # Reserved
    _write_field(0, 4)           # GDT Base (Upper 32 bits)
    _write_field(0, 4)           # LDT Base (Upper 32 bits)
    _write_field(0, 4)           # IDT Base (Upper 32 bits)
    _write_field(0, 12)          # Reserved
    _write_field(0, 8)           # IO_RIP
    _write_field(0, 80)          # Reserved
    _write_field(ql.reg.cr4, 4)
    _write_field(0, 72)          # Reserved
    _write_field(0, 4)           # GDT Base (lower 32 bits)
    _write_field(0, 4)           # Reserved
    _write_field(0, 4)           # IDT Base (lower 32 bits)
    _write_field(0, 4)           # Reserved
    _write_field(0, 4)           # LDT Base (lower 32 bits)
    _write_field(0, 56)          # Reserved
    _write_field(0, 8)           # Value of EPTP VM-execution control field
    _write_field(0, 4)           # Setting of “enable EPT” VM-execution control
    _write_field(0, 20)          # Reserved
    _write_field(0, 4)           # SMBASE Field (Doubleword)
    _write_field(0, 4)           # SMM Revision Identifier Field (Doubleword)
    _write_field(0, 2)           # I/O Instruction Restart Field (Word)
    _write_field(0, 2)           # Auto HALT Restart Field (Word) 
    _write_field(0, 24)          # Reserved
    _write_field(ql.reg.r15, 8)
    _write_field(ql.reg.r14, 8)
    _write_field(ql.reg.r13, 8)
    _write_field(ql.reg.r12, 8)
    _write_field(ql.reg.r11, 8)
    _write_field(ql.reg.r10, 8)
    _write_field(ql.reg.r9, 8)
    _write_field(ql.reg.r8, 8)
    _write_field(ql.reg.rax, 8)
    _write_field(ql.reg.rcx, 8)
    _write_field(ql.reg.rdx, 8)
    _write_field(ql.reg.rbx, 8)
    _write_field(ql.reg.rsp, 8)
    _write_field(ql.reg.rbp, 8)
    _write_field(ql.reg.rsi, 8)
    _write_field(ql.reg.rdi, 8)
    _write_field(0, 8)           # IO_MEM_ADDR
    _write_field(0, 4)           # IO_MISC
    _write_field(ql.reg.es, 4)
    _write_field(ql.reg.cs, 4)
    _write_field(ql.reg.ss, 4)
    _write_field(ql.reg.ds, 4)
    _write_field(ql.reg.fs, 4)
    _write_field(ql.reg.gs, 4)
    _write_field(0, 4)           # LDTR SEL
    _write_field(0, 4)           # TR SEL
    _write_field(0, 8)           # DR7
    _write_field(0, 8)           # DR6
    _write_field(ql.reg.rip, 8)
    _write_field(0, 8)           # IA32_EFER
    _write_field(ql.reg.ef, 8)
    _write_field(ql.reg.cr3, 8)
    _write_field(ql.reg.cr0, 8)

    assert(offset == 0x8000)
