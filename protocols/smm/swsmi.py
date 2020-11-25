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
