import sys
import struct
from qiling import Qiling
from qiling.const import *
from unicorn import *
from unicorn.x86_const import *
from rom_utils import *
from depex import *

def notify_after_module_execution(ql, number_of_modules_left):
    ql.nprint(f'*** done with {ql.os.running_module}, {number_of_modules_left}')
    ql.state = ql.save(reg=True, mem=False, cpu_context=True)
    return False

def check_and_load(ql):
    unloaded_modules = []
    for module in ql.os.unloaded_modules:
        if eval_depex(ql, module):
            module_path = dump_pe(module, ql.os.outdir)
            if module_path is None:
                continue
            try:
                ql.loader.map_and_load(module_path, execute_now=False)
            except Exception as e:
                print(e)
                print(file.guid, file.guid.hex())
        else:
            unloaded_modules.append(module)
    ql.os.unloaded_modules = unloaded_modules

def InstallMultipleProtocolInterfaces_onexit(ql, address, params):
    check_and_load(ql)
def InstallProtocolInterface_onexit(ql, address, params):
    check_and_load(ql)


def run(env, rom_file, volume_guid, outdir):
    build_guid_db()

    bios_region = get_bios_region(rom_file)
    assert bios_region is not None

    fv = get_firmware_volume(bios_region, volume_guid)
    assert fv is not None

    apriori_files, unloaded_modules = get_all_files(fv, APRIORI_DXE_GUID)

    # We are not checking depex for apriori_dxes since EDKII dxecore doesn't and loading PcdDxe late cuases crashes.
    executables = []
    for ap in apriori_files:
        fpath = dump_pe(ap, outdir)
        if fpath is not None: 
            executables.append(fpath)

    ql = Qiling(executables, ".", env=env, output="defualt")
    ql.os.unloaded_modules = unloaded_modules
    ql.os.outdir = outdir
    ql.os.notify_after_module_execution = notify_after_module_execution
    ql.set_api('InstallMultipleProtocolInterfaces', InstallMultipleProtocolInterfaces_onexit, QL_INTERCEPT.EXIT)
    ql.set_api('InstallProtocolInterface', InstallProtocolInterface_onexit, QL_INTERCEPT.EXIT)

    # HW mappeed memory
    ql.mem.map(0xf8000000, 0x10000000)
    # mapping the zero page, some modules read uninitialized data and use the IN instruction and get the worng reply...
    ql.mem.map(0, 0x1000)

    def hook_in(uc, port, size, ql):
        ql.count += 1
        return ql.count
    ql.count = 0
    ql.uc.hook_add(UC_HOOK_INSN, hook_in, ql, 1, 0, UC_X86_INS_IN)

    #TODO: fix bug in qiling ql.os.smm_dispatch is never initialize, but used in smm_sw_dispatch2_protocol.
    ql.os.smm_dispatch = [] #oooops this is a bug in qiling I need to fix
    

    begin = ql.os.entry_point
    while True:
        try:
            ql.run(begin=begin, timeout=1000)
            break
        except Exception as e:
            if len(ql.loader.modules) < 1:
                break
            if not ql.state:
                break
            # Restore the state to the end of the last secessful module.
            ql.restore(ql.state)
            begin = ql.reg.arch_pc



if __name__ == "__main__":
    run({}, 'rom2.bin', '4f1c52d3-d824-4d2a-a2f0-ec40c23c5916', '/tmp')
