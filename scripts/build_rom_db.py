import sys
import time
import struct
import pickle
from qiling import Qiling
from qiling.const import *
from unicorn import *
from unicorn.x86_const import *
from rom_utils import *
from depex import *

def notify_after_module_execution(ql, number_of_modules_left):
    ql.nprint(f'*** done with {ql.os.running_module}, {number_of_modules_left}')
    ql.state = ql.save(reg=True, mem=False, cpu_context=True)
    ql.module_start_time = time.time()
    return False

def check_and_load(ql):
    modules_not_yet_loaded = []
    for module in ql.os.modules_not_yet_loaded:
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
            modules_not_yet_loaded.append(module)
    ql.os.modules_not_yet_loaded = modules_not_yet_loaded

def InstallMultipleProtocolInterfaces_onexit(ql, address, params):
    check_and_load(ql)
def InstallProtocolInterface_onexit(ql, address, params):
    check_and_load(ql)

def restore_state(ql):
    if ql.state:
        # Restore the state to the end of the last secessful module.
        ql.restore(ql.state)
    else:
        # first module crash / timeout.
        ql.reg.arch_pc = ql.loader.end_of_execution_ptr
    
    return ql.reg.arch_pc

def run(env, rom_file, outdir, single_module_timeout):
    build_guid_db()

    data = open(rom_file, "rb").read()
    parser = uefi_firmware.AutoParser(data, True)
    if parser.type() == 'unknown':
        return None
    fv = parser.parse()

    apriori_files, modules_not_yet_loaded = get_all_files(fv, APRIORI_DXE_GUID)

    # We are not checking depex for apriori_dxes since EDKII dxecore doesn't and loading PcdDxe late cuases crashes.
    executables = []
    for ap in apriori_files:
        fpath = dump_pe(ap, outdir)
        if fpath is not None: 
            executables.append(fpath)

    ql = Qiling(executables, ".", env=env, output="default")
    ql.state = None
    ql.os.modules_not_yet_loaded = modules_not_yet_loaded
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

    ql.module_start_time = time.time()
    def hook_opcode_timeout(ql, address, size):
        if time.time() - ql.module_start_time > single_module_timeout:
            ql.nprint(f'*** Module timeout {ql.os.running_module} ***')
            restore_state(ql)
            
    # Hook every opcode.
    ql.hook_code(hook_opcode_timeout)


    #TODO: fix bug in qiling ql.os.smm_dispatch is never initialize, but used in smm_sw_dispatch2_protocol.
    ql.os.smm_dispatch = [] #oooops this is a bug in qiling I need to fix
    

    begin = ql.os.entry_point
    while True:
        try:
            ql.run(begin=begin)
            break
        except Exception as e:
            if len(ql.loader.modules) < 1:
                break
            begin = restore_state(ql)
    print(f'We didnt load {len(ql.os.modules_not_yet_loaded)} modules')


if __name__ == "__main__":
    env = {}
    with open('rom2_nvar.pickel', 'rb') as f:
        env = pickle.load(f)
    run(env, 'Thinkpad_9E21FD93-9C72-4C15-8C4B-E77F1DB2D792.vol', '/tmp', 20)
    # run(env, 'AMD_5C60F367-A505-419A-859E-2A4FF6CA6FE5.vol', '/tmp', 20)
    # run(env, 'Volume_FFSv2_4F1C52D3-D824-4D2A-A2F0-EC40C23C5916.vol', '/tmp', 20)
    # run(env, 'Dell_OptiPlex_9020M_System_BIOS_DXE.vol', '/tmp', 20)
