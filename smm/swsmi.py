from .save_state_area import create_smm_save_state

def after_module_execution_callback(ql, number_of_modules_left):
    if number_of_modules_left == 0:
        return trigger_swsmi(ql)
    return False


def trigger_next_smi_handler(ql):
    pointer_size = 8

    smi_params = ql.os.smm.swsmi_handlers.pop(0)
    ql.nprint(f"Executing SMI with params {smi_params}")
    out_pointers = ql.os.heap.alloc(pointer_size * 2)
    
    ql.reg.rcx = smi_params["DispatchHandle"]
    ql.reg.rdx = smi_params["RegisterContext"]
    ql.reg.r8 = out_pointers  # OUT VOID    *CommBuffer
    ql.reg.r9 = out_pointers + pointer_size  # OUT UINTN   *CommBufferSize
    ql.reg.rip = smi_params["DispatchFunction"]
    ql.stack_push(ql.loader.end_of_execution_ptr)
    return True

def trigger_swsmi(ql, user_data=None):
    if len(ql.os.smm.swsmi_handlers) < 1:
        # No SMI handlers
        return False

    # Apply fuzzed registers
    for (reg, value) in ql.os.smm.swsmi_args.items():
        ql.reg.write(reg, int.from_bytes(value, 'little'))
        
    create_smm_save_state(ql)

    # Call the dispatcher
    return trigger_next_smi_handler(ql)
