#!/usr/bin/env python3

try:
    import monkeyhex
except ImportError:
    pass

from qiling import Qiling
from qiling.const import QL_INTERCEPT

import sys
sys.path.append('..')
from taint.tracker import *
import mockito

def test_uninitialized_memory_tracker():
    enable_trace = True
    ql = Qiling(['./bin/UninitializedMemoryTrackerTest.efi'],
                ".",                                        # rootfs
                console=True if enable_trace else False,
                stdout=1 if enable_trace else None,
                stderr=1 if enable_trace else None,
                output='debug')

    # NVRAM environment.
    ql.env = {'foo': b'\xde\xad\xbe\xef'}

    def validate_taint_set_variable(ql, address, params):
        assert params['VariableName'] == 'bar' and params['DataSize'] == 0x14
        begin = params['Data']
        end = params['Data'] + params['DataSize']
        tainted_bytes = get_taint_range(ql, begin, end)
        assert tainted_bytes == [True, True, True, True, True, True, False, False, False, False,
                                 True, True, True, True, True, True, True, False, True, True]
        # Un-taint to avoid crashing the process.
        set_taint_range(ql, begin, end, False)
        return (address, params)

    # Hook SetVariable() to check the taint on the buffer.
    set_variable_spy = mockito.spy(validate_taint_set_variable)
    ql.set_api("SetVariable", set_variable_spy, QL_INTERCEPT.ENTER)

    # okay, ready to roll.
    enable_uninitialized_memory_tracker(ql)
    ql.run()

    # Make sure that SetVariable() was intercepted once.
    mockito.verify(set_variable_spy, times=1).__call__(*mockito.ARGS)