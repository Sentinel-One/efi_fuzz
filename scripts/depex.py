from queue import LifoQueue
from enum import Enum
from uefi_firmware.utils import sguid

class Stack():
    '''
    A simple stack implementation.
    '''

    def __init__(self):
        self.lifo = LifoQueue()

    def push(self, item):
        self.lifo.put_nowait(item)

    def pop(self):
        return self.lifo.get_nowait()

    def empty(self):
        return self.lifo.empty()

class DepexOpcode(Enum):
    PUSH  = 0x02
    AND   = 0x03
    OR    = 0x04
    NOT   = 0x05
    TRUE  = 0x06
    FALSE = 0x07
    END   = 0x08

def is_protocol_installed(ql, protocol):
    if type(protocol) == bool:
        return protocol

    for handle, guid_dic in ql.loader.handle_dict.items():
        if protocol in guid_dic:
            return True
    return False

def _eval_depex(ql, data, check_for_anything):
    stack = Stack()

    offset = 0
    while offset < len(data):
        opcode = ord(data[offset:offset+1])
        offset = offset + 1
        if opcode == DepexOpcode.PUSH.value or opcode == 0 or opcode == 1:
            guid = data[offset:offset+16]
            offset += 16
            stack.push(sguid(guid))
        elif opcode == DepexOpcode.AND.value:
            a = stack.pop()
            b = stack.pop()
            if check_for_anything:
                return False
            res = is_protocol_installed(ql, a) and is_protocol_installed(ql, b)
            stack.push(res)
        elif opcode == DepexOpcode.OR.value:
            a = stack.pop()
            b = stack.pop()
            if check_for_anything:
                return False
            res = is_protocol_installed(ql, a) or is_protocol_installed(ql, b)
            stack.push(res)
        elif opcode == DepexOpcode.NOT.value:
            a = stack.pop()
            res = not is_protocol_installed(a)
            stack.push(res)
        elif opcode == DepexOpcode.TRUE.value:
            stack.push(True)
        elif opcode == DepexOpcode.FALSE.value:
            stack.push(False)
        elif opcode == DepexOpcode.END.value:
            item = stack.pop()
            assert stack.empty(), "The END opcode was encountered, but the Depex Stack is not empty"

            if type(item) == str:
                if check_for_anything:
                    return False
                return is_protocol_installed(ql, item)
            elif type(item) == bool:
                return item
        else:
            return False
            assert False, "Unrecognized DepexOpcode"



def eval_depex(ql, file, check_for_anything=False):
    data = None
    for section in file.sections:
        if section.type == 0x13 or section.type == 0x1c:# DXE DEPEX
            data = section.data
            break
    if data is None:
        return True
    return _eval_depex(ql, data, check_for_anything)