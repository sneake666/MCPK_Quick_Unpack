import os
import struct
import logging
import sys
from contextlib import contextmanager

import uncompyle6

from typing import Any
from io import TextIOBase

from mcs_marshal import McsMarshal
from opcode_map import get_mcs2std_op_map

class FakeFileObject(TextIOBase):
    def __init__(self):
        self.data = bytearray()

    def write(self, b:bytes) -> None:
        self.data.extend(b)

    def getvalue(self):
        return bytes(self.data)

@contextmanager
def suppress_stderr():
    """临时禁止 stderr 输出"""
    with open(os.devnull, 'w') as devnull:
        old_stderr = sys.stderr
        sys.stderr = devnull
        try:
            yield
        finally:
            sys.stderr = old_stderr

def transform_code(mcs_obj: dict) -> bytes:
    magic = mcs_obj['magic']
    version = mcs_obj.get('version', 1)  # default to version 1 if not present
    op_map = get_mcs2std_op_map(version)
    mcs_code = bytearray(mcs_obj['code'])
    new_code = bytearray()
    i = 0
    
    obj_name = mcs_obj.get('name')
    if isinstance(obj_name, bytes):
        obj_name = obj_name.decode('utf-8', 'ignore')
    while i < len(mcs_code):
        mcs_op = mcs_code[i]
        if mcs_op >= 93:
            if i + 2 < len(mcs_code):
                arg = mcs_code[i+1] | (mcs_code[i+2] << 8)
                step = 3
            else:
                arg = 0
                step = len(mcs_code) - i
        else:
            arg = None
            step = 1

        std_op = op_map.get(mcs_op, mcs_op)
        new_code.append(std_op)
        if std_op >= 90:
            a = arg if arg is not None else 0
            new_code.extend([a & 0xFF, (a >> 8) & 0xFF])

        # DEBUG: Print mapping
        a_val = arg if arg is not None else 0

        i += step
    return bytes(new_code)

def w_long(val: int, f: TextIOBase) -> None:
    f.write(b'l')
    if val == 0:
        f.write(struct.pack('<i', 0))
        return
    sign = 1 if val >= 0 else -1
    v = abs(val)
    digits = []
    while v:
        digits.append(v & 0x7FFF)
        v >>= 15
    f.write(struct.pack('<i', sign * len(digits)))
    for d in digits:
        f.write(struct.pack('<H', d))

def w_object(obj: Any, f: TextIOBase) -> None:
    if obj is None:
        f.write(b'N')
    elif obj is True:
        f.write(b'T')
    elif obj is False:
        f.write(b'F')
    elif obj is Ellipsis:
        f.write(b'.')
    elif isinstance(obj, int):
        if -2147483648 <= obj <= 2147483647:
            f.write(b'i')
            f.write(struct.pack('<i', obj))
        else:
            w_long(obj, f)
    elif isinstance(obj, float):
        s = repr(obj).encode()
        f.write(b'f')
        f.write(struct.pack('B', len(s)))
        f.write(s)
    elif isinstance(obj, bytes):
        f.write(b's')
        f.write(struct.pack('<i', len(obj)))
        f.write(obj)
    elif isinstance(obj, str):
        b = obj.encode('utf-8')
        f.write(b's')
        f.write(struct.pack('<i', len(b)))
        f.write(b)
    elif isinstance(obj, (tuple, list, set, frozenset)):
        if isinstance(obj, tuple):
            f.write(b'(')
        elif isinstance(obj, list):
            f.write(b'[')
        elif isinstance(obj, frozenset):
            f.write(b'>')
        else:
            f.write(b'<')
        f.write(struct.pack('<i', len(obj)))
        for item in obj:
            w_object(item, f)
    elif isinstance(obj, dict) and 'magic' in obj:
        f.write(b'c')
        f.write(struct.pack('<i', obj['argcount']))
        f.write(struct.pack('<i', obj['nlocals']))
        f.write(struct.pack('<i', obj['stacksize']))
        f.write(struct.pack('<i', obj['flags']))
        w_object(transform_code(obj), f)
        w_object(tuple(obj['consts']), f)
        w_object(tuple(obj['names']), f)
        w_object(tuple(obj['varnames']), f)
        w_object(tuple(obj['freevars']), f)
        w_object(tuple(obj['cellvars']), f)
        w_object(obj['filename'], f)
        w_object(obj['name'], f)
        f.write(struct.pack('<i', obj['firstlineno']))
        w_object(obj['lnotab'], f)
    elif isinstance(obj, dict):
        f.write(b'{')
        for k, v in obj.items():
            w_object(k, f)
            w_object(v, f)
        f.write(b'0')
    else:
        f.write(b'N')

def restore_data(data: bytes) -> bytes:
    from crypto import decrypt_data
    
    decrypted_data = decrypt_data(data)
    # For debugging: save decrypted data to file
    # with open("decrypted_data.bin", "wb") as f:
    #     f.write(decrypted_data)
    parser = McsMarshal(decrypted_data)
    root = parser.r_object()
    f = FakeFileObject()
    f.write(b"\x03\xf3\x0d\x0a\x00\x00\x00\x00")
    w_object(root, f)
    return f.getvalue()

def anti_confuse(mode,in_file, out_file=None) -> bool:

    in_name = in_file
    temp_name = os.path.splitext(out_file)[0] + '.pyc' if out_file is not None else os.path.splitext(in_file)[0] + '.pyc'
    out_name = os.path.splitext(out_file)[0] + '.py' if out_file is not None else os.path.splitext(in_file)[0] + '.py'

    with open(in_name, 'rb') as f:
        data = f.read()

    restored_data = restore_data(data)
    with open(temp_name, 'wb') as temp_f:
        temp_f.write(restored_data)

    with open(out_name, 'w',encoding="utf-8") as out_f:
        try:
            logging.getLogger("uncompyle6").disabled = True
            with suppress_stderr():
                uncompyle6.decompile_file(temp_name,out_f)
        except:
            out_f.close()
            os.remove(temp_name)
            os.remove(out_name)
            return False

    if mode == '1':
        os.remove(in_name)
    os.remove(temp_name)
    return True
