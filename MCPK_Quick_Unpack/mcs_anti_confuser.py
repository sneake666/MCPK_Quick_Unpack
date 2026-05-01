import os
import struct
import subprocess

from typing import Any
from io import TextIOBase
from tools.mcs_marshal import McsMarshal
from tools.opcode_map import get_mcs2std_op_map

class FakeFileObject(TextIOBase):
    def __init__(self):
        self.data = bytearray()

    def write(self, b:bytes) -> None:
        self.data.extend(b)

    def getvalue(self):
        return bytes(self.data)

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
    from tools.crypto import decrypt_data
    
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

def handle_excess_file(is_error:bool,mode:str,in_name,temp_name,out_name):
    if is_error and os.path.exists(out_name):
        os.remove(out_name)
    if mode == '1':
        if os.path.exists(in_name):
            os.remove(in_name)
        if not is_error and os.path.exists(temp_name):
            os.remove(temp_name)
    if mode == '2':
        if os.path.exists(in_name):
            os.remove(in_name)
    if mode == '4':
        if os.path.exists(temp_name):
            os.remove(temp_name)

def anti_confuse(mode,in_file,out_dir = None) -> bool:
    in_name = in_file
    if out_dir is None:
        out_dir = os.path.dirname(in_file)
    temp_name = os.path.join(out_dir,os.path.splitext(os.path.basename(in_file))[0] + '.pyc')
    out_name = os.path.join(out_dir,os.path.splitext(os.path.basename(in_file))[0] + '.py')

    with open(in_name, 'rb') as f:
        data = f.read()

    restored_data = None
    try:
        restored_data = restore_data(data)
    except Exception as e:
        print("[!] 发现错误：" + str(e))
        if restored_data is not None:
            print("[!] 错误可能不影响运行，反混淆继续")
        else:
            print("[!] 错误导致反混淆失败")
            return False
    with open(temp_name, 'wb') as temp_f:
        temp_f.write(restored_data)

    #尝试反混淆MCS
    result = subprocess.run([r"./tools/pycdc/pycdc.exe",temp_name,],capture_output=True,text=True)
    if result.returncode != 0:

        if result.stdout is not None:
            print("\033[33m[!] 发现警告：" + result.stderr + "\033[0m")
        else:
            print("\033[31m[!] 发现错误：" + result.stderr + "\033[0m")
            handle_excess_file(True,mode,in_name,temp_name,out_name)
            return False

    with open(out_name, 'w') as out_f:
        out_f.write(result.stdout)

    handle_excess_file(False,mode,in_name,temp_name,out_name)
    return True

if __name__ == '__main__':
    print("[*] 本脚本用于对解包完成后得到的mcs反混淆到py")
    in_name = input("[*] mcs文件路径(必填)： ").strip('\"\'')
    if in_name == '':
        print("[!] 输入文件为空，程序退出")
        os.system("pause")
        exit(2)
    if not os.path.isfile(in_name):
        print(f"[!] {in_name} 不存在或者是一个文件夹，它应当是一个文件，程序退出")
        os.system("pause")
        exit(2)
    if os.path.splitext(in_name)[1] != ".mcs":
        if os.path.splitext(in_name)[1] == ".mcp":
            print("[!] 解包mcpk请使用mcpk_unpacker，而不是本脚本")
            exit(2)
        else:
            print("[!] 输入文件不是mcs")

    out_dir = input("[*] 输出路径(不填默认在相同目录创建同名文件)： ").strip('\"\'')
    if out_dir == "":
        out_dir = os.path.dirname(in_name)
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)

    print("[*] 选项(默认为4)：解包至py并删除多余文件(1)\n解包至py并保留pyc(2)\n解包至py并保留pyc和mcs(3)\n解包至py并保留mcs(4)")
    unpack_mode = input('[*] 选项(1/2/3)：')
    if unpack_mode not in ['1','2','3','4']:
        if unpack_mode == '':
            unpack_mode = '4'
        else:
            print("[!] 非法输入，程序退出")
            os.system("pause")
            exit(2)

    if anti_confuse(unpack_mode,in_name,out_dir):
        print("[*] 解包成功")
        os.system("pause")
        exit(0)
    else:
        print("[*] 解包失败，请自行用uncompyle6等工具手动重试")
        os.system("pause")
        exit(1)

