# -*- coding: UTF-8 -*-
import datetime
import struct
import zlib
import json
import os
from typing import Union, Tuple

from mcs_anti_confuser import anti_confuse

MAGIC1, MAGIC2 = 0x267B0B11, 0xBDEB77DE
MAGIC3, MAGIC4, MAGIC5 = 0x02040801, 0x7D7EBBDE, 0x00804021
H1_INIT, H2_INIT, ROT_INIT = 933775118, 2002301995, 0xF4FA8928

def _update_h1_h2(h1: int, h2: int, rot: int, chunk: int) -> Tuple[int, int]:
    x1, x2 = (h1 ^ chunk) & 0xFFFFFFFF, (h2 ^ chunk) & 0xFFFFFFFF
    
    # Update h1
    k1 = (((rot ^ MAGIC1) + x2) & 0xFFFFFFFF) & MAGIC2 | MAGIC3
    p1 = x1 * k1
    s1 = ((p1 >> 32) & 0xFFFFFFFF) + (1 if (p1 >> 32) & 0xFFFFFFFF != 0 else 0) + (p1 & 0xFFFFFFFF)
    nh1 = (s1 + (s1 >> 32)) & 0xFFFFFFFF
    
    # Update h2
    k2 = (((rot ^ MAGIC1) + x1) & 0xFFFFFFFF) & MAGIC4 | MAGIC5
    p2 = x2 * k2
    s2 = (p2 & 0xFFFFFFFF) + 2 * ((p2 >> 32) & 0xFFFFFFFF)
    nh2 = (s2 + 2 * (s2 >> 32)) & 0xFFFFFFFF
    
    return nh1, nh2

def _finalize_h1_h2(h1: int, h2: int, rot: int) -> int:
    f2, f1 = (h2 ^ 0x9BE74448) & 0xFFFFFFFF, (h1 ^ 0x9BE74448) & 0xFFFFFFFF
    
    rot_f1 = ((rot << 1) & 0xFFFFFFFF) | (rot >> 31)
    k1 = (rot_f1 ^ MAGIC1) & 0xFFFFFFFF
    
    t1 = ((k1 + f2) & 0xFFFFFFFF) & MAGIC2 | MAGIC3
    p1 = f1 * t1
    s1 = ((p1 >> 32) & 0xFFFFFFFF) + (1 if (p1 >> 32) & 0xFFFFFFFF != 0 else 0) + (p1 & 0xFFFFFFFF)
    y1 = ((s1 & 0xFFFFFFFF) + (s1 >> 32)) ^ 0x66F42C48
    
    t2 = ((k1 + f1) & 0xFFFFFFFF) & MAGIC4 | MAGIC5
    p2 = f2 * t2
    s2 = (p2 & 0xFFFFFFFF) + 2 * ((p2 >> 32) & 0xFFFFFFFF)
    y2 = ((s2 + 2 * (s2 >> 32)) & 0xFFFFFFFF) ^ 0x66F42C48
    
    rot_f2 = ((rot << 2) & 0xFFFFFFFF) | (rot >> 30)
    k2 = (rot_f2 ^ MAGIC1) & 0xFFFFFFFF
    
    t3 = ((k2 + y2) & 0xFFFFFFFF) & MAGIC2 | MAGIC3
    p3 = y1 * t3
    s3 = ((p3 >> 32) & 0xFFFFFFFF) + (1 if (p3 >> 32) & 0xFFFFFFFF != 0 else 0) + (p3 & 0xFFFFFFFF)
    part1 = ((s3 & 0xFFFFFFFF) + (s3 >> 32)) & 0xFFFFFFFF
    
    t4 = ((k2 + y1) & 0xFFFFFFFF) & MAGIC4 | MAGIC5
    p4 = y2 * t4
    p4_64 = p4 & 0xFFFFFFFFFFFFFFFF
    s4 = (p4_64 & 0xFFFFFFFF) + 2 * ((p4_64 >> 32) & 0xFFFFFFFF) + (p4_64 >> 63)
    part2 = ((s4 & 0xFFFFFFFF) + 2 * (s4 >> 32)) & 0xFFFFFFFF
    
    return (part1 ^ part2) & 0xFFFFFFFF

def _hash_directory(data: Union[str, bytes]) -> int:
    if isinstance(data, str): data = data.encode('ascii')
    
    last_slash = data.rfind(b'/')
    if last_slash != -1:
        data = data[:last_slash]
    else:
        return 0
    
    if not data:
        return 0

    h1, h2, rot = H1_INIT, H2_INIT, ROT_INIT
    length = len(data)
    i = 0
    while i + 4 <= length:
        rot = ((rot << 1) & 0xFFFFFFFF) | (rot >> 31)
        chunk = struct.unpack('<I', data[i:i+4])[0]
        h1, h2 = _update_h1_h2(h1, h2, rot, chunk)
        i += 4
    if i < length:
        rot = ((rot << 1) & 0xFFFFFFFF) | (rot >> 31)
        chunk = 0
        for j in range(length - i):
            chunk |= data[i + j] << (j * 8)
        h1, h2 = _update_h1_h2(h1, h2, rot, chunk)
    
    return _finalize_h1_h2(h1, h2, rot)

def _hash_file(data: Union[str, bytes]) -> int:
    if isinstance(data, str): data = data.encode('ascii')
    h1, h2, rot = H1_INIT, H2_INIT, ROT_INIT
    length = len(data)
    idx = 0
    if idx >= length or data[idx] == 0:
        return _finalize_h1_h2(h1, h2, rot)
    
    while idx < length:
        rot = ((rot << 1) & 0xFFFFFFFF) | (rot >> 31)
        chunk = 0
        for j in range(4):
            if idx < length and data[idx] != 0:
                chunk |= data[idx] << (j * 8)
                idx += 1
            else:
                h1, h2 = _update_h1_h2(h1, h2, rot, chunk)
                return _finalize_h1_h2(h1, h2, rot)
        
        h1, h2 = _update_h1_h2(h1, h2, rot, chunk)
    return _finalize_h1_h2(h1, h2, rot)

def unpack_mcpk(unpack_mode: str, file_path: str, output_dir: str) -> dict:
    success_count = 0
    error_count = 0
    os.makedirs(output_dir, exist_ok=True)
    with open(file_path, 'rb') as f:
        header = f.read(57)
        if header[:4] != b'MCPK':
            print("[!] 输入文件不是MCPK")
            return {"is_success":False}

        dir_table_offset = struct.unpack('<I', header[12:16])[0]
        index_base_offset = struct.unpack('<I', header[16:20])[0]
        
        f.seek(dir_table_offset)
        dir_count = (index_base_offset - dir_table_offset) // 12
        dir_entries = []
        max_index_rel_offset = 0
        last_dir_files = 0
        for _ in range(dir_count):
            entry = struct.unpack('<III', f.read(12))
            dir_entries.append(entry)
            if entry[1] >= max_index_rel_offset:
                max_index_rel_offset = entry[1]
                last_dir_files = entry[2]
        
        data_base_offset = index_base_offset + max_index_rel_offset + last_dir_files * 16
        print(f"[+] DirTable: {dir_table_offset}, IndexBase: {index_base_offset}, DataBase: {data_base_offset}")
        
        dir_map = {
            de[0]: {
                "offset": de[1],
                "count": de[2],
                "files": {}
            } for de in dir_entries}
        del dir_entries
        for d_hash, info in dir_map.items():
            f.seek(index_base_offset + info["offset"])
            for _ in range(info["count"]):
                fe = struct.unpack('<IIII', f.read(16))
                info["files"][fe[0]] = {
                    "offset": fe[1],
                    "c_size": fe[2],
                    "u_size": fe[3]
                }
        # with open("mcpk_debug_dirmap.json", 'w') as debug_f:
        #     json.dump(dir_map, debug_f, indent=4)

        contents_json_hash = _hash_file("contents.json")
        redirect_mcs_hash = _hash_file("redirect.mcs")

        contents_data = None
        if dir_map[0]["files"].get(contents_json_hash):
            f.seek(data_base_offset + dir_map[0]["files"][contents_json_hash]["offset"])
            c_size = dir_map[0]["files"][contents_json_hash]["c_size"]
            c_data = f.read(c_size)
            head_magic = c_data[:2]
            try:
                if head_magic == b'\x78\x9C' or head_magic == b'\x78\xDA':
                    contents_data = zlib.decompress(c_data)
                else:
                    contents_data = c_data
            except:
                contents_data = c_data
            
            with open(os.path.join(output_dir, "contents.json"), 'wb') as out_f:
                out_f.write(contents_data)
            print(f"\033[32m[+] 提取成功: contents.json (Directoty Hash: 00000000, File Hash: {contents_json_hash:08X})\033[0m")
            
            try:
                file_list_json = json.loads(contents_data.decode('utf-8'))
                if isinstance(file_list_json, dict):
                    files_to_extract = file_list_json.get("content", file_list_json)
                else:
                    files_to_extract = file_list_json
                
                if not isinstance(files_to_extract, list):
                    print("[!] contents.json 格式错误")
                    return {"is_success":True}
            except Exception as e:
                print(f"[!] 无法解析 contents.json: {e}")
                return {"is_success":False}
        if dir_map[0]["files"].get(redirect_mcs_hash):
            from tools.mcs import decrypt_data
            from mcs_anti_confuser import McsMarshal

            f.seek(data_base_offset + dir_map[0]["files"][redirect_mcs_hash]["offset"])
            c_size = dir_map[0]["files"][redirect_mcs_hash]["c_size"]
            c_data = f.read(c_size)
            
            with open(os.path.join(output_dir, "redirect.mcs"), 'wb') as out_f:
                try:
                    d_data = decrypt_data(c_data)
                    out_f.write(d_data)
                    success_count += 1
                    print(f"\033[32m[+] 提取成功： redirect.py (d_hash: 00000000, f_hash: {redirect_mcs_hash:08X})\033[0m")
                except Exception as e:
                    out_f.write(c_data)
                    error_count += 1
                    print(f"\033[31m[+] redirect.py 提取失败，已保存原始数据 (d_hash: 00000000, f_hash: {redirect_mcs_hash:08X}):{e}\033[0m")
        
        if contents_data is not None:
            del contents_data
            for file_item in files_to_extract:
                file_path_str = file_item.get("path", "")
                norm_path = file_path_str.replace('\\', '/')
                
                d_hash = _hash_directory(norm_path)
                if '/' in norm_path:
                    f_name = norm_path.rsplit('/', 1)[1]
                else:
                    f_name = norm_path
                f_hash = _hash_file(f_name)
                
                if d_hash not in dir_map:
                    print(f"\033[33m[!] 没有找到目录哈希值： {norm_path}, 已跳过\033[0m")
                    continue
                file_info = dir_map[d_hash]["files"].get(f_hash)
                if not file_info:
                    print(f"\033[33m[!] 没有找到文件哈希值： {norm_path}, 已跳过\033[0m")
                    continue
                
                f.seek(data_base_offset + file_info["offset"])
                c_size = file_info["c_size"]
                u_size = file_info["u_size"]
                c_data = f.read(c_size)
                head_magic = c_data[:2]
                is_error = False
                try:
                    if head_magic == b'\x78\x9C' or head_magic == b'\x78\xDA':
                        u_data = zlib.decompress(c_data)
                    else:
                        u_data = c_data
                    out_path = os.path.join(output_dir, norm_path)
                    os.makedirs(os.path.dirname(out_path), exist_ok=True)
                    with open(out_path, 'wb') as out_f:
                        out_f.write(u_data)
                    print(f"\033[32m[+] 提取成功： {norm_path} (目录哈希={d_hash:08X}, 文件哈希={f_hash:08X})\033[0m")
                except Exception as e:
                    error_count += 1
                    is_error = True
                    print(f"\033[31m[!] 无法提取 {norm_path} ，保存已有数据...(目录哈希={d_hash:08X}, 文件哈希={f_hash:08X}): {e}\033[0m")
                    try:
                        with open(out_path, 'wb') as out_f:
                            out_f.write(u_data)
                    except Exception as e:
                        print(f"[*] 已有数据保存失败:{e}")

                if not is_error:
                    if anti_confuse(unpack_mode, out_path):
                        success_count += 1
                        print(f"\033[32m[+] {norm_path} 已反混淆为" + os.path.splitext(norm_path)[0] + ".py\033[0m")
                    else:
                        error_count += 1
                        print(f"\033[31m[+] {norm_path} 反混淆为py失败，跳过反混淆\033[0m")
        else:
            for d_hash in dir_map:
                out_dir = os.path.join(output_dir, f"{d_hash:08X}")
                f.seek(index_base_offset + dir_map[d_hash]["offset"])
                for _ in range(dir_map[d_hash]["count"]):
                    fe = struct.unpack('<IIII', f.read(16))
                    f_hash, f_offset, c_size, u_size = fe
                    name = f"{f_hash:08X}"
                    pos = f.tell()
                    f.seek(data_base_offset + f_offset)
                    c_data = f.read(c_size)
                    head_magic = c_data[:2]
                    is_error = False
                    try:
                        if head_magic == b'\x78\x9C' or head_magic == b'\x78\xDA':
                            u_data = zlib.decompress(c_data)
                            with open(os.path.join(out_dir, name), 'wb') as out_f:
                                out_f.write(u_data)
                        else:
                            # decrypt for get filename
                            d_data = decrypt_data(c_data)
                            parser = McsMarshal(d_data)
                            root = parser.r_object()
                            file_name = root.get('filename', b'').decode('utf-8')
                            if file_name == '':
                                os.makedirs(out_dir, exist_ok=True)
                                with open(os.path.join(out_dir, name), 'wb') as out_f:
                                    out_f.write(c_data)
                            else:
                                file_name = file_name.replace('.py', '.mcs')
                                name = file_name
                                target_path = os.path.join(output_dir, file_name)
                                os.makedirs(os.path.dirname(target_path), exist_ok=True)
                                # write origin file data
                                with open(target_path, 'wb') as out_f:
                                    out_f.write(c_data)
                        print(f"\033[32m[+] 提取成功： {name} (d_hash={d_hash:08X}, f_hash={f_hash:08X})\033[0m")
                    except Exception as e:
                        error_count += 1
                        is_error = True
                        print(f"\033[31m[!] 无法提取 {name}, 保存已有数据...(目录哈希={d_hash:08X}, 文件哈希={f_hash:08X}): {e}\033[0m")
                        os.makedirs(out_dir, exist_ok=True)
                        try:
                            with open(os.path.join(out_dir, name), 'wb') as out_f:
                                out_f.write(c_data)
                        except Exception as e:
                            print(f"[!] 已有数据保存失败:{e}")

                    if not is_error:
                        if anti_confuse(unpack_mode, target_path):
                            success_count += 1
                            print(f"\033[32m[+] {name} 已反混淆为 " + os.path.splitext(name)[0] + ".py\033[0m")
                        else:
                            error_count += 1
                            print(f"\033[31m[+] {name} 反混淆为py失败，跳过反混淆\033[0m")

                    f.seek(pos)

    result = {"is_success":True,
              "success_count":success_count,
              "error_count":error_count}
    return result

if __name__ == "__main__":
    print("[*] 一键解包MCPK")
    print("[*] 由vanilla_mcp_util提供支持(github:https://github.com/Conla-AC/vanilla_mcp_util)")
    print("[*] 建议您不要大规模传播本脚本，否则可能导致网易更改加密使本脚本失效")
    mcpk_path = input("[*] MCPK输入目录(必填): ").strip('\"\'')
    if mcpk_path is None or mcpk_path.strip() == "":
        print("[!] 输入目录为空，程序退出")
        exit(1)
    elif not os.path.isfile(mcpk_path):
        print(f"[!] {mcpk_path} 不存在或者是一个文件夹，它应当是一个文件，程序退出")
        exit(1)
    output_directory = input("[*] 输出目录（不填默认在输入目录创建新文件夹）: ").strip('\"\'')
    print("[*] 选项(默认为1)：\n解包至py并删除多余文件(1)\n解包至py并保留pyc(2)\n解包至py并保留pyc和mcs(3)\n解包至py并保留mcs(4)")
    unpack_mode = input('[*] 选项(1/2/3)：')
    if unpack_mode not in ['1','2','3','4']:
        if unpack_mode == '':
            unpack_mode = '1'
        else:
            print("[!] 非法输入，程序退出")
            os.system("pause")
            exit(2)
    if output_directory is None or output_directory.strip() == "":
        output_directory = (os.path.splitext(mcpk_path))[0] + '_unpacked_' + datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    result = unpack_mcpk(unpack_mode,mcpk_path, output_directory)
    if result["is_success"]:
        print(f"[*] {result['success_count']}个文件解包成功，{result['error_count']}个文件解包失败")
        print(f"[*] 解包完成，输出目录："+ output_directory)
        print("[*] 再次提醒：建议您不要大规模传播本脚本，否则可能导致网易更改加密使本脚本失效")
        print("[*] 按任意键退出")
        os.system("pause")
        exit(0)
    else:
        print("[*] 解包失败")
        print("[*] 再次提醒：建议您不要大规模传播本脚本，否则可能导致网易更改加密使本脚本失效")
        print("[*] 按任意键退出")
        os.system("pause")
        exit(1)
