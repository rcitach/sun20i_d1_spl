# -*- coding: utf-8 -*-

'''
//增加安全启动下, toc1的头部数据结构
typedef struct sbrom_toc1_head_info
{
	char name[16]	;	//user can modify
	u32  magic	;	    //must equal TOC_U32_MAGIC
	u32  add_sum	;

	u32  serial_num	;	//user can modify
	u32  status		;	//user can modify,such as TOC_MAIN_INFO_STATUS_ENCRYP_NOT_USED

	u32  items_nr;	    //total entry number
	u32  valid_len;
	u32  version_main;	//only one byte
	u32  version_sub;   //two bytes
	u32  reserved[3];	//reserved for future

	u32  end;
}
sbrom_toc1_head_info_t;

typedef struct sbrom_toc1_item_info
{
	char name[64];			//such as ITEM_NAME_SBROMSW_CERTIF
	u32  data_offset;
	u32  data_len;
	u32  encrypt;			//0: no aes   //1: aes
	u32  type;				//0: normal file, dont care  1: key certif  2: sign certif 3: bin file
	u32  run_addr;          //if it is a bin file, then run on this address; if not, it should be 0
	u32  index;             //if it is a bin file, this value shows the index to run; if not
	                       //if it is a certif file, it should equal to the bin file index
	                       //that they are in the same group
	                       //it should be 0 when it anyother data type
	u32  reserved[69];	   //reserved for future;
	u32  end;
}sbrom_toc1_item_info_t;
'''

import sys
import os
import argparse
import struct
import zlib
from configparser import ConfigParser
from typing import Dict, List, Union, TypedDict, Optional

# --- 常量定义 ---
TOC1_MAGIC = "sunxi_toc1"
TOC1_HEADER_FORMAT = "<16s12I"  # 小端，16字节字符串 + 12个uint32
TOC1_ITEMS_FORMAT = "<64s76I"   # 小端，64字节字符串 + 76个uint32
TOC1_HEADER_NAME = "Allwinner D1S"
TOC1_HEADER_OFFSET = 0x40
TOC1_ITEMS_OFFSET = 0x170
TOC1_SECTOR_SIZE = 512
TOC_MAIN_INFO_MAGIC = 0x89119800
TOC1_HEADER_END_MARKER = 0x3b45494d
TOC1_ITEMS_END_MARKER = 0x3b454949

# --- 类型定义 ---
class Toc1Header(TypedDict):
    name: bytes
    magic: int
    add_sum: int
    serial_num: int
    status: int
    items_nr: int
    valid_len: int
    version_main: int
    version_sub: int
    reserved: List[int]
    end: int

class Toc1Item(TypedDict):
    name: bytes
    data_offset: int
    data_len: int
    encrypt: int
    type: int
    run_addr: int
    index: int
    reserved: List[int]
    end: int

class FileEntry(TypedDict):
    path: str
    offset: int
    size: int

# --- 工具函数 ---
def align_up(size: int, align: int) -> int:
    """计算对齐后的尺寸"""
    return (size + align - 1) & ~(align - 1)

def safe_read_file(path: str) -> bytes:
    """安全读取文件内容，避免路径遍历攻击"""
    if not os.path.abspath(path).startswith(os.getcwd()):
        raise ValueError(f"非法文件路径: {path}")
    with open(path, "rb") as f:
        return f.read()

def calculate_crc(filepath):
    """计算文件的CRC32校验和（内存友好方式）"""
    crc = 0
    with open(filepath, 'rb') as f:
        while chunk := f.read(4096):  # 每次读取4KB
            crc = zlib.crc32(chunk, crc)
    return crc

# --- 核心函数 ---
def init_toc1_header() -> Toc1Header:
    """初始化TOC1头结构体"""
    return {
        "name": TOC1_HEADER_NAME,
        "magic": TOC_MAIN_INFO_MAGIC,
        "add_sum": 0,
        "serial_num": 0,
        "status": 0,
        "items_nr": 2,
        "valid_len": 0,
        "version_main": 1,
        "version_sub": 0,
        "reserved": [0] * 3,
        "end": TOC1_HEADER_END_MARKER
    }

def init_toc1_item() -> Toc1Item:
    """初始化TOC1内容结构体"""
    return {
        "name": b" ",
        "data_offset": 0,
        "data_len": 0,
        "encrypt": 0,
        "type": 0,
        "run_addr": 2,
        "index": 0,
        "reserved": [0] * 69,
        "end": TOC1_ITEMS_END_MARKER
    }

def pack_toc1_header(header_data: Toc1Header) -> bytes:
    """打包TOC1头结构体"""
    # 类型检查和转换
    if not isinstance(header_data["name"], bytes):
        header_data["name"] = header_data["name"].encode('ascii')
    header_data["name"] = header_data["name"].ljust(16, b'\0')[:16]

    # 强制32位无符号整数
    int_fields = ["magic", "add_sum", "serial_num", "status", "items_nr", 
                 "valid_len", "version_main", "version_sub", "end"]
    for field in int_fields:
        header_data[field] &= 0xFFFFFFFF

    if len(header_data["reserved"]) != 3:
        raise ValueError("reserved必须包含3个整数")
    header_data["reserved"] = [x & 0xFFFFFFFF for x in header_data["reserved"]]

    packed = struct.pack(
        TOC1_HEADER_FORMAT,
        header_data["name"],
        header_data["magic"],
        header_data["add_sum"],
        header_data["serial_num"],
        header_data["status"],
        header_data["items_nr"],
        header_data["valid_len"],
        header_data["version_main"],
        header_data["version_sub"],
        *header_data["reserved"],
        header_data["end"]
    )

    if len(packed) != struct.calcsize(TOC1_HEADER_FORMAT):
        raise RuntimeError("头结构体打包长度异常")
    return packed

def pack_toc1_item(item_data: Toc1Item) -> bytes:
    """打包TOC1内容结构体"""
    if not isinstance(item_data["name"], bytes):
        item_data["name"] = item_data["name"].encode('ascii')
    item_data["name"] = item_data["name"].ljust(64, b'\0')[:64]

    int_fields = ["data_offset", "data_len", "encrypt", "type", 
                 "run_addr", "index", "end"]
    for field in int_fields:
        item_data[field] &= 0xFFFFFFFF

    if len(item_data["reserved"]) != 69:
        raise ValueError("reserved必须包含69个整数")
    item_data["reserved"] = [x & 0xFFFFFFFF for x in item_data["reserved"]]

    packed = struct.pack(
        TOC1_ITEMS_FORMAT,
        item_data["name"],
        item_data["data_offset"],
        item_data["data_len"],
        item_data["encrypt"],
        item_data["type"],
        item_data["run_addr"],
        item_data["index"],
        *item_data["reserved"],
        item_data["end"]
    )

    if len(packed) != struct.calcsize(TOC1_ITEMS_FORMAT):
        raise RuntimeError("内容结构体打包长度异常")
    return packed

def build_toc1_bin(output_path: str, config_data: Dict[str, Dict[str, Union[str, int]]]) -> None:
    """生成TOC1格式的二进制文件"""
    header_data = init_toc1_header()
    file_entries: List[FileEntry] = []
    packed_items = bytearray()

    # 校验配置项数量
    if (len(config_data) - 1) != header_data["items_nr"]:
        print(f"\033[93m警告: 配置项数量不符 (预期: {header_data['items_nr'] + 1}, 实际: {len(config_data)})\033[0m")
        print("配置项列表:")
        for section in config_data:
            print(f" - {section}")
        print()
        header_data["items_nr"] = len(config_data) - 1

    # 计算基础偏移
    base_offset = align_up(
        TOC1_HEADER_OFFSET + len(config_data) * TOC1_ITEMS_OFFSET,
        TOC1_SECTOR_SIZE
    )

    # 处理每个配置项
    file_size_offset = 0
    for index, (section, values) in enumerate(config_data.items()):
        if not section:
            raise ValueError("配置项名称不能为空")

        item_data = init_toc1_item()
        item_data.update({
            "name": section,
            "type": 3,
            "index": index,
            "data_offset": base_offset + (file_size_offset if index > 0 else 0)
        })

        # 处理文件和数据
        if "file" not in values:
            raise ValueError(f"配置项 '{section}' 缺少 'file' 字段")
        
        file_path = values["file"]
        file_size = os.path.getsize(file_path)
        aligned_size = align_up(file_size, TOC1_SECTOR_SIZE)

        item_data.update({
            "data_len": file_size,
            "run_addr": values.get("addr", 0)
        })
        header_data["add_sum"] += file_size & 0xFFFFFFFF

        file_entries.append({
            "path": file_path,
            "offset": item_data["data_offset"],
            "size": file_size,
            "aligned_size": aligned_size
        })
        file_size_offset += aligned_size

        packed_items.extend(pack_toc1_item(item_data))

    # 更新头部信息
    header_data["valid_len"] = base_offset + file_size_offset
    packed_header = pack_toc1_header(header_data)

    # 预分配并写入数据
    with open(output_path, "wb") as f:
        # 1. 写入头部
        f.write(packed_header)
        f.seek(TOC1_HEADER_OFFSET)
        
        # 2. 写入条目表
        f.write(packed_items)
        
        # 3. 写入文件内容
        for entry in file_entries:
            f.seek(entry["offset"])
            f.write(safe_read_file(entry["path"]))
            # 对齐填充
            padding_size = entry["aligned_size"] - entry["size"]
            if padding_size > 0:
                f.write(b'\x00' * padding_size)

    # 单独计算校验和（避免内存问题）
    try:
        print(f"文件生成成功,CRC32校验和: 0x{calculate_crc(output_path):08x}")
    except Exception as e:
        print(f"警告: 无法计算校验和 - {str(e)}")

# --- 主程序 ---
def main():
    parser = argparse.ArgumentParser(description="生成Allwinner D1S TOC1镜像")
    parser.add_argument("-T", "--type", required=True, help="镜像类型 (必须为'sunxi_toc1')")
    parser.add_argument("-d", "--config", required=True, help="配置文件路径")
    parser.add_argument("output", nargs="?", default="sd.bin", help="输出文件路径")
    args = parser.parse_args()

    if args.type.strip() != TOC1_MAGIC:
        raise ValueError("只支持 -T sunxi_toc1 类型")

    config = ConfigParser()
    config.read(args.config)
    config_data = {
        section: {k: int(v, 0) if isinstance(v, str) and v.startswith(('0x', '0X')) else v
                for k, v in config.items(section)}
        for section in config.sections()
    }

    try:
        build_toc1_bin(args.output, config_data)
        print(f"成功生成TOC1镜像: {args.output}")
    except Exception as e:
        print(f"\033[91m错误: {str(e)}\033[0m")
        sys.exit(1)

if __name__ == "__main__":
    main()