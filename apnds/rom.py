
from enum import IntEnum
from queue import SimpleQueue
from typing import Tuple

class HeaderField(IntEnum):
    TITLE = 0x000
    SERIAL = 0x00C
    MAKER = 0x010
    CHIPCAPACITY = 0x014
    REVISION = 0x01E
    ARM9_ROMOFFSET = 0x020
    ARM9_ENTRYPOINT = 0x024
    ARM9_LOADADDR = 0x028
    ARM9_LOADSIZE = 0x02C
    ARM7_ROMOFFSET = 0x030
    ARM7_ENTRYPOINT = 0x034
    ARM7_LOADADDR = 0x038
    ARM7_LOADSIZE = 0x03C
    FNTB_ROMOFFSET = 0x040
    FNTB_BSIZE = 0x044
    FATB_ROMOFFSET = 0x048
    FATB_BSIZE = 0x04C
    OVT9_ROMOFFSET = 0x050
    OVT9_BSIZE = 0x054
    OVT7_ROMOFFSET = 0x058
    OVT7_BSIZE = 0x05C
    ROMCTRL_DEC = 0x060
    ROMCTRL_ENC = 0x064
    BANNER_ROMOFFSET = 0x068
    SECURECRC = 0x06C
    SECURE_DELAY = 0x06E
    ARM9_AUTOLOADCB = 0x070
    ARM7_AUTOLOADCB = 0x074
    ROMSIZE = 0x080
    HEADERSIZE = 0x084
    STATICFOOTER = 0x088
    HEADERCRC = 0x15E
    HEADERCRC_END = 0x15E
    ENTIRE_HEADER = 0x4000

    def succ(self) -> "HeaderField":
        match self:
            case HeaderField.TITLE:
                return HeaderField.SERIAL
            case HeaderField.SERIAL:
                return HeaderField.MAKER
            case HeaderField.MAKER:
                return HeaderField.CHIPCAPACITY
            case HeaderField.CHIPCAPACITY:
                return HeaderField.REVISION
            case HeaderField.REVISION:
                return HeaderField.ARM9_ROMOFFSET
            case HeaderField.ARM9_ROMOFFSET:
                return HeaderField.ARM9_ENTRYPOINT
            case HeaderField.ARM9_ENTRYPOINT:
                return HeaderField.ARM9_LOADADDR
            case HeaderField.ARM9_LOADADDR:
                return HeaderField.ARM9_LOADSIZE
            case HeaderField.ARM9_LOADSIZE:
                return HeaderField.ARM7_ROMOFFSET
            case HeaderField.ARM7_ROMOFFSET:
                return HeaderField.ARM7_ENTRYPOINT
            case HeaderField.ARM7_ENTRYPOINT:
                return HeaderField.ARM7_LOADADDR
            case HeaderField.ARM7_LOADADDR:
                return HeaderField.ARM7_LOADSIZE
            case HeaderField.ARM7_LOADSIZE:
                return HeaderField.FNTB_ROMOFFSET
            case HeaderField.FNTB_ROMOFFSET:
                return HeaderField.FNTB_BSIZE
            case HeaderField.FNTB_BSIZE:
                return HeaderField.FATB_ROMOFFSET
            case HeaderField.FATB_ROMOFFSET:
                return HeaderField.FATB_BSIZE
            case HeaderField.FATB_BSIZE:
                return HeaderField.OVT9_ROMOFFSET
            case HeaderField.OVT9_ROMOFFSET:
                return HeaderField.OVT9_BSIZE
            case HeaderField.OVT9_BSIZE:
                return HeaderField.OVT7_ROMOFFSET
            case HeaderField.OVT7_ROMOFFSET:
                return HeaderField.OVT7_BSIZE
            case HeaderField.OVT7_BSIZE:
                return HeaderField.ROMCTRL_DEC
            case HeaderField.ROMCTRL_DEC:
                return HeaderField.ROMCTRL_ENC
            case HeaderField.ROMCTRL_ENC:
                return HeaderField.BANNER_ROMOFFSET
            case HeaderField.BANNER_ROMOFFSET:
                return HeaderField.SECURECRC
            case HeaderField.SECURECRC:
                return HeaderField.SECURE_DELAY
            case HeaderField.SECURE_DELAY:
                return HeaderField.ARM9_AUTOLOADCB
            case HeaderField.ARM9_AUTOLOADCB:
                return HeaderField.ARM7_AUTOLOADCB
            case HeaderField.ARM7_AUTOLOADCB:
                return HeaderField.ROMSIZE
            case HeaderField.ROMSIZE:
                return HeaderField.HEADERSIZE
            case HeaderField.HEADERSIZE:
                return HeaderField.STATICFOOTER
            case HeaderField.STATICFOOTER:
                return HeaderField.HEADERCRC
            case HeaderField.HEADERCRC:
                return HeaderField.HEADERCRC_END
            case HeaderField.HEADERCRC_END:
                return HeaderField.ENTIRE_HEADER
            case HeaderField.ENTIRE_HEADER:
                return HeaderField.ENTIRE_HEADER

    def len(self) -> int:
        if self == HeaderField.ENTIRE_HEADER:
            return self
        else:
            return self.succ() - self

class Header:
    data: bytearray

    def __init__(self, data: bytes):
        if len(data) != HeaderField.ENTIRE_HEADER:
            raise ValueError("header data is of incorrect length (expected 0x4000 bytes)")
        self.data = bytearray(data)

    def __getitem__(self, key: HeaderField) -> bytes:
        if key == HeaderField.ENTIRE_HEADER:
            return bytes(self.data)
        else:
            return bytes(self.data[key:key.succ()])
    
    def __setitem__(self, key: HeaderField, value: bytes | int) -> None:
        if isinstance(value, int):
            value = value.to_bytes(key.len(), 'little')
        if key == HeaderField.ENTIRE_HEADER:
            self.data[:] = value
        else:
            self.data[key:key.succ()] = value

    def get_le(self, key: HeaderField) -> int:
        if key == HeaderField.ENTIRE_HEADER:
            return int.from_bytes(self.data, 'little')
        else:
            return int.from_bytes(self[key], 'little')

    def get_rom_region(self, rom: bytes, offset: HeaderField, length: HeaderField) -> bytes:
        off = self.get_le(offset)
        return rom[off:off + self.get_le(length)]

def get_files(header: Header, rom: bytes) -> list[bytes]:
    fatb = header.get_rom_region(rom, HeaderField.FATB_ROMOFFSET, HeaderField.FATB_BSIZE)
    fatb_ints = [int.from_bytes(fatb[i:i + 4], 'little') for i in range(0, len(fatb), 4)]
    return [rom[fatb_ints[i]:fatb_ints[i + 1]] for i in range(0, len(fatb_ints), 2)]

def get_filename_id_map(header: Header, rom: bytes) -> dict[bytes, int]:
    fntb = header.get_rom_region(rom, HeaderField.FNTB_ROMOFFSET, HeaderField.FNTB_BSIZE)

    # returns (contents offset, id of first file child, id of parent dir).
    # (these ids are of different types)
    def dir_entry(i: int) -> Tuple[int, int, int]:
        entry = fntb[i * 8:(i + 1) * 8]
        return (int.from_bytes(entry[:4], 'little'), int.from_bytes(entry[4:6], 'little'), int.from_bytes(entry[6:8], 'little'))

    ret = {}
    dir_queue: SimpleQueue[Tuple[int, bytes]] = SimpleQueue()
    # queue is (dir id, dir path)
    dir_queue.put((0, b''))

    while not dir_queue.empty():
        dir_id, dir_path = dir_queue.get()
        contents_off, file_id, _ = dir_entry(dir_id)

        while fntb[contents_off] != 0:
            is_dir = fntb[contents_off] & 0x80 != 0
            name_len = fntb[contents_off] & 0x7F
            contents_off += 1
            path = dir_path + b'/' + fntb[contents_off:contents_off + name_len]
            contents_off += name_len
            if is_dir:
                dir_id = 0xFFF & int.from_bytes(fntb[contents_off:contents_off + 2], 'little')
                dir_queue.put((dir_id, path))
                contents_off += 2
            else:
                ret[path] = file_id
                file_id += 1

    return ret
