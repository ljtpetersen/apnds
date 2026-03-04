# apnds/code.py
#
# Copyright (C) 2026 James Petersen <m@jamespetersen.ca>
# Licensed under MIT. See LICENSE

from collections import defaultdict
from dataclasses import dataclass
from struct import unpack_from
from typing import Optional, Tuple

START_INFO_SIGNATURE_DS = bytes.fromhex("2106C0DEDEC00621")
START_INFO_SIGNATURE_DSI = bytes.fromhex("6314C0DEDEC01463")

@dataclass
class AutoloadSectionInfo:
    """
    Certain sections of the code are automatically loaded
    to other memory addresses when the game starts.
    This class contains the information about one of these
    sections.
    """

    destination: int
    """
    To which address this section should be copied.
    """
    size: int
    """
    How much data should be copied to this section.
    """
    bss_size: int
    """
    How large the BSS data after this section's code is.
    The BSS data will be zeroed.
    """
    static_init_table: int | None = None
    """
    A table to static initializers for this section.
    This field is only present on newer DSi-compatible ROMs.
    """

@dataclass
class ArmStartParams:
    """
    This structure contains the start parameters of the ARM code.
    """

    autoload_sections: Tuple[int, int]
    """
    The address range containing the autoload section info.
    """
    autoload_start: int
    """
    The starting address to copy into the autoload sections.
    """
    bss_bounds: Tuple[int, int]
    """
    The bounds of the BSS segment of this code.
    This region is zeroed during the C runtime, before main is called.
    The endpoint is excluded. These must be on 4-byte boundaries.
    """
    compressed_end: Optional[int] = None
    """
    The end address of the compressed section of this code, if the code is compressed.
    """
    sdk_version: Optional[int] = None
    """
    The NITRO/TWL SDK version this code was made with.
    This is somewhat inconsistent. A 32-bit value.
    The top 8 bits should always be major version.
    """
    armi_autoload_sections: Optional[Tuple[int, int]] = None
    """
    The address range containing the ARM i autoload section info,
    if it exists.
    """
    armi_autoload_start: Optional[int] = None
    """
    The starting address to copy into the ARM i autoload section info,
    if it exists.
    """
    armi_compressed_end: Optional[int] = None
    """
    The end address of the compressed section of the ARM i, if it exists.
    """

    @staticmethod
    def from_arm9(arm9: bytes, loadaddress: int, entrypoint: int | None = None) -> Optional["ArmStartParams"]:
        """
        Try to find the ARM9 start parameters.
        This is only useful for official titles, not Homebrew ones.

        In some older titles, a certain signature is not present to help locate the start parameters structure.
        For these, a best-guess approach is used, scanning the area containing
        the C runtime for this structure. In this case, the sdk_version
        field will be None. For more details on this,
        see the try_find_start_info_no_signature function.
        """
        arm9_start_info_idx = arm9.find(START_INFO_SIGNATURE_DS)
        if arm9_start_info_idx == -1:
            # assuming now that this isn't compressed code, and is in an old (pre-DSi) game.
            # try to find start info by other means...
            if entrypoint is not None:
                arm9_start_info_idx = try_find_start_info_no_signature(arm9, loadaddress, entrypoint, True)
                if arm9_start_info_idx is None:
                    return None
                compressed_end = 0
                sdk_version = None
            else:
                return None
        else:
            compressed_end, sdk_version = unpack_from("<2I", arm9, arm9_start_info_idx - 8)
            arm9_start_info_idx -= 28

        arm9i_start_info_idx = arm9.find(START_INFO_SIGNATURE_DSI)
        if arm9i_start_info_idx == -1:
            arm9i_autoload_sections = arm9i_autoload_start = arm9i_compressed_end = None
        else:
            au9_secs_start, au9_secs_end, arm9i_autoload_start, arm9i_compressed_end = \
                unpack_from("<4I", arm9, arm9i_start_info_idx - 16)
            arm9i_autoload_sections = (au9_secs_start, au9_secs_end)
            if arm9i_compressed_end == 0:
                arm9i_compressed_end = None

        au_secs_start, au_secs_end, au_start, bss_start, bss_end = \
            unpack_from("<5I", arm9, arm9_start_info_idx)
        return ArmStartParams(
            (au_secs_start, au_secs_end),
            au_start,
            (bss_start, bss_end),
            compressed_end if compressed_end != 0 else None,
            sdk_version,
            arm9i_autoload_sections,
            arm9i_autoload_start,
            arm9i_compressed_end,
        )

    @staticmethod
    def from_arm7(arm7: bytes, loadaddress: int, entrypoint: int | None = None) -> Optional["ArmStartParams"]:
        """
        Try to find the ARM7 start parameters.
        This is only useful for official titles, not Homebrew ones.

        In DS title and older DSi titles, a certain signature is not present to help locate the start parameters structure.
        For these, a best-guess approach is used, scanning the area containing
        the C runtime for this structure. In this case, the sdk_version
        field will be None. For more details on this,
        see the try_find_start_info_no_signature function.
        """
        arm7_start_info_idx = arm7.find(START_INFO_SIGNATURE_DS)
        if arm7_start_info_idx == -1:
            if entrypoint is not None:
                arm7_start_info_idx = try_find_start_info_no_signature(arm7, loadaddress, entrypoint, True)
                if arm7_start_info_idx is None:
                    return None
                arm7i_autoload_sections = arm7i_autoload_start = arm7i_compressed_end = None
                compressed_end = 0
                sdk_version = None
            else:
                return None
        else:
            # because nintendo hates me specifically, this structure
            # sometimes has the sdk version and sometimes
            # it doesn't. we need to detect this case separately.
            # under the assumption that in its place would be compression end address
            # (which I have always found to be zero, but I'll check for it anyways),
            # we check the highest-order byte of the word before the signature.
            # if it is 5, then it is the version number.
            # otherwise, assume it is compression info.
            if arm7[arm7_start_info_idx - 1] == 5:
                arm7_start_info_idx -= 4
                sdk_version, = unpack_from("<I", arm7, arm7_start_info_idx)
            else:
                sdk_version = None

            compressed_end, = unpack_from("<I", arm7, arm7_start_info_idx - 4)
            if compressed_end == 0:
                compressed_end = None
            arm7_start_info_idx -= 24

            # we should be on a DSi ROM with the other signature present
            # as well...
            arm7i_start_info_idx = arm7.find(START_INFO_SIGNATURE_DSI)
            if arm7i_start_info_idx == -1:
                arm7i_autoload_sections = arm7i_autoload_start = arm7i_compressed_end = None
                print(f"found unexpected case of ARM7 code.\nplease report the game this function was called on to m@jamespetersen.ca")
            else:
                au7_secs_start, au7_secs_end, arm7i_autoload_start, arm7i_compressed_end = \
                    unpack_from("<4I", arm7, arm7i_start_info_idx - 16)
                arm7i_autoload_sections = (au7_secs_start, au7_secs_end)

        au_secs_start, au_secs_end, au_start, bss_start, bss_end = \
            unpack_from("<5I", arm7, arm7_start_info_idx)
        return ArmStartParams(
            (au_secs_start, au_secs_end),
            au_start,
            (bss_start, bss_end),
            compressed_end if compressed_end != 0 else None,
            sdk_version,
            arm7i_autoload_sections,
            arm7i_autoload_start,
            arm7i_compressed_end,
        )


def try_find_start_info_no_signature(code: bytes, loadaddress: int, entrypoint: int, check_autoload: bool = False) -> Optional[int]:
    """
    This function looks through the C runtime trying to find the start
    parameters structure, which contains autoload and bss information.
    It does so by locating addresses which are read to,
    and then read at offsets 0, 4, 8, 12, 16, 20.
    After finding these candidates, it narrows down to those which
    satisfy the expected properties of the structure. If a single
    best candidate can be found, it is returned.

    This function should only be called on (old) Nintendo DS ROMs. On Nintendo DSi ROMs
    and newer (relatively speaking) Nintendo DS ROMs, a signature is present to help locate
    the start info structure(s). Furthermore, the autoload code was updated at some point
    in the DSi's lifespan. This function will not work properly on this newer Autoload
    structure.
    """
    # look for candidates that are obviously read at some of the offets 0, 4, 8, 12, 16, 20
    # check that it satisfies obvious expectations about the start info structure

    # we are expecting ldr into a register and then immediately load into other registers
    # from offsets. e.g.
    # ldr r0, addr
    # ldr r1, [r0, #0]
    # ldr r2, [r0, #4]
    # expect ARM (not thumb)

    # returns: (X, Y, off) if ins is
    # ldr rX, [rY, #off]
    # otherwise returns None.
    # PC is Y=15, in which case it is offset from instruction after address
    def get_read_offset(ins: bytes) -> Optional[Tuple[int, int, int]]:
        # unconditional memory operation with immediate offset/pre-index
        if ins[3] != 0b11100101:
            return None
        # word access, load, offset.
        if ins[2] & 0b01110000 != 0b00010000:
            return None
        sgn = 1 if ins[2] & 0b10000000 != 0 else -1
        off = sgn * (ins[0] | ((ins[1] & 0b1111) << 8))
        rn = ins[2] & 0b1111
        if rn == 15:
            off += 4
        rd = ins[1] >> 4
        return (rd, rn, off)

    lc_aligned = (len(code) + 3) & ~3

    candidates = defaultdict(set)

    cur = start = entrypoint - loadaddress
    # crt will be at most 0x4000 bytes (guess).
    while cur - start < 0x4000 and cur + 4 <= lc_aligned:
        ins = code[cur:cur + 4]
        cur += 4
        ro = get_read_offset(ins)
        if ro is None:
            continue
        rd, rn, off = ro
        if rd >= 8 or rn != 15:
            continue
        addr, = unpack_from("<I", code, cur + off)
        if (addr & 3) != 0 or addr - loadaddress > 0x4000 or addr - loadaddress < 0:
            continue
        read_offs = set()
        while cur + 4 <= lc_aligned:
            ins = code[cur:cur + 4]
            ro = get_read_offset(ins)
            if ro is None:
                cur += 4
                break
            if ro[0] != rd and ro[1] == rd:
                cur += 4
                if ro[2] in {0, 4, 8, 12, 16, 20}:
                    read_offs.add(ro[2])
                elif ro[2] > 32 or ro[2] < 0:
                    # invalidate candidate for offset out of range
                    read_offs = set()
                    if addr in candidates:
                        del candidates[addr]
                    break
            else:
                break
        if len(read_offs) > 0:
            candidates[addr] |= read_offs

    valid_candidates = []
    for candidate in candidates:
        if candidate - loadaddress + 20 > lc_aligned:
            continue
        au_secs_start, au_secs_end, au_start = \
            unpack_from("<3I", code, candidate - loadaddress)
        if au_start < loadaddress or au_start & 3 != 0:
            continue
        if au_secs_end & 3 != 0 or (au_secs_end - au_secs_start) % 12 != 0:
            continue
        if check_autoload:
            for i in range(au_secs_start, au_secs_end, 12):
                if i - loadaddress + 12 > lc_aligned:
                    break
                destination, size, bss_size = unpack_from("<3I", code, i - loadaddress)
                if destination & 3 != 0 or size & 3 != 0 or bss_size & 3 != 0:
                    break
                au_start += size
            else:
                if au_start - loadaddress <= lc_aligned:
                    valid_candidates.append(candidate)
        else:
            valid_candidates.append(candidate)
    srt_valid = sorted(valid_candidates, key=lambda c : len(candidates[c]))
    if len(srt_valid) == 0 or len(srt_valid) >= 2 and len(candidates[srt_valid[0]]) == len(candidates[srt_valid[1]]):
        return None
    return srt_valid[0] - loadaddress
