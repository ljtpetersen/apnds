<a id="apnds.rom"></a>

# apnds.rom

<a id="apnds.rom.HeaderField"></a>

## HeaderField Objects

```python
class HeaderField(IntEnum)
```

These are the fields of the header, and their corresponding offsets.
The length of each entry is the difference of its successor's offset with it.

<a id="apnds.rom.HeaderField.TITLE"></a>

#### TITLE

The title of the ROM. This should be null-terminated ASCII.

<a id="apnds.rom.HeaderField.CHIPCAPACITY"></a>

#### CHIPCAPACITY

This is computed and set automatically when converting the ROM to bytes.

<a id="apnds.rom.HeaderField.ARM9_ROMOFFSET"></a>

#### ARM9\_ROMOFFSET

This is computed and set automatically when converting the ROM to bytes.

<a id="apnds.rom.HeaderField.ARM9_LOADSIZE"></a>

#### ARM9\_LOADSIZE

This is computed and set automatically when converting the ROM to bytes.

<a id="apnds.rom.HeaderField.ARM7_ROMOFFSET"></a>

#### ARM7\_ROMOFFSET

This is computed and set automatically when converting the ROM to bytes.

<a id="apnds.rom.HeaderField.ARM7_LOADSIZE"></a>

#### ARM7\_LOADSIZE

This is computed and set automatically when converting the ROM to bytes.

<a id="apnds.rom.HeaderField.FNTB_ROMOFFSET"></a>

#### FNTB\_ROMOFFSET

This is computed and set automatically when converting the ROM to bytes.

<a id="apnds.rom.HeaderField.FNTB_BSIZE"></a>

#### FNTB\_BSIZE

This is computed and set automatically when converting the ROM to bytes.

<a id="apnds.rom.HeaderField.FATB_ROMOFFSET"></a>

#### FATB\_ROMOFFSET

This is computed and set automatically when converting the ROM to bytes.

<a id="apnds.rom.HeaderField.FATB_BSIZE"></a>

#### FATB\_BSIZE

This is computed and set automatically when converting the ROM to bytes.

<a id="apnds.rom.HeaderField.OVT9_ROMOFFSET"></a>

#### OVT9\_ROMOFFSET

This is computed and set automatically when converting the ROM to bytes.

<a id="apnds.rom.HeaderField.OVT9_BSIZE"></a>

#### OVT9\_BSIZE

This is computed and set automatically when converting the ROM to bytes.

<a id="apnds.rom.HeaderField.OVT7_ROMOFFSET"></a>

#### OVT7\_ROMOFFSET

This is computed and set automatically when converting the ROM to bytes.

<a id="apnds.rom.HeaderField.OVT7_BSIZE"></a>

#### OVT7\_BSIZE

This is computed and set automatically when converting the ROM to bytes.

<a id="apnds.rom.HeaderField.ROMCTRL_DEC"></a>

#### ROMCTRL\_DEC

This is computed and set automatically when converting the ROM to bytes.

<a id="apnds.rom.HeaderField.ROMCTRL_ENC"></a>

#### ROMCTRL\_ENC

This is computed and set automatically when converting the ROM to bytes.

<a id="apnds.rom.HeaderField.BANNER_ROMOFFSET"></a>

#### BANNER\_ROMOFFSET

This is computed and set automatically when converting the ROM to bytes.

<a id="apnds.rom.HeaderField.SECURE_DELAY"></a>

#### SECURE\_DELAY

This is computed and set automatically when converting the ROM to bytes.

<a id="apnds.rom.HeaderField.ROMSIZE"></a>

#### ROMSIZE

This is computed and set automatically when converting the ROM to bytes.

<a id="apnds.rom.HeaderField.HEADERSIZE"></a>

#### HEADERSIZE

This is computed and set automatically when converting the ROM to bytes.

<a id="apnds.rom.HeaderField.STATICFOOTER"></a>

#### STATICFOOTER

This is computed and set automatically when converting the ROM to bytes.

<a id="apnds.rom.HeaderField.STATICFOOTER_END"></a>

#### STATICFOOTER\_END

This entry exists so that the STATICFOOTER entry's length is computed correctly.

<a id="apnds.rom.HeaderField.HEADERCRC"></a>

#### HEADERCRC

This is computed and set automatically when converting the ROM to bytes.

<a id="apnds.rom.HeaderField.HEADERCRC_END"></a>

#### HEADERCRC\_END

This entry exists so that the HEADERCRC entry's length is computed correctly.

<a id="apnds.rom.HeaderField.ENTIRE_HEADER"></a>

#### ENTIRE\_HEADER

This is the size of the entire header.

<a id="apnds.rom.HeaderField.succ"></a>

#### succ

```python
def succ() -> "HeaderField"
```

Given a header field, this returns the subsequent header field.
For ENTIRE_HEADER, it returns ENTIRE_HEADER.

<a id="apnds.rom.HeaderField.len"></a>

#### len

```python
def len() -> int
```

This is the length of this header field, computed by `self.succ() - self`.

<a id="apnds.rom.Header"></a>

## Header Objects

```python
class Header()
```

This is the header of a DS ROM. Its fields can be accessed using indexing notation:
`header[HeaderField.TITLE]` will return the title, in bytes.

<a id="apnds.rom.Header.data"></a>

#### data

The underlying data of the header.

<a id="apnds.rom.Header.__init__"></a>

#### \_\_init\_\_

```python
def __init__(data: bytes)
```

Initialize a header with some underlying data. The length of the data must be 0x4000 bytes.

<a id="apnds.rom.Header.__getitem__"></a>

#### \_\_getitem\_\_

```python
def __getitem__(key: HeaderField) -> bytes
```

Get a field from the header as bytes.

<a id="apnds.rom.Header.__setitem__"></a>

#### \_\_setitem\_\_

```python
def __setitem__(key: HeaderField, value: bytes | int) -> None
```

Set a field from the header from bytes or an integer. If an integer
is passed, it is interpreted as little endian.

<a id="apnds.rom.Header.get_le"></a>

#### get\_le

```python
def get_le(key: HeaderField) -> int
```

Get a field from the header as an integer. It is interpreted as little endian.

<a id="apnds.rom.Header.get_rom_region"></a>

#### get\_rom\_region

```python
def get_rom_region(rom: bytes, offset: HeaderField,
                   length: HeaderField) -> bytes
```

Given the entire ROM, the field corresponding to the offset in the ROM, and the
field corresponding to the binary size in the ROM, return the region in the ROM.

<a id="apnds.rom.get_files"></a>

#### get\_files

```python
def get_files(header: Header,
              rom: bytes) -> Tuple[MutableSequence[bytes], Sequence[int]]
```

Given a header and ROM, return the sequence of files in the FAT, as bytes,
along with the order of these files within ROM.

<a id="apnds.rom.get_filename_id_map"></a>

#### get\_filename\_id\_map

```python
def get_filename_id_map(header: Header,
                        rom: bytes) -> MutableMapping[str, int]
```

Given a header and ROM, return a mapping from file paths to file IDs (in the FAT).

<a id="apnds.rom.Overlay"></a>

## Overlay Objects

```python
@dataclass
class Overlay()
```

This is a single overlay.

<a id="apnds.rom.Overlay.id"></a>

#### id

This is the overlay's ID.

<a id="apnds.rom.Overlay.ram_address"></a>

#### ram\_address

This is the RAM address at which the overlay is to be loaded.

<a id="apnds.rom.Overlay.ram_size"></a>

#### ram\_size

This is the RAM size of the overlay when loaded.

<a id="apnds.rom.Overlay.data"></a>

#### data

This is the data of the overlay.

<a id="apnds.rom.get_overlays"></a>

#### get\_overlays

```python
def get_overlays(
        header: Header, rom: bytes, files: Sequence[bytes],
        which: Literal["9"] | Literal["7"]) -> MutableSequence[Overlay]
```

Given a header, ROM, and the files in the ROM, return the overlays for either the ARM9 or ARM7 processor.

<a id="apnds.rom.construct_overlay_table"></a>

#### construct\_overlay\_table

```python
def construct_overlay_table(
        overlays: Sequence[Overlay],
        file_id_off: int = 0) -> Tuple[bytes, Sequence[bytes]]
```

Given a sequence of overlays, and a starting file ID, return the overlay table and the sequence of overlays.

<a id="apnds.rom.path_key"></a>

#### path\_key

```python
def path_key(path: str) -> Tuple
```

The path key is the decomposition of a path `'/a/b/c'` into
a tuple of its components, `('a', 'b', 'c')`

<a id="apnds.rom.path_key_to_path"></a>

#### path\_key\_to\_path

```python
def path_key_to_path(*kwargs: str) -> str
```

This recomposes a path from its path key.

<a id="apnds.rom.construct_fntb"></a>

#### construct\_fntb

```python
def construct_fntb(filenames: Iterable[str],
                   file_id_off: int) -> Tuple[bytes, Mapping[str, int]]
```

Given the filenames in the ROM, and the first file ID for the files, construct the FNT
and the mapping from filenames to file IDs.

<a id="apnds.rom.crc16"></a>

#### crc16

```python
def crc16(data: bytes, crc: int) -> int
```

Compute the 16-bit CRC value for some bytes.

<a id="apnds.rom.Rom"></a>

## Rom Objects

```python
@dataclass
class Rom()
```

This is the decomposition of a DS ROM into its parts.

<a id="apnds.rom.Rom.header"></a>

#### header

This is the header of the ROM.

<a id="apnds.rom.Rom.arm9"></a>

#### arm9

This is the ARM9 code of the ROM.

<a id="apnds.rom.Rom.arm7"></a>

#### arm7

This is the ARM7 code of the ROM.

<a id="apnds.rom.Rom.arm9_overlays"></a>

#### arm9\_overlays

These are the ARM9 overlays of the ROM.

<a id="apnds.rom.Rom.arm7_overlays"></a>

#### arm7\_overlays

These are the ARM7 overlays of the ROM.

<a id="apnds.rom.Rom.files"></a>

#### files

This is the mapping of file paths to files in the ROM.

<a id="apnds.rom.Rom.file_order"></a>

#### file\_order

This is the physical order the files are located in the ROM, by path.

<a id="apnds.rom.Rom.banner"></a>

#### banner

This is the ROM's banner.

<a id="apnds.rom.Rom.from_bytes"></a>

#### from\_bytes

```python
@staticmethod
def from_bytes(rom: bytes) -> "Rom"
```

Decompose a ROM into its components.

<a id="apnds.rom.Rom.to_bytes"></a>

#### to\_bytes

```python
def to_bytes(storage_type: Literal["MROM"] | Literal["PROM"] = "PROM",
             fill_tail: bool = True,
             fill_with: bytes = b'\xFF') -> bytes
```

From the components of a ROM, construct the ROM.

