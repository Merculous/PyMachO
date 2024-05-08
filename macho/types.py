
from dataclasses import dataclass
from enum import Enum

LC_REQ_DYLD = 0x80000000


@dataclass
class MachoHeader:
    # '<7I'
    magic: int
    cputype: int
    cpusubtype: int
    filetype: int
    ncmds: int
    sizeofcmds: int
    flags: int


@dataclass
class LoadCommand:
    # '<2I'
    cmd: int
    cmdsize: int


@dataclass
class SegmentCommand:
    # '<2I16s8I'
    cmd: int
    cmdsize: int
    segname: bytes
    vmaddr: int
    vmsize: int
    fileoff: int
    filesize: int
    maxprot: int
    initprot: int
    nsects: int
    flags: int


@dataclass
class Section:
    # '<16s16s9I'
    sectname: bytes
    segname: bytes
    addr: int
    size: int
    offset: int
    align: int
    reloff: int
    nreloc: int
    flags: int
    reserved1: int
    reserved2: int


@dataclass
class SymTabCommand:
    # '<6I'
    cmd: int
    cmdsize: int
    symoff: int
    nsyms: int
    stroff: int
    strsize: int


@dataclass
class NList:
    # '<I2BHI'
    n_strx: int
    n_type: int
    n_sect: int
    n_desc: int
    n_value: int


@dataclass
class UUIDCommand:
    # '<2I16s'
    cmd: int
    cmdsize: int
    uuid: bytes


# https://developer.apple.com/documentation/kernel/kmod_info_t

@dataclass
class KModInfo:
    # '<I2i64s64si6I'
    next: int
    info_version: int
    id: int
    name: bytes
    version: bytes
    reference_count: int
    reference_list: int
    address: int
    size: int
    hdr_size: int
    start: int
    stop: int


@dataclass
class ThreadCommand:
    cmd: int
    cmdsize: int
    flavor: int
    count: int
    state: bytes


class FileType(Enum):
    MH_OBJECT = 0x1
    MH_EXECUTE = 0x2
    MH_FVMLIB = 0x3
    MH_CORE = 0x4
    MH_PRELOAD = 0x5
    MH_DYLIB = 0x6
    MH_DYLINKER = 0x7
    MH_BUNDLE = 0x8
    MH_DYLIB_STUB = 0x9
    MH_DSYM = 0xa
    MH_KEXT_BUNDLE = 0xb


class Command(Enum):
    LC_SEGMENT = 0x1
    LC_SYMTAB = 0x2
    LC_SYMSEG = 0x3
    LC_THREAD = 0x4
    LC_UNIXTHREAD = 0x5
    LC_LOADFVMLIB = 0x6
    LC_IDFVMLIB = 0x7
    LC_IDENT = 0x8
    LC_FVMFILE = 0x9
    LC_PREPAGE = 0xa
    LC_DYSYMTAB = 0xb
    LC_LOAD_DYLIB = 0xc
    LC_ID_DYLIB = 0xd
    LC_LOAD_DYLINKER = 0xe
    LC_ID_DYLINKER = 0xf
    LC_PREBOUND_DYLIB = 0x10
    LC_ROUTINES = 0x11
    LC_SUB_FRAMEWORK = 0x12
    LC_SUB_UMBRELLA = 0x13
    LC_SUB_CLIENT = 0x14
    LC_SUB_LIBRARY = 0x15
    LC_TWOLEVEL_HINTS = 0x16
    LC_PREBIND_CKSUM = 0x17
    LC_LOAD_WEAK_DYLIB = (0x18 | LC_REQ_DYLD)
    LC_SEGMENT_64 = 0x19
    LC_ROUTINES_64 = 0x1a
    LC_UUID = 0x1b
    LC_RPATH = (0x1c | LC_REQ_DYLD)
    LC_CODE_SIGNATURE = 0x1d
    LC_SEGMENT_SPLIT_INFO = 0x1e
    LC_REEXPORT_DYLIB = (0x1f | LC_REQ_DYLD)
    LC_LAZY_LOAD_DYLIB = 0x20
    LC_ENCRYPTION_INFO = 0x21
    LC_DYLD_INFO = 0x22
    LC_DYLD_INFO_ONLY = (0x22 | LC_REQ_DYLD)
    LC_LOAD_UPWARD_DYLIB = (0x23 | LC_REQ_DYLD)
    LC_VERSION_MIN_MACOSX = 0x24
    LC_VERSION_MIN_IPHONEOS = 0x25
    LC_FUNCTION_STARTS = 0x26
    LC_DYLD_ENVIRONMENT = 0x27
    LC_MAIN = (0x28 | LC_REQ_DYLD)
    LC_DATA_IN_CODE = 0x29
    LC_SOURCE_VERSION = 0x2A
    LC_DYLIB_CODE_SIGN_DRS = 0x2B


# https://opensource.apple.com/source/xnu/xnu-4570.41.2/osfmk/mach/arm/thread_status.h.auto.html

class ARMThreadState(Enum):
    ARM_THREAD_STATE = 1
    ARM_VFP_STATE = 2
    ARM_EXCEPTION_STATE = 3
    ARM_DEBUG_STATE = 4
    THREAD_STATE_NONE = 5
    ARM_THREAD_STATE64 = 6
    ARM_EXCEPTION_STATE64 = 7
    ARM_THREAD_STATE_LAST = 8
    ARM_THREAD_STATE32 = 9
