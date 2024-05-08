
import re
# from dataclasses import astuple
from typing import Any

from .types import (
    MachoHeader,
    Command,
    LoadCommand,
    SegmentCommand,
    Section,
    SymTabCommand,
    NList,
    UUIDCommand,
    ThreadCommand,
    KModInfo,
    FileType
)

from .kplist import kplist_parse
from .utils import getAllNullTerminatedStrings, readStruct

MACHO_HEADER_SIZE = 28
LOAD_COMMAND_SIZE = 8
SEGMENT_COMMAND_SIZE = 56
SECTION_SIZE = 68
SYMBOL_TABLE_SIZE = 24
NLIST_SIZE = 12
UUID_COMMAND_SIZE = 24
KMOD_INFO_SIZE = 168

MACHO_MAGIC = b'\xfe\xed\xfa\xce'[::-1]

PRELINK_INFO_SEGNAME = b'__PRELINK_INFO'
PRELINK_INFO_SECTNAME = b'__info'
PRELINK_BUNDLE_PATH = '_PrelinkBundlePath'

DATA_SEGNAME = b'__DATA'
DATA_SECTNAME = b'__data'


class MachO:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.head, self.headCommands = self.getMachOHeaderWithCommands(0)
        self.kexts = self.getKexts()
        self.prelinkInfo = self.getPrelinkInfo()
        self.kextNames = self.listAllKextNames()

    def readMachoHeader(self, offset: int) -> MachoHeader:
        data = self.data[offset:offset+MACHO_HEADER_SIZE]
        return readStruct('<7I', MachoHeader, data)

    def readLoadCommand(self, offset: int) -> LoadCommand:
        data = self.data[offset:offset+LOAD_COMMAND_SIZE]
        return readStruct('<2I', LoadCommand, data)

    def readSegmentCommand(self, offset: int) -> SegmentCommand:
        data = self.data[offset:offset+SEGMENT_COMMAND_SIZE]
        return readStruct('<2I16s8I', SegmentCommand, data)

    def readSection(self, offset: int) -> Section:
        data = self.data[offset:offset+SECTION_SIZE]
        return readStruct('<16s16s9I', Section, data)

    def readSymbolTable(self, offset: int) -> SymTabCommand:
        data = self.data[offset:offset+SYMBOL_TABLE_SIZE]
        return readStruct('<6I', SymTabCommand, data)

    def readNList(self, offset: int) -> NList:
        data = self.data[offset:offset+NLIST_SIZE]
        return readStruct('<I2BHI', NList, data)

    def readUUID(self, offset: int) -> UUIDCommand:
        data = self.data[offset:offset+UUID_COMMAND_SIZE]
        return readStruct('<2I16s', UUIDCommand, data)

    def readThread(self, offset: int, cmdsize: int) -> ThreadCommand:
        state_size = cmdsize - 16  # FIXME State is a struct
        data = self.data[offset:offset+cmdsize]
        return readStruct(f'<4I{state_size}s', ThreadCommand, data)

    def readKmodInfo(self, offset: int) -> KModInfo:
        data = self.data[offset:offset+KMOD_INFO_SIZE]
        return readStruct('<I2i64s64si6I', KModInfo, data)

    def getCommandsAtPosition(self, position: int, ncmds: int) -> list[Any]:
        pos = position
        commands = []

        for _ in range(ncmds):
            lcmd = self.readLoadCommand(pos)
            lcmd_type = Command(lcmd.cmd)

            pos_end = pos + lcmd.cmdsize

            if lcmd_type is Command.LC_SEGMENT:
                segcmd = self.readSegmentCommand(pos)
                pos += SEGMENT_COMMAND_SIZE

                sections = []

                for _ in range(segcmd.nsects):
                    section = self.readSection(pos)
                    sections.append(section)
                    pos += SECTION_SIZE

                assert pos == pos_end
                commands.append([segcmd, sections])

            elif lcmd_type is Command.LC_SYMTAB:
                symtab = self.readSymbolTable(pos)
                symdata = self.data[symtab.stroff:symtab.stroff+symtab.strsize]
                syms = getAllNullTerminatedStrings(symdata)

                assert len(syms) == symtab.nsyms

                prev_pos = pos
                prev_end = pos_end
                pos = symtab.symoff
                pos_end = pos + symtab.nsyms * NLIST_SIZE

                assert (pos_end - pos) % NLIST_SIZE == 0

                sym_offsets = []

                for _ in range(symtab.nsyms):
                    nlist = self.readNList(pos)
                    sym_offsets.append(nlist)
                    pos += NLIST_SIZE

                assert pos == pos_end

                symbols = [[s, n] for s, n in zip(syms, sym_offsets)]
                commands.append([symtab, symbols])

                pos = prev_pos + SYMBOL_TABLE_SIZE
                pos_end = prev_end

            elif lcmd_type is Command.LC_UUID:
                uuid = self.readUUID(pos)
                commands.append(uuid)
                pos += UUID_COMMAND_SIZE

            elif lcmd_type in (Command.LC_THREAD, Command.LC_UNIXTHREAD):
                # Address in thread.state command will be _start
                thread = self.readThread(pos, lcmd.cmdsize)
                assert len(thread.state) == thread.count * 4
                commands.append(thread)
                pos += lcmd.cmdsize

            else:
                pass

        return commands

    def getMachOHeaderWithCommands(self, offset: int) -> list[Any]:
        header = self.readMachoHeader(offset)
        ncmds = header.ncmds
        offset += MACHO_HEADER_SIZE
        commands = self.getCommandsAtPosition(offset, ncmds)
        return [header, commands]

    def getKexts(self) -> list[Any]:
        commands = self.headCommands

        prelink_text = []

        for command in commands:
            if not isinstance(command, list):
                continue

            segment, sections = command
            segname = segment.segname.translate(None, b'\x00')

            if segname != b'__PRELINK_TEXT':
                continue

            prelink_text.extend([segment, sections])
            break

        segment, sections = prelink_text

        kextStart = segment.fileoff
        kextSize = segment.filesize
        kextData = self.data[kextStart:kextStart+kextSize]

        machoReg = re.compile(MACHO_MAGIC)
        machos = [x.start() + kextStart for x in machoReg.finditer(kextData)]

        kexts = []

        for offset in machos:
            kextHeader, kextCommands = self.getMachOHeaderWithCommands(offset)
            assert FileType(kextHeader.filetype) == FileType.MH_KEXT_BUNDLE

            kexts.append([kextHeader, kextCommands])

        return kexts

    def getSegmentWithSectionsFromName(
            self,
            name: bytes,
            isKext: bool = False
    ) -> list[list[SegmentCommand, list[Section]]]:

        matches = []

        if not isKext:
            for cmd in self.headCommands:
                if not isinstance(cmd, list):
                    continue

                seg, sects = cmd

                if not isinstance(seg, SegmentCommand):
                    continue

                segname = seg.segname.translate(None, b'\x00')

                if segname != name:
                    continue

                matches.append([seg, sects])

        else:
            pass

        return matches

    def getPrelinkInfo(self) -> list[dict]:
        prelinkInfo = self.getSegmentWithSectionsFromName(PRELINK_INFO_SEGNAME)
        assert len(prelinkInfo) == 1

        _, sects = prelinkInfo[0]
        assert len(sects) == 1

        sect = sects[0]
        sectName = sect.sectname.translate(None, b'\x00')

        if sectName != PRELINK_INFO_SECTNAME:
            raise Exception(f'{PRELINK_INFO_SECTNAME} section missing!')

        sectData = self.data[sect.offset:sect.offset+sect.size-1]
        return kplist_parse(sectData)

    def listAllKextNames(self) -> list[str]:
        names = []

        for info in self.prelinkInfo:
            path = info.get(PRELINK_BUNDLE_PATH)

            if path is None:
                continue

            name = path.split('/')[-1]
            names.append(name)

        return names

    def getDataFromSegment(self, segment: SegmentCommand) -> bytes:
        assert isinstance(segment, SegmentCommand)
        data = self.data[segment.fileoff:segment.fileoff+segment.filesize]
        return data

    def getDataFromSection(self, section: Section) -> bytes:
        assert isinstance(section, Section)
        data = self.data[section.offset:section.offset+section.size]
        return data

    def extractKexts(self):
        # TODO Kext size check from PRELINK_TEXT

        # https://github.com/xerub/macho
        # Thanks for the 32-bit support :P

        pass
