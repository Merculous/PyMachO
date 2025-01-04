
from .types import (
    LoadCommand,
    MachoHeader,
    Command,
    SegmentCommand,
    Section,
    SymTabCommand,
    UUIDCommand,
    ThreadCommand,
    KModInfo,
    DSYMTabCommand,
    VersionMinCommand,
    SourceVersionCommand,
    LinkEditDataCommand
)

from .kplist import kplist_parse
from .utils import readStruct


class MachO:
    MACHO_MAGIC = b'\xfe\xed\xfa\xce'

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.size = len(self.data)
        self.pos = 0
        self.head = self.parseMacho()
        self.kexts = self.parseKexts()

    def getMachoHeader(self) -> MachoHeader:
        return readStruct(self.pos, '<7I', 28, MachoHeader, self.data)

    def getLoadCommand(self) -> LoadCommand:
        return readStruct(self.pos, '<2I', 8, LoadCommand, self.data)

    def getLoadCommandType(self, cmd: int) -> Command:
        return Command(cmd)

    def getSegmentCommand(self) -> SegmentCommand:
        return readStruct(self.pos, '<2I16s8I', 56, SegmentCommand, self.data)

    def getSection(self) -> Section:
        return readStruct(self.pos, '<16s16s9I', 68, Section, self.data)

    def getSymbolTableCommand(self) -> SymTabCommand:
        return readStruct(self.pos, '<6I', 24, SymTabCommand, self.data)

    def getUUIDCommand(self) -> UUIDCommand:
        return readStruct(self.pos, '<2I16s', 24, UUIDCommand, self.data)

    def getThreadState(self) -> ThreadCommand:
        return readStruct(self.pos, '<4I68s', 84, ThreadCommand, self.data)

    def getKModInfo(self) -> KModInfo:
        return readStruct(self.pos, '<I2i64s64si6I', 168, KModInfo, self.data)

    def getDSYMTabCommand(self) -> DSYMTabCommand:
        return readStruct(self.pos, '<20I', 80, DSYMTabCommand, self.data)
    
    def getVersionMinCommand(self) -> VersionMinCommand:
        return readStruct(self.pos, '<4I', 16, VersionMinCommand, self.data)

    def getSourceVersionCommand(self) -> SourceVersionCommand:
        return readStruct(self.pos, '<2IQ', 16, SourceVersionCommand, self.data)

    def getLinkEditDataCommand(self) -> LinkEditDataCommand:
        return readStruct(self.pos, '<4I', 16, LinkEditDataCommand, self.data)

    def parseMacho(self) -> list:
        cmds = []

        machoHeader = self.getMachoHeader()

        if machoHeader.magic != int.from_bytes(self.MACHO_MAGIC):
            raise ValueError('Macho header magic is not 0xfeedface')

        self.pos += 28

        for _ in range(machoHeader.ncmds):
            lCmd = self.getLoadCommand()
            lCmdType = self.getLoadCommandType(lCmd.cmd)

            lCmdEndPos = self.pos + lCmd.cmdsize

            if lCmdType is Command.LC_SEGMENT:
                segCmd = self.getSegmentCommand()

                # TODO Check against load command data for sanity

                self.pos += 56
                sections = []

                if segCmd.nsects >= 1:
                    for _ in range(segCmd.nsects):
                        sect = self.getSection()
                        sections.append(sect)

                        self.pos += 68

                cmds.append([segCmd, sections])

            elif lCmdType is Command.LC_SYMTAB:
                symTab = self.getSymbolTableCommand()
                cmds.append(symTab)

                self.pos += 24

            elif lCmdType is Command.LC_UUID:
                uuidCmd = self.getUUIDCommand()
                cmds.append(uuidCmd)

                self.pos += 24

            elif lCmdType is Command.LC_UNIXTHREAD:
                thread = self.getThreadState()
                cmds.append(thread)

                self.pos += 84

            elif lCmdType is Command.LC_DYSYMTAB:
                dSymTabCmd = self.getDSYMTabCommand()
                cmds.append(dSymTabCmd)

                self.pos += 80

            elif lCmdType is Command.LC_VERSION_MIN_IPHONEOS:
                version = self.getVersionMinCommand()
                cmds.append(version)

                self.pos += 16

            elif lCmdType is Command.LC_SOURCE_VERSION:
                sVersion = self.getSourceVersionCommand()
                cmds.append(sVersion)

                self.pos += 16

            elif lCmdType is Command.LC_FUNCTION_STARTS:
                fStart = self.getLinkEditDataCommand()
                cmds.append(fStart)

                self.pos += 16

            else:
                pass

            if self.pos != lCmdEndPos:
                raise ValueError('Failed reading the correct amount of data!')

        return [machoHeader, cmds]

    def getKmodInfoOffset(self) -> None:
        pass

    def parseKexts(self) -> None:
        pass

    def getKextNames(self) -> list:
        return [kext[1].name.translate(None, b'\x00') for kext in self.kexts[1]]

    def printKextNames(self) -> None:
        names = sorted(self.getKextNames())
        kextCount = len(names)

        for i, name in enumerate(names, 1):
            print(f'[{i}/{kextCount}]: {name}')
