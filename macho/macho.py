
from .types import (
    LoadCommand,
    MachoHeader,
    Command,
    SegmentCommand,
    Section,
    SymTabCommand,
    UUIDCommand,
    ThreadCommand,
    KModInfo
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

            else:
                pass

            if self.pos != lCmdEndPos:
                raise ValueError('Failed reading the correct amount of data!')

        return [machoHeader, cmds]

    def getSegmentWithName(self, name: bytes, cmds: list) -> SegmentCommand:
        segCmd = None

        for cmd in cmds:
            if not isinstance(cmd, list):
                continue

            seg = cmd[0]
            segName = seg.segname.translate(None, b'\x00')

            if segName != name:
                continue

            segCmd = seg
            break

        if segCmd is None:
            raise ValueError(f'Could not segment with name {name}!')

        return segCmd

    def parseKexts(self) -> list:
        headCmds = self.head[1]

        prelinkText = self.getSegmentWithName(b'__PRELINK_TEXT', headCmds)
        kextStart = prelinkText.fileoff
        kextEnd = kextStart + prelinkText.filesize

        self.pos = kextStart

        kexts = []

        while self.pos != kextEnd and self.pos <= self.size:
            kextHeader, kextCmds = self.parseMacho()
            self.pos -= self.pos - kextStart

            # kModInfo lives at kextStart + __DATA.__data.fileoff
            # 0x288000 + 0x26000 = 0x2ae000 roughly...

            kextDataSeg = self.getSegmentWithName(b'__DATA', kextCmds)
            dataSegStart = self.pos + kextDataSeg.fileoff

            kModInfoData = self.data[dataSegStart:dataSegStart+kextDataSeg.filesize]
            kModPos = kModInfoData.find(b'com.')

            if kModPos == -1:
                # FIXME I don't like how I'm doing this, at least naming wise.
                # I don't know if other kexts start without "com." like so,
                # but this is temporary for now.
                kModSeatbeltPos = kModInfoData.find(b'security.mac_seatbelt')

                if kModSeatbeltPos == -1:
                    raise ValueError('Could not find kModInfo!')

                kModPos = kModSeatbeltPos

            kModInfoStart = dataSegStart + kModPos - 12
            self.pos = kModInfoStart

            kMod = self.getKModInfo()

            if kModPos > 12:
                self.pos -= kModPos - 12

            self.pos -= kextDataSeg.fileoff
            self.pos += kMod.size
            kextStart = self.pos

            kexts.append([kextHeader, kMod, kextCmds])

        prelinkInfo = self.getSegmentWithName(b'__PRELINK_INFO', headCmds)

        if self.pos != prelinkInfo.fileoff:
            raise ValueError('Current position does not match PRELINK_INFO!')

        prelinkInfoData = self.data[prelinkInfo.fileoff:prelinkInfo.fileoff+prelinkInfo.filesize]
        infoEndBuff = prelinkInfoData[-200:]  # FIXME This is sucky

        prelinkInfoData = prelinkInfoData.replace(infoEndBuff, infoEndBuff.translate(None, b'\x00'))
        prelinkInfoPlist = kplist_parse(prelinkInfoData)

        return [prelinkInfoPlist, kexts]

    def getKextNames(self) -> list:
        return [kext[1].name.translate(None, b'\x00') for kext in self.kexts[1]]

    def printKextNames(self) -> None:
        names = sorted(self.getKextNames())
        kextCount = len(names)

        for i, name in enumerate(names, 1):
            print(f'[{i}/{kextCount}]: {name}')
