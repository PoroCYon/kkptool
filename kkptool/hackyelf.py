
# custom elf parser because a standard one wouldn't be trustable because the
# ELFs we're parsing will be a bit wonky anyway

from struct import unpack
from typing import NamedTuple, Callable, Optional, Sequence, Dict, Union, Tuple
from pathlib import Path


_bytes = Union[bytes, bytearray]


ELFCLASS32 = 1
ELFCLASS64 = 2

ELFDATA2LSB = 1
ELFDATA2MSB = 2

EM_386    =  3
EM_ARM    = 40
EM_X86_64 = 62

PT_NULL    = 0
PT_LOAD    = 1
PT_DYNAMIC = 2
PT_INTERP  = 3
PT_NOTE    = 4
PT_PHDR    = 6
PT_GNU_STACK = 0x6474e551

DT_NULL    =  0
DT_NEEDED  =  1
DT_PLTRELSZ=  2
DT_PLTGOT  =  3
DT_STRTAB  =  5
DT_SYMTAB  =  6
DT_RELA    =  7
DT_RELASZ  =  8
DT_RELAENT =  9
DT_STRSZ   = 10
DT_SYMENT  = 11
DT_SONAME  = 14
DT_REL     = 17
DT_RELSZ   = 18
DT_RELENT  = 19
DT_PLTREL  = 20
DT_DEBUG   = 21
DT_TEXTREL = 22
DT_JMPREL  = 23
DT_BIND_NOW= 24
DT_FLAGS_1 = 0x6ffffffb

DF_1_PIE = 0x08000000

SHT_NULL     =  0
SHT_PROGBITS =  1
SHT_SYMTAB   =  2
SHT_STRTAB   =  3
SHT_RELA     =  4
SHT_DYNAMIC  =  6
SHT_NOBITS   =  8
SHT_REL      =  9
SHT_DYNSYM   = 11

SHF_WRITE     = 1<<0
SHF_ALLOC     = 1<<1
SHF_EXECINSTR = 1<<2
SHF_MERGE     = 1<<4
SHF_STRINGS   = 1<<5
SHF_INFO_LINK = 1<<6

STB_LOCAL  = 0
STB_GLOBAL = 1
STB_WEAK   = 2

STT_NOTYPE = 0
STT_OBJECT = 1
STT_FUNC   = 2
STT_SECTION= 3
STT_FILE   = 4
STT_COMMON = 5
STT_TLS    = 6
STT_GNU_IFUNC = 10

STV_DEFAULT   = 0
STV_INTERNAL  = 1
STV_HIDDEN    = 2
STV_PROTECTED = 3

class Phdr(NamedTuple):
    ptype: int
    off  : int
    vaddr: int
    paddr: int
    filesz: int
    memsz: int
    flags: int
    align: int

class Dyn(NamedTuple):
    tag: int
    val: int

class Shdr(NamedTuple):
    name: Union[int, str]
    type: int
    flags: int
    addr: int
    offset: int
    size: int
    link: int
    info: int
    addralign: int
    entsize: int

class Sym(NamedTuple):
    name: Union[str, _bytes, Tuple[int, int]]
    value: int
    size: int
    type: int
    binding: int
    visibility: int
    shndx: int

class Rel(NamedTuple):
    offset: int
    symbol: Union[Sym, int]
    type: int
class Rela(NamedTuple):
    offset: int
    symbol: Union[Sym, int]
    type: int
    addend: int
Reloc = Union[Rel, Rela]

class Note(NamedTuple):
    name: str|_bytes
    type: int
    desc: bytes

class Ehdr(NamedTuple):
    ident   : bytes
    etype   : int
    mach    : int
    version : int
    entry   : int
    phoff   : int
    shoff   : int
    flags   : int
    ehsize  : int
    phentsz : int
    phnum   : int
    shentsz : int
    shnum   : int
    shstrndx: int

    @property
    def eclass(self) -> int: return self.ident[4]
    @property
    def endian(self) -> int: return self.ident[5]
    @property
    def version(self) -> int: return self.ident[6]
    @property
    def osabi(self) -> int: return self.ident[7]
    @property
    def abiversion(self) -> int: return self.ident[8]

class ElfReader(NamedTuple):
    ehdr: Callable[_bytes, Ehdr]
    phdr: Callable[[_bytes, Ehdr], Sequence[Phdr]]
    shdr: Callable[[_bytes, Ehdr], Sequence[Shdr]]
    dyn: Callable[[_bytes, Phdr], Sequence[Dyn]]
    note: Callable[[_bytes, Phdr], Sequence[Note]]
    sym: Callable[[_bytes, int, Optional[int], int, int, Optional[int]], Sequence[Sym]]
    reloc: Callable[[_bytes, int, Optional[int], int, Optional[Sequence[Sym]], bool], Sequence[Reloc]]

    def sym_shdr(self, data: _bytes, symtab: Shdr, strtab: Union[Shdr, int]) -> Sequence[Sym]:
        return self.sym(data, symtab.offset, symtab.size, symtab.entsize,
                        *((strtab, None) if isinstance(strtab, int) else (strtab.offset, strtab.size)))
    def reloc_shdr(self, data: _bytes, relocs: Shdr, symtab: Sequence[Sym]) -> Sequence[Reloc]:
        return self.reloc(data, relocs.offset, relocs.size, relocs.entsize, symtab, relocs.type == SHT_RELA)


class ELF(NamedTuple):
    data: _bytes
    ehdr: Ehdr

    # runtime view
    phdrs : Sequence[Phdr]
    dyn   : Sequence[Dyn]
    dynsym: Sequence[Sym]
    dynrel: Sequence[Reloc]
    pltrel: Sequence[Reloc]
    notes : Sequence[Note]

    # offline linking view
    shdrs : Sequence[Shdr]
    symtab: Dict[str, Sequence[Sym]]
    relocs: Dict[str, Sequence[Reloc]]

    bits  : int

def readstr(data: _bytes, off: int) -> str|_bytes:
    strb = bytearray()
    while data[off] != 0 and off < len(data):
        strb.append(data[off])
        off = off + 1
    try:
        return strb.decode('utf-8')
    except:
        return strb

def find_dyn(dyn: Sequence[Dyn], tag: int) -> Optional[int]:
    for x in dyn:
        if x.tag == tag: return x.val
    return None

### 32-bit parsers ############################################################

def parse_phdr32(data: _bytes, ehdr: Ehdr) -> Sequence[Phdr]:
    ps = []
    for off in range(ehdr.phoff, ehdr.phoff+ehdr.phentsz*ehdr.phnum, ehdr.phentsz):
        if off + ehdr.phentsz > len(data):
            break

        ptype, poff, vaddr, paddr, filesz, memsz, flags, align = \
            unpack('<IIIIIIII', data[off:off+8*4])
        p = Phdr(ptype, poff, vaddr, paddr, filesz, memsz, flags, align)
        ps.append(p)

    return ps

def parse_dyn32(data: _bytes, dynp: Phdr) -> Sequence[Dyn]:
    ds = []

    off = dynp.off
    while True:
        tag, val = unpack('<II', data[off:off+2*4])
        ds.append(Dyn(tag, val))

        if tag == DT_NULL: break
        off = off + 2*4

    return ds

def parse_reloc32(data: _bytes, reloff: int, relsz: Optional[int], entsz: int, syms: Optional[Sequence[Sym]], rela: bool) -> Sequence[Reloc]:
    rr=[]

    rsz = relsz or (len(data) - reloff)
    for off in range(reloff, reloff+rsz, entsz):
        roff, inf, add = unpack('<IIi', data[off:(off+12)]) if rela else (*unpack('<Ii', data[off:(off+8)]),None)
        sym = syms[inf >> 8] if syms is not None and (inf >> 8) < len(syms) else (inf >> 8)
        type = inf & 0xff

        if relsz is None:  # no defined end -> need to stop somehwere
            if isinstance(sym, int): break

        rr.append(Rela(roff, sym, type, add) if rela else Rel(roff, sym, type))

    return rr

def parse_shdr32(data: _bytes, ehdr: Ehdr) -> Sequence[Shdr]:
    if ehdr.shnum*ehdr.shentsz+ehdr.shoff > len(data) or ehdr.shentsz==0 or ehdr.shnum==0 or ehdr.shoff==0:
        #print("snum*shentsz+shoff",shnum*shentsz+shoff)
        #print("len(data)",len(data))
        #print("shentsz",shentsz)
        #print("shnum",shnum)
        #print("shoff",shoff)
        return []

    ss = []
    for off in range(ehdr.shoff, ehdr.shoff+ehdr.shentsz*ehdr.shnum, ehdr.shentsz):
        noff, typ, flags, addr, soff, size, link, info, align, entsz = \
            unpack('<IIIIIIIIII', data[off:off+10*4])
        s = Shdr(noff, typ, flags, addr, soff, size, link, info, align, entsz)
        ss.append(s)

    if ehdr.shstrndx < ehdr.shnum:
        shstr = ss[ehdr.shstrndx]
        for i in range(len(ss)):
            sname = readstr(data, shstr.offset + ss[i].name) \
                if ss[i].name < shstr.size else None
            ss[i] = Shdr(sname, ss[i].type, ss[i].flags, ss[i].addr,
                         ss[i].offset, ss[i].size, ss[i].link, ss[i].info,
                         ss[i].addralign, ss[i].entsize)

    return ss

def parse_sym32(data: _bytes, symoff: int, symsz: Optional[int], symentsz: int, stroff: int, strsz: Optional[int]) -> Sequence[Sym]:
    ss = []
    ssz = symsz or (len(data)-symoff)
    for off in range(symoff, symoff+ssz, symentsz):
        noff, val, sz, info, other, shndx = unpack('<IIIBBH', data[off:off+3*4+2+2])

        if symsz is None:  # need to stop at some point when table has no defined end
            if strsz is not None and noff >= strsz: break
            if other > 3: break  # invalid symbol visibility
            if shndx > 63: break  # probably a good heuristic

        sn = readstr(data, stroff + noff) if strsz is not None and noff < strsz else (stroff, noff)
        s = Sym(sn, val, sz, (info & 15), (info >> 4), other, shndx)
        ss.append(s)
    return ss#sorted(ss, key=lambda x:x.value)

def parse_note32(data: bytes, nphdr: Phdr) -> Sequence[Note]:
    ret = []

    assert nphdr.ptype == PT_NOTE

    off = nphdr.off
    end = off + nphdr.filesz

    while off < end:
        namesz, descsz, typ = unpack('<III', data[off:off+3*4])
        off += 3*4
        name = readstr(data, off)
        off += namesz

        # realign here; typically alignment is 4 bytes
        if (off % nphdr.align) != 0:
            off += nphdr.align - (off % nphdr.align)
        desc = data[off:off+descsz]

        off += descsz

        # realign here; typically alignment is 4 bytes
        if (off % nphdr.align) != 0:
            off += nphdr.align - (off % nphdr.align)

        ret.append(Note(name, typ, desc))

    return ret

def parse_ehdr32(data: _bytes) -> Ehdr:
    ident = data[:16]
    etype, mach, version, entry, phoff, shoff, flags, ehsize, phentsz, phnum, \
        shentsz, shnum, shstrndx = unpack('<HHIIIIIHHHHHH', data[16:52])

    return Ehdr(ident, etype, mach, version, entry, phoff, shoff, flags, ehsize, phentsz, phnum, shentsz, shnum, shstrndx)

### 64-bit now ################################################################

def parse_phdr64(data: _bytes, ehdr: Ehdr) -> Sequence[Phdr]:
    ps = []
    for off in range(ehdr.phoff, ehdr.phoff+ehdr.phentsz*ehdr.phnum, ehdr.phentsz):
        if off + ehdr.phentsz > len(data):
            break

        # TODO # what is TODO exactly??
        ptype, flags, poff, vaddr, paddr, filesz, memsz, align = \
            unpack('<IIQQQQQQ', data[off:off+2*4+6*8])
        p = Phdr(ptype, poff, vaddr, paddr, filesz, memsz, flags, align)
        ps.append(p)

    return ps

def parse_dyn64(data: _bytes, dynp: Phdr) -> Dyn:
    ds = []

    off = dynp.off
    while True:
        tag, val = unpack('<QQ', data[off:off+2*8])
        ds.append(Dyn(tag, val))

        if tag == DT_NULL: break
        off = off + 2*8

    return ds

def parse_reloc64(data: _bytes, reloff: int, relsz: Optional[int], entsz: int, syms: Optional[Sequence[Sym]], rela: bool) -> Reloc:
    rr=[]

    rsz = relsz or (len(data) - reloff)
    for off in range(reloff, reloff+rsz, entsz):
        roff, inf, add = unpack('<QQq', data[off:(off+24)]) if rela \
            else (*unpack('<Qq', data[off:(off+16)]),None)
        sym = syms[inf >> 32] if syms is not None and (inf >> 32) < len(syms) else (inf >> 32)
        type = inf & 0xffffffff

        if relsz is None:  # no defined end -> need to stop somehwere
            if isinstance(sym, int): break

        rr.append(Rela(roff, sym, type, add) if rela else Rel(roff, sym, type))

    return rr

def parse_shdr64(data: _bytes, ehdr: Ehdr) -> Sequence[Shdr]:

    if ehdr.shnum*ehdr.shentsz+ehdr.shoff > len(data) or ehdr.shentsz==0 or ehdr.shnum==0 or ehdr.shoff==0:
        return []

    ss = []
    for off in range(ehdr.shoff, ehdr.shoff+ehdr.shentsz*ehdr.shnum, ehdr.shentsz):
        noff, typ, flags, addr, soff, size, link, info, align, entsz = \
            unpack('<IIQQQQIIQQ', data[off:off+4*4+6*8])
        s = Shdr(noff, typ, flags, addr, soff, size, link, info, align, entsz)
        ss.append(s)

    if ehdr.shstrndx < ehdr.shnum:
        shstr = ss[ehdr.shstrndx]
        for i in range(len(ss)):
            sname = readstr(data, shstr.offset + ss[i].name) \
                if ss[i].name < shstr.size else None
            ss[i] = Shdr(sname, ss[i].type, ss[i].flags, ss[i].addr,
                         ss[i].offset, ss[i].size, ss[i].link, ss[i].info,
                         ss[i].addralign, ss[i].entsize)

    return ss

def parse_sym64(data: _bytes, symoff: int, symsz: Optional[int], symentsz: int, stroff: int, strsz: Optional[int]) -> Sequence[Sym]:
    ss = []
    ssz = symsz or (len(data)-symoff)
    for off in range(symoff, symoff+ssz, symentsz):
        noff, info, other, shndx, value, sz = unpack('<IBBHQQ', data[off:off+4+2+2+8*2])

        if symsz is None:  # need to stop at some point when table has no defined end
            if strsz is not None and noff >= strsz: break
            if other > 3: break  # invalid symbol visibility
            if shndx > 63: break  # probably a good heuristic

        sn = readstr(data, stroff + noff) if strsz is not None and noff < strsz else (stroff, noff)
        s = Sym(sn, value, sz, (info & 15), (info >> 4), other, shndx)
        ss.append(s)
    return ss#sorted(ss, key=lambda x:x.value)

# format is same as note32, so eh
parse_note64 = parse_note32

def parse_ehdr64(data: _bytes) -> Ehdr:
    ident   = data[:16]
    etype, mach, version, entry, phoff, shoff, flags, ehsize, phentsz, phnum, \
        shentsz, shnum, shstrndx = unpack('<HHIQQQIHHHHHH', data[16:64])

    return Ehdr(ident, etype, mach, version, entry, phoff, shoff, flags, ehsize, phentsz, phnum, shentsz, shnum, shstrndx)

### higher-level parsing ######################################################

_READERS = {
    32: ElfReader(parse_ehdr32, parse_phdr32, parse_shdr32, parse_dyn32, parse_note32,
                  parse_sym32, parse_reloc32),
    64: ElfReader(parse_ehdr64, parse_phdr64, parse_shdr64, parse_dyn64, parse_note64,
                  parse_sym64, parse_reloc64)
}


def parse(data) -> ELF:
    if isinstance(data, (str, Path)):
        data = open(data, 'rb').read()
    elif not isinstance(data, _bytes):
        data = data.read()

    if data[:4] != b'\x7FELF' or len(data) < 42:  # good enough
        raise Exception("Not a valid ELF file: %s, (len %d)" % (repr(data[:4]), len(data)))

    bits = None

    ecls = data[4]
    emch = unpack('<H', data[18:18+2])[0]
    if ecls == ELFCLASS32:
        # thank you, epoqe, for this extra special-casing that's somehow needed
        # (because the linux kernel's ELF file parser is very weird)
        bits = 64 if emch == EM_X86_64 else 32
    elif ecls == ELFCLASS64: bits = 64
    else:
        if emch == EM_386: bits = 32
        elif emch == EM_X86_64: bits = 64
        else:
            raise Exception("bad E_CLASS %d and e_machine %d (0x%x)" % (ecls, emch, emch))
    assert bits is not None

    # skip x86es for this check, for "reasons"
    if emch not in (EM_386, EM_X86_64) and data[5] == ELFDATA2MSB:
        raise Exception("Sorry, big-endian ELF files not supported")

    reader = _READERS[bits]
    ehdr = reader.ehdr(data)

    # runtime view

    phdrs = [] if ehdr.phentsz == 0 else reader.phdr(data, ehdr)
    dyn   = None
    notes = []

    for p in phdrs:
        if p.ptype == PT_DYNAMIC and dyn is None:
            dyn = reader.dyn(data, p)
        elif p.ptype == PT_NOTE:
            notes += reader.note(data, p)

    # symtab, syment, strtab, strsz ---> can't derive dynsym size!
    # RELA, RELASZ, RELAENT
    # REL, RELSZ, RELENT
    # JMPREL, PLTREL, PLTRELSZ ---> can't derive table size!
    dynsym = []
    dynrel = []
    pltrel = []
    if dyn is not None:
        dyn_symtab = find_dyn(dyn, DT_SYMTAB)
        dyn_syment = find_dyn(dyn, DT_SYMENT) or {32:16,64:24}[bits]
        dyn_strtab = find_dyn(dyn, DT_STRTAB)
        dyn_strsz  = find_dyn(dyn, DT_STRSZ)  or \
            ((len(data)-dyn_strtab) if dyn_strtab is not None else None)
        if dyn_symtab is not None:
            dynsym = reader.sym(data, dyn_symtab, None, dyn_syment,
                                *((dyn_strtab, dyn_strsz) if dyn_strtab is not None else (-1, None)))

        dyn_rela    = find_dyn(dyn, DT_RELA)
        dyn_relasz  = find_dyn(dyn, DT_RELASZ)
        dyn_relaent = find_dyn(dyn, DT_RELAENT) or {32:12,64:24}[bits]
        if dyn_rela is not None:  # and dyn_relasz is not None:
            dynrel += reader.reloc(data, dyn_rela, dyn_relasz, dyn_relaent, dynsym, True)

        dyn_rel    = find_dyn(dyn, DT_REL)
        dyn_relsz  = find_dyn(dyn, DT_RELSZ)
        dyn_relent = find_dyn(dyn, DT_RELENT) or {32:12,64:24}[bits]
        if dyn_rel is not None:  # and dyn_relsz is not None:
            dynrel += reader.reloc(data, dyn_rel, dyn_relsz, dyn_relent, dynsym, True)

        pltrel_has_a = find_dyn(dyn, DT_PLTREL) != DT_REL
        jmprel = find_dyn(dyn, DT_JMPREL)
        pltrelsz = find_dyn(dyn, DT_PLTRELSZ)
        pltrelent = (3 if pltrel_has_a else 2) * {32:4,64:8}[bits]  # default is RELA
        if jmprel is not None:
            pltrel = reader.reloc(data, jmprel, pltrelsz, pltrelent, dynsym, pltrel_has_a)

    # offline linking view

    shdrs = [] if ehdr.shentsz == 0 else reader.shdr(data, ehdr)

    symtabs = {}
    relocs = {}
    for s in shdrs:
        if s.type == SHT_SYMTAB or s.type == SHT_DYNSYM:
            strt = shdrs[s.link] if s.link < len(shdrs) and shdrs[s.link].type == SHT_STRTAB else s.link
            assert s.name not in symtabs, s
            symtabs[s.name] = reader.sym_shdr(data, s, strt)
        elif s.type == SHT_REL or s.type == SHT_RELA:
            symt = shdrs[s.link] if s.link < len(shdrs) and shdrs[s.link].type in (SHT_SYMTAB, SHT_DYNSYM) else None
            assert s.name not in relocs, s
            relocs[s.name] = reader.reloc_shdr(data, s, symtabs.get(None if symt is None else symt.name))

    return ELF(data, ehdr,
               phdrs, dyn, dynsym, dynrel, pltrel, notes,
               shdrs, symtabs, relocs,
               bits)

__all__ = [ 'ELF',  #'parse', 'find_dyn',
            'Phdr', 'Dyn', 'Shdr', 'Sym', 'Rel', 'Rela', 'Ehdr', 'Reloc', 'Note',
            *(s for s in locals().keys() if s.upper() == s and s[0] != '_')]

