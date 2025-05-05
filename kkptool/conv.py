
import io, sys
from collections import OrderedDict
from pathlib import Path
from typing import Optional, Any, Callable, NamedTuple, Tuple, Union

from . import hackyelf
from . import linkmap
from . import kkp

from .kkp import *
from .linkmap import *
from .hackyelf import *


__all__ = ['conv', 'from_map', 'from_elf']


try:  # elftools is only an optional dependency
    import elftools
    from elftools.elf.elffile import ELFFile
    from elftools.dwarf.dwarfinfo import DWARFInfo

    # from https://github.com/eliben/pyelftools/blob/main/examples/dwarf_decode_address.py
    def decode_file_line(dwarfinfo, address):
        # Go over all the line programs in the DWARF information, looking for
        # one that describes the given address.
        for CU in dwarfinfo.iter_CUs():
            # First, look at line programs to find the file/line for the address
            lineprog = dwarfinfo.line_program_for_CU(CU)
            delta = 1 if lineprog.header.version < 5 else 0
            prevstate = None
            for entry in lineprog.get_entries():
                # We're interested in those entries where a new state is assigned
                if entry.state is None:
                    continue
                # Looking for a range of addresses in two consecutive states that
                # contain the required address.
                if prevstate and prevstate.address <= address < entry.state.address:
                    filename = lineprog['file_entry'][prevstate.file - delta].name
                    line = prevstate.line
                    return filename, line
                if entry.state.end_sequence:
                    # For the state with `end_sequence`, `address` means the address
                    # of the first byte after the target machine instruction
                    # sequence and other information is meaningless. We clear
                    # prevstate so that it's not used in the next iteration. Address
                    # info is used in the above comparison to see if we need to use
                    # the line information for the prevstate.
                    prevstate = None
                else:
                    prevstate = entry.state
        return None, None

    def decode_funcname(dwarfinfo, address):
        # Go over all DIEs in the DWARF information, looking for a subprogram
        # entry with an address range that includes the given address. Note that
        # this simplifies things by disregarding subprograms that may have
        # split address ranges.
        for CU in dwarfinfo.iter_CUs():
            for DIE in CU.iter_DIEs():
                try:
                    if DIE.tag == 'DW_TAG_subprogram':
                        lowpc = DIE.attributes['DW_AT_low_pc'].value

                        # DWARF v4 in section 2.17 describes how to interpret the
                        # DW_AT_high_pc attribute based on the class of its form.
                        # For class 'address' it's taken as an absolute address
                        # (similarly to DW_AT_low_pc); for class 'constant', it's
                        # an offset from DW_AT_low_pc.
                        highpc_attr = DIE.attributes['DW_AT_high_pc']
                        highpc_attr_class = describe_form_class(highpc_attr.form)
                        if highpc_attr_class == 'address':
                            highpc = highpc_attr.value
                        elif highpc_attr_class == 'constant':
                            highpc = lowpc + highpc_attr.value
                        else:
                            print('Error: invalid DW_AT_high_pc class:',
                                  highpc_attr_class)
                            continue

                        if lowpc <= address < highpc:
                            return DIE.attributes['DW_AT_name'].value
                except KeyError:
                    continue
        return None
except ImportError:
    elftools = None
    def decode_file_line(dwarfinfo, address): return None, None
    def decode_funcname(dwarfinfo, address): return None


__all__ = ['conv', 'from_map', 'from_elf']


class SymInfo(NamedTuple):
    ST_UNK = 0
    ST_TEXT = 1
    ST_DATA = 2  # not caring about ro vs rw here
    ST_BSS = 3

    name: str
    addr: int
    type: int

class DwarfInfo(NamedTuple):
    sym: Optional[SymInfo]
    file: Optional[str]
    line: Optional[int]

class WIPFile:
    def __init__(self, idx, name):
        self.idx = idx
        self.name = name
        self.uncompr_tot = 0
        self.compr_tot = 0.0
class WIPSymbol:
    def __init__(self, idx, name, off, iscode):
        self.idx = idx
        self.name = name
        self.off = off
        self.uncompr_tot = 0
        self.compr_tot = 0.0
        self.fileind = None
        self.iscode = iscode
class WIPContext:
    def __init__(self, relf, srcs, syms):
        self.relf = relf
        self.srcs = srcs
        self.syms = syms

    def getsym(self, name: str, off: int, iscode: bool) -> WIPSymbol:
        wsym = self.syms.get(name)
        if wsym is not None: return wsym

        if off == 0 and len(self.syms) == 1 and '<none>' in self.syms:
            del self.syms['<none>']

        wsym = WIPSymbol(len(self.syms), name, off, iscode)
        self.syms[name] = wsym
        return wsym

    def getsrc(self, file: Union[str, int]) -> WIPFile:
        if isinstance(file, int):
            if file < 0 or file >= len(self.srcs):
                raise ValueError("source index outside of range")

            for v in self.srcs.values():
                if v.idx == file: return v

            raise Exception("??? %d" % file)

        wsrc = self.srcs.get(file, None)
        if wsrc is not None: return wsrc

        wsrc = WIPFile(len(self.srcs), file)
        self.srcs[file] = wsrc
        return wsrc


CallbackFn = Callable[[int, KKPByte, Any, WIPContext], KKPByte]


def off2addr(relf: ELF, off: int) -> Optional[int]:
    for p in relf.phdrs:
        if off >= p.off and off < p.off + p.filesz:
            return p.vaddr + (off - p.off)
    return None

def addr2off(relf: ELF, addr: int) -> Optional[int]:
    for p in relf.phdrs:
        if addr >= p.vaddr and addr < p.vaddr + p.filesz:
            offoff = addr - p.vaddr
            return p.off + offoff
        elif addr >= p.vaddr and addr < p.vaddr + p.memsz:
            offoff = addr - p.vaddr
            return -(p.off + offoff) # BSS
    return None

def addr2sym_map(relf: ELF, map: LinkMap, addr: int) -> Optional[SymInfo]:
    lastmmap = None
    l = len(map.mmap)
    for i in range(l):  # these are already sorted by org (address)
        m = map.mmap[i]
        if m.org > addr: break

        end = None
        for j in range(i+1, l):
            if map.mmap[j].org == m.org: continue
            end = map.mmap[j].org
            break

        inrange = m.org <= addr and (end is None or end > addr)
        if inrange and (lastmmap is None or m.sym != '.'):
            lastmmap = m  # always use the last possible one

    if lastmmap is None: return None
    m = lastmmap

    typ = SymInfo.ST_UNK
    if m.sect.startswith('.text'): typ = SymInfo.ST_TEXT
    elif m.sect.startswith('.data') or m.sect.startswith('.rodata'): typ = SymInfo.ST_DATA
    elif m.sect.startswith('.bss'): typ = SymInfo.ST_BSS

    #print("addr", hex(addr), "->", m.sym, hex(m.org), typ)
    return SymInfo(m.sym, m.org, typ)

def addr2sym_elf(helf: ELF, addr: int) -> Optional[SymInfo]:
    symtabs = OrderedDict()
    # symtab first, then dynsym as backup (and then the rest)
    for x in ('.symtab', '.dynsym'):
        if x in helf.symtab: symtabs[x] = helf.symtab[x]
    for k, v in helf.symtab.items():
        if k not in ('.symtab', '.dynsym'): symtabs[k] = v

    lastsym = None
    for stname, symtab in symtabs.items():
        symtab = sorted(symtab, key=lambda sym: sym.value)
        l = len(symtab)
        for i in range(l):
            s = symtab[i]
            if s.value > addr: break  # went too far, stop

            end = None
            for j in range(i+1, l):
                if symtab[j].value == s.value: continue
                end = symtab[j].value
                break

            inrange = s.value <= addr and (end is None or end > addr)
            if inrange and (lastsym is None or s.name != '.' or isinstance(s.name, str)):
                lastsym = s # always use the last possible one that has ok info

        if lastsym is not None: break  # don't use backup symtab if we found a symbol

    if lastsym is None: return None
    s = lastsym

    typ = SymInfo.ST_UNK
    if s.type in (STT_FUNC, STT_GNU_IFUNC): typ = SymInfo.ST_TEXT
    elif s.type in (STT_OBJECT, STT_TLS, STT_COMMON): typ = SymInfo.ST_DATA
    #elif TODO: typ = SymInfo.ST_BSS  # TODO: implemlent

    return SymInfo(s.name if isinstance(s.name, str) else str(s.name), s.value, typ)

def addr2sym_dwarf(helf: ELF, dwarf, addr: int) -> DwarfInfo:
    elf_si = addr2sym_elf(helf, addr)

    dwarf_si = None
    try:
        name = decode_funcname(dwarf, addr)
    except Exception:
        name = None

    if name is not None:
        dwarf_si = SymInfo(name, addr, SymInfo.ST_UNK)

    try:
        file, line = decode_file_line(dwarf, addr)
    except Exception:
        file, line = None, None

    si = elf_si
    if dwarf_si is not None:  # merge info from elf & dwarf stuff
        si = SymInfo(dwarf_si.name, addr, elf_si.typ)

    return DwarfInfo(si, file, line)


def lookup_from_map(i: int, b: KKPByte, map: LinkMap, ctx: WIPContext) -> KKPByte:
    if ctx.relf is None:
        raise Exception("ERROR: when using a link map for metadata, the compressed data must be an ELF file!")

    addr = off2addr(ctx.relf, i)
    if addr is None:  # oops, nothing?
        return b._replace(sym=0, srcfile=0, srcline=0)

    sym = addr2sym_map(ctx.relf, map, addr)
    if sym is None:  # oops, nothing?
        return b._replace(sym=0, srcfile=0, srcline=0)

    symoff = addr2off(ctx.relf, sym.addr)
    if symoff is None or symoff < 0:  # bss or something -> shouldn't happen
        assert False, (sym, symoff)
        return b._replace(sym=0, srcfile=0, srcline=0)

    wsym = ctx.getsym(sym.name, symoff, sym.type < SymInfo.ST_DATA)
    wsym.uncompr_tot += 1
    wsym.compr_tot += b.compr_sz

    return KKPByte(b.value, wsym.idx, b.compr_sz, 0, 0)

def lookup_from_dwarf(i: int, b: KKPByte, elfdwarf: Tuple[ELF, Any], ctx: WIPContext) -> KKPByte:
    helf, dwarf = elfdwarf

    addr = off2addr(ctx.relf or helf, i)
    if addr is None:  # oops, nothing?
        return b._replace(sym=0, srcfile=0, srcline=0)

    sym, file, line = addr2sym_dwarf(helf, dwarf, addr)
    line = line or 0

    srcind = 0
    if file is not None:
        wsrc = ctx.getsrc(file)
        wsrc.uncompr_tot += 1
        wsrc.compr_tot += b.compr_sz
        srcind = wsrc.idx

    if sym is None:  # oops, nothing?
        return b._replace(sym=0, srcfile=srcind, srcline=line)

    symoff = addr2off(ctx.relf or helf, sym.addr)
    if symoff is None or symoff < 0:  # bss or something -> shouldn't happen
        assert False, (hex(addr), sym, symoff)
        return b._replace(sym=0, srcfile=srcind, srcline=line)

    wsym = ctx.getsym(sym.name, symoff, sym.type < SymInfo.ST_DATA)
    wsym.uncompr_tot += 1
    wsym.compr_tot += b.compr_sz

    if srcind != 0:
        if wsym.fileind != srcind and wsym.fileind is not None:
            print("WARNING: conflicting files for symbol '%s': '%s'<->'%s'"%\
                  (wsym.name, ctx.getsrc(wsym.fileind).name, ctx.getsrc(srcind).name), file=sys.stderr)
        wsym.fileind = srcind

    return KKPByte(b.value, wsym.idx, b.compr_sz, srcind, line)


def build_kkp(raw: KKP, cb: CallbackFn, ud) -> KKP:
    rawelf = None
    try:
        rawelf = hackyelf.parse(raw.extract_inner())
    except Exception:
        print("inner", raw.extract_inner())
        pass  # probably weird epoqe stuff

    srcdict = OrderedDict()
    symdict = OrderedDict()
    bins = []

    # dummy entries at index 0
    srcdict['<none>'] = WIPFile(0, '<none>')
    symdict['<none>'] = WIPSymbol(0, '<none>', 0, True)

    ctx = WIPContext(rawelf, srcdict, symdict)

    for i in range(len(raw.bindata)):
        bins.append(cb(i, raw.bindata[i], ud, ctx))

    if len(srcdict) == 1 and '<none>' in srcdict:  # no sources
        srcdict.clear()
    if len(symdict) == 1 and '<none>' in symdict:  # no symbols
        symdict.clear()

    srcs = []
    i = 0
    for v in srcdict.values():
        assert i == v.idx, (i, v)
        i += 1
        srcs.append(KKPSource(v.name, v.compr_tot, v.uncompr_tot))

    syms = []
    i = 0
    for v in symdict.values():
        assert i == v.idx, (i, v)
        i += 1
        syms.append(KKPSymbol(v.name, v.compr_tot, v.uncompr_tot, v.iscode, v.fileind or 0, v.off))

    return KKP(srcs, syms, bins)

def from_map(raw: KKP, map: LinkMap) -> KKP:
    return build_kkp(raw, lookup_from_map, map)

def from_elf(raw: KKP, elf: ELF, pelf) -> KKP:
    dwarf = None
    if pelf is not None and pelf.has_dwarf_info():
        dwarf = pelf.get_dwarf_info()

    return build_kkp(raw, lookup_from_dwarf, (elf, dwarf))

def conv(rawkkp: KKP, sym) -> KKP:
    #rawkkp = kkp.parse(inkkp)

    map, helf = None, None

    try:
        map = linkmap.parse(sym)
    except Exception:
        helf = hackyelf.parse(sym)

        if elftools is not None:
            if isinstance(sym, (str, Path)):
                with open(sym, 'rb') as f:
                    return from_elf(rawkkp, helf, ELFFile(f))
            elif isinstance(sym, (bytes, bytearray)):
                with io.BytesIO(sym) as f:
                    return from_elf(rawkkp, helf, ELFFile(f))
            else:
                return from_elf(rawkkp, helf, ELFFile(sym))

    if map is not None:
        return from_map(rawkkp, map)
    elif helf is not None:
        return from_elf(rawkkp, helf, None)

    raise Exception("huh??")

