
from io import BytesIO
from struct import pack, unpack
from typing import NamedTuple, Sequence, Union
from pathlib import Path


__all__ = ['KKPSource', 'KKPSymbol', 'KKPByte', 'KKP',
           #'parse', 'write_file', 'write_bytes'
          ]


class KKPSource(NamedTuple):
    name: str
    compr_sz: float
    uncompr_sz: int
class KKPSymbol(NamedTuple):
    name: str
    compr_sz: float
    uncompr_sz: int
    iscode: bool
    srcfile: Union[int, KKPSource]
    offset_in_binary: int
class KKPByte(NamedTuple):
    value: int
    sym: Union[int, KKPSymbol]
    compr_sz: float
    srcline: int
    srcfile: Union[int, KKPSource]

class KKP(NamedTuple):
    sources: Sequence[KKPSource]
    symbols: Sequence[KKPSymbol]
    bindata: Sequence[KKPByte]

    def extract_inner(self) -> bytes:
        ba = bytearray(len(self.bindata))
        for i in range(len(self.bindata)):
            ba[i] = self.bindata[i].value
        return ba


def read_strz(f) -> str:
    ba = bytearray()
    while True:
        r = f.read(1)
        if len(r) != 1: raise IOError("Unexpected end of file")
        if r[0] == 0: break
        ba.extend(r)
    return ba.decode('utf-8')

def write_strz(s: str, f):
    f.write(s if isinstance(s, (bytes, bytearray)) else s.encode('utf-8'))
    f.write(b'\x00')


def parse_file(f) -> KKP:
    if f.read(4) != b"KK64":  # check magic bytes
        raise Exception("Bad file header!")

    srcs, syms, bs = [], [], []

    nbytes, nsources = unpack('<II', f.read(8))
    for i in range(nsources):
        srcn = read_strz(f)
        compr, uncompr = unpack('<fI', f.read(8))
        srcs.append(KKPSource(srcn, compr, uncompr))

    nsyms = unpack('<I', f.read(4))[0]
    for i in range(nsyms):
        symn = read_strz(f)
        csz, usz, isc, srcidx, symoff = unpack('<dI?II', f.read(8+4+1+2*4))
        syms.append(KKPSymbol(symn, csz, usz, isc, srcidx, symoff))

    for i in range(nbytes):
        val, symidx, csz, srcln, srcidx = unpack('<BHdHH', f.read(1+2+8+2+2))
        bs.append(KKPByte(val, symidx, csz, srcln, srcidx))

    return KKP(srcs, syms, bs)


def parse(inp) -> KKP:
    if isinstance(inp, (bytes, bytearray)):
        with BytesIO(inp) as f:
            return parse_file(f)
    elif isinstance(inp, (str, Path)):
        with open(inp, 'rb') as f:
            return parse_file(f)
    else:
        return parse_file(inp)


def write_file_impl(kkp: KKP, f):
    f.write(b"KK64")
    f.write(pack('<II', len(kkp.bindata), len(kkp.sources)))

    for src in kkp.sources:
        write_strz(src.name, f)
        print("src", src)
        f.write(pack('<fI', src.compr_sz, src.uncompr_sz))

    f.write(pack('<I', len(kkp.symbols)))

    for sym in kkp.symbols:
        write_strz(sym.name, f)
        srcf = sym.srcfile
        if isinstance(srcf, KKPSource):
            srcf = kkp.sources.index(srcf)
        f.write(pack('<dI?II', sym.compr_sz, sym.uncompr_sz, sym.iscode, srcf, sym.offset_in_binary))

    for b in kkp.bindata:
        symidx, srcf = b.sym, b.srcfile
        if isinstance(symidx, KKPSymbol):
            symidx = kkp.symbols.index(symidx)
        if isinstance(srcf, KKPSource):
            srcf = kkp.sources.index(srcf)
        f.write(pack('<BHdHH', b.value, symidx, b.compr_sz, srcf, b.srcline))

def write_file(kkp: KKP, f):
    if isinstance(f, (str, Path)):
        with open(f, 'wb') as ff:
            write_file_impl(kkp, ff)
    else:
        write_file_impl(kkp, f)


def write_bytes(kkp: KKP) -> bytes:
    with BytesIO() as f:
        write_file_impl(kkp, f)
        return f.getvalue()

