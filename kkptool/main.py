#!/usr/bin/env python3

import argparse, os, shutil, subprocess, sys, traceback
from pathlib import Path

from . import kkp
from . import conv

__all__ = ['main']


try:
    import elftools
except ImportError:
    elftools = None


def get_rawkkp(args):
    inblob = None
    with open(args.input, 'rb') as f:
        inblob = f.read()

    rawkkp = None
    if inblob[0:4] == b"KK64":
        return kkp.parse(inblob)
    else:
        lzmaspec = args.lzmaspec
        if lzmaspec is None:
            raise Exception("'LzmaSpec' utility not found! Please either supply a KKP file as input, or specify the --lzmaspec flag.")

        rr = subprocess.run([lzmaspec, "--kkp", "/dev/stdout", args.input], capture_output=True)
        errstr = None if rr.stderr is None else rr.stderr.decode()
        if errstr and len(errstr) > 0 and len(errstr.strip()) > 0:
            print(errstr, file=sys.stderr)
        rr.check_returncode()
        return kkp.parse(rr.stdout)


def main_toc(args):
    akkp = get_rawkkp(args)

    if args.info is not None:
        try:
            if len(akkp.symbols) > 0 or len(akkp.sources) > 0:
                print("WARNING: KKP already has pre-existing information, discarding...", file=sys.stderr)
            akkp = conv.conv(rawkkp, args.info)
        except Exception:
            print("WARNING: couldn't use -s/--info symbol sources: " + traceback.format_exc(), file=sys.stderr)

    print("TODO")  # TODO

def main_conv(args):
    if args.info is None:
        print("ERROR: A symbol source file (using the -s/--info flag) is required for this command.", file=sys.stderr)
        return 1

    rawkkp = get_rawkkp(args)

    if len(rawkkp.symbols) > 0 or len(rawkkp.sources) > 0:
        print("WARNING: KKP already has pre-existing information, discarding...", file=sys.stderr)

    outkkp = conv(rawkkp, args.info)
    kkp.write_file(outkkp, args.output)
    return 0

def file_path(s: str) -> Path:
    p = Path(s)
    if p.is_file(): return p
    raise IOError("Path '%s' is not a file!"%s)

def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("-s", "--info", help="ELF or linker map file to source symbol and debug information from",
                        default=None, type=file_path)
    parser.add_argument("--lzmaspec", help="Path to the 'LzmaSpec' utility (needed if the input specified is an LZMA file).",
                        default=os.getenv("LZMASPEC", shutil.which("LzmaSpec")), type=str)

    subs = parser.add_subparsers(dest="subcommand",help="Selects the action to perform",required=True)

    toc = subs.add_parser("toc", help="Show a table-of-contents of the inputs.")
    toc.add_argument('input', type=file_path, help="Input file (KKP or LZMA)")

    conv = subs.add_parser("conv", help="Convert inputs to an information-rich KKP file.")
    conv.add_argument('input', type=file_path, help="Input file (KKP or LZMA)")
    conv.add_argument('output', type=Path, help="Output file (KKP)")

    args = parser.parse_args()
    #print(args)

    if args.subcommand == 'toc':
        main_toc(args)
    elif args.subcommand == 'conv':
        main_conv(args)
    else:
        assert False, args

if __name__ == '__main__':
    main()

