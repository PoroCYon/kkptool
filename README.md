# kkptool

Tool and library to add symbol and source file and line information from ELF
executables to a KKP file (kkrunchy compression statistics report). Output KKP
files can be used with Conspiracy's [kkpView](https://github.com/ConspiracyHu/kkpView-public).

## Dependencies

* Python 3.9 or newer
* `pyelftools` (optional, for parsing DWARF information). Currently needs the
  latest development commit because of bugs otherwise not fixed.

## License

GPLv3+

## Usage

**NOTE**: the `toc` command is currently not yet implemented.

```
$ kkptool --help
usage: kkptool [-h] [-s INFO] [--lzmaspec LZMASPEC] {toc,conv} ...

positional arguments:
  {toc,conv}           Selects the action to perform
    toc                Show a table-of-contents of the inputs.
    conv               Convert inputs to an information-rich KKP file.

options:
  -h, --help           show this help message and exit
  -s, --info INFO      ELF or linker map file to source symbol and debug information from
  --lzmaspec LZMASPEC  Path to the 'LzmaSpec' utility (needed if the input specified is an LZMA file).
```
```
$ kkptool conv --help
usage: kkptool conv [-h] input output

positional arguments:
  input       Input file (KKP or LZMA)
  output      Output file (KKP)

options:
  -h, --help  show this help message and exit
```
```
$ kkptool toc --help
usage: kkptool toc [-h] input

positional arguments:
  input       Input file (KKP or LZMA)

options:
  -h, --help  show this help message and exit
```

## Example usage

Add information to an LZMA-compressed executable (using [LZMA-Vizualizer
](https://github.com/blackle/LZMA-Vizualizer)):

```sh
LzmaSpec --kkp without-info.kkp input.elf.lzma
kkptool -s input.elf.map conv without-info.kkp with-info.kkp  # using a linker map (-Wl,-Map)
kkptool -s input-dbg-build.elf conv without-info.kkp with-info.kkp  # using ELF symbol and debug information
```

Or simply:

```sh
kkptool --lzmaspec $(which LzmaSpec) -s input.elf.map conv input.elf.lzma with-info.kkp  # using a linker map (-Wl,-Map)
```

Or, using it as a Python library:

```python
import kkptool

rawkkp = kkptool.kkp.parse("path/to/without-info.kkp")
infoelf = kkptool.hackyelf.parse("path/to/input-with-symbols.elf")

kkp_with_info = kkptool.from_elf(rawkkp, hasinfo)

kkptool.kkp.write_file(kkp_with_info, "path/to/output-with-info.kkp")
```
