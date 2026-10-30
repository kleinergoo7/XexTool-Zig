# XexTool Zig

Zig 0.17.0 rewrite of [XexTool](https://github.com/Team-Resurgent/XexTool), the Xbox 360
XEX inspector, patcher, and packer.

The port is feature-complete. Valid-input output matches the C++ reference on every
exercised path; XeCrypt, libLZX, and tinyxml2 are Zig modules in this tree.

## What works

| Command | Status |
|---|---|
| no arguments / usage | byte-identical |
| `-l` extended info | byte-identical on raw and compressed reference fixtures |
| `-b <file>` basefile dump | byte-identical |
| `-i <file>` IDC dump | byte-identical |
| `-d <dir>` resource dump | byte-identical |
| `-x <flags>` XML metadata | byte-identical for implemented flags |
| `-z g <file>` info XML | byte-identical |
| `-z s <file>` set info | byte-identical |
| `-r`, `-m`, `-c`, `-e`, `-a`, `-o` | byte-identical on reference fixtures |
| `applyxml <xex> --xml <file>` | byte-identical |
| `-p <xexp>` XEXP patch | ported; synthetic patcher tests |
| `-u`, `-s`, `-r s` | ported; synthetic/table tests |
| `pack <elf> -o <xex>` | byte-identical on PPC ELF fixture |
| `genstubs` | ported; help/error behavior matches |

`pack` and the writer cover resources, imports, TLS, execution info, static libraries,
flags, strings, logo, multidisc IDs, and unknown entries.

Retail and devkit classification matches the reference. The encrypted devkit read path is
verified against a locally encrypted copy of a real devkit XEX. Remaining validation gaps
are a real XEXP/title-update fixture and a full XDK `.lib` directory for `genstubs`
output comparison.

## Build

Requires Zig 0.17.0.

```sh
zig build
zig build test
```

CI builds release binaries on Linux and Windows and uploads them as workflow
artifacts. The macOS runner is disabled until hosted capacity is reliable.

`XexTool/` is the C++ reference tree. It is intentionally ignored; build it separately
when running differential tests.

## Layout

```text
src/cli/        option parsing and generated usage text
src/core/       endian, bounded cursor, DataBlock, file I/O
src/xecrypt/    XeCrypt subset used by XexTool
src/xex/        XEX model, header, reader, packer, printer, dumps, XML
src/lzx/        libLZX port
src/tinyxml2/   tinyxml2 port
```

## Differential tests

The reference build used during development:

```sh
git clone --recurse-submodules https://github.com/Team-Resurgent/XexTool.git
cmake -S XexTool -B /tmp/xextool-ref -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build /tmp/xextool-ref
```

Fixtures are generated locally and are not committed. Run comparisons with `TZ=UTC`.
The banner carries the build time, so either strip its first line or pin it to the
reference text:

```sh
zig build -Dbuild-title="XexTool v7.0  -  xorloser 2006-2017 (Build ...)"
```

## License

GPL-3.0-or-later. See `LICENSE` and `NOTICE`.
