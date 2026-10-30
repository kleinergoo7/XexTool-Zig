# XexTool Zig

Zig 0.17.0 rewrite of [XexTool](https://github.com/Team-Resurgent/XexTool), the Xbox 360
XEX inspector, patcher, and packer.

The rewrite is in progress. The read-only XEX path already matches the C++ reference on
synthetic and reference-generated fixtures. The write path and the ported dependency
modules are being integrated.

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

Not implemented yet: `-p`, `-u`, `-s`, `-r s`, `pack`, and `genstubs`.

## Build

Requires Zig 0.17.0.

```sh
zig build
zig build test
```

`XexTool/` is the C++ reference tree. It is intentionally ignored; build it separately
when running differential tests.

## Layout

```text
src/cli/        option parsing and generated usage text
src/core/       endian, bounded cursor, DataBlock, file I/O
src/xecrypt/    XeCrypt subset used by XexTool
src/xex/        XEX model, header, reader, packer, printer, dumps, XML
src/lzx/        libLZX port (in progress)
src/tinyxml2/   tinyxml2 port (in progress)
```

## Differential tests

The reference build used during development:

```sh
git clone --recurse-submodules https://github.com/Team-Resurgent/XexTool.git
cmake -S XexTool -B /tmp/xextool-ref -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build /tmp/xextool-ref
```

Fixtures are generated locally and are not committed. Run comparisons with `TZ=UTC`.

## License

GPL-3.0-or-later. See `LICENSE` and `NOTICE`.
