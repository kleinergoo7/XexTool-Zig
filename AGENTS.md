# XexTool Zig rewrite agent rules

Canonical policy for coding agents in this repository. The user's current request wins,
then this file, then the original `XexTool/` sources.

## Mission

Rewrite XexTool and its dependencies (XeCrypt, libLZX, tinyxml2) in Zig 0.17.0 with
byte-identical behavior for valid inputs. `XexTool/` is the reference tree and is never
modified.

## Build and verify

- Toolchain: Zig 0.17.0, pinned in `build.zig.zon`.
- After every Zig change: `zig fmt . && zig build && zig build test`.
- Decide success from the exit status. This host emits German diagnostics (`Fehler:`), so
  grepping for `error:` reports zero matches on a failed build.
- After a build, check the artifact mtime or hash. A stale binary looks like success.
- Never claim "done", "fixed", or "works" without the command and its output.
- Reference build: `cmake -S XexTool -B /tmp/opencode/xextool-ref -G Ninja -DCMAKE_BUILD_TYPE=Release`.
- Differential runs use the reference binary, `TZ=UTC`, and normalized build timestamps.

## Language rules

- New code is Zig 0.17.0. Never write std or build APIs from memory; read the installed
  std source (`zig env`, field `std_dir`) first.
- No C/C++ application files and no external Zig packages in the shipped tree.
- Fixed-width integers (`u8`..`u64`, `i8`..`i64`) for file data. Never `usize` for on-disk
  values.
- Bounds-check every read against the real buffer length before using it. Truncated input is
  the normal failure mode.
- On-disk layouts use `extern` or `packed struct` plus `comptime` size assertions, or explicit
  byte serialization.
- Use wrapping ops (`+%`, `-%`, `*%`) where the C++ original wraps or relies on unsigned
  arithmetic.
- Comment every `@intCast`, `@ptrCast`, and `@bitCast` with the check that makes it valid.
- Named constants for offsets and flags, not inline hex.

## Fidelity rules

- Preserve observable behavior: file layout, field order, header ordering, endianness,
  integer widths, fixed-width strings, error text, exit codes, and printf formatting.
- Port the algorithm; do not invent an equivalent one. This matters most for LZX output,
  RSA/signature paths, and tinyxml2 parse/print behavior.
- Preserve shipped quirks on valid inputs. For malformed inputs, return a named error instead
  of reproducing undefined behavior.
- No new features and no CLI redesign. The command surface stays `XexTool`.

## Errors and tests

- No silent failures: no `catch {}`, no `catch null`, no default that hides an error.
- Failures name the operation and input: path, offset, field, or record.
- Every function with a branch, loop, parser, or file-data arithmetic gets a test.
- Test blocks live beside the code and use `std.testing.allocator`.
- Assert concrete bytes, hashes, offsets, and counts, not truthiness.
- Fixtures come from `XEXTOOL_TEST_DIR` and are never committed. Tests skip with a clear
  message when the variable is unset.
- Tests never modify fixtures; output goes to a temp directory.

## Style

- Types PascalCase, functions camelCase, everything else snake_case.
- Short functions, early returns, shallow nesting.
- Comments explain why, citing the format fact, offset, or reference function.
- SPDX header on every source file: `GPL-3.0-or-later`.
- Keep module boundaries: `core` knows no XEX format details; `xex` does not own XML or CLI.
