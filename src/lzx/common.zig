// SPDX-FileCopyrightText: 2026 XexTool Zig rewrite contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Shared libLZX definitions, transliterated from
// XexTool/third_party/libLZX/lzx/lzx.h and its encoder/decoder tables.

const std = @import("std");

/// LZX_WINDOW_SIZE: the default window and the largest one the format allows.
pub const window_size: u32 = 128 * 1024;
/// LZX_CHUNK_SIZE: uncompressed bytes per output block.
pub const chunk_size: u32 = 32 * 1024;
/// LZX_MAX_GROWTH: extra compressed bytes a chunk may need.
pub const max_growth: u32 = 6144;
/// LZX_OUTPUT_SIZE: capacity of the encoder/decoder bit buffers.
pub const output_size: u32 = chunk_size + max_growth;
/// LZX_NUM_REPEATED_OFFSETS.
pub const num_repeated_offsets: u32 = 3;
/// LZX_MIN_MATCH.
pub const min_match: u32 = 2;
/// LZX_MAX_MATCH.
pub const max_match: u32 = min_match + 255;
/// LZX_NUM_PRIMARY_LEN.
pub const num_primary_len: u32 = 7;
/// LZX_NUM_SECONDARY_LEN (249): match lengths 9..257 live in the second tree.
pub const num_secondary_len: u32 = (max_match - min_match + 1) - num_primary_len;
/// LZX_ALIGNED_TABLE_BITS.
pub const aligned_table_bits: u5 = 7;
/// LZX_ALIGNED_NUM_ELEMENTS.
pub const aligned_num_elements: u32 = 8;
/// LZX_MAX_MAIN_TREE_ELEMENTS.
pub const max_main_tree_elements: u32 = 700;
/// MAIN_TREE_TABLE_BITS.
pub const main_tree_table_bits: u5 = 10;
/// SECONDARY_LEN_TREE_TABLE_BITS.
pub const secondary_len_tree_table_bits: u5 = 8;
/// DS_TABLE_BITS used by the meta tree reader.
pub const small_tree_table_bits: u5 = 8;
/// NUM_DECODE_SMALL: number of meta tree symbols.
pub const num_decode_small: u32 = 20;
/// LZX_MAIN_TREE_ELEMENTS(x) = 256 + (x << 3).
pub fn mainTreeElements(num_position_slots: u32) u32 {
    return 256 + (num_position_slots << 3);
}

/// The window must be a power of two from 2^15 to 2^21.
pub fn isValidWindowSize(size: u32) bool {
    return size >= (1 << 15) and size <= (1 << 21) and (size & (size - 1)) == 0;
}

/// Error codes from lzx.h, kept so callers can report the original number.
pub const ErrorCode = enum(u32) {
    success = 0,
    failed = 1,
    buffer_overflow = 4,
    out_of_memory = 5,
    invalid_data = 6,
};

pub const Error = std.mem.Allocator.Error || error{
    LzxFailed,
    LzxBufferOverflow,
    LzxInvalidData,
};

pub fn codeOf(err: Error) ErrorCode {
    return switch (err) {
        error.OutOfMemory => .out_of_memory,
        error.LzxFailed => .failed,
        error.LzxBufferOverflow => .buffer_overflow,
        error.LzxInvalidData => .invalid_data,
    };
}

pub const BlockType = enum(u32) {
    invalid = 0,
    verbatim = 1,
    aligned = 2,
    uncompressed = 3,
};

/// lzx_extra_bits from both C files (they are identical).
pub const extra_bits = [51]u8{
    0,  0,  0,  0,  1,  1,  2,  2,
    3,  3,  4,  4,  5,  5,  6,  6,
    7,  7,  8,  8,  9,  9,  10, 10,
    11, 11, 12, 12, 13, 13, 14, 14,
    15, 15, 16, 16, 17, 17, 17, 17,
    17, 17, 17, 17, 17, 17, 17, 17,
    17, 17, 17,
};

/// match_pos_minus2 from lzx_decoder.c. Kept signed, the C table is long.
pub const match_pos_minus2 = [51]i32{
    0 - 2,       1 - 2,       2 - 2,       3 - 2,       4 - 2,       6 - 2,       8 - 2,       12 - 2,
    16 - 2,      24 - 2,      32 - 2,      48 - 2,      64 - 2,      96 - 2,      128 - 2,     192 - 2,
    256 - 2,     384 - 2,     512 - 2,     768 - 2,     1024 - 2,    1536 - 2,    2048 - 2,    3072 - 2,
    4096 - 2,    6144 - 2,    8192 - 2,    12288 - 2,   16384 - 2,   24576 - 2,   32768 - 2,   49152 - 2,
    65536 - 2,   98304 - 2,   131072 - 2,  196608 - 2,  262144 - 2,  393216 - 2,  524288 - 2,  655360 - 2,
    786432 - 2,  917504 - 2,  1048576 - 2, 1179648 - 2, 1310720 - 2, 1441792 - 2, 1572864 - 2, 1703936 - 2,
    1835008 - 2, 1966080 - 2, 2097152 - 2,
};

/// log2_table from lzx_encoder.c.
pub const log2_table = [256]u8{
    0, 1, 2, 2, 3, 3, 3, 3,
    4, 4, 4, 4, 4, 4, 4, 4,
    5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5,
    6, 6, 6, 6, 6, 6, 6, 6,
    6, 6, 6, 6, 6, 6, 6, 6,
    6, 6, 6, 6, 6, 6, 6, 6,
    6, 6, 6, 6, 6, 6, 6, 6,
    7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7,
    8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8,
};

/// square_table from lzx_encoder.c.
pub const square_table = [17]i64{
    0, 1, 4, 9, 16, 25, 36, 49, 64, 81, 100, 121, 144, 169, 196, 225, 256,
};

/// slot_mask from lzx_encoder.c.
pub const slot_mask = [51]u32{
    0,      0,      0,      0,      1,      1,      3,      3,
    7,      7,      15,     15,     31,     31,     63,     63,
    127,    127,    255,    255,    511,    511,    1023,   1023,
    2047,   2047,   4095,   4095,   8191,   8191,   16383,  16383,
    32767,  32767,  65535,  65535,  131071, 131071, 131071, 131071,
    131071, 131071, 131071, 131071, 131071, 131071, 131071, 131071,
    131071, 131071, 131071,
};

/// log2(x) macro from lzx_encoder.c.
pub fn log2(x: u16) u32 {
    return if (x < 256) log2_table[x] else 8 + @as(u32, log2_table[x >> 8]);
}

test "window size validation matches the C checks" {
    try std.testing.expect(!isValidWindowSize(0));
    try std.testing.expect(!isValidWindowSize(1 << 14));
    try std.testing.expect(isValidWindowSize(1 << 15));
    try std.testing.expect(isValidWindowSize(0x8000));
    try std.testing.expect(isValidWindowSize(0x20000));
    try std.testing.expect(isValidWindowSize(1 << 21));
    try std.testing.expect(!isValidWindowSize(1 << 22));
    try std.testing.expect(!isValidWindowSize((1 << 16) + (1 << 15)));
}

test "main tree element count and secondary length" {
    try std.testing.expectEqual(@as(u32, 496), mainTreeElements(30)); // 32 KiB window
    try std.testing.expectEqual(@as(u32, 528), mainTreeElements(34)); // 128 KiB window
    try std.testing.expectEqual(@as(u32, 656), mainTreeElements(50)); // 2 MiB window
    try std.testing.expectEqual(@as(u32, 249), num_secondary_len);
    try std.testing.expectEqual(@as(u32, 257), max_match);
    try std.testing.expectEqual(@as(u32, 38912), output_size);
}

test "log2 table matches the macro" {
    try std.testing.expectEqual(@as(u32, 0), log2(0));
    try std.testing.expectEqual(@as(u32, 1), log2(1));
    try std.testing.expectEqual(@as(u32, 2), log2(2));
    try std.testing.expectEqual(@as(u32, 2), log2(3));
    try std.testing.expectEqual(@as(u32, 3), log2(4));
    try std.testing.expectEqual(@as(u32, 7), log2(127));
    try std.testing.expectEqual(@as(u32, 8), log2(128));
    try std.testing.expectEqual(@as(u32, 8), log2(255));
    try std.testing.expectEqual(@as(u32, 9), log2(256));
    try std.testing.expectEqual(@as(u32, 16), log2(65535));
}

test "error code mapping preserves lzx.h numbers" {
    try std.testing.expectEqual(@as(u32, 1), @backingInt(codeOf(error.LzxFailed)));
    try std.testing.expectEqual(@as(u32, 4), @backingInt(codeOf(error.LzxBufferOverflow)));
    try std.testing.expectEqual(@as(u32, 5), @backingInt(codeOf(error.OutOfMemory)));
    try std.testing.expectEqual(@as(u32, 6), @backingInt(codeOf(error.LzxInvalidData)));
}
