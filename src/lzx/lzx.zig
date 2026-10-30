// SPDX-FileCopyrightText: 2026 XexTool Zig rewrite contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
// libLZX public surface used by XexTool: a 32 KiB / 128 KiB window decoder and
// encoder with the same block format as the C library.

const std = @import("std");

pub const common = @import("common.zig");
pub const decoder = @import("decoder.zig");
pub const encoder = @import("encoder.zig");

pub const window_size = common.window_size;
pub const chunk_size = common.chunk_size;
pub const max_match = common.max_match;
pub const num_secondary_len = common.num_secondary_len;
pub const output_size = common.output_size;

pub const Error = common.Error;
pub const ErrorCode = common.ErrorCode;
pub const codeOf = common.codeOf;
pub const BlockType = common.BlockType;

pub const Decoder = decoder.Decoder;
pub const Encoder = encoder.Encoder;

/// lzx_create_decompression_window.
pub const createDecompressionWindow = decoder.createDecompressionWindow;
/// lzx_create_decompression.
pub const createDecompression = decoder.createDecompression;
/// lzx_destroy_decompression.
pub const destroyDecompression = decoder.destroyDecompression;
/// lzx_set_window_data.
pub const setWindowData = decoder.setWindowData;
/// lzx_decompress_block.
pub const decompressBlock = decoder.decompressBlock;
/// lzx_calc_decompress_size.
pub const calcDecompressSize = decoder.calcDecompressSize;

/// lzx_create_compression_window.
pub const createCompressionWindow = encoder.createCompressionWindow;
/// lzx_create_compression.
pub const createCompression = encoder.createCompression;
/// lzx_destroy_compression.
pub const destroyCompression = encoder.destroyCompression;
/// lzx_compress_block.
pub const compressBlock = encoder.compressBlock;
/// lzx_compress_next_block.
pub const compressNextBlock = encoder.compressNextBlock;
/// lzx_flush_compression.
pub const flushCompression = encoder.flushCompression;

test {
    std.testing.refAllDecls(@This());
    _ = @import("decoder.zig");
    _ = @import("encoder.zig");
    _ = @import("XexLzx.zig");
}

/// Number of bytes the encoder may emit for `input_len` bytes. The C caller
/// guesses with a quarter of the input as growth; the worst case is one
/// uncompressed block per chunk plus headers.
pub fn worstCaseCompressedSize(input_len: usize) usize {
    const chunks = input_len / chunk_size + 1;
    return input_len + chunks * 16 + 4096;
}

/// Compress `input` into `dest` exactly like lzx_compress: flush, feed whole
/// chunks, flush. Returns the used part of `dest`.
pub fn compress(allocator: std.mem.Allocator, dest: []u8, input: []const u8, window: u32) Error![]u8 {
    const enc = try createCompressionWindow(allocator, dest, window);
    defer destroyCompression(enc);

    try flushCompression(enc);

    var pos: usize = 0;
    while (pos < input.len) {
        const take = @min(input.len - pos, chunk_size);
        try compressNextBlock(enc, input[pos..][0..take]);
        pos += take;
    }

    try flushCompression(enc);
    return dest[0..encoder.compressedSize(enc)];
}

/// Decompress a framed stream (4 byte little-endian { compressed, uncompressed }
/// headers) exactly like lzx_decompress. `dest.len` is the expected output.
pub fn decompress(allocator: std.mem.Allocator, src: []const u8, dest: []u8, window: u32) Error!u32 {
    const dec = try createDecompressionWindow(allocator, window);
    defer destroyDecompression(dec);

    var src_pos: usize = 0;
    var dest_pos: usize = 0;

    while (src_pos < src.len) {
        if (src_pos + 4 > src.len) return error.LzxInvalidData;

        const compressed = std.mem.readInt(u16, src[src_pos..][0..2], .little);
        const uncompressed = std.mem.readInt(u16, src[src_pos + 2 ..][0..2], .little);
        src_pos += 4;

        if (compressed == 0) return error.LzxInvalidData;
        if (src_pos + compressed > src.len) return error.LzxInvalidData;
        if (dest_pos + uncompressed > dest.len) return error.LzxBufferOverflow;

        const produced = try decompressBlock(dec, src[src_pos..][0..compressed], dest[dest_pos..][0..uncompressed]);
        if (produced != uncompressed) return error.LzxFailed;

        src_pos += compressed;
        dest_pos += uncompressed;
    }

    return @intCast(dest_pos);
}

const testing = std.testing;

fn roundtrip(window: u32, input: []const u8) !void {
    const allocator = testing.allocator;

    const dest = try allocator.alloc(u8, worstCaseCompressedSize(input.len));
    defer allocator.free(dest);

    const encoded = try compress(allocator, dest, input, window);

    const out = try allocator.alloc(u8, input.len);
    defer allocator.free(out);

    const produced = try decompress(allocator, encoded, out, window);
    try testing.expectEqual(@as(u32, @intCast(input.len)), produced);
    try testing.expectEqualSlices(u8, input, out);
}

test "roundtrip empty input" {
    try roundtrip(0x8000, "");
    try roundtrip(0x20000, "");
}

test "roundtrip tiny input" {
    try roundtrip(0x8000, "a");
    try roundtrip(0x8000, "abc");
    try roundtrip(0x8000, "hello, lzx");
    try roundtrip(0x20000, "the quick brown fox jumps over the lazy dog");
}

test "roundtrip repeated bytes" {
    const allocator = testing.allocator;

    const data = try allocator.alloc(u8, 0x20000 + 17);
    defer allocator.free(data);
    @memset(data, 0x41);

    try roundtrip(0x8000, data);
    try roundtrip(0x20000, data);
}

test "roundtrip zero bytes in a 128 KiB window" {
    const allocator = testing.allocator;
    const data = try allocator.alloc(u8, 0x20000);
    defer allocator.free(data);
    @memset(data, 0);

    try roundtrip(0x8000, data);
    try roundtrip(0x20000, data);
}

test "roundtrip deterministic pseudo random bytes" {
    const allocator = testing.allocator;

    var prng = std.Random.DefaultPrng.init(0x4c5a58);
    const random = prng.random();

    var len: usize = 1;
    while (len <= 70000) : (len = len * 3 + 1) {
        const data = try allocator.alloc(u8, len);
        defer allocator.free(data);
        random.bytes(data);
        try roundtrip(0x8000, data);
    }
}

test "roundtrip structured data that produces matches" {
    const allocator = testing.allocator;

    const data = try allocator.alloc(u8, 0x20000);
    defer allocator.free(data);
    for (data, 0..) |*b, i| b.* = @truncate((i / 7) *% 13 + (i % 3));

    try roundtrip(0x8000, data);
    try roundtrip(0x20000, data);
}

test "roundtrip at the 32 KiB chunk boundary" {
    const allocator = testing.allocator;

    for ([_]usize{ 0x7fff, 0x8000, 0x8001 }) |len| {
        const data = try allocator.alloc(u8, len);
        defer allocator.free(data);
        for (data, 0..) |*b, i| b.* = @truncate(i *% 7 + (i >> 5));
        try roundtrip(0x8000, data);
    }
}

test "roundtrip across the secondary partition slide" {
    const allocator = testing.allocator;

    const data = try allocator.alloc(u8, 4 * 0x8000 + 1234);
    defer allocator.free(data);
    for (data, 0..) |*b, i| b.* = @truncate((i % 97) +% (i / 1000));

    try roundtrip(0x8000, data);
}

test "corrupted compressed data returns an error" {
    const allocator = testing.allocator;

    const input = "corrupt me please, this is only a test string";
    const dest = try allocator.alloc(u8, worstCaseCompressedSize(input.len));
    defer allocator.free(dest);
    const encoded = try compress(allocator, dest, input, 0x8000);

    const out = try allocator.alloc(u8, input.len * 2);
    defer allocator.free(out);

    // Truncated payload.
    try testing.expectError(error.LzxInvalidData, decompress(allocator, encoded[0 .. encoded.len - 1], out, 0x8000));

    // A header that claims more data than the stream holds.
    const bad_header = [_]u8{ 0xFF, 0xFF, 0x20, 0x00 };
    try testing.expectError(error.LzxInvalidData, decompress(allocator, &bad_header, out, 0x8000));

    // A block whose first bits declare block type 7.
    const bad_block = [_]u8{ 0x02, 0x00, 0x20, 0x00, 0xFF, 0xFF };
    try testing.expectError(error.LzxFailed, decompress(allocator, &bad_block, out, 0x8000));
}

test "product lzx output matches the reference when XEXTOOL_TEST_DIR is set" {
    const allocator = testing.allocator;

    const dir = std.process.Environ.getPosix(std.testing.environ, "XEXTOOL_TEST_DIR") orelse {
        std.debug.print("skipping LZX fixture test: XEXTOOL_TEST_DIR is unset\n", .{});
        return;
    };

    const path = try std.fs.path.join(allocator, &.{ dir, "lzx", "window.bin" });
    defer allocator.free(path);

    const data = std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, allocator, .limited(1 << 24)) catch |err| switch (err) {
        error.FileNotFound => {
            std.debug.print("skipping LZX fixture test: {s} is missing\n", .{path});
            return;
        },
        else => return err,
    };
    defer allocator.free(data);

    try roundtrip(0x8000, data);
    try roundtrip(0x20000, data);
}
