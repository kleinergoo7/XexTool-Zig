// SPDX-FileCopyrightText: 2026 XexTool Zig rewrite contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Zig equivalent of XexTool/src/lzx/XexLzx.cpp: a decoder wrapper for XEX
// basefile chunks whose chunks are pieces of one stream, so the window and the
// repeated offsets carry across calls.

const std = @import("std");
const lzx = @import("lzx.zig");

pub const Decoder = lzx.Decoder;

pub const XexLzxDecoder = struct {
    context: *Decoder,
};

/// XexLzxCreate.
pub fn XexLzxCreate(allocator: std.mem.Allocator, window_size: u32) lzx.Error!*XexLzxDecoder {
    const context = try lzx.createDecompressionWindow(allocator, window_size);

    const decoder = allocator.create(XexLzxDecoder) catch |err| {
        lzx.destroyDecompression(context);
        return err;
    };
    decoder.* = .{ .context = context };
    return decoder;
}

/// XexLzxDestroy.
pub fn XexLzxDestroy(decoder: *XexLzxDecoder) void {
    const allocator = decoder.context.allocator;
    lzx.destroyDecompression(decoder.context);
    allocator.destroy(decoder);
}

/// XexLzxSeedWindow.
pub fn XexLzxSeedWindow(decoder: *XexLzxDecoder, data: []const u8) lzx.Error!void {
    return lzx.setWindowData(decoder.context, data);
}

/// XexLzxDecodeChunk. `output.len` is the expected uncompressed size; a short
/// or long block is a failure, exactly like the C++ wrapper's `produced ==
/// outputSize` check.
pub fn XexLzxDecodeChunk(decoder: *XexLzxDecoder, input: []const u8, output: []u8) lzx.Error!void {
    const produced = try lzx.decompressBlock(decoder.context, input, output);
    if (produced != output.len) return error.LzxFailed;
}

test "wrapper decodes a chunk produced by the encoder" {
    const allocator = std.testing.allocator;

    const input = "wrapper roundtrip data, wrapper roundtrip data";
    const dest = try allocator.alloc(u8, lzx.worstCaseCompressedSize(input.len));
    defer allocator.free(dest);
    const encoded = try lzx.compress(allocator, dest, input, 0x8000);

    const decoder = try XexLzxCreate(allocator, 0x8000);
    defer XexLzxDestroy(decoder);
    try XexLzxSeedWindow(decoder, "");

    var out: [input.len]u8 = @splat(0);

    var pos: usize = 0;
    while (pos < encoded.len) {
        const compressed = std.mem.readInt(u16, encoded[pos..][0..2], .little);
        const uncompressed = std.mem.readInt(u16, encoded[pos + 2 ..][0..2], .little);
        pos += 4;
        try XexLzxDecodeChunk(decoder, encoded[pos..][0..compressed], out[0..uncompressed]);
        pos += compressed;
    }

    try std.testing.expectEqualSlices(u8, input, &out);
}

test "wrapper reports a short block" {
    const allocator = std.testing.allocator;

    const input = "abcabcabc";
    const dest = try allocator.alloc(u8, lzx.worstCaseCompressedSize(input.len));
    defer allocator.free(dest);
    const encoded = try lzx.compress(allocator, dest, input, 0x8000);

    const decoder = try XexLzxCreate(allocator, 0x8000);
    defer XexLzxDestroy(decoder);

    var out: [input.len + 1]u8 = @splat(0);
    const compressed = std.mem.readInt(u16, encoded[0..2], .little);
    try std.testing.expectError(error.LzxFailed, XexLzxDecodeChunk(decoder, encoded[4..][0..compressed], &out));
}
