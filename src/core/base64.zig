// SPDX-FileCopyrightText: 2026 XexTool Zig rewrite contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Port of `XexTool/src/base64.h` / `base64.cpp` (RFC2045 section 6.8).
//!
//! Only the encoder is ported: the shipped command surface only calls
//! `base64::encode` (game icon XML output). The C++ decoder is unused there.

const std = @import("std");

/// RFC2045 alphabet, byte-for-byte the `_to_table` of `base64.cpp`.
pub const to_table: [64]u8 = .{
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '+', '/',
};

/// Length of a full output line before the encoder inserts CRLF.
const line_limit: usize = 76;

const cr: u8 = 13;
const lf: u8 = 10;

/// Port of `base64::encode`. Writes CRLF after every 76 output characters.
///
/// The C++ encoder tests the line length after each 3-byte group, including a
/// final short group, so a message whose length is an exact multiple of 57
/// bytes ends with CRLF. That quirk is preserved. Padding (`=`) is added after
/// the loop and is never followed by a line break.
pub fn encode(writer: *std.Io.Writer, input: []const u8) !void {
    var line_size: usize = 0;
    var at: usize = 0;
    var bytes: usize = 0;

    while (true) {
        var value: u32 = 0;

        bytes = 0;
        while (bytes < 3 and at < input.len) {
            value = (value << 8) + input[at];
            bytes += 1;
            at += 1;
        }

        var bits: i32 = @intCast(bytes * 8);
        while (bits > 0) {
            bits -= 6;
            // bytes <= 3, so bits is in -4..18 and both shifts fit u5.
            const index: u8 = if (bits < 0)
                @intCast((value << @intCast(-bits)) & 0x3F)
            else
                @intCast((value >> @intCast(bits)) & 0x3F);
            try writer.writeByte(to_table[index]);
            line_size += 1;
        }

        if (line_size >= line_limit) {
            try writer.writeByte(cr);
            try writer.writeByte(lf);
            line_size = 0;
        }

        if (bytes != 3) break;
    }

    if (bytes > 0) {
        var pad = bytes;
        while (pad < 3) : (pad += 1) try writer.writeByte('=');
    }
}

test "base64: RFC2045 vectors match the C++ encoder" {
    const allocator = std.testing.allocator;
    const cases = [_]struct { input: []const u8, expected: []const u8 }{
        .{ .input = "", .expected = "" },
        .{ .input = "f", .expected = "Zg==" },
        .{ .input = "fo", .expected = "Zm8=" },
        .{ .input = "foo", .expected = "Zm9v" },
        .{ .input = "foob", .expected = "Zm9vYg==" },
        .{ .input = "fooba", .expected = "Zm9vYmE=" },
        .{ .input = "foobar", .expected = "Zm9vYmFy" },
        .{ .input = "\x00\x00\x00", .expected = "AAAA" },
        .{ .input = "\xFB\xFF\xBF", .expected = "+/+/" },
    };

    for (cases) |case| {
        var buffer: std.Io.Writer.Allocating = .init(allocator);
        defer buffer.deinit();
        try encode(&buffer.writer, case.input);
        try std.testing.expectEqualStrings(case.expected, buffer.written());
    }
}

test "base64: 57 bytes fill exactly one line and end with CRLF" {
    var input: [57]u8 = @splat('a');
    var buffer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer buffer.deinit();
    try encode(&buffer.writer, &input);

    var expected: [78]u8 = undefined;
    for (0..19) |i| @memcpy(expected[i * 4 ..][0..4], "YWFh");
    expected[76] = '\r';
    expected[77] = '\n';
    try std.testing.expectEqualSlices(u8, &expected, buffer.written());
}

test "base64: 58 bytes wrap then pad without a trailing CRLF" {
    var input: [58]u8 = @splat('a');
    var buffer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer buffer.deinit();
    try encode(&buffer.writer, &input);

    var expected: [82]u8 = undefined;
    for (0..19) |i| @memcpy(expected[i * 4 ..][0..4], "YWFh");
    @memcpy(expected[76..], "\r\nYQ==");
    try std.testing.expectEqualSlices(u8, &expected, buffer.written());
}
