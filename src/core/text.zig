// SPDX-FileCopyrightText: 2026 XexTool Zig rewrite contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! C stdio opens stdout, stderr, and the IDC file in text mode. On Windows that
//! turns every LF into CRLF. Zig writes bytes directly, so translate explicitly.

const std = @import("std");
const builtin = @import("builtin");

/// Whether text output on this target needs LF -> CRLF translation.
pub const translate = builtin.os.tag == .windows;

/// Returns `input` with every LF replaced by CRLF. Only used by tests and
/// callers that already hold a whole buffer.
pub fn encodeCrlf(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var extra: usize = 0;
    for (input) |byte| {
        if (byte == '\n') extra += 1;
    }
    const output = try allocator.alloc(u8, input.len + extra);
    var index: usize = 0;
    for (input) |byte| {
        if (byte == '\n') {
            output[index] = '\r';
            index += 1;
        }
        output[index] = byte;
        index += 1;
    }
    return output;
}

/// Buffered text writer that translates LF to CRLF when the target needs it.
/// `writer` must stay the first field so `drain` can recover the parent value.
pub const Writer = struct {
    writer: std.Io.Writer,
    file: std.Io.File,
    io: std.Io,
    allocator: std.mem.Allocator,
    pending: std.ArrayList(u8) = .empty,
    buffer: [4096]u8 = undefined,

    pub fn init(self: *Writer, file: std.Io.File, io: std.Io, allocator: std.mem.Allocator) void {
        self.file = file;
        self.io = io;
        self.allocator = allocator;
        self.pending = .empty;
        self.writer = .{ .vtable = &vtable, .buffer = &self.buffer };
    }

    pub fn deinit(self: *Writer) void {
        self.pending.deinit(self.allocator);
    }

    const vtable: std.Io.Writer.VTable = .{
        .drain = drain,
        .flush = flush,
    };

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *Writer = @ptrCast(@alignCast(w)); // `writer` is the first field.
        self.append(w.buffer[0..w.end]) catch return error.WriteFailed;
        w.end = 0;

        var consumed: usize = 0;
        for (data, 0..) |slice, index| {
            const count: usize = if (index + 1 == data.len) splat else 1;
            var repeat: usize = 0;
            while (repeat < count) : (repeat += 1) {
                self.append(slice) catch return error.WriteFailed;
            }
            if (index + 1 == data.len) consumed += slice.len * count;
        }
        return consumed;
    }

    fn flush(w: *std.Io.Writer) std.Io.Writer.Error!void {
        try std.Io.Writer.defaultFlush(w);
        const self: *Writer = @ptrCast(@alignCast(w)); // `writer` is the first field.
        if (self.pending.items.len == 0) return;
        self.file.writeStreamingAll(self.io, self.pending.items) catch return error.WriteFailed;
        self.pending.clearRetainingCapacity();
    }

    fn append(self: *Writer, slice: []const u8) !void {
        if (!translate) return self.pending.appendSlice(self.allocator, slice);
        var start: usize = 0;
        for (slice, 0..) |byte, index| {
            if (byte != '\n') continue;
            try self.pending.appendSlice(self.allocator, slice[start..index]);
            try self.pending.append(self.allocator, '\r');
            start = index;
        }
        try self.pending.appendSlice(self.allocator, slice[start..]);
    }
};

test "encodeCrlf expands every LF and leaves CRLF bytes predictable" {
    const allocator = std.testing.allocator;
    const encoded = try encodeCrlf(allocator, "a\nb\r\nc");
    defer allocator.free(encoded);
    try std.testing.expectEqualStrings("a\r\nb\r\r\nc", encoded);
}

test "encodeCrlf returns the input unchanged when no LF is present" {
    const allocator = std.testing.allocator;
    const encoded = try encodeCrlf(allocator, "plain");
    defer allocator.free(encoded);
    try std.testing.expectEqualStrings("plain", encoded);
}
