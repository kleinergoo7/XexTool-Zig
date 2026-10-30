// SPDX-FileCopyrightText: 2026 XexTool Zig rewrite contributors
// SPDX-License-Identifier: GPL-3.0-or-later

const std = @import("std");
const text = @import("text.zig");

pub const Error = error{
    OutOfMemory,
    OutOfBounds,
    FileOpen,
    FileRead,
    FileWrite,
};

pub fn readAll(io: std.Io, path: []const u8, gpa: std.mem.Allocator) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(1 << 40));
}

pub fn writeAll(io: std.Io, path: []const u8, bytes: []const u8) !void {
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = bytes });
}

pub fn writeAllBlock(io: std.Io, path: []const u8, block: anytype) !void {
    try writeAll(io, path, block.data());
}

/// Writes a text file using the C runtime text-mode newline rule.
pub fn writeAllText(io: std.Io, path: []const u8, bytes: []const u8, allocator: std.mem.Allocator) !void {
    if (!text.translate) return writeAll(io, path, bytes);
    const encoded = try text.encodeCrlf(allocator, bytes);
    defer allocator.free(encoded);
    try writeAll(io, path, encoded);
}
