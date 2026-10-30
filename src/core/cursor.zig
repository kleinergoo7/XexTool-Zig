// SPDX-FileCopyrightText: 2026 XexTool Zig rewrite contributors
// SPDX-License-Identifier: GPL-3.0-or-later

const std = @import("std");
const endian = @import("endian.zig");

pub const Error = error{ OutOfBounds, Overflow };

pub const Cursor = struct {
    bytes: []const u8,
    pos: usize = 0,

    pub fn init(bytes: []const u8) Cursor {
        return .{ .bytes = bytes };
    }

    pub fn remaining(self: Cursor) usize {
        return self.bytes.len - self.pos;
    }

    pub fn seek(self: *Cursor, position: usize) Error!void {
        if (position > self.bytes.len) return error.OutOfBounds;
        self.pos = position;
    }

    pub fn skip(self: *Cursor, count: usize) Error!void {
        if (count > self.remaining()) return error.OutOfBounds;
        self.pos += count;
    }

    pub fn readBytes(self: *Cursor, count: usize) Error![]const u8 {
        if (count > self.remaining()) return error.OutOfBounds;
        const slice = self.bytes[self.pos..][0..count];
        self.pos += count;
        return slice;
    }

    pub fn readU8(self: *Cursor) Error!u8 {
        const slice = try self.readBytes(1);
        return slice[0];
    }

    pub fn readU16be(self: *Cursor) Error!u16 {
        const slice = try self.readBytes(2);
        return endian.get16be(slice, 0);
    }

    pub fn readU32be(self: *Cursor) Error!u32 {
        const slice = try self.readBytes(4);
        return endian.get32be(slice, 0);
    }

    pub fn readU64be(self: *Cursor) Error!u64 {
        const slice = try self.readBytes(8);
        return endian.get64be(slice, 0);
    }

    pub fn readU16le(self: *Cursor) Error!u16 {
        const slice = try self.readBytes(2);
        return endian.get16le(slice, 0);
    }

    pub fn readU32le(self: *Cursor) Error!u32 {
        const slice = try self.readBytes(4);
        return endian.get32le(slice, 0);
    }

    pub fn readU64le(self: *Cursor) Error!u64 {
        const slice = try self.readBytes(8);
        return endian.get64le(slice, 0);
    }

    pub fn readCString(self: *Cursor) Error![]const u8 {
        const start = self.pos;
        while (self.pos < self.bytes.len) : (self.pos += 1) {
            if (self.bytes[self.pos] == 0) {
                const result = self.bytes[start..self.pos];
                self.pos += 1;
                return result;
            }
        }
        return error.OutOfBounds;
    }
};

pub fn readU16beAt(bytes: []const u8, offset: usize) Error!u16 {
    if (offset > bytes.len or bytes.len - offset < 2) return error.OutOfBounds;
    return endian.get16be(bytes, offset);
}

pub fn readU32beAt(bytes: []const u8, offset: usize) Error!u32 {
    if (offset > bytes.len or bytes.len - offset < 4) return error.OutOfBounds;
    return endian.get32be(bytes, offset);
}

pub fn readU64beAt(bytes: []const u8, offset: usize) Error!u64 {
    if (offset > bytes.len or bytes.len - offset < 8) return error.OutOfBounds;
    return endian.get64be(bytes, offset);
}

pub fn readU16leAt(bytes: []const u8, offset: usize) Error!u16 {
    if (offset > bytes.len or bytes.len - offset < 2) return error.OutOfBounds;
    return endian.get16le(bytes, offset);
}

pub fn readU32leAt(bytes: []const u8, offset: usize) Error!u32 {
    if (offset > bytes.len or bytes.len - offset < 4) return error.OutOfBounds;
    return endian.get32le(bytes, offset);
}

pub fn readU64leAt(bytes: []const u8, offset: usize) Error!u64 {
    if (offset > bytes.len or bytes.len - offset < 8) return error.OutOfBounds;
    return endian.get64le(bytes, offset);
}

test "Cursor reads and advances" {
    var cursor = Cursor.init(&.{ 0x12, 0x34, 0x56, 0x78 });
    try std.testing.expectEqual(@as(u16, 0x1234), try cursor.readU16be());
    try std.testing.expectEqual(@as(u8, 0x56), try cursor.readU8());
    try std.testing.expectEqual(@as(usize, 1), cursor.remaining());
    try std.testing.expectError(error.OutOfBounds, cursor.readU32be());
}

test "Cursor reads little endian" {
    var cursor = Cursor.init(&.{ 0x78, 0x56, 0x34, 0x12 });
    try std.testing.expectEqual(@as(u32, 0x12345678), try cursor.readU32le());
}

test "Cursor reads a bounded C string" {
    var cursor = Cursor.init("abc\x00tail");
    try std.testing.expectEqualStrings("abc", try cursor.readCString());
    try std.testing.expectEqualStrings("tail", try cursor.readBytes(4));
}
