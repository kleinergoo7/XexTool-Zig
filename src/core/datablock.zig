// SPDX-FileCopyrightText: 2026 XexTool Zig rewrite contributors
// SPDX-License-Identifier: GPL-3.0-or-later

const std = @import("std");
const builtin = @import("builtin");
const endian = @import("endian.zig");

pub const Error = error{
    InvalidRange,
    OutOfMemory,
};

const native_endian = builtin.cpu.arch.endian();

/// Port of the original DataBlock. Offsets stay signed because the C++ callers
/// compute them as s32; negative values are rejected instead of reproducing UB.
pub const DataBlock = struct {
    storage: []u8 = &.{},
    len: usize = 0,

    pub fn init() DataBlock {
        return .{};
    }

    pub fn deinit(self: *DataBlock, gpa: std.mem.Allocator) void {
        gpa.free(self.storage);
        self.* = .{};
    }

    pub fn size(self: *const DataBlock) i32 {
        std.debug.assert(self.len <= std.math.maxInt(i32));
        return @intCast(self.len);
    }

    pub fn clear(self: *DataBlock, gpa: std.mem.Allocator) void {
        gpa.free(self.storage);
        self.* = .{};
    }

    pub fn truncate(self: *DataBlock, new_size: i32) void {
        std.debug.assert(new_size >= 0 and @as(usize, @intCast(new_size)) <= self.len);
        self.len = @intCast(new_size);
    }

    pub fn fill(self: *DataBlock, gpa: std.mem.Allocator, value: u8, offset: i32, length: i32) Error!void {
        const off = try checkRange(offset, length);
        try self.ensure(gpa, off, @intCast(length));
        @memset(self.storage[off .. off + @as(usize, @intCast(length))], value);
    }

    pub fn set(self: *DataBlock, gpa: std.mem.Allocator, source: []const u8, offset: i32, length: i32) Error!void {
        const off = try checkRange(offset, length);
        const len: usize = @intCast(length);
        if (len > source.len) return error.InvalidRange;
        try self.ensure(gpa, off, len);
        @memcpy(self.storage[off .. off + len], source[0..len]);
    }

    pub fn get(self: *const DataBlock, destination: []u8, offset: i32, length: i32) Error!void {
        const off = try checkRange(offset, length);
        const len: usize = @intCast(length);
        if (len > destination.len) return error.InvalidRange;
        if (off >= self.len) {
            @memset(destination[0..len], 0);
        } else if (len > self.len - off) {
            const available = self.len - off;
            @memcpy(destination[0..available], self.storage[off .. off + available]);
            @memset(destination[available..len], 0);
        } else {
            @memcpy(destination[0..len], self.storage[off .. off + len]);
        }
    }

    pub fn setBlock(self: *DataBlock, gpa: std.mem.Allocator, source: *const DataBlock, source_offset: i32, destination_offset: i32, length: i32) Error!void {
        const temp = try gpa.alloc(u8, @intCast(length));
        defer gpa.free(temp);
        try source.get(temp, source_offset, length);
        try self.set(gpa, temp, destination_offset, length);
    }

    pub fn getBlock(self: *const DataBlock, gpa: std.mem.Allocator, destination: *DataBlock, destination_offset: i32, source_offset: i32, length: i32) Error!void {
        const temp = try gpa.alloc(u8, @intCast(length));
        defer gpa.free(temp);
        try self.get(temp, source_offset, length);
        try destination.set(gpa, temp, destination_offset, length);
    }

    pub fn clone(self: *const DataBlock, gpa: std.mem.Allocator) Error!DataBlock {
        return .{ .storage = try gpa.dupe(u8, self.data()), .len = self.len };
    }

    pub fn cdata(self: *const DataBlock) []const u8 {
        return self.data();
    }

    pub fn data(self: *const DataBlock) []const u8 {
        return self.storage[0..self.len];
    }

    pub fn dataMut(self: *DataBlock) []u8 {
        return self.storage[0..self.len];
    }

    pub fn set8(self: *DataBlock, gpa: std.mem.Allocator, value: u8, offset: i32) Error!void {
        try self.set(gpa, &.{value}, offset, 1);
    }

    pub fn set16(self: *DataBlock, gpa: std.mem.Allocator, value: u16, offset: i32) Error!void {
        var bytes: [2]u8 = undefined;
        writeNative16(&bytes, value);
        try self.set(gpa, &bytes, offset, 2);
    }

    pub fn set32(self: *DataBlock, gpa: std.mem.Allocator, value: u32, offset: i32) Error!void {
        var bytes: [4]u8 = undefined;
        writeNative32(&bytes, value);
        try self.set(gpa, &bytes, offset, 4);
    }

    pub fn set64(self: *DataBlock, gpa: std.mem.Allocator, value: u64, offset: i32) Error!void {
        var bytes: [8]u8 = undefined;
        writeNative64(&bytes, value);
        try self.set(gpa, &bytes, offset, 8);
    }

    pub fn get8(self: *const DataBlock, offset: i32) u8 {
        var bytes: [1]u8 = undefined;
        self.get(&bytes, offset, 1) catch unreachable; // fixed size, checked by get
        return bytes[0];
    }

    pub fn get16(self: *const DataBlock, offset: i32) u16 {
        var bytes: [2]u8 = undefined;
        self.get(&bytes, offset, 2) catch unreachable; // fixed size, checked by get
        return readNative16(&bytes);
    }

    pub fn get32(self: *const DataBlock, offset: i32) u32 {
        var bytes: [4]u8 = undefined;
        self.get(&bytes, offset, 4) catch unreachable; // fixed size, checked by get
        return readNative32(&bytes);
    }

    pub fn get64(self: *const DataBlock, offset: i32) u64 {
        var bytes: [8]u8 = undefined;
        self.get(&bytes, offset, 8) catch unreachable; // fixed size, checked by get
        return readNative64(&bytes);
    }

    pub fn set16be(self: *DataBlock, gpa: std.mem.Allocator, value: u16, offset: i32) Error!void {
        var bytes: [2]u8 = undefined;
        endian.set16be(&bytes, 0, value);
        try self.set(gpa, &bytes, offset, 2);
    }

    pub fn set32be(self: *DataBlock, gpa: std.mem.Allocator, value: u32, offset: i32) Error!void {
        var bytes: [4]u8 = undefined;
        endian.set32be(&bytes, 0, value);
        try self.set(gpa, &bytes, offset, 4);
    }

    pub fn set64be(self: *DataBlock, gpa: std.mem.Allocator, value: u64, offset: i32) Error!void {
        var bytes: [8]u8 = undefined;
        endian.set64be(&bytes, 0, value);
        try self.set(gpa, &bytes, offset, 8);
    }

    pub fn get16be(self: *const DataBlock, offset: i32) u16 {
        var bytes: [2]u8 = undefined;
        self.get(&bytes, offset, 2) catch unreachable; // fixed size, checked by get
        return endian.get16be(&bytes, 0);
    }

    pub fn get32be(self: *const DataBlock, offset: i32) u32 {
        var bytes: [4]u8 = undefined;
        self.get(&bytes, offset, 4) catch unreachable; // fixed size, checked by get
        return endian.get32be(&bytes, 0);
    }

    pub fn get64be(self: *const DataBlock, offset: i32) u64 {
        var bytes: [8]u8 = undefined;
        self.get(&bytes, offset, 8) catch unreachable; // fixed size, checked by get
        return endian.get64be(&bytes, 0);
    }

    pub fn set16le(self: *DataBlock, gpa: std.mem.Allocator, value: u16, offset: i32) Error!void {
        var bytes: [2]u8 = undefined;
        endian.set16le(&bytes, 0, value);
        try self.set(gpa, &bytes, offset, 2);
    }

    pub fn set32le(self: *DataBlock, gpa: std.mem.Allocator, value: u32, offset: i32) Error!void {
        var bytes: [4]u8 = undefined;
        endian.set32le(&bytes, 0, value);
        try self.set(gpa, &bytes, offset, 4);
    }

    pub fn set64le(self: *DataBlock, gpa: std.mem.Allocator, value: u64, offset: i32) Error!void {
        var bytes: [8]u8 = undefined;
        endian.set64le(&bytes, 0, value);
        try self.set(gpa, &bytes, offset, 8);
    }

    pub fn get16le(self: *const DataBlock, offset: i32) u16 {
        var bytes: [2]u8 = undefined;
        self.get(&bytes, offset, 2) catch unreachable; // fixed size, checked by get
        return endian.get16le(&bytes, 0);
    }

    pub fn get32le(self: *const DataBlock, offset: i32) u32 {
        var bytes: [4]u8 = undefined;
        self.get(&bytes, offset, 4) catch unreachable; // fixed size, checked by get
        return endian.get32le(&bytes, 0);
    }

    pub fn get64le(self: *const DataBlock, offset: i32) u64 {
        var bytes: [8]u8 = undefined;
        self.get(&bytes, offset, 8) catch unreachable; // fixed size, checked by get
        return endian.get64le(&bytes, 0);
    }

    fn ensure(self: *DataBlock, gpa: std.mem.Allocator, offset: usize, length: usize) Error!void {
        const needed = std.math.add(usize, offset, length) catch return error.InvalidRange;
        if (needed <= self.len) return;
        if (needed > self.storage.len) {
            self.storage = try gpa.realloc(self.storage, needed);
        }
        if (offset > self.len) @memset(self.storage[self.len..offset], 0);
        self.len = needed;
    }
};

fn checkRange(offset: i32, size: i32) Error!usize {
    if (offset < 0 or size < 0) return error.InvalidRange;
    return @intCast(offset);
}

fn readNative16(bytes: *const [2]u8) u16 {
    return switch (native_endian) {
        .little => endian.get16le(bytes, 0),
        .big => endian.get16be(bytes, 0),
    };
}

fn writeNative16(bytes: *[2]u8, value: u16) void {
    switch (native_endian) {
        .little => endian.set16le(bytes, 0, value),
        .big => endian.set16be(bytes, 0, value),
    }
}

fn readNative32(bytes: *const [4]u8) u32 {
    return switch (native_endian) {
        .little => endian.get32le(bytes, 0),
        .big => endian.get32be(bytes, 0),
    };
}

fn writeNative32(bytes: *[4]u8, value: u32) void {
    switch (native_endian) {
        .little => endian.set32le(bytes, 0, value),
        .big => endian.set32be(bytes, 0, value),
    }
}

fn readNative64(bytes: *const [8]u8) u64 {
    return switch (native_endian) {
        .little => endian.get64le(bytes, 0),
        .big => endian.get64be(bytes, 0),
    };
}

fn writeNative64(bytes: *[8]u8, value: u64) void {
    switch (native_endian) {
        .little => endian.set64le(bytes, 0, value),
        .big => endian.set64be(bytes, 0, value),
    }
}

test "DataBlock: append and zero-fill a gap" {
    var block = DataBlock.init();
    defer block.deinit(std.testing.allocator);

    try block.set(std.testing.allocator, &.{ 0xAA, 0xBB }, 4, 2);
    try std.testing.expectEqual(@as(i32, 6), block.size());
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0xAA, 0xBB }, block.cdata());
}

test "DataBlock: get past the end zero-fills" {
    var block = DataBlock.init();
    defer block.deinit(std.testing.allocator);
    try block.set(std.testing.allocator, &.{ 1, 2, 3 }, 1, 3);

    var out = [_]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    try block.get(&out, 2, 5);
    try std.testing.expectEqualSlices(u8, &.{ 2, 3, 0, 0, 0 }, &out);
}

test "DataBlock: fill grows and writes only the requested range" {
    var block = DataBlock.init();
    defer block.deinit(std.testing.allocator);
    try block.fill(std.testing.allocator, 0x7E, 3, 4);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0x7E, 0x7E, 0x7E, 0x7E }, block.cdata());
}

test "DataBlock: endian accessors match raw bytes" {
    var block = DataBlock.init();
    defer block.deinit(std.testing.allocator);

    try block.set32be(std.testing.allocator, 0x12345678, 0);
    try std.testing.expectEqualSlices(u8, &.{ 0x12, 0x34, 0x56, 0x78 }, block.cdata());
    try std.testing.expectEqual(@as(u32, 0x12345678), block.get32be(0));
    try std.testing.expectEqual(@as(u32, 0x78563412), block.get32le(0));

    try block.set64le(std.testing.allocator, 0x0123456789ABCDEF, 0);
    try std.testing.expectEqualSlices(u8, &.{ 0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01 }, block.cdata());
    try std.testing.expectEqual(@as(u64, 0x0123456789ABCDEF), block.get64le(0));
}

test "DataBlock: native accessors depend on host byte order" {
    var block = DataBlock.init();
    defer block.deinit(std.testing.allocator);
    try block.set32(std.testing.allocator, 0x01020304, 0);
    try std.testing.expectEqual(@as(u32, 0x01020304), block.get32(0));
    try std.testing.expectEqual(@as(u32, 0x01020304), block.get32le(0) + 0);
    try std.testing.expectEqual(@as(u32, 0x04030201), block.get32be(0) + 0);
}

test "DataBlock: truncate shrinks the logical size" {
    var block = DataBlock.init();
    defer block.deinit(std.testing.allocator);
    try block.set(std.testing.allocator, &.{ 1, 2, 3, 4 }, 0, 4);
    block.truncate(2);
    try std.testing.expectEqual(@as(i32, 2), block.size());
    try std.testing.expectEqualSlices(u8, &.{ 1, 2 }, block.cdata());
}

test "DataBlock: clone is independent" {
    var block = DataBlock.init();
    defer block.deinit(std.testing.allocator);
    try block.set(std.testing.allocator, &.{ 1, 2, 3 }, 0, 3);

    var copy = try block.clone(std.testing.allocator);
    defer copy.deinit(std.testing.allocator);
    try copy.set(std.testing.allocator, &.{9}, 0, 1);

    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, block.cdata());
    try std.testing.expectEqualSlices(u8, &.{ 9, 2, 3 }, copy.cdata());
}

test "DataBlock: negative offsets are rejected" {
    var block = DataBlock.init();
    defer block.deinit(std.testing.allocator);
    try std.testing.expectError(error.InvalidRange, block.set(std.testing.allocator, &.{1}, -1, 1));
    try std.testing.expectError(error.InvalidRange, block.fill(std.testing.allocator, 0, 0, -1));
}
