// SPDX-FileCopyrightText: 2026 XexTool Zig rewrite contributors
// SPDX-License-Identifier: GPL-3.0-or-later

const std = @import("std");

pub fn get16be(bytes: []const u8, offset: usize) u16 {
    std.debug.assert(offset <= bytes.len and bytes.len - offset >= 2);
    return (@as(u16, bytes[offset]) << 8) | bytes[offset + 1];
}

pub fn get16le(bytes: []const u8, offset: usize) u16 {
    std.debug.assert(offset <= bytes.len and bytes.len - offset >= 2);
    return bytes[offset] | (@as(u16, bytes[offset + 1]) << 8);
}

pub fn get32be(bytes: []const u8, offset: usize) u32 {
    std.debug.assert(offset <= bytes.len and bytes.len - offset >= 4);
    return (@as(u32, bytes[offset]) << 24) |
        (@as(u32, bytes[offset + 1]) << 16) |
        (@as(u32, bytes[offset + 2]) << 8) |
        bytes[offset + 3];
}

pub fn get32le(bytes: []const u8, offset: usize) u32 {
    std.debug.assert(offset <= bytes.len and bytes.len - offset >= 4);
    return bytes[offset] |
        (@as(u32, bytes[offset + 1]) << 8) |
        (@as(u32, bytes[offset + 2]) << 16) |
        (@as(u32, bytes[offset + 3]) << 24);
}

pub fn get64be(bytes: []const u8, offset: usize) u64 {
    std.debug.assert(offset <= bytes.len and bytes.len - offset >= 8);
    return (@as(u64, bytes[offset]) << 56) |
        (@as(u64, bytes[offset + 1]) << 48) |
        (@as(u64, bytes[offset + 2]) << 40) |
        (@as(u64, bytes[offset + 3]) << 32) |
        (@as(u64, bytes[offset + 4]) << 24) |
        (@as(u64, bytes[offset + 5]) << 16) |
        (@as(u64, bytes[offset + 6]) << 8) |
        bytes[offset + 7];
}

pub fn get64le(bytes: []const u8, offset: usize) u64 {
    std.debug.assert(offset <= bytes.len and bytes.len - offset >= 8);
    return bytes[offset] |
        (@as(u64, bytes[offset + 1]) << 8) |
        (@as(u64, bytes[offset + 2]) << 16) |
        (@as(u64, bytes[offset + 3]) << 24) |
        (@as(u64, bytes[offset + 4]) << 32) |
        (@as(u64, bytes[offset + 5]) << 40) |
        (@as(u64, bytes[offset + 6]) << 48) |
        (@as(u64, bytes[offset + 7]) << 56);
}

pub fn set16be(bytes: []u8, offset: usize, value: u16) void {
    std.debug.assert(offset <= bytes.len and bytes.len - offset >= 2);
    bytes[offset] = @truncate(value >> 8);
    bytes[offset + 1] = @truncate(value);
}

pub fn set16le(bytes: []u8, offset: usize, value: u16) void {
    std.debug.assert(offset <= bytes.len and bytes.len - offset >= 2);
    bytes[offset] = @truncate(value);
    bytes[offset + 1] = @truncate(value >> 8);
}

pub fn set32be(bytes: []u8, offset: usize, value: u32) void {
    std.debug.assert(offset <= bytes.len and bytes.len - offset >= 4);
    bytes[offset] = @truncate(value >> 24);
    bytes[offset + 1] = @truncate(value >> 16);
    bytes[offset + 2] = @truncate(value >> 8);
    bytes[offset + 3] = @truncate(value);
}

pub fn set32le(bytes: []u8, offset: usize, value: u32) void {
    std.debug.assert(offset <= bytes.len and bytes.len - offset >= 4);
    bytes[offset] = @truncate(value);
    bytes[offset + 1] = @truncate(value >> 8);
    bytes[offset + 2] = @truncate(value >> 16);
    bytes[offset + 3] = @truncate(value >> 24);
}

pub fn set64be(bytes: []u8, offset: usize, value: u64) void {
    std.debug.assert(offset <= bytes.len and bytes.len - offset >= 8);
    bytes[offset] = @truncate(value >> 56);
    bytes[offset + 1] = @truncate(value >> 48);
    bytes[offset + 2] = @truncate(value >> 40);
    bytes[offset + 3] = @truncate(value >> 32);
    bytes[offset + 4] = @truncate(value >> 24);
    bytes[offset + 5] = @truncate(value >> 16);
    bytes[offset + 6] = @truncate(value >> 8);
    bytes[offset + 7] = @truncate(value);
}

pub fn set64le(bytes: []u8, offset: usize, value: u64) void {
    std.debug.assert(offset <= bytes.len and bytes.len - offset >= 8);
    bytes[offset] = @truncate(value);
    bytes[offset + 1] = @truncate(value >> 8);
    bytes[offset + 2] = @truncate(value >> 16);
    bytes[offset + 3] = @truncate(value >> 24);
    bytes[offset + 4] = @truncate(value >> 32);
    bytes[offset + 5] = @truncate(value >> 40);
    bytes[offset + 6] = @truncate(value >> 48);
    bytes[offset + 7] = @truncate(value >> 56);
}

test "endian: big and little reads are byte-exact" {
    const bytes = [_]u8{ 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };
    try std.testing.expectEqual(@as(u16, 0x1234), get16be(&bytes, 0));
    try std.testing.expectEqual(@as(u16, 0x3412), get16le(&bytes, 0));
    try std.testing.expectEqual(@as(u32, 0x12345678), get32be(&bytes, 0));
    try std.testing.expectEqual(@as(u32, 0x78563412), get32le(&bytes, 0));
    try std.testing.expectEqual(@as(u64, 0x123456789ABCDEF0), get64be(&bytes, 0));
    try std.testing.expectEqual(@as(u64, 0xF0DEBC9A78563412), get64le(&bytes, 0));
}

test "endian: writes round-trip in both byte orders" {
    var bytes: [8]u8 = undefined;
    set16be(&bytes, 0, 0x1234);
    try std.testing.expectEqualSlices(u8, &.{ 0x12, 0x34 }, bytes[0..2]);
    set16le(&bytes, 0, 0x1234);
    try std.testing.expectEqualSlices(u8, &.{ 0x34, 0x12 }, bytes[0..2]);

    set32be(&bytes, 0, 0x12345678);
    try std.testing.expectEqualSlices(u8, &.{ 0x12, 0x34, 0x56, 0x78 }, bytes[0..4]);
    set32le(&bytes, 0, 0x12345678);
    try std.testing.expectEqualSlices(u8, &.{ 0x78, 0x56, 0x34, 0x12 }, bytes[0..4]);

    set64be(&bytes, 0, 0x123456789ABCDEF0);
    try std.testing.expectEqualSlices(u8, &.{ 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 }, &bytes);
    set64le(&bytes, 0, 0x123456789ABCDEF0);
    try std.testing.expectEqualSlices(u8, &.{ 0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12 }, &bytes);
}
