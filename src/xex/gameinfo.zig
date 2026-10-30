// SPDX-FileCopyrightText: 2026 XexTool Zig rewrite contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Port of `XexTool/src/XexGameInfo.cpp`: extracts the game name and icon from
//! the SPA resource named after the title id.
//!
//! SPA decryption layout, as parsed by the original code: a chunk table at
//! 0x18, a variable number of 18-byte `DataChunk` records, then an "XTHD"
//! container whose "XSTR" string block holds the localized name.

const std = @import("std");
const DataBlock = @import("../core/datablock.zig").DataBlock;
const endian = @import("../core/endian.zig");
const model = @import("model.zig");

pub const Error = error{
    OutOfMemory,
    InvalidRange,
    InvalidResource,
    InvalidSpaChunk,
};

/// `sizeof(DataChunk)` in XexGameInfo.cpp (#pragma pack(1)).
const chunk_size: u32 = 18;
const chunk_table_offset: u32 = 0x18;
/// `offsetof(DataChunk, ...)`
const chunk_type_offset: u32 = 0;
const chunk_id_offset: u32 = 6;
const chunk_offset_offset: u32 = 10;
const chunk_size_offset: u32 = 14;

const xthd_magic: u32 = 0x58544844; // "XTHD"
const xstr_magic: u32 = 0x58535452; // "XSTR"

const chunk_type_icon: u16 = 0x02;
const chunk_type_string: u16 = 0x03;
const main_icon_id: u32 = 0x8000;
const english_locale_id: u32 = 0x01;
const main_string_id: u16 = 0x8000;

const Chunk = struct {
    offset: u32 = 0,
    size: u32 = 0,
};

const Chunks = struct {
    strings: Chunk = .{},
    icon: Chunk = .{},
};

/// `XexGameInfo::GetSPA`: the SPA resource whose name is the 8-digit title id.
/// Returns null when the XEX has no execution id or no matching resource.
pub fn getSPA(gpa: std.mem.Allocator, xex: *const model.Xex) Error!?DataBlock {
    const exec_id = xex.execution_id orelse return null;

    var title_text: [8]u8 = undefined;
    _ = std.fmt.bufPrint(&title_text, "{X:0>8}", .{exec_id.title_id}) catch unreachable; // 8 hex digits fit

    for (xex.resources.items, 0..) |resource, index| {
        if (!std.mem.eql(u8, &title_text, std.mem.sliceTo(&resource.name, 0))) continue;
        return try resourceBlock(gpa, xex, index);
    }
    return null;
}

fn resourceBlock(gpa: std.mem.Allocator, xex: *const model.Xex, index: usize) Error!DataBlock {
    if (index >= xex.resources.items.len) return error.InvalidResource;
    const resource = xex.resources.items[index];
    if (resource.size < 0) return error.InvalidResource;

    // The C++ difference is computed in u32 and passed to a s32 API.
    const offset_u32 = resource.addr -% xex.load_address;
    const offset: i32 = @bitCast(offset_u32);
    if (offset < 0) return error.InvalidResource;

    const size: usize = @intCast(resource.size);
    const storage = try gpa.alloc(u8, size);
    @memset(storage, 0);

    // DataBlock::get zero-fills the part past the end of the basefile.
    const data = xex.basefile.data();
    const start: usize = @intCast(offset);
    if (start < data.len) {
        const available = @min(size, data.len - start);
        @memcpy(storage[0..available], data[start..][0..available]);
    }
    return .{ .storage = storage, .len = size };
}

/// `XexGameInfo::SPAGetGameName`. The buffer is zeroed first (the C++ uses
/// `strncpy(gameName, "", gameNameLen)`), then filled with the 0x8000 string.
pub fn getGameName(spa: *const DataBlock, buffer: []u8) bool {
    if (buffer.len == 0) return false;
    @memset(buffer, 0);

    const num_entries = readU32be(spa, 8);
    const chunks = scanChunks(spa, num_entries);
    const base = findBase(spa, num_entries) orelse return false;

    if (chunks.strings.offset == 0) return false;

    const strings_size: i32 = @bitCast(chunks.strings.size);
    const limit: i64 = @as(i64, strings_size) - 4;
    var scan: i64 = 0;
    while (scan < limit) : (scan += 1) {
        const at = @as(i64, base) + @as(i64, chunks.strings.offset) + scan;
        if (readU32be(spa, at) != xstr_magic) continue;

        var str_offset: i64 = at + 12;
        const num_strings = readU16be(spa, str_offset);
        str_offset += 2;
        var string_index: u16 = 0;
        while (string_index < num_strings) : (string_index += 1) {
            const code = readU16be(spa, str_offset);
            const size = readU16be(spa, str_offset + 2);
            if (code == main_string_id) {
                const max_name = buffer.len - 1; // checked above
                const name_size: usize = @min(max_name, @as(usize, size));
                readBytes(spa, str_offset + 4, buffer[0..name_size]);
                buffer[name_size] = 0;
                break;
            }
            str_offset += @as(i64, size) + 4;
        }
        break;
    }
    return true;
}

/// `XexGameInfo::SPAGetGameIcon`. Returns null where the C++ returns false.
pub fn getGameIcon(gpa: std.mem.Allocator, spa: *const DataBlock) Error!?DataBlock {
    const num_entries = readU32be(spa, 8);
    const chunks = scanChunks(spa, num_entries);
    const base = findBase(spa, num_entries) orelse return null;

    if (chunks.icon.offset == 0) return null;

    const icon_size: i32 = @bitCast(chunks.icon.size);
    if (icon_size < 0) return error.InvalidSpaChunk;

    var icon = DataBlock.init();
    errdefer icon.deinit(gpa);
    const offset_u32 = base +% chunks.icon.offset;
    const offset: i32 = @bitCast(offset_u32);
    if (offset < 0) return error.InvalidSpaChunk;
    try icon.setBlock(gpa, spa, offset, 0, icon_size);
    return icon;
}

/// `XexGameInfo::GameName`: getSPA + getGameName.
pub fn gameName(gpa: std.mem.Allocator, xex: *const model.Xex, buffer: []u8) Error!bool {
    var spa = try getSPA(gpa, xex) orelse return false;
    defer spa.deinit(gpa);
    return getGameName(&spa, buffer);
}

/// `XexGameInfo::GameIcon`: getSPA + getGameIcon.
pub fn gameIcon(gpa: std.mem.Allocator, xex: *const model.Xex) Error!?DataBlock {
    var spa = try getSPA(gpa, xex) orelse return null;
    defer spa.deinit(gpa);
    return try getGameIcon(gpa, &spa);
}

fn scanChunks(spa: *const DataBlock, num_entries: u32) Chunks {
    var result: Chunks = .{};
    var i: u32 = 0;
    while (i < num_entries) : (i += 1) {
        // Offsets are 64-bit so a corrupt count cannot overflow u32; the C++
        // truncates the same product into an s32 argument.
        const entry: i64 = @as(i64, chunk_table_offset) + @as(i64, i) * chunk_size;
        const chunk: Chunk = .{
            .offset = readU32be(spa, entry + chunk_offset_offset),
            .size = readU32be(spa, entry + chunk_size_offset),
        };
        switch (readU16be(spa, entry + chunk_type_offset)) {
            chunk_type_icon => {
                if (readU32be(spa, entry + chunk_id_offset) == main_icon_id) result.icon = chunk;
            },
            chunk_type_string => {
                if (readU32be(spa, entry + chunk_id_offset) == english_locale_id) result.strings = chunk;
            },
            else => {},
        }
    }
    return result;
}

/// Scans byte-by-byte for "XTHD". The C++ uses 0 as "not found", so a match at
/// offset 0 (only possible with `num_entries == 0`) is reported as not found.
fn findBase(spa: *const DataBlock, num_entries: u32) ?u32 {
    const len = std.math.cast(i64, spa.data().len) orelse return null;
    const limit = len - 4;
    var i: u64 = @as(u64, num_entries) * chunk_size;
    while (true) : (i += 1) {
        const at = std.math.cast(i64, i) orelse break;
        if (at >= limit) break;
        if (readU32be(spa, at) == xthd_magic) {
            if (at == 0) return null;
            return @intCast(at);
        }
    }
    return null;
}

/// `DataBlock::get` with zero fill for offsets past the end. A negative offset
/// is out of bounds in the C++ too; it is treated as a zero-filled read instead
/// of reproducing that undefined behaviour.
fn readBytes(block: *const DataBlock, offset: i64, destination: []u8) void {
    @memset(destination, 0);
    if (offset < 0) return;
    const data = block.data();
    const start = std.math.cast(usize, offset) orelse return;
    if (start >= data.len) return;
    const available = @min(destination.len, data.len - start);
    @memcpy(destination[0..available], data[start..][0..available]);
}

fn readU16be(block: *const DataBlock, offset: i64) u16 {
    var bytes: [2]u8 = undefined;
    readBytes(block, offset, &bytes);
    return endian.get16be(&bytes, 0);
}

fn readU32be(block: *const DataBlock, offset: i64) u32 {
    var bytes: [4]u8 = undefined;
    readBytes(block, offset, &bytes);
    return endian.get32be(&bytes, 0);
}

test "game info: SPA name skips a non-0x8000 string" {
    const allocator = std.testing.allocator;
    var spa: [192]u8 = @splat(0);
    endian.set32be(&spa, 8, 2); // num_entries

    // Chunk table at 0x18: strings (type 3, ID 1, offset 0x40, size 0x30),
    // icon (type 2, ID 0x8000, offset 0x80, size 4).
    endian.set16be(&spa, 0x18 + 0, 3);
    endian.set32be(&spa, 0x18 + 2, 0);
    endian.set32be(&spa, 0x18 + 6, 1);
    endian.set32be(&spa, 0x18 + 10, 0x40);
    endian.set32be(&spa, 0x18 + 14, 0x30);

    endian.set16be(&spa, 0x2A + 0, 2);
    endian.set32be(&spa, 0x2A + 6, 0x8000);
    endian.set32be(&spa, 0x2A + 10, 0x80);
    endian.set32be(&spa, 0x2A + 14, 4);

    @memcpy(spa[60..64], "XTHD"); // base
    @memcpy(spa[0x7C..0x80], "XSTR");
    endian.set16be(&spa, 0x88, 2); // two strings
    endian.set16be(&spa, 0x8A, 0x0001); // locale string, skipped
    endian.set16be(&spa, 0x8C, 3);
    @memcpy(spa[0x8E..0x91], "abc");
    endian.set16be(&spa, 0x91, 0x8000); // main string
    endian.set16be(&spa, 0x93, 5);
    @memcpy(spa[0x95..0x9A], "Hello");
    @memcpy(spa[0xBC..0xC0], &.{ 1, 2, 3, 4 });

    var block = DataBlock.init();
    defer block.deinit(allocator);
    try block.set(allocator, &spa, 0, spa.len);

    var name: [1024]u8 = @splat(0xFF);
    try std.testing.expect(getGameName(&block, &name));
    try std.testing.expectEqualStrings("Hello", std.mem.sliceTo(&name, 0));

    var icon = (try getGameIcon(allocator, &block)).?;
    defer icon.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, icon.data());
}

test "game info: XTHD at offset zero counts as not found" {
    var spa: [8]u8 = @splat(0);
    @memcpy(spa[0..4], "XTHD");
    var block = DataBlock.init();
    defer block.deinit(std.testing.allocator);
    try block.set(std.testing.allocator, &spa, 0, spa.len);

    var name: [16]u8 = @splat(0);
    try std.testing.expect(!getGameName(&block, &name));
    try std.testing.expectEqualStrings("", std.mem.sliceTo(&name, 0));
    try std.testing.expect((try getGameIcon(std.testing.allocator, &block)) == null);
}

test "game info: getSPA finds the title id resource" {
    const allocator = std.testing.allocator;
    var xex = model.Xex.init(allocator);
    defer xex.deinit();
    xex.load_address = 0x82000000;
    xex.execution_id = .{ .title_id = 0x415607D0 };
    try xex.basefile.set(allocator, &.{ 9, 9, 1, 2, 3, 9 }, 0, 6);
    try xex.resources.append(allocator, .{
        .name = .{ '4', '1', '5', '6', '0', '7', 'D', '0' },
        .addr = 0x82000002,
        .size = 3,
    });

    var spa = (try getSPA(allocator, &xex)).?;
    defer spa.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, spa.data());

    xex.execution_id = .{ .title_id = 0x00000001 };
    try std.testing.expect((try getSPA(allocator, &xex)) == null);
}
