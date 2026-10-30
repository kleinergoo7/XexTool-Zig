// SPDX-FileCopyrightText: 2026 XexTool Zig rewrite contributors
// SPDX-License-Identifier: GPL-3.0-or-later

const std = @import("std");
const DataBlock = @import("../core/datablock.zig").DataBlock;
const cursor = @import("../core/cursor.zig");
const header = @import("header.zig");
const model = @import("model.zig");
const packer = @import("packer.zig");
const Keys = @import("keys.zig").Keys;

pub const Error = error{
    InvalidRange,
    OutOfMemory,
    OutOfBounds,
    Overflow,
    InvalidMagic,
    InvalidSecurityInfo,
    InvalidImageEntry,
    InvalidBaseFileInfo,
    Unsupported,
    UnsupportedCompression,
    HashMismatch,
    LzxFailed,
};

pub fn readFile(xex: *model.Xex, io: std.Io, path: []const u8, keys: Keys) !bool {
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, xex.gpa, .limited(1 << 40));
    defer xex.gpa.free(bytes);
    return readBytes(xex, bytes, keys);
}

pub fn readBytes(xex: *model.Xex, bytes: []const u8, keys: Keys) Error!bool {
    if (bytes.len < 0x18) return error.OutOfBounds;
    if (!std.mem.eql(u8, bytes[0..4], &@import("defines.zig").xex_magic)) return error.InvalidMagic;

    const headers_size_u32 = try cursor.readU32beAt(bytes, 0x08);
    if (headers_size_u32 > std.math.maxInt(i32)) return error.Overflow;
    const headers_size: usize = headers_size_u32;
    if (headers_size > bytes.len) return error.OutOfBounds;

    var headers = DataBlock.init();
    defer headers.deinit(xex.gpa);
    try headers.set(xex.gpa, bytes[0..headers_size], 0, @intCast(headers_size_u32));

    var basefile_format = DataBlock.init();
    defer basefile_format.deinit(xex.gpa);

    const image_size = try header.readHeaders(xex, headers, keys);
    basefile_format = try xex.basefile_format.clone(xex.gpa);

    const basefile_size = bytes.len - headers_size;
    if (basefile_size > std.math.maxInt(i32)) return error.Overflow;
    var basefile_in = DataBlock.init();
    defer basefile_in.deinit(xex.gpa);
    try basefile_in.set(xex.gpa, bytes[headers_size..], 0, @intCast(basefile_size));

    try packer.unpack(xex, basefile_in, basefile_format, image_size);
    return true;
}
