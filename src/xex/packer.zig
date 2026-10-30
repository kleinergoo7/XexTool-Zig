// SPDX-FileCopyrightText: 2026 XexTool Zig rewrite contributors
// SPDX-License-Identifier: GPL-3.0-or-later

const std = @import("std");
const DataBlock = @import("../core/datablock.zig").DataBlock;
const cursor = @import("../core/cursor.zig");
const endian = @import("../core/endian.zig");
const crypto = @import("../xecrypt/xecrypt.zig");
const defines = @import("defines.zig");
const model = @import("model.zig");
const types = @import("types.zig");

pub const Error = error{
    InvalidRange,
    OutOfMemory,
    OutOfBounds,
    InvalidBaseFileInfo,
    UnsupportedCompression,
};

pub fn unpack(xex: *model.Xex, basefile_in: DataBlock, basefile_format: DataBlock, image_size: i32) Error!void {
    if (xex.is_binary) {
        try unpackBinary(xex, basefile_in);
    } else if (xex.is_raw) {
        try unpackRaw(xex, basefile_in, basefile_format, image_size);
    } else if (xex.is_compressed) {
        return error.UnsupportedCompression;
    } else if (xex.is_delta_compressed) {
        xex.patch_data = try basefile_in.clone(xex.gpa);
        xex.patch_info = try basefile_format.clone(xex.gpa);
    } else {
        return error.InvalidBaseFileInfo;
    }
}

fn unpackBinary(xex: *model.Xex, basefile_in: DataBlock) Error!void {
    xex.basefile = try basefile_in.clone(xex.gpa);
    if (xex.is_encrypted) try decrypt(xex, &xex.basefile);
}

fn unpackRaw(xex: *model.Xex, basefile_in: DataBlock, unpack_info: DataBlock, image_size: i32) Error!void {
    var input = try basefile_in.clone(xex.gpa);
    defer input.deinit(xex.gpa);
    if (xex.is_encrypted) try decrypt(xex, &input);

    const info = unpack_info.data();
    if (info.len < 8) return error.InvalidBaseFileInfo;

    xex.basefile.clear(xex.gpa);
    var input_offset: i32 = 0;
    var output_offset: i32 = 0;
    var current_image_size: i32 = 0;
    var block_offset: usize = 8;

    while (output_offset < image_size) {
        if (block_offset + 8 > info.len) return error.InvalidBaseFileInfo;
        const data_size: i32 = @bitCast(endian.get32be(info, block_offset));
        const zero_size: i32 = @bitCast(endian.get32be(info, block_offset + 4));
        block_offset += 8;
        if (data_size < 0 or zero_size < 0) return error.InvalidBaseFileInfo;

        if (data_size != 0) {
            try xex.basefile.setBlock(xex.gpa, &input, input_offset, output_offset, data_size);
            input_offset += data_size;
            output_offset += data_size;
            current_image_size += data_size;
        }
        if (zero_size != 0) {
            try xex.basefile.fill(xex.gpa, 0, output_offset, zero_size);
            output_offset += zero_size;
            current_image_size += zero_size;
        }
        if (zero_size == 0) break;
    }

    const tail = image_size - current_image_size;
    if (tail > 0) try xex.basefile.fill(xex.gpa, 0, xex.basefile.size(), tail);
}

fn decrypt(xex: *model.Xex, block: *DataBlock) Error!void {
    const bytes = block.size();
    if (@mod(bytes, 16) != 0) return error.InvalidBaseFileInfo;
    var aes: crypto.AesState = undefined;
    crypto.XeCryptAesKey(&aes, &xex.image_key.data);
    var iv: [16]u8 = @splat(0);
    const source = try xex.gpa.dupe(u8, block.data());
    defer xex.gpa.free(source);
    crypto.XeCryptAesCbc(&aes, source, block.dataMut(), &iv, false);
}

test "unpackRaw: copies blocks and expands zero runs" {
    var xex = model.Xex.init(std.testing.allocator);
    defer xex.deinit();
    xex.is_raw = true;

    var input = DataBlock.init();
    defer input.deinit(std.testing.allocator);
    try input.set(std.testing.allocator, &.{ 1, 2, 3, 4 }, 0, 4);

    var info = DataBlock.init();
    defer info.deinit(std.testing.allocator);
    var raw_info: [16]u8 = @splat(0);
    endian.set32be(&raw_info, 0, 16);
    endian.set32be(&raw_info, 8, 4);
    endian.set32be(&raw_info, 12, 4);
    try info.set(std.testing.allocator, &raw_info, 0, 16);

    try unpackRaw(&xex, input, info, 8);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 0, 0, 0, 0 }, xex.basefile.data());
}
