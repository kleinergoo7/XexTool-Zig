// SPDX-FileCopyrightText: 2026 XexTool Zig rewrite contributors
// SPDX-License-Identifier: GPL-3.0-or-later

const std = @import("std");
const DataBlock = @import("../core/datablock.zig").DataBlock;
const endian = @import("../core/endian.zig");
const crypto = @import("../xecrypt/xecrypt.zig");
const lzx = @import("../lzx/lzx.zig");
const model = @import("model.zig");

pub const Error = error{
    InvalidRange,
    OutOfMemory,
    OutOfBounds,
    InvalidBaseFileInfo,
    UnsupportedCompression,
    HashMismatch,
    LzxFailed,
};

pub fn unpack(xex: *model.Xex, basefile_in: DataBlock, basefile_format: DataBlock, image_size: i32) Error!void {
    if (xex.is_binary) {
        try unpackBinary(xex, basefile_in);
    } else if (xex.is_raw) {
        try unpackRaw(xex, basefile_in, basefile_format, image_size);
    } else if (xex.is_compressed) {
        try unpackCompressed(xex, basefile_in, basefile_format, image_size);
    } else if (xex.is_delta_compressed) {
        xex.patch_data = try basefile_in.clone(xex.gpa);
        xex.patch_info = try basefile_format.clone(xex.gpa);
    } else {
        return error.InvalidBaseFileInfo;
    }
}

pub fn pack(xex: *model.Xex, basefile_out: *DataBlock, unpack_info: *DataBlock, image_size: i32) Error!void {
    if (xex.is_binary) {
        try packBinary(xex, basefile_out, unpack_info, image_size);
    } else if (xex.is_raw) {
        try packRaw(xex, basefile_out, unpack_info, image_size);
    } else if (xex.is_compressed) {
        try packCompressed(xex, basefile_out, unpack_info, image_size);
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

fn unpackCompressed(xex: *model.Xex, basefile_in: DataBlock, unpack_info: DataBlock, image_size: i32) Error!void {
    var input = try basefile_in.clone(xex.gpa);
    defer input.deinit(xex.gpa);
    if (xex.is_encrypted) try decrypt(xex, &input);

    const info = unpack_info.data();
    if (info.len < 0x24) return error.InvalidBaseFileInfo;
    const window_size = endian.get32be(info, 8);
    const input_bytes = input.data();

    xex.basefile.clear(xex.gpa);
    const decoder = lzx.createDecompressionWindow(xex.gpa, window_size) catch return error.LzxFailed;
    defer lzx.destroyDecompression(decoder);

    var input_offset: usize = 0;
    var output_offset: i32 = 0;
    var block_size: usize = 0;
    var first = true;

    while (output_offset < image_size) {
        const data_size: usize = if (first) endian.get32be(info, 12) else endian.get32be(input_bytes, input_offset);
        const hash = if (first) info[16..36] else input_bytes[input_offset + 4 ..][0..20];
        input_offset += block_size;
        block_size = data_size;
        if (input_offset > input_bytes.len or block_size > input_bytes.len - input_offset) return error.OutOfBounds;

        const block = input_bytes[input_offset..][0..block_size];
        var digest: [20]u8 = undefined;
        crypto.XeCryptSha(block, "", "", &digest, 20);
        if (!std.mem.eql(u8, &digest, hash)) return error.HashMismatch;

        var comp_offset: usize = 24;
        while (true) {
            if (comp_offset + 2 > block.len) return error.InvalidBaseFileInfo;
            const comp_size = endian.get16be(block, comp_offset);
            comp_offset += 2;
            if (comp_size == 0) break;
            if (comp_offset + comp_size > block.len) return error.OutOfBounds;

            const uncomp_size: i32 = @min(0x8000, image_size - output_offset);
            var temporary: [0x8000]u8 = undefined;
            const produced = lzx.decompressBlock(decoder, block[comp_offset..][0..comp_size], temporary[0..@intCast(uncomp_size)]) catch return error.LzxFailed;
            if (produced != uncomp_size) return error.LzxFailed;
            try xex.basefile.set(xex.gpa, temporary[0..@intCast(uncomp_size)], output_offset, uncomp_size);
            output_offset += uncomp_size;
            comp_offset += comp_size;
        }
        first = false;
    }
}

fn packBinary(xex: *model.Xex, basefile_out: *DataBlock, unpack_info: *DataBlock, image_size: i32) Error!void {
    _ = image_size;
    basefile_out.clear(xex.gpa);
    basefile_out.* = try xex.basefile.clone(xex.gpa);
    if (xex.is_encrypted) try encrypt(xex, basefile_out);

    unpack_info.clear(xex.gpa);
    try unpack_info.set32(xex.gpa, 0x10, 0);
    try unpack_info.set16(xex.gpa, if (xex.is_encrypted) 1 else 0, 4);
    try unpack_info.set16(xex.gpa, 1, 6);
    try unpack_info.set32(xex.gpa, basefile_out.size(), 8);
    try unpack_info.set32(xex.gpa, 0, 12);
}

fn packRaw(xex: *model.Xex, basefile_out: *DataBlock, unpack_info: *DataBlock, image_size: i32) Error!void {
    _ = image_size;
    const data = xex.basefile.data();
    const page_size: i32 = 0x8000;
    const data_size: i32 = @intCast(data.len);

    basefile_out.clear(xex.gpa);
    unpack_info.clear(xex.gpa);
    try unpack_info.set32(xex.gpa, 0, 0);
    try unpack_info.set16(xex.gpa, 0, 4);
    try unpack_info.set16(xex.gpa, 0, 6);

    var data_block_size: i32 = 0;
    var zero_block_size: i32 = 0;
    var output_offset: i32 = 0;
    var data_offset: i32 = 0;

    while (data_offset < data_size) {
        if (data_block_size != 0 and @mod(data_offset, page_size) == 0) {
            var scan = data_offset;
            while (scan < data_size and data[scan] == 0) : (scan += 1) {
                zero_block_size += 1;
            }
        }
        zero_block_size &= -page_size;

        if (zero_block_size >= page_size or data_offset + zero_block_size == data_size) {
            const info_offset = unpack_info.size();
            try unpack_info.set32(xex.gpa, data_block_size, info_offset);
            try unpack_info.set32(xex.gpa, if (data_offset + zero_block_size != data_size) zero_block_size else 0, info_offset + 4);

            try basefile_out.set(xex.gpa, data[@intCast(data_offset - data_block_size)..][0..@intCast(data_block_size)], output_offset, data_block_size);
            output_offset += data_block_size;
            data_block_size = 0;

            data_offset += zero_block_size;
            zero_block_size = 0;
        } else {
            var increment = @mod(data_offset, page_size);
            if (increment == 0) increment = page_size;
            if (increment > data_size - data_offset) increment = data_size - data_offset;
            data_block_size += increment;
            data_offset += increment;
        }
    }

    if (data_block_size != 0 or zero_block_size != 0) {
        const info_offset = unpack_info.size();
        try unpack_info.set32(xex.gpa, data_block_size, info_offset);
        try unpack_info.set32(xex.gpa, 0, info_offset + 4);
        try basefile_out.set(xex.gpa, data[@intCast(data_offset - data_block_size)..][0..@intCast(data_block_size)], output_offset, data_block_size);
    }

    if (xex.is_encrypted) try encrypt(xex, basefile_out);
    try unpack_info.set32(xex.gpa, unpack_info.size(), 0);
}

fn packCompressed(xex: *model.Xex, basefile_out: *DataBlock, unpack_info: *DataBlock, image_size: i32) Error!void {
    const window_size: u32 = 0x8000;
    const source = xex.basefile.data();
    if (source.len != @as(usize, @intCast(image_size))) return error.InvalidBaseFileInfo;

    const capacity = source.len + source.len / 4 + 0x10000;
    const encoded = try xex.gpa.alloc(u8, capacity);
    defer xex.gpa.free(encoded);
    const framed = lzx.compress(xex.gpa, encoded, source, window_size) catch return error.LzxFailed;

    var comp_data: std.ArrayList(u8) = .empty;
    defer comp_data.deinit(xex.gpa);
    var pos: usize = 0;
    while (pos + 4 <= framed.len) {
        const comp_size = std.mem.readInt(u16, framed[pos..][0..2], .little);
        pos += 4;
        if (comp_size == 0 or pos + comp_size > framed.len) break;
        var size_bytes: [2]u8 = undefined;
        endian.set16be(&size_bytes, 0, comp_size);
        try comp_data.appendSlice(xex.gpa, &size_bytes);
        try comp_data.appendSlice(xex.gpa, framed[pos..][0..comp_size]);
        pos += comp_size;
    }

    basefile_out.clear(xex.gpa);
    var sizes: std.ArrayList(usize) = .empty;
    defer sizes.deinit(xex.gpa);

    const header_size: usize = 24;
    const max_block: usize = 0x10000;
    var comp_offset: usize = 0;
    var current_size: usize = 0;
    var current_offset: usize = 0;

    const append_block = struct {
        fn call(gpa: std.mem.Allocator, out: *DataBlock, data: []const u8, offset: usize, size: usize, header: usize, aligned: usize, sizes_list: *std.ArrayList(usize)) !void {
            const output_offset = out.size();
            try out.fill(gpa, 0, output_offset, @intCast(header));
            try out.set(gpa, data[offset..][0..size], output_offset + @as(i32, @intCast(header)), @intCast(size));
            try out.fill(gpa, 0, output_offset + @as(i32, @intCast(header + size)), @intCast(aligned - (size + header)));
            try sizes_list.append(gpa, aligned);
        }
    }.call;

    while (comp_offset < comp_data.items.len) {
        const block_size = @as(usize, endian.get16be(comp_data.items, comp_offset)) + 2;
        if (current_size + block_size + header_size + 2 >= max_block) {
            const aligned = alignUp(current_size + header_size + 2);
            try append_block(xex.gpa, basefile_out, comp_data.items, current_offset, current_size, header_size, aligned, &sizes);
            current_offset += current_size;
            current_size = block_size;
        } else {
            current_size += block_size;
        }
        comp_offset += block_size;
        if (comp_offset >= comp_data.items.len) {
            const aligned = alignUp(current_size + header_size);
            try append_block(xex.gpa, basefile_out, comp_data.items, current_offset, current_size, header_size, aligned, &sizes);
            current_offset += current_size;
            current_size = block_size;
        }
    }

    var block_offset = @as(usize, @intCast(basefile_out.size()));
    var index = sizes.items.len;
    while (index > 0) {
        index -= 1;
        const block_size = sizes.items[index];
        block_offset -= block_size;
        var digest: [20]u8 = undefined;
        crypto.XeCryptSha(basefile_out.data()[block_offset..][0..block_size], "", "", &digest, 20);
        if (index != 0) {
            const out_offset: i32 = @intCast(block_offset - sizes.items[index - 1]);
            try basefile_out.set32be(xex.gpa, @intCast(block_size), out_offset);
            try basefile_out.set(xex.gpa, &digest, out_offset + 4, 20);
        } else {
            unpack_info.clear(xex.gpa);
            try unpack_info.set32(xex.gpa, 0x24, 0);
            try unpack_info.set16(xex.gpa, if (xex.is_encrypted) 1 else 0, 4);
            try unpack_info.set16(xex.gpa, 2, 6);
            try unpack_info.set32(xex.gpa, window_size, 8);
            try unpack_info.set32(xex.gpa, @intCast(block_size), 12);
            try unpack_info.set(xex.gpa, &digest, 16, 20);
        }
    }

    if (xex.is_encrypted) try encrypt(xex, basefile_out);
}

fn alignUp(value: usize) usize {
    return (value + 0x800 - 1) & ~@as(usize, 0x800 - 1);
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

fn encrypt(xex: *model.Xex, block: *DataBlock) Error!void {
    const bytes = block.size();
    if (@mod(bytes, 16) != 0) return error.InvalidBaseFileInfo;
    var aes: crypto.AesState = undefined;
    crypto.XeCryptAesKey(&aes, &xex.image_key.data);
    var iv: [16]u8 = @splat(0);
    const source = try xex.gpa.dupe(u8, block.data());
    defer xex.gpa.free(source);
    crypto.XeCryptAesCbc(&aes, source, block.dataMut(), &iv, true);
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

test "packRaw then unpackRaw round-trips" {
    var xex = model.Xex.init(std.testing.allocator);
    defer xex.deinit();
    xex.is_raw = true;

    const input = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    try xex.basefile.set(std.testing.allocator, &input, 0, input.len);

    var packed_block = DataBlock.init();
    defer packed_block.deinit(std.testing.allocator);
    var info = DataBlock.init();
    defer info.deinit(std.testing.allocator);
    try packRaw(&xex, &packed_block, &info, input.len);

    var decoded = model.Xex.init(std.testing.allocator);
    defer decoded.deinit();
    decoded.is_raw = true;
    try unpackRaw(&decoded, packed_block, info, input.len);
    try std.testing.expectEqualSlices(u8, &input, decoded.basefile.data());
}

test "packCompressed then unpackCompressed round-trips" {
    var xex = model.Xex.init(std.testing.allocator);
    defer xex.deinit();
    xex.is_compressed = true;

    const input = "compressed basefile test data, repeated repeated repeated";
    try xex.basefile.set(std.testing.allocator, input, 0, input.len);

    var packed_block = DataBlock.init();
    defer packed_block.deinit(std.testing.allocator);
    var info = DataBlock.init();
    defer info.deinit(std.testing.allocator);
    try packCompressed(&xex, &packed_block, &info, input.len);

    var decoded = model.Xex.init(std.testing.allocator);
    defer decoded.deinit();
    decoded.is_compressed = true;
    try unpackCompressed(&decoded, packed_block, info, input.len);
    try std.testing.expectEqualSlices(u8, input, decoded.basefile.data());
}
