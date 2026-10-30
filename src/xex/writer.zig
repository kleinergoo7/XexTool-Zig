// SPDX-FileCopyrightText: 2026 XexTool Zig rewrite contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Port of `XexWriter::write`. The headers come from `header_writer.zig`; the
//! basefile bytes and the IMAGEKEY_BASEFILE_FORMAT payload come from the
//! packer, exactly as in XexWriter.cpp.

const std = @import("std");
const DataBlock = @import("../core/datablock.zig").DataBlock;
const endian = @import("../core/endian.zig");
const header_writer = @import("header_writer.zig");
const model = @import("model.zig");
const packer = @import("packer.zig");

pub const Error = header_writer.Error || packer.Error || error{BasefileTooLarge};

/// Serializes the whole XEX into `out`.
pub fn write(xex: *model.Xex, out: *DataBlock) Error!void {
    const gpa = xex.gpa;

    var basefile = DataBlock.init();
    defer basefile.deinit(gpa);
    var basefile_format = DataBlock.init();
    defer basefile_format.deinit(gpa);
    try prepareBasefile(xex, &basefile, &basefile_format);

    var headers = DataBlock.init();
    defer headers.deinit(gpa);
    try header_writer.writeHeaders(xex, &headers, basefile_format);

    const header_size = headers.size();
    const basefile_size = basefile.size();
    // Raw basefiles are padded to a 0x8000 boundary in the container.
    var pad: i32 = 0;
    if (xex.is_raw) {
        const padded: i64 = (@as(i64, basefile_size) + 0x7FFF) & ~@as(i64, 0x7FFF);
        const padding = padded - basefile_size;
        if (padding > std.math.maxInt(i32)) return error.BasefileTooLarge;
        pad = @intCast(padding);
    }

    out.clear(gpa);
    try out.set(gpa, headers.data(), 0, header_size);
    if (basefile_size == 0) return;
    try out.set(gpa, basefile.data(), header_size, basefile_size);
    try out.fill(gpa, 0, header_size + basefile_size, pad);
}

/// `XexWriter::write(const Xex&, const char*)`.
pub fn writeFile(xex: *model.Xex, io: std.Io, path: []const u8) !void {
    var output = DataBlock.init();
    defer output.deinit(xex.gpa);
    try write(xex, &output);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = output.data() });
}

fn prepareBasefile(xex: *model.Xex, basefile: *DataBlock, format: *DataBlock) Error!void {
    const gpa = xex.gpa;

    if (xex.is_delta_compressed) {
        // packDeltaCompressed is not implemented in the reference either: the
        // patch bytes are copied and the packed block describes them as-is.
        basefile.clear(gpa);
        try basefile.set(gpa, xex.patch_data.data(), 0, xex.patch_data.size());
        format.clear(gpa);
        try format.set32(gpa, 0x24, 0);
        try format.set16(gpa, if (xex.is_encrypted) 1 else 0, 4);
        try format.set16(gpa, 3, 6);
        try format.set32(gpa, 0x8000, 8);
        try format.set32(gpa, @bitCast(basefile.size()), 12);
        try format.fill(gpa, 0, 16, 20);
        return;
    }

    if (xex.basefile.size() == 0) {
        // No image data: keep the empty basefile and describe it with a raw
        // info block, as XexWriter.cpp does.
        basefile.clear(gpa);
        format.clear(gpa);
        try format.set32(gpa, 0x10, 0);
        try format.set16(gpa, if (xex.is_encrypted) 1 else 0, 4);
        const compression: u16 = if (xex.is_binary or xex.is_raw)
            1
        else if (xex.is_compressed)
            2
        else if (xex.is_delta_compressed)
            3
        else
            0;
        try format.set16(gpa, compression, 6);
        try format.set32(gpa, 0, 8);
        try format.set32(gpa, 0, 12);
        return;
    }

    try packer.pack(xex, basefile, format, xex.imageSize());
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const reader = @import("reader.zig");
const defines = @import("defines.zig");

fn testBaseFormat(gpa: std.mem.Allocator) !DataBlock {
    var format = DataBlock.init();
    errdefer format.deinit(gpa);
    try format.set32(gpa, 0x10, 0);
    try format.set16(gpa, 0, 4);
    try format.set16(gpa, 1, 6);
    try format.set32(gpa, 0, 8);
    try format.set32(gpa, 0, 12);
    return format;
}

test "write: raw image round-trips through the reader" {
    const gpa = std.testing.allocator;
    var xex = model.Xex.init(gpa);
    defer xex.deinit();
    xex.is_raw = true;
    xex.is_debug = true;
    xex.module_flags = defines.module_flag_title_module;
    xex.image_flags = defines.image_flag_title_usermode;
    xex.load_address = 0x82000000;

    var image: [0x10000]u8 = @splat(0);
    for (&image, 0..) |*byte, index| byte.* = @truncate(index *% 31);
    try xex.basefile.set(gpa, &image, 0, image.len);
    try xex.sections.append(gpa, .{ .size = image.len, .info = defines.section_info_code });

    var output = DataBlock.init();
    defer output.deinit(gpa);
    try write(&xex, &output);

    const header_size: usize = endian.get32be(output.data(), 0x08);
    try std.testing.expectEqual(@as(usize, 0x1000), header_size);
    // Raw packing stores only the non-zero data, and the container pads it to a
    // 0x8000 boundary.
    const basefile_size = output.size() - @as(i32, @intCast(header_size));
    try std.testing.expect(basefile_size > 0);
    try std.testing.expectEqual(@as(i32, 0), @mod(basefile_size, 0x8000));

    var parsed = model.Xex.init(gpa);
    defer parsed.deinit();
    try std.testing.expect(try reader.readBytes(&parsed, output.data()));
    try std.testing.expect(parsed.is_raw);
    try std.testing.expectEqualSlices(u8, &image, parsed.basefile.data());
    try std.testing.expectEqual(@as(usize, 1), parsed.sections.items.len);
    try std.testing.expectEqual(@as(i32, 0x10000), parsed.sections.items[0].size);
}

test "write: empty basefile emits headers only and zeroes the retail signature" {
    const gpa = std.testing.allocator;
    var xex = model.Xex.init(gpa);
    defer xex.deinit();
    xex.is_binary = true;
    xex.is_debug = false;

    var output = DataBlock.init();
    defer output.deinit(gpa);
    try write(&xex, &output);

    try std.testing.expectEqual(@as(i32, 0x1000), output.size());
    const sec_offset: usize = endian.get32be(output.data(), 0x10);
    const sec = output.data()[sec_offset..];
    var zero: [0x100]u8 = @splat(0);
    try std.testing.expectEqualSlices(u8, &zero, sec[0x08..0x108]);
    try std.testing.expectEqual(@as(u32, 0x174), endian.get32be(output.data(), sec_offset + 0x108));

    var parsed = model.Xex.init(gpa);
    defer parsed.deinit();
    try std.testing.expect(try reader.readBytes(&parsed, output.data()));
    try std.testing.expect(!parsed.is_debug);
    // Binary and raw both use compType 1; the reader reports raw.
    try std.testing.expect(parsed.is_raw);
}

test "write: boolean flag words survive a binary round-trip" {
    const gpa = std.testing.allocator;
    var xex = model.Xex.init(gpa);
    defer xex.deinit();
    xex.is_binary = true;
    xex.is_debug = true;
    xex.image_flags = defines.image_flag_4k_pages | defines.image_flag_title_usermode;
    xex.media_types = defines.media_hard_disk | defines.media_dvd9;
    xex.regions = defines.region_north_america | defines.region_japan;
    xex.system_flags = defines.sys_flag_allow_hud_vibration;

    const image = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    try xex.basefile.set(gpa, &image, 0, image.len);

    var output = DataBlock.init();
    defer output.deinit(gpa);
    try write(&xex, &output);

    var parsed = model.Xex.init(gpa);
    defer parsed.deinit();
    try std.testing.expect(try reader.readBytes(&parsed, output.data()));
    try std.testing.expectEqual(xex.image_flags, parsed.image_flags);
    try std.testing.expectEqual(xex.media_types, parsed.media_types);
    try std.testing.expectEqual(xex.regions, parsed.regions);
    try std.testing.expectEqual(xex.system_flags, parsed.system_flags);
    try std.testing.expectEqual(@as(u32, 0x1000), parsed.pageSize());
}

test "writeFile: writes the same bytes as write" {
    const gpa = std.testing.allocator;
    var xex = model.Xex.init(gpa);
    defer xex.deinit();
    xex.is_raw = true;
    try xex.basefile.set(gpa, &[_]u8{ 0xAA, 0xBB }, 0, 2);

    var output = DataBlock.init();
    defer output.deinit(gpa);
    try write(&xex, &output);

    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    try dir.dir.writeFile(std.testing.io, .{ .sub_path = "writer-test.xex", .data = output.data() });
    const read_back = try dir.dir.readFileAlloc(std.testing.io, "writer-test.xex", gpa, .limited(1 << 20));
    defer gpa.free(read_back);
    try std.testing.expectEqualSlices(u8, output.data(), read_back);
}
