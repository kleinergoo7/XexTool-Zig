// SPDX-FileCopyrightText: 2026 XexTool Zig rewrite contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Port of XexTool/src/SpecialPatches.cpp. The title-id dispatch, patch-bitflag
// selection, byte patching and console messages follow the reference; the
// byte tables live in special_retail_data.zig and special_xefu.zig.

const std = @import("std");
const DataBlock = @import("../core/datablock.zig").DataBlock;
const endian = @import("../core/endian.zig");
const xecrypt = @import("../xecrypt/xecrypt.zig");
const model = @import("model.zig");
const pe = @import("pe.zig");
const types = @import("types.zig");
const retail = @import("special_retail_data.zig");
const xefu = @import("special_xefu.zig");

pub const Error = error{
    OutOfMemory,
    InvalidRange,
    WriteFailed,
    InvalidPe,
    InvalidSection,
    OutOfBounds,
    InvalidCode,
    InvalidString,
};

const SectionInfo = struct {
    name: [8]u8,
    offset: u32,
    size: u32,

    fn nameSlice(self: *const SectionInfo) []const u8 {
        return std.mem.sliceTo(&self.name, 0);
    }
};

fn emit(out: anytype, comptime format: []const u8, args: anytype) Error!void {
    out.print(format, args) catch return error.WriteFailed;
}

fn toI32(value: u32) Error!i32 {
    // DataBlock offsets and lengths are s32 in the reference.
    if (value > std.math.maxInt(i32)) return error.InvalidSection;
    return @intCast(value);
}

fn sectionInfo(parser: pe.Parser, index: u16) Error!SectionInfo {
    const section = parser.section(index) orelse return error.InvalidPe;
    return .{
        .name = section.name,
        .offset = section.virtual_address,
        .size = section.virtual_size,
    };
}

fn readSection(gpa: std.mem.Allocator, block: *const DataBlock, section: SectionInfo) Error![]u8 {
    const buffer = try gpa.alloc(u8, @as(usize, section.size));
    errdefer gpa.free(buffer);
    try block.get(buffer, try toI32(section.offset), try toI32(section.size));
    return buffer;
}

fn patchAt(gpa: std.mem.Allocator, block: *DataBlock, data: []const u8, base: u32, delta: i64) Error!void {
    const absolute = @as(i64, base) + delta;
    if (absolute < 0 or absolute > std.math.maxInt(i32)) return error.OutOfBounds;
    if (data.len > std.math.maxInt(i32)) return error.OutOfBounds;
    // Both casts are checked by the two guards above.
    try block.set(gpa, data, @intCast(absolute), @intCast(data.len));
}

fn replaceBasefile(xex: *model.Xex, basefile: *DataBlock) void {
    xex.basefile.deinit(xex.gpa);
    xex.basefile = basefile.*;
}

fn searchDataMaskWords(buff: []const u8, data: []const u32, mask: []const u32) ?usize {
    if (data.len != mask.len) return null;
    const words = buff.len / 4;
    if (data.len == 0) return 0;
    if (words < data.len) return null;
    var index: usize = 0;
    // Reference condition: index < buffsize/4 - datasize/4.
    while (index + data.len < words) : (index += 1) {
        var matched = true;
        for (0..data.len) |slot| {
            const value = endian.get32be(buff, (index + slot) * 4);
            if ((value & mask[slot]) != (data[slot] & mask[slot])) {
                matched = false;
                break;
            }
        }
        if (matched) return index * 4;
    }
    return null;
}

fn searchDataMaskBytes(buff: []const u8, data: []const u8, mask: []const u8) ?usize {
    if (data.len != mask.len) return null;
    if (buff.len <= data.len) return null;
    var offset: usize = 0;
    // Reference condition: offset < buffsize - datasize.
    while (offset + data.len < buff.len) : (offset += 1) {
        if ((buff[offset] & mask[0]) != (data[0] & mask[0])) continue;
        var matched = true;
        for (0..data.len) |index| {
            if ((buff[offset + index] & mask[index]) != (data[index] & mask[index])) {
                matched = false;
                break;
            }
        }
        if (matched) return offset;
    }
    return null;
}

fn contains(haystack: ?[]const u8, needle: []const u8) bool {
    const text = haystack orelse return false;
    return std.mem.indexOf(u8, text, needle) != null;
}

/// Performs the special patches selected by `patch_num`.
/// A `patch_num` of 0 lists the patches, `0xFFFFFFFF` selects all of them.
pub fn doSpecialPatches(gpa: std.mem.Allocator, xex: *model.Xex, patch_num: u32, out: anytype) Error!bool {
    const exec_id = xex.execution_id orelse return false;

    switch (exec_id.title_id) {
        // Rockband 1, 2, 3, AC/DC, Beatles and Lego.
        0x45410829, 0x45410869, 0x45410914, 0x45410889, 0x454108B1, 0x575207F0 => {
            return rockbandCryptPatch(gpa, xex, patch_num, out);
        },
        // Dance Central beta, final, 2 beta, 2 final and 3 final.
        0x545687D7, 0x545607D3, 0x373387D4, 0x373307D2, 0x373307D9 => {
            return danceCryptPatch(gpa, xex, patch_num, out);
        },
        // dash.xex
        0xFFFE07D1 => return dashPatches(gpa, xex, patch_num, out),
        // xbox.xex, xefu.xex and the xefutitle variants.
        0xFFFE07D2 => {
            if (contains(xex.bounding_path, "xefutitle") or contains(xex.original_pe_name, "xefutitle")) {
                // Not xefutitle??.xex: fall through to the "no special patch" message.
            } else if (contains(xex.bounding_path, "xbox") or contains(xex.original_pe_name, "xbox")) {
                return xboxPatches(gpa, xex, patch_num, out);
            } else if (contains(xex.bounding_path, "xefu") or contains(xex.original_pe_name, "xefu")) {
                return xefuPatches(gpa, xex, patch_num, out);
            } else {
                // xefu1_1.xex and xefu2.xex have neither name: patch them anyway.
                return xefuPatches(gpa, xex, patch_num, out);
            }
        },
        // A DLL such as xam.xex or xbdm.xex.
        0x00000000 => {
            if (contains(xex.bounding_path, "xam") or contains(xex.original_pe_name, "xam")) {
                return xamPatches(gpa, xex, patch_num, out);
            } else if (contains(xex.bounding_path, "xbdm") or contains(xex.original_pe_name, "xbdm")) {
                return xbdmPatches(gpa, xex, patch_num, out);
            }
        },
        else => {},
    }

    try emit(out, "  no special patch found for this xex\n", .{});
    return false;
}

// ---------------------------------------------------------------------------
// Update-patch fix
// ---------------------------------------------------------------------------

const update_key = "update:";
const update_unicode_key = [_]u8{ 0, 'u', 0, 'p', 0, 'd', 0, 'a', 0, 't', 0, 'e', 0, ':' };
const max_update_name = 1024;

/// Rewrites "update:..." and its UTF-16 form in `.rdata` to "D:...".
pub fn doUpdatePatchFix(gpa: std.mem.Allocator, xex: *model.Xex) Error!bool {
    const parser = pe.Parser.init(xex.basefile.data());
    const section_count = parser.numberOfSections() orelse return error.InvalidPe;

    var basefile = try xex.basefile.clone(gpa);
    errdefer basefile.deinit(gpa);

    var result = false;
    var index: u16 = 0;
    while (index < section_count) : (index += 1) {
        const section = try sectionInfo(parser, index);
        if (!std.mem.eql(u8, section.nameSlice(), ".rdata")) continue;

        const buff = try readSection(gpa, &basefile, section);
        defer gpa.free(buff);
        const size: i64 = section.size;
        var i: i64 = 4 - @as(i64, section.offset & 3);
        while (i < size - 20) : (i += 4) {
            const at: usize = @intCast(i); // i is never negative here
            if ((buff[at] | 0x20) == 'u' and
                std.ascii.eqlIgnoreCase(buff[at..][0..update_key.len], update_key))
            {
                const end = std.mem.indexOfScalarPos(u8, buff, at, 0) orelse return error.InvalidString;
                const len = end - at;
                if (len < update_key.len or len >= max_update_name) continue;
                var printable = true;
                for (buff[at..][0..len]) |byte| {
                    if (!std.ascii.isPrint(byte)) printable = false;
                }
                if (!printable) continue;

                var fixname: [max_update_name]u8 = @splat(0);
                fixname[0] = 'D';
                fixname[1] = ':';
                @memcpy(fixname[2..][0 .. len - update_key.len], buff[at + update_key.len ..][0 .. len - update_key.len]);
                try patchAt(gpa, &basefile, fixname[0..len], section.offset, i);
                result = true;
            }

            // UTF-16LE "\0u\0p\0d\0a\0t\0e\0:".
            if (at + update_unicode_key.len <= buff.len and
                std.mem.eql(u8, buff[at..][0..update_unicode_key.len], &update_unicode_key))
            {
                var len: usize = 0;
                while (true) : (len += 2) {
                    if (at + 1 + len >= buff.len) return error.InvalidString;
                    if (buff[at + 1 + len] == 0) break;
                }
                if (len > max_update_name * 2) continue;
                var printable = true;
                var x: usize = 0;
                while (x < len) : (x += 2) {
                    if (!std.ascii.isPrint(buff[at + 1 + x])) printable = false;
                }
                if (!printable) continue;

                var fixname: [max_update_name * 2]u8 = @splat(0);
                fixname[0] = 0;
                fixname[1] = 'D';
                fixname[2] = 0;
                fixname[3] = ':';
                x = update_unicode_key.len;
                while (x < len) : (x += 1) {
                    fixname[x - update_unicode_key.len + 4] = buff[at + x];
                }
                try patchAt(gpa, &basefile, fixname[0..len], section.offset, i);
                result = true;
            }
        }
        // The reference stops after the first ".rdata" section.
        break;
    }

    if (result) {
        replaceBasefile(xex, &basefile);
    } else {
        basefile.deinit(gpa);
    }
    return result;
}

// ---------------------------------------------------------------------------
// Disc-swap check removal
// ---------------------------------------------------------------------------

/// Removes the XamSwapDisc/XamSwapCancel calls found in `.text`.
pub fn doDiscSwapChecksFix(gpa: std.mem.Allocator, xex: *model.Xex) Error!bool {
    const parser = pe.Parser.init(xex.basefile.data());
    const section_count = parser.numberOfSections() orelse return error.InvalidPe;

    var text: ?SectionInfo = null;
    var index: u16 = 0;
    while (index < section_count) : (index += 1) {
        const section = try sectionInfo(parser, index);
        if (std.mem.eql(u8, section.nameSlice(), ".text")) {
            text = section;
            break;
        }
    }
    const section = text orelse return false;

    var basefile = try xex.basefile.clone(gpa);
    errdefer basefile.deinit(gpa);
    const text_data = try readSection(gpa, &basefile, section);
    defer gpa.free(text_data);

    const text_sect_addr = section.offset +% xex.load_address;
    var swapdisc_func_addr: u32 = 0;
    var swapcancel_func_addr: u32 = 0;
    var setevent_func_addr: u32 = 0;

    for (xex.import_libraries.items) |library| {
        const name = std.mem.sliceTo(&library.name, 0);
        const is_xam = std.mem.eql(u8, name, "xam.xex");
        const is_kernel = std.mem.eql(u8, name, "xboxkrnl.exe");
        if (!is_xam and !is_kernel) continue;

        for (library.addresses) |func_addr| {
            const func_offset = func_addr -% text_sect_addr;
            // The reference checks func_offset+4 but reads two words; both are
            // validated here so malformed imports fail instead of over-reading.
            if (func_offset +% 4 > section.size) continue;
            if (@as(u64, func_offset) + 8 > section.size) continue;
            const at: usize = @intCast(func_offset); // guarded against section.size above
            const func_num1 = endian.get32be(text_data, at);
            const func_num2 = endian.get32be(text_data, at + 4);
            if (((func_num1 >> 24) & 0xFF) != 1 or
                ((func_num2 >> 24) & 0xFF) != 2 or
                ((func_num1 >> 16) & 0xFF) != library.module_index or
                ((func_num2 >> 16) & 0xFF) != library.module_index or
                ((func_num1 & 0xFFFF) != (func_num2 & 0xFFFF)))
            {
                continue;
            }
            const func_num = func_num1 & 0xFFFF;
            if (is_xam) {
                if (func_num == 0xA28) swapdisc_func_addr = func_addr;
                if (func_num == 0xA2A) swapcancel_func_addr = func_addr;
                if (swapdisc_func_addr != 0 and swapcancel_func_addr != 0) break;
            } else {
                if (func_num == 0x9D) setevent_func_addr = func_addr;
                if (setevent_func_addr != 0) break;
            }
        }
    }

    var patch_count: u32 = 0;
    var offset: u32 = 0;
    while (offset < section.size) : (offset += 4) {
        if (@as(u64, offset) + 4 > section.size) break;
        const at: usize = @intCast(offset); // offset < section.size and +4 fits
        const data = endian.get32be(text_data, at);
        const addr = text_sect_addr +% offset;
        const bl_swapdisc = 0x48000001 | ((swapdisc_func_addr -% addr) & 0x3FFFFFE);
        const bl_swapcancel = 0x48000001 | ((swapcancel_func_addr -% addr) & 0x3FFFFFE);

        if (data == bl_swapdisc) {
            // The reference writes 0xC bytes before the call.
            if (offset < 0xC) return error.InvalidCode;
            const bl_setevent = 0x48000001 | ((setevent_func_addr -% (addr -% 4)) & 0x3FFFFFE);
            endian.set32be(text_data, at - 0xC, 0x38800001); // li r4, 1
            endian.set32be(text_data, at - 0x8, 0x38A00000); // li r5, 0
            endian.set32be(text_data, at - 0x4, bl_setevent); // bl KeSetEvent
            endian.set32be(text_data, at, 0x38600000); // li r3, 0
            patch_count += 1;
        } else if (data == bl_swapcancel) {
            endian.set32be(text_data, at, 0x38600000); // li r3, 0
            patch_count += 1;
        }

        if (patch_count == 2) break;
    }

    try basefile.set(gpa, text_data, try toI32(section.offset), try toI32(section.size));
    replaceBasefile(xex, &basefile);
    return patch_count == 2;
}

// ---------------------------------------------------------------------------
// xam.xex
// ---------------------------------------------------------------------------

const kinect_search_data1 = [_]u32{ 0x38600008, 0x4BFFFCB0, 0x4BFFEAC9, 0x7C7D1B79, 0x40800044 };
const kinect_search_data2 = [_]u32{ 0x38600008, 0x4BFFFCB0, 0x4BFFEAC9, 0x2C030000, 0x40800044 };
const kinect_search_mask = [_]u32{ 0xFFFFFFFE, 0xFFFFF001, 0xFC000001, 0xFFE0FFFF, 0xFFFFF000 };
const license_search_data = [_]u8{ 0x39, 0x60, 0x00, 0x57, 0x7D, 0x63, 0x5B, 0x78 };
const license_patch_data = [_]u8{
    0x3D, 0x60, 0x00, 0x00, // lis %r11, 0x0000
    0x61, 0x6B, 0x00, 0x01, // ori %r11, %r11, 0x0001
    0x91, 0x63, 0x00, 0x00, // stw %r11, 0(%r3)
    0x38, 0x60, 0x00, 0x00, // li r3, 0
    0x4E, 0x80, 0x00, 0x20, // blr
};
const func_start = [_]u8{ 0x7D, 0x88, 0x02, 0xA6 }; // mflr r12
const dash_search_data = "dash.xex\x00";
const dash_patch_data = "load.xex\x00";

fn xamPatches(gpa: std.mem.Allocator, xex: *model.Xex, patch_flags: u32, out: anytype) Error!bool {
    if (patch_flags == 0) {
        try emit(out, "  1 = force all arcade games to be licensed/unlocked/full\n", .{});
        try emit(out, "  2 = allow unauthenticated kinect hw usage\n", .{});
        try emit(out, "  4 = loads load.xex instead of dash.xex\n", .{});
        return true;
    }
    if ((patch_flags & (1 | 2 | 4)) == 0) {
        try emit(out, "  unsupported patch flags\n", .{});
        return false;
    }

    const do_license = (patch_flags & 1) != 0;
    const do_kinect = (patch_flags & 2) != 0;
    const do_dash = (patch_flags & 4) != 0;

    var done_license = false;
    var done_kinect = false;
    var done_dash = false;

    const parser = pe.Parser.init(xex.basefile.data());
    const section_count = parser.numberOfSections() orelse return error.InvalidPe;

    var basefile = try xex.basefile.clone(gpa);
    errdefer basefile.deinit(gpa);

    var result = false;
    var index: u16 = 0;
    while (index < section_count) : (index += 1) {
        const section = try sectionInfo(parser, index);
        const name = section.nameSlice();

        if (std.mem.eql(u8, name, ".text") and
            ((do_license and !done_license) or (do_kinect and !done_kinect)))
        {
            const buff = try readSection(gpa, &basefile, section);
            defer gpa.free(buff);

            if (do_kinect and !done_kinect) {
                var data_offset = searchDataMaskWords(buff, &kinect_search_data1, &kinect_search_mask);
                if (data_offset == null) {
                    data_offset = searchDataMaskWords(buff, &kinect_search_data2, &kinect_search_mask);
                }
                if (data_offset) |found| {
                    var i: usize = 0;
                    while (i < 4 * 8) : (i += 4) {
                        if (found + i > buff.len) break;
                        if (found + i + 2 > buff.len) break;
                        if (buff[found + i] == 0x40 and buff[found + i + 1] == 0x80) {
                            if (found + i < 4) return error.InvalidCode;
                            const exec_id = xex.execution_id orelse types.ExecutionId{};
                            if ((types.Version32{ .dword = exec_id.version }).build() >= 15574) {
                                // li rXX, 0 / nop
                                const reg: u8 = @truncate(basefile.get16be(try relativeI32(section.offset, found + i - 4)) & 0x1F);
                                var patch = [_]u8{ 0x38, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00 };
                                patch[0] |= reg >> 3;
                                patch[1] |= reg << 5;
                                try patchAt(gpa, &basefile, &patch, section.offset, @intCast(found + i - 4));
                            } else {
                                // b auth_successful
                                try patchAt(gpa, &basefile, &[_]u8{ 0x48, 0x00 }, section.offset, @intCast(found + i));
                            }
                            done_kinect = true;
                            break;
                        }
                    }
                }
            }

            var i: usize = 0;
            const sect_end: i64 = @as(i64, section.size) - 0x100;
            while (@as(i64, @intCast(i)) < sect_end) : (i += 1) {
                if (do_license and !done_license and
                    buff[i] == license_search_data[0] and
                    std.mem.eql(u8, buff[i..][0..license_search_data.len], &license_search_data))
                {
                    while (i > 0) {
                        if (std.mem.eql(u8, buff[i..][0..func_start.len], &func_start)) break;
                        i -= 1;
                    }
                    try patchAt(gpa, &basefile, &license_patch_data, section.offset, @intCast(i));
                    done_license = true;
                }

                if (do_license and !done_license) continue;
                break;
            }
        } else if (std.mem.eql(u8, name, ".rdata")) {
            if (do_dash and !done_dash) {
                const buff = try readSection(gpa, &basefile, section);
                defer gpa.free(buff);
                const limit: i64 = @as(i64, section.size) - @as(i64, dash_search_data.len);
                var i: i64 = 0;
                while (i < limit) : (i += 1) {
                    const at: usize = @intCast(i); // i >= 0
                    if (buff[at] == dash_search_data[0] and
                        std.mem.eql(u8, buff[at..][0..dash_search_data.len], dash_search_data))
                    {
                        try patchAt(gpa, &basefile, dash_patch_data, section.offset, i);
                        done_dash = true;
                    }
                    if (do_dash and !done_dash) continue;
                    break;
                }
            }
        }
    }

    if (do_license) {
        if (done_license) {
            try emit(out, "  patched force all arcade games to be licensed/unlocked/full\n", .{});
            result = true;
        } else {
            try emit(out, "  error patching force all arcade games to be licensed/unlocked/full\n", .{});
        }
    }
    if (do_kinect) {
        if (done_kinect) {
            try emit(out, "  patched allow unauthenticated kinect hw usage\n", .{});
            result = true;
        } else {
            try emit(out, "  error patching allow unauthenticated kinect hw usage\n", .{});
        }
    }
    if (do_dash) {
        if (done_dash) {
            try emit(out, "  patched loads load.xex instead of dash.xex\n", .{});
            result = true;
        } else {
            try emit(out, "  error patching loads load.xex instead of dash.xex\n", .{});
        }
    }

    if (result) replaceBasefile(xex, &basefile) else basefile.deinit(gpa);
    return result;
}

fn relativeI32(base: u32, delta: usize) Error!i32 {
    const value = @as(u64, base) + delta;
    if (value > std.math.maxInt(i32)) return error.OutOfBounds;
    return @intCast(value);
}

// ---------------------------------------------------------------------------
// xbdm.xex
// ---------------------------------------------------------------------------

const map_new_search_data = [_]u32{ 0x38A00000, 0x4BFFC5D9, 0x4BFFECF5 };
const map_new_search_mask = [_]u32{ 0xFFFFFFFF, 0xFC000001, 0xFC000001 };
const map_old_search_data = [_]u32{ 0x816B8084, 0x2F0B0000, 0x419A0008, 0x4BFFD989, 0x39610058 };
const map_old_search_mask = [_]u32{ 0xFE000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFC000001, 0xFF000000 };

fn readBaseWord(block: *const DataBlock, offset: i64) Error!u32 {
    if (offset < 0 or offset > std.math.maxInt(i32)) return error.InvalidCode;
    const size = block.size();
    if (offset > size - 4) return error.InvalidCode;
    return block.get32be(@intCast(offset)); // range checked above
}

fn xbdmPatches(gpa: std.mem.Allocator, xex: *model.Xex, patch_flags: u32, out: anytype) Error!bool {
    if (patch_flags == 0) {
        try emit(out, "  1 = allow access to extra drives in network neighbourhood\n", .{});
        try emit(out, "  2 = disable flagging of slim devkits as testkits\n", .{});
        return true;
    }
    if ((patch_flags & (1 | 2)) == 0) {
        try emit(out, "  unsupported patch flags\n", .{});
        return false;
    }

    const do_map = (patch_flags & 1) != 0;
    const do_testkit = (patch_flags & 2) != 0;

    var internal_addr_reg: u32 = 0;
    var internal_addr: u32 = 0;
    var got_internal_addr_lo = false;
    var got_internal_addr = false;
    var patched_internal = false;
    var patched_map_flags = false;

    const parser = pe.Parser.init(xex.basefile.data());
    const section_count = parser.numberOfSections() orelse return error.InvalidPe;

    var basefile = try xex.basefile.clone(gpa);
    errdefer basefile.deinit(gpa);

    var result = false;
    var index: u16 = 0;
    while (index < section_count) : (index += 1) {
        const section = try sectionInfo(parser, index);
        if (std.mem.eql(u8, section.nameSlice(), ".text")) {
            const buff = try readSection(gpa, &basefile, section);
            defer gpa.free(buff);

            var data_offset = searchDataMaskWords(buff, &map_new_search_data, &map_new_search_mask);
            if (data_offset == null) {
                data_offset = searchDataMaskWords(buff, &map_old_search_data, &map_old_search_mask);
            }
            if (data_offset) |found| {
                var i: usize = 0;
                while (i < 20 * 4) : (i += 4) {
                    const value = try readBaseWord(&basefile, try relativeI32(section.offset, found + i));

                    if ((do_map or do_testkit) and !got_internal_addr_lo and
                        (value & 0xFFE00000) == 0x81600000)
                    {
                        internal_addr = value & 0xFFFF;
                        if ((internal_addr & 0x8000) != 0) internal_addr |= 0xFFFF0000;
                        internal_addr_reg = (value >> 16) & 0x1F;
                        got_internal_addr_lo = true;
                    }

                    if (do_map and got_internal_addr_lo and !patched_map_flags and
                        (value & 0xFC000001) == 0x48000001)
                    {
                        var func_addr = value & 0x00FFFFFC;
                        if (func_addr >= 0x800000) func_addr |= 0xFF000000;
                        func_addr +%= xex.load_address +% section.offset +% @as(u32, @intCast(found + i));
                        const func_offset = func_addr -% xex.load_address;
                        var first_skipped = false;
                        var x: i64 = func_offset;
                        while (try readBaseWord(&basefile, x) != 0x4E800020) : (x += 4) {
                            const word = try readBaseWord(&basefile, x);
                            if ((word & 0xFFFF0000) == 0x38A00000) {
                                if (first_skipped) try basefile.set32be(gpa, 0x38A00001, @intCast(x));
                                first_skipped = true;
                            }
                        }
                        patched_map_flags = true;
                    }

                    if (do_map and (!got_internal_addr_lo or !patched_map_flags)) continue;
                    if (do_testkit and !got_internal_addr_lo) continue;
                    break;
                }

                var i_signed: i64 = -@as(i64, @intCast(i));
                while (i_signed < 80 * 4) : (i_signed += 4) {
                    const at = try relativeI32(section.offset, found) - i_signed;
                    if (at < 0) return error.InvalidCode;
                    const word = try readBaseWord(&basefile, at);
                    if ((do_map or do_testkit) and !got_internal_addr and
                        (word & 0xFFFF0000) == (0x3C000000 | (internal_addr_reg << 21)))
                    {
                        internal_addr +%= (word & 0xFFFF) << 16;
                        got_internal_addr = true;
                        break;
                    }
                    if (word == 0x7D8802A6) break;
                }
            }
        } else if (std.mem.eql(u8, section.nameSlice(), ".data")) {
            if ((do_map or do_testkit) and got_internal_addr) {
                const var_offset = internal_addr -% (xex.load_address +% section.offset);
                if (var_offset +% 4 <= section.size) {
                    const absolute = @as(u64, var_offset) + section.offset;
                    if (absolute > std.math.maxInt(i32)) return error.OutOfBounds;
                    try basefile.set32be(gpa, 1, @intCast(absolute)); // checked above
                    patched_internal = true;
                    break;
                }
            }
        }
    }

    if (do_map) {
        if (patched_map_flags and patched_internal) {
            try emit(out, "  patched allow access to extra drives in network neighbourhood\n", .{});
            result = true;
        } else {
            try emit(out, "  error patching allow access to extra drives in network neighbourhood\n", .{});
        }
    }
    if (do_testkit) {
        if (patched_internal) {
            try emit(out, "  patched disable flagging of slim devkits as testkits\n", .{});
            result = true;
        } else {
            try emit(out, "  error patching disable flagging of slim devkits as testkits\n", .{});
        }
    }

    if (result) replaceBasefile(xex, &basefile) else basefile.deinit(gpa);
    return result;
}

// ---------------------------------------------------------------------------
// Harmonix crypto patch shared by Rockband and Dance Central
// ---------------------------------------------------------------------------

const rdata_search1 = [_]u8{ 0x00, 0x01, 0x02, 0x4B, 0x00, 0x01, 0x02, 0x42 };
const rdata_patch1 = [_]u8{ 0x00, 0x01, 0x01, 0x5B, 0x00, 0x01, 0x01, 0x59 };
const rdata_search2 = [_]u8{ 0x00, 0x01, 0x02, 0x42, 0x00, 0x01, 0x02, 0x4B };
const rdata_patch2 = [_]u8{ 0x00, 0x01, 0x01, 0x59, 0x00, 0x01, 0x01, 0x5B };
const text_search1 = [_]u8{
    0x01, 0x01, 0x02, 0x42, 0x02, 0x01, 0x02, 0x42, 0x7D, 0x69, 0x03, 0xA6, 0x4E, 0x80, 0x04, 0x20,
    0x01, 0x01, 0x02, 0x4B, 0x02, 0x01, 0x02, 0x4B, 0x7D, 0x69, 0x03, 0xA6, 0x4E, 0x80, 0x04, 0x20,
};
const text_patch1 = [_]u8{
    0x01, 0x01, 0x01, 0x59, 0x02, 0x01, 0x01, 0x59, 0x7D, 0x69, 0x03, 0xA6, 0x4E, 0x80, 0x04, 0x20,
    0x01, 0x01, 0x01, 0x5B, 0x02, 0x01, 0x01, 0x5B, 0x7D, 0x69, 0x03, 0xA6, 0x4E, 0x80, 0x04, 0x20,
};
const text_search2 = [_]u8{
    0x01, 0x01, 0x02, 0x4B, 0x02, 0x01, 0x02, 0x4B, 0x7D, 0x69, 0x03, 0xA6, 0x4E, 0x80, 0x04, 0x20,
    0x01, 0x01, 0x02, 0x42, 0x02, 0x01, 0x02, 0x42, 0x7D, 0x69, 0x03, 0xA6, 0x4E, 0x80, 0x04, 0x20,
};
const text_patch2 = [_]u8{
    0x01, 0x01, 0x01, 0x5B, 0x02, 0x01, 0x01, 0x5B, 0x7D, 0x69, 0x03, 0xA6, 0x4E, 0x80, 0x04, 0x20,
    0x01, 0x01, 0x01, 0x59, 0x02, 0x01, 0x01, 0x59, 0x7D, 0x69, 0x03, 0xA6, 0x4E, 0x80, 0x04, 0x20,
};

fn wordAt(buff: []const u8, offset: i64) Error!u32 {
    if (offset < 0 or offset > std.math.maxInt(i32)) return error.InvalidCode;
    const at: usize = @intCast(offset); // checked above
    if (at > buff.len or buff.len - at < 4) return error.InvalidCode;
    return endian.get32be(buff, at);
}

/// Reference condition: `off + section.offset + load_address > tc_crypt_addr`.
/// A negative `off` is malformed input; the original would wrap and read OOB.
fn signedOffset(value: u32) i64 {
    // The reference treats the wrapped u32 difference as a signed int index.
    return @as(i32, @bitCast(value));
}

fn aboveCrypt(off: i64, section_offset: u32, load_address: u32, tc_crypt_addr: u32) Error!bool {
    if (off < 0) return error.InvalidCode;
    const address = @as(u64, @intCast(off)) + section_offset + load_address;
    return address > tc_crypt_addr;
}

fn putWord(buff: []u8, offset: i64, value: u32) Error!void {
    if (offset < 0 or offset > std.math.maxInt(i32)) return error.InvalidCode;
    const at: usize = @intCast(offset); // checked above
    if (at > buff.len or buff.len - at < 4) return error.InvalidCode;
    endian.set32be(buff, at, value);
}

fn harmonixCryptPatch(gpa: std.mem.Allocator, xex: *model.Xex) Error!bool {
    const original = xex.basefile.data();
    const parser = pe.Parser.init(original);
    const load_address = parser.loadAddress() orelse return error.InvalidPe;
    const section_count = parser.numberOfSections() orelse return error.InvalidPe;

    var basefile = try xex.basefile.clone(gpa);
    errdefer basefile.deinit(gpa);

    var xe_keys_set_key_addr: u32 = 0;
    var tc_set_key_addr: u32 = 0;
    var tc_crypt_addr: u32 = 0;
    var tc_crypt_data_addr: u32 = 0;
    var tc_key_addr: u32 = 0;
    var tc_key_count: u32 = 0;

    var index: u16 = 0;
    while (index < section_count) : (index += 1) {
        const section = try sectionInfo(parser, index);
        const name = section.nameSlice();
        const section_size: i64 = section.size;

        if (std.mem.eql(u8, name, ".rdata")) {
            const buff = try readSection(gpa, &basefile, section);
            defer gpa.free(buff);

            var patched = false;
            const limit = section_size - @as(i64, rdata_search1.len);
            var i: i64 = 0;
            while (i < limit) : (i += 1) {
                const at: usize = @intCast(i); // i >= 0
                if (buff[at] == rdata_search1[0] and
                    std.mem.eql(u8, buff[at..][0..rdata_search1.len], &rdata_search1))
                {
                    try patchAt(gpa, &basefile, &rdata_patch1, section.offset, i);
                    patched = true;
                    break;
                }
                if (buff[at] == rdata_search2[0] and
                    std.mem.eql(u8, buff[at..][0..rdata_search2.len], &rdata_search2))
                {
                    try patchAt(gpa, &basefile, &rdata_patch2, section.offset, i);
                    patched = true;
                    break;
                }
            }
            if (!patched) {
                basefile.deinit(gpa);
                return false;
            }
        } else if (std.mem.eql(u8, name, ".text")) {
            const buff = try readSection(gpa, &basefile, section);
            defer gpa.free(buff);

            var i: i64 = 0;
            const limit = section_size - @as(i64, text_search1.len);
            while (i < limit) : (i += 1) {
                const at: usize = @intCast(i); // i >= 0
                if (buff[at] == text_search1[0] and
                    std.mem.eql(u8, buff[at..][0..text_search1.len], &text_search1))
                {
                    @memcpy(buff[at..][0..text_patch1.len], &text_patch1);
                    xe_keys_set_key_addr = section.offset +% @as(u32, @intCast(i)) +% load_address;
                    break;
                }
                if (buff[at] == text_search2[0] and
                    std.mem.eql(u8, buff[at..][0..text_search2.len], &text_search2))
                {
                    @memcpy(buff[at..][0..text_patch2.len], &text_patch2);
                    xe_keys_set_key_addr = section.offset +% @as(u32, @intCast(i)) +% load_address;
                    break;
                }
            }
            if (xe_keys_set_key_addr == 0) {
                basefile.deinit(gpa);
                return false;
            }

            // Find a call to XeKeysSetKey, then its mflr prologue (TCSetKey).
            i = 0;
            while (i < section_size - 4) : (i += 4) {
                const word = try wordAt(buff, i);
                const opcode = 0x48000001 |
                    (xe_keys_set_key_addr -% load_address -% section.offset -% @as(u32, @intCast(i)));
                if (word == opcode) {
                    while (try wordAt(buff, i) != 0x7D8802A6) i -= 4;
                    tc_set_key_addr = load_address +% section.offset +% @as(u32, @intCast(i));
                    break;
                }
            }
            if (tc_set_key_addr == 0) {
                basefile.deinit(gpa);
                return false;
            }

            // Find a call to TCSetKey, then TCCrypt and TCCryptData.
            i = 0;
            while (i < section_size - 4) : (i += 4) {
                const word = try wordAt(buff, i);
                const opcode = 0x48000001 |
                    (tc_set_key_addr -% load_address -% section.offset -% @as(u32, @intCast(i)));
                if (word != opcode) continue;

                var off: i64 = i;
                while (try wordAt(buff, off) != 0x7D8802A6) off -= 4;
                tc_crypt_addr = load_address +% section.offset +% @as(u32, @intCast(off));

                off = i + 4;
                while (off < section_size) : (off += 4) {
                    const branch = try wordAt(buff, off);
                    if ((branch & 0xF8000000) == 0x48000000) {
                        var target = branch & 0x00FFFFFC;
                        if (target >= 0x800000) target |= 0xFF000000;
                        tc_crypt_data_addr = target +% load_address +% section.offset +% @as(u32, @intCast(off));
                        break;
                    }
                }

                // Single-key variant (r4 loaded from r11).
                off = i;
                while (try aboveCrypt(off, section.offset, load_address, tc_crypt_addr)) : (off -= 4) {
                    const word2 = try wordAt(buff, off);
                    if ((word2 & 0xFFFF0000) == 0x388B0000) tc_key_addr |= word2 & 0xFFFF;
                    if ((word2 & 0xFFFF0000) == 0x3D600000 and tc_key_addr != 0) {
                        if (tc_key_addr < 0x8000) {
                            tc_key_addr |= (word2 & 0xFFFF) << 16;
                        } else {
                            tc_key_addr |= ((word2 & 0xFFFF) -% 1) << 16;
                        }
                        break;
                    }
                }
                tc_key_count = 1;
                if (tc_key_addr != 0) break;

                // Multiple-key variants. The reference counts bl instructions
                // while scanning backwards to choose the key count.
                var bl_count: u32 = 0;
                off = i;
                while (try aboveCrypt(off, section.offset, load_address, tc_crypt_addr)) : (off -= 4) {
                    const word2 = try wordAt(buff, off);
                    if ((word2 & 0xFC000000) == 0x48000000) bl_count += 1;
                    if ((word2 & 0xFFFF0000) == 0x396B0000) tc_key_addr |= word2 & 0xFFFF;
                    if ((word2 & 0xFFFF0000) == 0x3D600000 and tc_key_addr != 0) {
                        if (tc_key_addr < 0x8000) {
                            tc_key_addr |= (word2 & 0xFFFF) << 16;
                        } else {
                            tc_key_addr |= ((word2 & 0xFFFF) -% 1) << 16;
                        }
                    }
                }
                while (try aboveCrypt(off, section.offset, load_address, tc_crypt_addr)) : (off -= 4) {
                    const word2 = try wordAt(buff, off);
                    if ((word2 & 0xFC000000) == 0x48000000) bl_count += 1;
                }
                if (bl_count == 2) {
                    tc_key_count = 4;
                    if (tc_key_addr != 0) break;
                } else {
                    tc_key_count = 2;
                    if (tc_key_addr != 0) break;
                }

                off = i;
                while (try aboveCrypt(off, section.offset, load_address, tc_crypt_addr)) : (off -= 4) {
                    const word2 = try wordAt(buff, off);
                    if ((word2 & 0xFFFF0000) == 0x396B0000) tc_key_addr |= word2 & 0xFFFF;
                    if ((word2 & 0xFFFF0000) == 0x3D600000 and tc_key_addr != 0) {
                        if (tc_key_addr < 0x8000) {
                            tc_key_addr |= (word2 & 0xFFFF) << 16;
                        } else {
                            tc_key_addr |= ((word2 & 0xFFFF) -% 1) << 16;
                        }
                    }
                }
                tc_key_count = 2;
                if (tc_key_addr != 0) break;

                off = i;
                while (try aboveCrypt(off, section.offset, load_address, tc_crypt_addr)) : (off -= 4) {
                    const word2 = try wordAt(buff, off);
                    if ((word2 & 0xFFFF0000) == 0x396A0000) tc_key_addr |= word2 & 0xFFFF;
                    if ((word2 & 0xFFFF0000) == 0x3D400000 and tc_key_addr != 0) {
                        if (tc_key_addr < 0x8000) {
                            tc_key_addr |= (word2 & 0xFFFF) << 16;
                        } else {
                            tc_key_addr |= ((word2 & 0xFFFF) -% 1) << 16;
                        }
                    }
                }
                tc_key_count = 2;
                if (tc_key_addr != 0) break;

                off = i;
                while (try aboveCrypt(off, section.offset, load_address, tc_crypt_addr)) : (off -= 4) {
                    const word2 = try wordAt(buff, off);
                    if ((word2 & 0xFFFF0000) == 0x394A0000) tc_key_addr |= word2 & 0xFFFF;
                    if ((word2 & 0xFFFF0000) == 0x3D400000 and tc_key_addr != 0) {
                        if (tc_key_addr < 0x8000) {
                            tc_key_addr |= (word2 & 0xFFFF) << 16;
                        } else {
                            tc_key_addr |= ((word2 & 0xFFFF) -% 1) << 16;
                        }
                    }
                }
                tc_key_count = 3;
                if (tc_key_addr != 0) break;

                off = i;
                while (try aboveCrypt(off, section.offset, load_address, tc_crypt_addr)) : (off -= 4) {
                    const word2 = try wordAt(buff, off);
                    if ((word2 & 0xFFFF0000) == 0x39690000) tc_key_addr |= word2 & 0xFFFF;
                    if ((word2 & 0xFFFF0000) == 0x3D200000 and tc_key_addr != 0) {
                        if (tc_key_addr < 0x8000) {
                            tc_key_addr |= (word2 & 0xFFFF) << 16;
                        } else {
                            tc_key_addr |= ((word2 & 0xFFFF) -% 1) << 16;
                        }
                    }
                }
                tc_key_count = 2;
                if (tc_key_addr != 0) break;

                tc_key_count = 0;
                break;
            }
            if (tc_key_addr == 0 or tc_key_count == 0) {
                basefile.deinit(gpa);
                return false;
            }

            // TCCrypt: reserve a SHA context on the stack and pass it as arg0.
            var off = signedOffset(tc_crypt_addr -% load_address -% section.offset);
            while ((try wordAt(buff, off) & 0xFFFF0000) != 0x94210000) off += 4;
            var stack_size: u32 = ((try wordAt(buff, off)) & 0xFFFF) ^ 0xFFFF;
            stack_size +%= 1;
            try putWord(buff, off, 0x94210000 | ((stack_size +% 0x190 -% 1) ^ 0xFFFF));

            while (try wordAt(buff, off) != 0x38600000) off += 4;
            try putWord(buff, off, 0x38610000 | (stack_size -% 0x20));

            while (try wordAt(buff, off) != 0x38600000) off += 4;
            try putWord(buff, off, 0x38610000 | (stack_size -% 0x20));

            while ((try wordAt(buff, off) & 0xFFFF0000) != 0x38210000) off += 4;
            try putWord(buff, off, 0x38210000 | (stack_size +% 0x190));

            // TCSetKey: use the SHA context.
            off = signedOffset(tc_set_key_addr -% load_address -% section.offset);
            while (try wordAt(buff, off) != 0x4E800020) {
                const word = try wordAt(buff, off);
                if (word == 0x386300E0) {
                    try putWord(buff, off, 0x60000000);
                } else if (word == 0x2B030008) {
                    try putWord(buff, off, 0x60000000);
                    off += 4;
                    try putWord(buff, off, 0x48000000 | (try wordAt(buff, off) & 0xFFFF));
                }
                off += 4;
            }

            // TCCryptData: put the zero IV on the stack.
            off = signedOffset(tc_crypt_data_addr -% load_address -% section.offset);
            while ((try wordAt(buff, off) & 0xFFFF0000) != 0x94210000) off += 4;
            stack_size = ((try wordAt(buff, off)) & 0xFFFF) ^ 0xFFFF;
            stack_size +%= 1;
            try putWord(buff, off, 0x94210000 | ((stack_size +% 0x10 -% 1) ^ 0xFFFF));

            while (try wordAt(buff, off) != 0x38E00000) {
                if (try wordAt(buff, off) == 0x2B030008) {
                    try putWord(buff, off, 0x60000000);
                    off += 4;
                    try putWord(buff, off, 0x48000000 | (try wordAt(buff, off) & 0xFFFF));
                }
                off += 4;
            }
            try putWord(buff, off, 0x38E10000 | (stack_size -% 0x10));
            off += 4;
            try putWord(buff, off, 0xF9070000);
            off += 4;
            try putWord(buff, off, 0xF9070008);
            off += 4;

            while ((try wordAt(buff, off) & 0xFFFF0000) != 0x38210000) off += 4;
            try putWord(buff, off, 0x38210000 | (stack_size +% 0x10));
            off += 4;

            try basefile.set(gpa, buff, try toI32(section.offset), try toI32(section.size));
        } else if (std.mem.eql(u8, name, ".data")) {
            if (tc_key_count == 0) continue;
            const key_count: usize = tc_key_count;
            const key_bytes = try gpa.alloc(u8, key_count * 0x10);
            defer gpa.free(key_bytes);

            const text_offset = tc_key_addr -% load_address;
            try basefile.get(key_bytes, try toI32(text_offset), try toI32(@intCast(key_count * 0x10)));

            for (0..key_count) |key_index| {
                const key = key_bytes[key_index * 0x10 ..][0..0x10];
                var state: xecrypt.HmacShaState = undefined;
                xecrypt.XeCryptHmacShaInit(&state, key);
                xecrypt.XeCryptHmacShaUpdate(&state, &retail.g_1bl_pub_key);
                xecrypt.XeCryptHmacShaUpdate(&state, &retail.g_1bl_other_keys);
                xecrypt.XeCryptHmacShaUpdate(&state, &retail.g_integrity_sig);
                xecrypt.XeCryptHmacShaUpdate(&state, &retail.g_constant_keys);
                xecrypt.XeCryptHmacShaUpdate(&state, &retail.g_xex_dvd_keys);
                xecrypt.XeCryptHmacShaUpdate(&state, &retail.g_roam_obfusc_key);
                xecrypt.XeCryptHmacShaUpdate(&state, &retail.g_cp_syslink_key);
                xecrypt.XeCryptHmacShaFinal(&state, key, 0x10);
            }
            try basefile.set(gpa, key_bytes, try toI32(text_offset), try toI32(@intCast(key_count * 0x10)));
        }
    }

    replaceBasefile(xex, &basefile);
    return true;
}

fn danceCryptPatch(gpa: std.mem.Allocator, xex: *model.Xex, patch_flags: u32, out: anytype) Error!bool {
    if (patch_flags == 0) {
        try emit(out, "  1 = patch dance central crypt to work on devkits\n", .{});
        return true;
    }
    if ((patch_flags & 1) == 0) {
        try emit(out, "  unsupported patch flags\n", .{});
        return false;
    }

    const result = try harmonixCryptPatch(gpa, xex);
    if (result) {
        try emit(out, "  patched dance central crypt to work on devkits\n", .{});
    } else {
        try emit(out, "  error patching dance central crypt to work on devkits\n", .{});
    }
    return result;
}

fn rockbandCryptPatch(gpa: std.mem.Allocator, xex: *model.Xex, patch_flags: u32, out: anytype) Error!bool {
    if (patch_flags == 0) {
        try emit(out, "  1 = patch rockband crypt to work on devkits\n", .{});
        return true;
    }
    if ((patch_flags & 1) == 0) {
        try emit(out, "  unsupported patch flags\n", .{});
        return false;
    }

    const result = try harmonixCryptPatch(gpa, xex);
    if (result) {
        try emit(out, "  patched rockband crypt to work on devkits\n", .{});
    } else {
        try emit(out, "  error patching rockband crypt to work on devkits\n", .{});
    }
    return result;
}

// ---------------------------------------------------------------------------
// xbox.xex
// ---------------------------------------------------------------------------

const xbox_update_search = "update:\\";
const xbox_search_data = [_]u32{ 0x3D608200, 0x7C6A1B78, 0x396B06F4, 0x39200005, 0x7D2903A6 };
const xbox_search_mask = [_]u32{ 0xFFFF0000, 0xFFFFFFFF, 0xFFFF0000, 0xFFFFFFFF, 0xFFFFFFFF };

fn xboxPatches(gpa: std.mem.Allocator, xex: *model.Xex, patch_flags: u32, out: anytype) Error!bool {
    if (patch_flags == 0) {
        try emit(out, "  1 = allow unsupported xbox1 games\n", .{});
        return true;
    }
    if ((patch_flags & 1) == 0) {
        try emit(out, "  unsupported patch flags\n", .{});
        return false;
    }

    const parser = pe.Parser.init(xex.basefile.data());
    const section_count = parser.numberOfSections() orelse return error.InvalidPe;

    var basefile = try xex.basefile.clone(gpa);
    errdefer basefile.deinit(gpa);

    var result = false;
    var index: u16 = 0;
    while (index < section_count) : (index += 1) {
        const section = try sectionInfo(parser, index);
        if (std.mem.eql(u8, section.nameSlice(), ".rdata")) {
            const buff = try readSection(gpa, &basefile, section);
            defer gpa.free(buff);
            const limit: i64 = @as(i64, section.size) - @as(i64, xbox_update_search.len + 1); // + NUL, as sizeof()
            var i: i64 = 0;
            while (i < limit) : (i += 1) {
                const at: usize = @intCast(i); // i >= 0
                if (buff[at] != 'u') continue;
                if (!std.mem.eql(u8, buff[at..][0..xbox_update_search.len], xbox_update_search)) continue;

                var tmp: [260]u8 = @splat(0);
                const end = std.mem.indexOfScalarPos(u8, buff, at, 0) orelse return error.InvalidString;
                const len = end - at;
                if (len + 1 > tmp.len) return error.InvalidString;
                @memcpy(tmp[0..len], buff[at..][0..len]);
                tmp[5] = 'X';
                @memset(buff[at..][0..len], 0);
                @memcpy(buff[at..][0 .. len - 5], tmp[5..][0 .. len - 5]);
                result = true;
            }
            try basefile.set(gpa, buff, try toI32(section.offset), try toI32(section.size));
        } else if (std.mem.eql(u8, section.nameSlice(), ".text")) {
            const buff = try readSection(gpa, &basefile, section);
            defer gpa.free(buff);

            const found = searchDataMaskWords(buff, &xbox_search_data, &xbox_search_mask);
            if (found) |data_offset| {
                // nop out "bne cr6, ..."
                var off: i64 = @intCast(data_offset);
                while (try wordAt(buff, off) != 0x7D8802A6) : (off -= 4) {
                    if ((try wordAt(buff, off) & 0xFFFF0000) == 0x409A0000) {
                        try putWord(buff, off, 0x60000000);
                        break;
                    }
                }
                // nop out the first "beq cr6, ..."
                off = @intCast(data_offset);
                while (try wordAt(buff, off) != 0x7D8802A6) : (off -= 4) {
                    if ((try wordAt(buff, off) & 0xFFFF0000) == 0x419A0000) {
                        try putWord(buff, off, 0x60000000);
                        break;
                    }
                }
                // nop out the second "beq cr6, ..."
                off = @intCast(data_offset);
                while (try wordAt(buff, off) != 0x4E800020) : (off += 4) {
                    if ((try wordAt(buff, off) & 0xFFFF0000) == 0x419A0000) {
                        try putWord(buff, off, 0x60000000);
                        break;
                    }
                }

                // Default-title options: 0x80000002 -> 0.
                var options_addr = endian.get32be(buff, data_offset + 8) & 0x0000FFFF;
                if (options_addr >= 0x8000) options_addr |= 0xFFFF0000;
                options_addr +%= (endian.get32be(buff, data_offset) & 0x0000FFFF) << 16;
                const options_offset = options_addr -% xex.load_address;
                try patchAt(gpa, &basefile, &[_]u8{ 0, 0, 0, 0 }, options_offset, 12);
                result = true;
            }

            try basefile.set(gpa, buff, try toI32(section.offset), try toI32(section.size));
        }
    }

    if (result) {
        try emit(out, "  patched allow unsupported xbox1 games\n", .{});
    } else {
        try emit(out, "  error patching allow unsupported xbox1 games\n", .{});
    }

    if (result) replaceBasefile(xex, &basefile) else basefile.deinit(gpa);
    return result;
}

// ---------------------------------------------------------------------------
// xefu.xex
// ---------------------------------------------------------------------------

fn xefuPatches(gpa: std.mem.Allocator, xex: *model.Xex, patch_flags: u32, out: anytype) Error!bool {
    if (patch_flags == 0) {
        try emit(out, "   1 = fix retail/debug address xor handling\n", .{});
        try emit(out, "   2 = remove emulator xbe signature check\n", .{});
        try emit(out, "   4 = remove kernel xbe signature check\n", .{});
        try emit(out, "   8 = remove kernel xbe region check\n", .{});
        try emit(out, "  10 = remove kernel xbe media check\n", .{});
        try emit(out, "  20 = remove kernel xbe hash check\n", .{});
        return true;
    }
    if ((patch_flags & 0xFF) == 0) {
        try emit(out, "  unsupported patch flags\n", .{});
        return false;
    }

    var basefile = try xex.basefile.clone(gpa);
    errdefer basefile.deinit(gpa);
    const buff = basefile.dataMut();

    var patched_all_ok = true;
    for (xefu.xbox_emu_patches, 0..) |patch, patch_num| {
        if ((patch_flags & (@as(u32, 2) << @intCast(patch_num))) == 0) continue;
        const offset = searchDataMaskBytes(buff, patch.search_data, patch.search_mask);
        if (offset) |found| {
            if (found == 0) {
                try emit(out, "  error patching {s}\n", .{patch.name});
                patched_all_ok = false;
                continue;
            }
            const target = found + patch.patch_offset;
            if (target > buff.len or buff.len - target < patch.patch_data.len) return error.OutOfBounds;
            try emit(out, "  patched {s}\n", .{patch.name});
            @memcpy(buff[target..][0..patch.patch_data.len], patch.patch_data);
        } else {
            try emit(out, "  error patching {s}\n", .{patch.name});
            patched_all_ok = false;
        }
    }

    if ((patch_flags & 1) != 0) {
        var num_xor_patches: u32 = 0;
        for (xefu.xbox_emu_xor_patches) |patch| {
            const offset = searchDataMaskBytes(buff, patch.search_data, patch.search_mask);
            if (offset) |found| {
                if (found == 0) continue;
                const target = found + patch.patch_offset;
                if (target > buff.len or buff.len - target < patch.patch_data.len) return error.OutOfBounds;
                try emit(out, "  patched {s}\n", .{patch.name});
                @memcpy(buff[target..][0..patch.patch_data.len], patch.patch_data);
                num_xor_patches += 1;
            }
        }
        if (num_xor_patches != 1) {
            try emit(out, "  error patching {s}\n", .{xefu.xbox_emu_xor_patches[0].name});
            patched_all_ok = false;
        }
    }

    replaceBasefile(xex, &basefile);
    return patched_all_ok;
}

// ---------------------------------------------------------------------------
// dash.xex
// ---------------------------------------------------------------------------

const dash_all_region_data = [_]u32{ 0x3D60003F, 0x8123032C, 0x81090018, 0x7D075838, 0x2B070000, 0x409A0038 };
const dash_all_region_mask = [_]u32{ 0xFFFFFFFF, 0, 0, 0, 0, 0xFC000001 };

fn dashPatches(gpa: std.mem.Allocator, xex: *model.Xex, patch_flags: u32, out: anytype) Error!bool {
    if (patch_flags == 0) {
        try emit(out, "  1 = allow all region dvd videos\n", .{});
        return true;
    }
    if ((patch_flags & 1) == 0) {
        try emit(out, "  unsupported patch flags\n", .{});
        return false;
    }

    const parser = pe.Parser.init(xex.basefile.data());
    const section_count = parser.numberOfSections() orelse return error.InvalidPe;

    var basefile = try xex.basefile.clone(gpa);
    errdefer basefile.deinit(gpa);

    var patched_all_region = false;
    var index: u16 = 0;
    while (index < section_count) : (index += 1) {
        const section = try sectionInfo(parser, index);
        if (!std.mem.eql(u8, section.nameSlice(), ".text")) continue;

        const buff = try readSection(gpa, &basefile, section);
        defer gpa.free(buff);

        if (searchDataMaskWords(buff, &dash_all_region_data, &dash_all_region_mask)) |data_offset| {
            try patchAt(gpa, &basefile, &[_]u8{ 0x60, 0, 0, 0 }, section.offset, @as(i64, @intCast(data_offset)) + 0x14);
            patched_all_region = true;
        }
    }

    var result = false;
    if (patched_all_region) {
        try emit(out, "  patched allow all region dvd videos\n", .{});
        result = true;
    } else {
        try emit(out, "  error patching allow all region dvd videos\n", .{});
    }

    if (result) replaceBasefile(xex, &basefile) else basefile.deinit(gpa);
    return result;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const TestSection = struct {
    name: []const u8,
    offset: u32,
    size: u32,
};

/// Builds a minimal PE image with the section table the patch code reads.
fn makePe(gpa: std.mem.Allocator, load_address: u32, sections: []const TestSection) !DataBlock {
    const image = try gpa.alloc(u8, 0x1000);
    defer gpa.free(image);
    @memset(image, 0);

    image[0] = 'M';
    image[1] = 'Z';
    endian.set32le(image, 0x3C, 0x40);
    const pe_offset: usize = 0x44;
    image[pe_offset] = 'P';
    image[pe_offset + 1] = 'E';
    endian.set16le(image, pe_offset + 0x02, @intCast(sections.len));
    endian.set16le(image, pe_offset + 0x10, 0xE0);
    endian.set32le(image, pe_offset + 0x14 + 0x1C, load_address);

    const section_offset = pe_offset + 0x14 + 0xE0;
    for (sections, 0..) |section, index| {
        const at = section_offset + index * 0x28;
        @memcpy(image[at..][0..section.name.len], section.name);
        endian.set32le(image, at + 0x08, section.size);
        endian.set32le(image, at + 0x0C, section.offset);
    }

    var block = DataBlock.init();
    errdefer block.deinit(gpa);
    try block.set(gpa, image, 0, @intCast(image.len));
    return block;
}

fn setBytes(gpa: std.mem.Allocator, block: *DataBlock, bytes: []const u8, offset: u32) !void {
    // Test offsets are well below maxInt(i32).
    try block.set(gpa, bytes, @intCast(offset), @intCast(bytes.len));
}

fn captureOutput(gpa: std.mem.Allocator) std.Io.Writer.Allocating {
    return .init(gpa);
}

fn addImport(gpa: std.mem.Allocator, xex: *model.Xex, name: []const u8, addresses: []const u32, module_index: u8) !void {
    var library: types.ImportLibraryData = .{
        .addresses = try gpa.dupe(u32, addresses),
        .module_index = module_index,
    };
    @memcpy(library.name[0..name.len], name);
    try xex.import_libraries.append(gpa, library);
}

test "special: no execution id does nothing" {
    const gpa = std.testing.allocator;
    var xex = model.Xex.init(gpa);
    defer xex.deinit();
    var output = captureOutput(gpa);
    defer output.deinit();

    try std.testing.expect(!try doSpecialPatches(gpa, &xex, 0, &output.writer));
    try std.testing.expectEqualStrings("", output.written());
}

test "special: unknown title prints the no-special message" {
    const gpa = std.testing.allocator;
    var xex = model.Xex.init(gpa);
    defer xex.deinit();
    xex.execution_id = .{ .title_id = 0x12345678 };
    var output = captureOutput(gpa);
    defer output.deinit();

    try std.testing.expect(!try doSpecialPatches(gpa, &xex, 0, &output.writer));
    try std.testing.expectEqualStrings("  no special patch found for this xex\n", output.written());
}

test "special: patch lists match the reference text" {
    const gpa = std.testing.allocator;
    var xex = model.Xex.init(gpa);
    defer xex.deinit();
    var output = captureOutput(gpa);
    defer output.deinit();

    xex.execution_id = .{ .title_id = 0x45410829 };
    try std.testing.expect(try doSpecialPatches(gpa, &xex, 0, &output.writer));
    try std.testing.expectEqualStrings("  1 = patch rockband crypt to work on devkits\n", output.written());

    output.clearRetainingCapacity();
    xex.execution_id = .{ .title_id = 0x545607D3 };
    try std.testing.expect(try doSpecialPatches(gpa, &xex, 0, &output.writer));
    try std.testing.expectEqualStrings("  1 = patch dance central crypt to work on devkits\n", output.written());

    output.clearRetainingCapacity();
    xex.execution_id = .{ .title_id = 0xFFFE07D1 };
    try std.testing.expect(try doSpecialPatches(gpa, &xex, 0, &output.writer));
    try std.testing.expectEqualStrings("  1 = allow all region dvd videos\n", output.written());

    output.clearRetainingCapacity();
    xex.execution_id = .{ .title_id = 0xFFFE07D2 };
    try std.testing.expect(try doSpecialPatches(gpa, &xex, 0, &output.writer));
    try std.testing.expectEqualStrings(
        "   1 = fix retail/debug address xor handling\n" ++
            "   2 = remove emulator xbe signature check\n" ++
            "   4 = remove kernel xbe signature check\n" ++
            "   8 = remove kernel xbe region check\n" ++
            "  10 = remove kernel xbe media check\n" ++
            "  20 = remove kernel xbe hash check\n",
        output.written(),
    );

    output.clearRetainingCapacity();
    if (xex.bounding_path) |old| gpa.free(old);
    xex.bounding_path = try gpa.dupe(u8, "xbox.xex");
    try std.testing.expect(try doSpecialPatches(gpa, &xex, 0, &output.writer));
    try std.testing.expectEqualStrings("  1 = allow unsupported xbox1 games\n", output.written());

    output.clearRetainingCapacity();
    xex.execution_id = .{ .title_id = 0 };
    if (xex.bounding_path) |old| gpa.free(old);
    xex.bounding_path = try gpa.dupe(u8, "xam.xex");
    try std.testing.expect(try doSpecialPatches(gpa, &xex, 0, &output.writer));
    try std.testing.expectEqualStrings(
        "  1 = force all arcade games to be licensed/unlocked/full\n" ++
            "  2 = allow unauthenticated kinect hw usage\n" ++
            "  4 = loads load.xex instead of dash.xex\n",
        output.written(),
    );

    output.clearRetainingCapacity();
    if (xex.bounding_path) |old| gpa.free(old);
    xex.bounding_path = try gpa.dupe(u8, "xbdm.xex");
    try std.testing.expect(try doSpecialPatches(gpa, &xex, 0, &output.writer));
    try std.testing.expectEqualStrings(
        "  1 = allow access to extra drives in network neighbourhood\n" ++
            "  2 = disable flagging of slim devkits as testkits\n",
        output.written(),
    );
}

test "special: xefutitle is skipped" {
    const gpa = std.testing.allocator;
    var xex = model.Xex.init(gpa);
    defer xex.deinit();
    xex.execution_id = .{ .title_id = 0xFFFE07D2 };
    xex.bounding_path = try gpa.dupe(u8, "xefutitle1.xex");
    var output = captureOutput(gpa);
    defer output.deinit();

    try std.testing.expect(!try doSpecialPatches(gpa, &xex, 0, &output.writer));
    try std.testing.expectEqualStrings("  no special patch found for this xex\n", output.written());
}

test "special: unsupported patch flags" {
    const gpa = std.testing.allocator;
    var xex = model.Xex.init(gpa);
    defer xex.deinit();
    var output = captureOutput(gpa);
    defer output.deinit();

    xex.execution_id = .{ .title_id = 0x45410829 };
    try std.testing.expect(!try doSpecialPatches(gpa, &xex, 2, &output.writer));
    try std.testing.expectEqualStrings("  unsupported patch flags\n", output.written());

    output.clearRetainingCapacity();
    xex.execution_id = .{ .title_id = 0xFFFE07D2 };
    try std.testing.expect(!try doSpecialPatches(gpa, &xex, 0x100, &output.writer));
    try std.testing.expectEqualStrings("  unsupported patch flags\n", output.written());
}

test "special: masked searches use the reference strict end bound" {
    const data = [_]u32{ 0x11223344, 0xAABBCCDD };
    const mask = [_]u32{ 0xFFFFFFFF, 0xFFFF0000 };
    var bytes: [12]u8 = undefined;
    endian.set32be(&bytes, 0, 0x11223344);
    endian.set32be(&bytes, 4, 0xAABBCC11);
    endian.set32be(&bytes, 8, 0);
    try std.testing.expectEqual(@as(?usize, 0), searchDataMaskWords(&bytes, &data, &mask));
    // A hit starting at the last word is not accepted by the reference loop.
    try std.testing.expectEqual(@as(?usize, null), searchDataMaskWords(bytes[4..], &data, &mask));

    const bytes_data = [_]u8{ 0x12, 0x34 };
    const bytes_mask = [_]u8{ 0xFF, 0xF0 };
    try std.testing.expectEqual(@as(?usize, 0), searchDataMaskBytes(&[_]u8{ 0x12, 0x3F, 0 }, &bytes_data, &bytes_mask));
    try std.testing.expectEqual(@as(?usize, null), searchDataMaskBytes(&[_]u8{0x12}, &bytes_data, &bytes_mask));
}

test "special: update fix rewrites ASCII and UTF-16 names" {
    const gpa = std.testing.allocator;
    var xex = model.Xex.init(gpa);
    defer xex.deinit();
    xex.basefile = try makePe(gpa, 0x82000000, &.{.{ .name = ".rdata", .offset = 0x200, .size = 0x100 }});

    const ascii_source = "update:\\game\\data.bin";
    try setBytes(gpa, &xex.basefile, ascii_source, 0x204);
    const unicode_source = [_]u8{ 0, 'u', 0, 'p', 0, 'd', 0, 'a', 0, 't', 0, 'e', 0, ':', 0, 'x', 0, 0 };
    try setBytes(gpa, &xex.basefile, &unicode_source, 0x240);

    try std.testing.expect(try doUpdatePatchFix(gpa, &xex));

    const ascii_expected = "D:\\game\\data.bin";
    try std.testing.expectEqualSlices(u8, ascii_expected, xex.basefile.data()[0x204..][0..ascii_expected.len]);
    const ascii_tail = xex.basefile.data()[0x204 + ascii_expected.len ..][0 .. ascii_source.len - ascii_expected.len];
    const ascii_tail_expected: [5]u8 = @splat(0);
    try std.testing.expectEqualSlices(u8, &ascii_tail_expected, ascii_tail);

    const unicode_expected = [_]u8{ 0, 'D', 0, ':', 0, 'x', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    try std.testing.expectEqualSlices(u8, &unicode_expected, xex.basefile.data()[0x240..][0..unicode_expected.len]);
}

test "special: update fix leaves files without .rdata alone" {
    const gpa = std.testing.allocator;
    var xex = model.Xex.init(gpa);
    defer xex.deinit();
    xex.basefile = try makePe(gpa, 0x82000000, &.{.{ .name = ".text", .offset = 0x200, .size = 0x40 }});
    const before = try gpa.dupe(u8, xex.basefile.data());
    defer gpa.free(before);

    try std.testing.expect(!try doUpdatePatchFix(gpa, &xex));
    try std.testing.expectEqualSlices(u8, before, xex.basefile.data());
}

test "special: disc swap fix patches both calls and KeSetEvent" {
    const gpa = std.testing.allocator;
    var xex = model.Xex.init(gpa);
    defer xex.deinit();
    xex.load_address = 0x82000000;
    xex.basefile = try makePe(gpa, 0x82000000, &.{.{ .name = ".text", .offset = 0x200, .size = 0x100 }});

    // Import thunks: XamSwapDisc (0xA28), XamSwapCancel (0xA2A), KeSetEvent (0x9D).
    try xex.basefile.set32be(gpa, 0x01010A28, 0x210);
    try xex.basefile.set32be(gpa, 0x02010A28, 0x214);
    try xex.basefile.set32be(gpa, 0x01010A2A, 0x218);
    try xex.basefile.set32be(gpa, 0x02010A2A, 0x21C);
    try xex.basefile.set32be(gpa, 0x0101009D, 0x220);
    try xex.basefile.set32be(gpa, 0x0201009D, 0x224);
    try addImport(gpa, &xex, "xam.xex", &.{ 0x82000210, 0x82000218 }, 1);
    try addImport(gpa, &xex, "xboxkrnl.exe", &.{0x82000220}, 1);

    // Calls at text+0x40 and text+0x50.
    try xex.basefile.set32be(gpa, 0x4BFFFFD1, 0x240);
    try xex.basefile.set32be(gpa, 0x4BFFFFC9, 0x250);

    try std.testing.expect(try doDiscSwapChecksFix(gpa, &xex));
    try std.testing.expectEqual(@as(u32, 0x38800001), xex.basefile.get32be(0x234));
    try std.testing.expectEqual(@as(u32, 0x38A00000), xex.basefile.get32be(0x238));
    try std.testing.expectEqual(@as(u32, 0x4BFFFFE5), xex.basefile.get32be(0x23C));
    try std.testing.expectEqual(@as(u32, 0x38600000), xex.basefile.get32be(0x240));
    try std.testing.expectEqual(@as(u32, 0x38600000), xex.basefile.get32be(0x250));
}

test "special: xefu signature patch uses the table offset" {
    const gpa = std.testing.allocator;
    var xex = model.Xex.init(gpa);
    defer xex.deinit();
    xex.execution_id = .{ .title_id = 0xFFFE07D2 };
    const zeros: [0x100]u8 = @splat(0);
    try xex.basefile.set(gpa, &zeros, 0, 0x100);
    try setBytes(gpa, &xex.basefile, xefu.xbox_emu_patches[0].search_data, 0x10);
    var output = captureOutput(gpa);
    defer output.deinit();

    try std.testing.expect(try doSpecialPatches(gpa, &xex, 2, &output.writer));
    try std.testing.expectEqualStrings("  patched Emulator Xbe Signature Check\n", output.written());
    try std.testing.expectEqualSlices(u8, xefu.xbox_emu_patches[0].patch_data, xex.basefile.data()[0x10 + 68 ..][0..4]);
}

test "special: xefu xor patch requires exactly one hit" {
    const gpa = std.testing.allocator;
    var xex = model.Xex.init(gpa);
    defer xex.deinit();
    xex.execution_id = .{ .title_id = 0xFFFE07D2 };
    const zeros: [0x100]u8 = @splat(0);
    try xex.basefile.set(gpa, &zeros, 0, 0x100);
    try setBytes(gpa, &xex.basefile, xefu.xbox_emu_xor_patches[0].search_data, 0x10);
    var output = captureOutput(gpa);
    defer output.deinit();

    try std.testing.expect(try doSpecialPatches(gpa, &xex, 1, &output.writer));
    try std.testing.expectEqualStrings("  patched Emulator Retail/Debug Xor Value A\n", output.written());
    try std.testing.expectEqualSlices(
        u8,
        xefu.xbox_emu_xor_patches[0].patch_data,
        xex.basefile.data()[0x10 + 32 ..][0..xefu.xbox_emu_xor_patches[0].patch_data.len],
    );
}

test "special: retail tables feed the documented HMAC" {
    const expected = [_]u8{
        0xF8, 0x03, 0xCB, 0x11, 0xE9, 0x20, 0x0E, 0x16,
        0x39, 0x90, 0x52, 0xEA, 0xD1, 0xF9, 0xFB, 0xD9,
    };
    try std.testing.expectEqual(@as(usize, 0x110), retail.g_1bl_pub_key.len);
    try std.testing.expectEqual(@as(usize, 0x1A), retail.g_1bl_other_keys.len);
    try std.testing.expectEqual(@as(usize, 0x590), retail.g_constant_keys.len);
    try std.testing.expectEqual(@as(usize, 0x20), retail.g_xex_dvd_keys.len);

    var key: [16]u8 = @splat(0);
    for (&key, 0..) |*byte, index| byte.* = @intCast(index);
    var state: xecrypt.HmacShaState = undefined;
    xecrypt.XeCryptHmacShaInit(&state, &key);
    xecrypt.XeCryptHmacShaUpdate(&state, &retail.g_1bl_pub_key);
    xecrypt.XeCryptHmacShaUpdate(&state, &retail.g_1bl_other_keys);
    xecrypt.XeCryptHmacShaUpdate(&state, &retail.g_integrity_sig);
    xecrypt.XeCryptHmacShaUpdate(&state, &retail.g_constant_keys);
    xecrypt.XeCryptHmacShaUpdate(&state, &retail.g_xex_dvd_keys);
    xecrypt.XeCryptHmacShaUpdate(&state, &retail.g_roam_obfusc_key);
    xecrypt.XeCryptHmacShaUpdate(&state, &retail.g_cp_syslink_key);
    var digest: [16]u8 = undefined;
    xecrypt.XeCryptHmacShaFinal(&state, &digest, 16);
    try std.testing.expectEqualSlices(u8, &expected, &digest);
}

test "special: xam license patch starts at the mflr prologue" {
    const gpa = std.testing.allocator;
    var xex = model.Xex.init(gpa);
    defer xex.deinit();
    xex.execution_id = .{ .title_id = 0 };
    xex.bounding_path = try gpa.dupe(u8, "xam.xex");
    xex.basefile = try makePe(gpa, 0x82000000, &.{.{ .name = ".text", .offset = 0x200, .size = 0x200 }});

    try setBytes(gpa, &xex.basefile, &func_start, 0x240);
    try setBytes(gpa, &xex.basefile, &license_search_data, 0x248);
    var output = captureOutput(gpa);
    defer output.deinit();

    try std.testing.expect(try doSpecialPatches(gpa, &xex, 1, &output.writer));
    try std.testing.expectEqualStrings("  patched force all arcade games to be licensed/unlocked/full\n", output.written());
    try std.testing.expectEqualSlices(u8, &license_patch_data, xex.basefile.data()[0x240..][0..license_patch_data.len]);
}

test "special: xam kinect patch finds the bge instruction" {
    const gpa = std.testing.allocator;
    var xex = model.Xex.init(gpa);
    defer xex.deinit();
    xex.execution_id = .{ .title_id = 0, .version = types.Version32.fromParts(2, 0, 15574, 0).dword };
    xex.bounding_path = try gpa.dupe(u8, "xam.xex");
    xex.basefile = try makePe(gpa, 0x82000000, &.{.{ .name = ".text", .offset = 0x200, .size = 0x200 }});

    var search: [20]u8 = undefined;
    for (kinect_search_data1, 0..) |word, index| endian.set32be(&search, index * 4, word);
    try setBytes(gpa, &xex.basefile, &search, 0x220);
    var output = captureOutput(gpa);
    defer output.deinit();

    try std.testing.expect(try doSpecialPatches(gpa, &xex, 2, &output.writer));
    try std.testing.expectEqualStrings("  patched allow unauthenticated kinect hw usage\n", output.written());
    // reg = low five bits of the instruction at bge-4 (0x7C7D_1B79 -> r29).
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x3B, 0xA0, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00 }, xex.basefile.data()[0x22C..][0..8]);
}

test "special: dash all-region patch replaces the branch" {
    const gpa = std.testing.allocator;
    var xex = model.Xex.init(gpa);
    defer xex.deinit();
    xex.execution_id = .{ .title_id = 0xFFFE07D1 };
    xex.basefile = try makePe(gpa, 0x82000000, &.{.{ .name = ".text", .offset = 0x200, .size = 0x100 }});

    var search: [24]u8 = undefined;
    for (dash_all_region_data, 0..) |word, index| endian.set32be(&search, index * 4, word);
    try setBytes(gpa, &xex.basefile, &search, 0x210);
    var output = captureOutput(gpa);
    defer output.deinit();

    try std.testing.expect(try doSpecialPatches(gpa, &xex, 1, &output.writer));
    try std.testing.expectEqualStrings("  patched allow all region dvd videos\n", output.written());
    try std.testing.expectEqual(@as(u32, 0x60000000), xex.basefile.get32be(0x224));
}

test "special: xbox patch rewrites the update path" {
    const gpa = std.testing.allocator;
    var xex = model.Xex.init(gpa);
    defer xex.deinit();
    xex.execution_id = .{ .title_id = 0xFFFE07D2 };
    xex.bounding_path = try gpa.dupe(u8, "xbox.xex");
    xex.basefile = try makePe(gpa, 0x82000000, &.{
        .{ .name = ".rdata", .offset = 0x200, .size = 0x100 },
        .{ .name = ".text", .offset = 0x300, .size = 0x100 },
    });

    try setBytes(gpa, &xex.basefile, "update:\\foo", 0x204);
    var output = captureOutput(gpa);
    defer output.deinit();

    try std.testing.expect(try doSpecialPatches(gpa, &xex, 1, &output.writer));
    try std.testing.expectEqualStrings("  patched allow unsupported xbox1 games\n", output.written());
    try std.testing.expectEqualSlices(u8, "X:\\foo\x00", xex.basefile.data()[0x204..][0..7]);
}

test "special: xbdm reports both patches when nothing matches" {
    const gpa = std.testing.allocator;
    var xex = model.Xex.init(gpa);
    defer xex.deinit();
    xex.execution_id = .{ .title_id = 0 };
    xex.bounding_path = try gpa.dupe(u8, "xbdm.xex");
    xex.basefile = try makePe(gpa, 0x82000000, &.{.{ .name = ".text", .offset = 0x200, .size = 0x100 }});
    var output = captureOutput(gpa);
    defer output.deinit();

    try std.testing.expect(!try doSpecialPatches(gpa, &xex, 3, &output.writer));
    try std.testing.expectEqualStrings(
        "  error patching allow access to extra drives in network neighbourhood\n" ++
            "  error patching disable flagging of slim devkits as testkits\n",
        output.written(),
    );
}

test "special: rockband reports a crypt patch failure" {
    const gpa = std.testing.allocator;
    var xex = model.Xex.init(gpa);
    defer xex.deinit();
    xex.execution_id = .{ .title_id = 0x45410829 };
    xex.basefile = try makePe(gpa, 0x82000000, &.{.{ .name = ".rdata", .offset = 0x200, .size = 0x40 }});
    var output = captureOutput(gpa);
    defer output.deinit();

    try std.testing.expect(!try doSpecialPatches(gpa, &xex, 1, &output.writer));
    try std.testing.expectEqualStrings("  error patching rockband crypt to work on devkits\n", output.written());
}

test "special: disc swap fix without .text changes nothing" {
    const gpa = std.testing.allocator;
    var xex = model.Xex.init(gpa);
    defer xex.deinit();
    xex.basefile = try makePe(gpa, 0x82000000, &.{.{ .name = ".data", .offset = 0x200, .size = 0x40 }});
    const before = try gpa.dupe(u8, xex.basefile.data());
    defer gpa.free(before);

    try std.testing.expect(!try doDiscSwapChecksFix(gpa, &xex));
    try std.testing.expectEqualSlices(u8, before, xex.basefile.data());
}
