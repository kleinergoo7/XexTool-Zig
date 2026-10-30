// SPDX-FileCopyrightText: 2026 XexTool Zig rewrite contributors
// SPDX-License-Identifier: GPL-3.0-or-later

const std = @import("std");
const DataBlock = @import("../core/datablock.zig").DataBlock;
const cursor = @import("../core/cursor.zig");
const endian = @import("../core/endian.zig");
const crypto = @import("../xecrypt/xecrypt.zig");
const data = @import("data.zig");
const defines = @import("defines.zig");
const Keys = @import("keys.zig").Keys;
const model = @import("model.zig");
const types = @import("types.zig");

pub const Error = error{
    InvalidRange,
    OutOfMemory,
    OutOfBounds,
    Overflow,
    InvalidMagic,
    InvalidSecurityInfo,
    InvalidImageEntry,
    Unsupported,
};

const image_header_size = 0x18;
const image_entry_size = 0x8;
const security_info_size = 0x184;

pub fn readHeaders(xex: *model.Xex, headers: DataBlock, keys: Keys) Error!i32 {
    const bytes = headers.data();
    if (bytes.len < image_header_size) return error.OutOfBounds;
    if (!std.mem.eql(u8, bytes[0..4], &defines.xex_magic)) return error.InvalidMagic;

    const module_flags = try cursor.readU32beAt(bytes, 4);
    const security_offset = try cursor.readU32beAt(bytes, 0x10);
    const entry_count = try cursor.readU32beAt(bytes, 0x14);

    xex.module_flags = module_flags;
    xex.discardable_header_size = @bitCast(try cursor.readU32beAt(bytes, 0x0C));

    var entry_offset: usize = image_header_size;
    var i: u32 = 0;
    while (i < entry_count) : (i += 1) {
        const entry = types.ImageEntry{
            .key = try cursor.readU32beAt(bytes, entry_offset),
            .value = try cursor.readU32beAt(bytes, entry_offset + 4),
        };
        entry_offset += image_entry_size;

        var block = DataBlock.init();
        errdefer block.deinit(xex.gpa);

        if (!defines.isDataOffset(entry.key)) {
            try block.set32(xex.gpa, entry.value, 0);
        } else {
            const data_offset: usize = @intCast(entry.value);
            const data_size: usize = if (defines.isVariableSize(entry.key))
                @intCast(try cursor.readU32beAt(bytes, data_offset))
            else
                @intCast(defines.headerSizeFor(entry.key));
            if (data_offset > bytes.len or data_size > bytes.len - data_offset) return error.OutOfBounds;
            try block.set(xex.gpa, bytes[data_offset..][0..data_size], 0, @intCast(data_size));
        }

        try dispatchEntry(xex, entry, &block);
        block.deinit(xex.gpa);
    }

    if (security_offset > bytes.len or bytes.len - security_offset < security_info_size) return error.InvalidSecurityInfo;
    const sec = bytes[security_offset..];

    const image_info_size: usize = try cursor.readU32beAt(sec, 0x108);
    // infoSize counts from the signature field at sec+0x08, so the hashed region
    // spans infoSize-0x100 bytes starting at sec+0x108.
    if (image_info_size < 0x100 or image_info_size > sec.len - 8) return error.InvalidSecurityInfo;

    const raw_image_flags = try cursor.readU32beAt(sec, 0x10C);
    const salt = if ((raw_image_flags & defines.image_flag_revocation_check_req) != 0)
        data.xex_salt_rev[0..]
    else
        data.xex_salt_xex[0..];

    var hash: [20]u8 = undefined;
    const hash_end = 8 + image_info_size;
    crypto.XeCryptRotSumSha(sec[0x108..hash_end], "", &hash, 20);

    const signature = sec[0x008..0x108];
    const retail_valid = crypto.XeCryptBnQwBeSigVerify(
        signature,
        &hash,
        salt,
        &data.xex_retail_public_key,
    );
    var all_zero = true;
    for (signature) |byte| {
        if (byte != 0) {
            all_zero = false;
            break;
        }
    }
    // Reference rule: a security info whose retail signature does not verify is
    // a debug build, unless the signature is all zeros (retail files rewritten
    // without signing).
    xex.is_debug = !retail_valid and !all_zero;

    var sec_info = try parseSecurityInfo(sec);
    const is_mfg = (sec_info.image_info.image_flags & (defines.image_flag_manufacturing_utility | defines.image_flag_manufacturing_tool)) != 0;
    if (!xex.isPatchModule()) {
        const key = keys.select(xex.is_debug, is_mfg);
        var image_key = sec_info.image_info.image_key;
        try decryptImageKey(xex, &image_key, &key);
        sec_info.image_info.image_key = image_key;
    }
    applySecurityInfo(xex, sec_info);

    var section_offset = security_offset + security_info_size;
    var section_index: i32 = 0;
    while (section_index < sec_info.section_count) : (section_index += 1) {
        const dword = try cursor.readU32beAt(bytes, section_offset);
        const section = types.HvSectionInfo{ .dword = dword };
        const page_size = xex.pageSize();
        const section_size = std.math.mul(i32, @intCast(section.size()), @intCast(page_size)) catch return error.InvalidSecurityInfo;
        try xex.sections.append(xex.gpa, .{ .size = section_size, .info = section.info() });
        section_offset += 0x18;
    }

    xex.original_headers = try headers.clone(xex.gpa);
    return sec_info.image_size;
}

fn parseSecurityInfo(sec: []const u8) Error!types.SecurityInfo {
    if (sec.len < security_info_size) return error.InvalidSecurityInfo;
    var info = types.SecurityInfo{
        .size = @bitCast(try cursor.readU32beAt(sec, 0x000)),
        .image_size = @bitCast(try cursor.readU32beAt(sec, 0x004)),
        .allowed_media_types = try cursor.readU32beAt(sec, 0x17C),
        .section_count = @bitCast(try cursor.readU32beAt(sec, 0x180)),
    };
    @memcpy(&info.image_info.signature, sec[0x008..0x108]);
    info.image_info.info_size = @bitCast(try cursor.readU32beAt(sec, 0x108));
    info.image_info.image_flags = try cursor.readU32beAt(sec, 0x10C);
    info.image_info.load_address = try cursor.readU32beAt(sec, 0x110);
    @memcpy(&info.image_info.image_hash.data, sec[0x114..0x128]);
    info.image_info.import_table_count = @bitCast(try cursor.readU32beAt(sec, 0x128));
    @memcpy(&info.image_info.import_hash.data, sec[0x12C..0x140]);
    @memcpy(&info.image_info.media_id.data, sec[0x140..0x150]);
    @memcpy(&info.image_info.image_key.data, sec[0x150..0x160]);
    info.image_info.export_table_address = try cursor.readU32beAt(sec, 0x160);
    @memcpy(&info.image_info.header_hash.data, sec[0x164..0x178]);
    info.image_info.game_region = try cursor.readU32beAt(sec, 0x178);
    return info;
}

fn applySecurityInfo(xex: *model.Xex, info: types.SecurityInfo) void {
    xex.image_flags = info.image_info.image_flags;
    xex.load_address = info.image_info.load_address;
    xex.media_id = info.image_info.media_id;
    xex.image_key = info.image_info.image_key;
    xex.export_table_address = info.image_info.export_table_address;
    xex.regions = info.image_info.game_region;
    xex.media_types = info.allowed_media_types;
}

fn decryptImageKey(xex: *model.Xex, key: *types.Key, crypt_key: []const u8) Error!void {
    var aes: crypto.AesState = undefined;
    crypto.XeCryptAesKey(&aes, crypt_key);
    var output: [16]u8 = undefined;
    crypto.XeCryptAesEcb(&aes, &key.data, &output, false);
    key.data = output;
    _ = xex;
}

fn dispatchEntry(xex: *model.Xex, entry: types.ImageEntry, block: *const DataBlock) Error!void {
    const raw = block.data();
    const info_size: i32 = if (raw.len >= 4) @bitCast(endian.get32be(raw, 0)) else 0;

    switch (entry.key) {
        defines.image_key_resource_section => try parseResources(xex, raw, info_size),
        defines.image_key_basefile_format => try parseBasefileFormat(xex, raw, block),
        defines.image_key_base_reference => {
            if (raw.len < 20) return error.InvalidImageEntry;
            xex.base_reference = raw[0..20].*;
        },
        defines.image_key_delta_patch_descriptor => {
            xex.delta_patch_descriptor = try block.clone(xex.gpa);
        },
        defines.image_key_restrict_kv_privs => {
            if (raw.len < 16) return error.InvalidImageEntry;
            const mask = endian.get64be(raw, 0);
            const val = endian.get64be(raw, 8);
            xex.restrict_kv_privs = .{ .mask = mask, .val = val };
        },
        defines.image_key_restrict_dates => {
            if (raw.len < 16) return error.InvalidImageEntry;
            const start = endian.get64be(raw, 0);
            const end = endian.get64be(raw, 8);
            xex.restrict_dates = .{ .start = start, .end = end };
        },
        defines.image_key_restrict_console_ids => try parseConsoleIds(xex, raw, info_size),
        defines.image_key_disc_profile_id => {
            if (raw.len < 16) return error.InvalidImageEntry;
            xex.disc_profile_id = raw[0..16].*;
        },
        defines.image_key_bound_pathname => {
            if (raw.len < 5) return error.InvalidImageEntry;
            const text = raw[4..];
            const end = std.mem.indexOfScalar(u8, text, 0) orelse text.len;
            xex.bounding_path = try xex.gpa.dupe(u8, text[0..end]);
        },
        defines.image_key_bound_device_id => {
            if (raw.len < 20) return error.InvalidImageEntry;
            xex.bounding_device_id = raw[0..20].*;
        },
        defines.image_key_original_base_address => xex.has_original_load_address = true,
        defines.image_key_entry_point, defines.image_key_image_base_address => {},
        defines.image_key_import_libraries => try parseImportLibraries(xex, raw, info_size),
        defines.image_key_image_checksum => {},
        defines.image_key_image_callcap => {
            if (raw.len < 8) return error.InvalidImageEntry;
            xex.call_cap = .{ endian.get32be(raw, 0), endian.get32be(raw, 4) };
        },
        defines.image_key_image_fastcap => xex.fast_cap = entry.value,
        defines.image_key_original_pe_name => {
            if (raw.len < 5) return error.InvalidImageEntry;
            const text = raw[4..];
            const end = std.mem.indexOfScalar(u8, text, 0) orelse text.len;
            xex.original_pe_name = try xex.gpa.dupe(u8, text[0..end]);
        },
        defines.image_key_library_versions => try parseStaticLibraries(xex, raw, info_size),
        defines.image_key_tls_values => {
            if (raw.len < 16) return error.InvalidImageEntry;
            xex.tls_info = .{
                .num_slots = @bitCast(endian.get32be(raw, 0)),
                .raw_address = endian.get32be(raw, 4),
                .raw_size = endian.get32be(raw, 8),
                .data_size = endian.get32be(raw, 12),
            };
        },
        defines.image_key_stack_size => xex.stack_size = @bitCast(entry.value),
        defines.image_key_filesystem_cache_size => xex.filesystem_cache_size = @bitCast(entry.value),
        defines.image_key_heap_size => xex.heap_size = @bitCast(entry.value),
        defines.image_key_page_heap => {
            if (raw.len < 8) return error.InvalidImageEntry;
            xex.page_heap = .{ .size = endian.get32be(raw, 0), .flags = endian.get32be(raw, 4) };
        },
        defines.image_key_system_flags => xex.system_flags = entry.value,
        defines.image_key_system_flags2 => xex.system_flags2 = entry.value,
        defines.image_key_execution_id => try parseExecutionId(xex, raw),
        defines.image_key_title_workspace_size => xex.workspace_size = @bitCast(entry.value),
        defines.image_key_game_ratings => {
            if (raw.len < 64) return error.InvalidImageEntry;
            var ratings: types.GameRatings = .{};
            @memcpy(&ratings.data, raw[0..64]);
            xex.game_ratings = ratings;
        },
        defines.image_key_lan_key => {
            if (raw.len < 16) return error.InvalidImageEntry;
            xex.lan_key = raw[0..16].*;
        },
        defines.image_key_logo_data => try parseLogo(xex, raw, info_size),
        defines.image_key_multidisc_media_ids => try parseMultidiscIds(xex, raw, info_size),
        defines.image_key_alt_title_ids => try parseAltTitleIds(xex, raw, info_size),
        defines.image_key_extra_debug_memory => xex.extra_debug_memory = entry.value,
        defines.image_key_exports_by_name => {
            if (raw.len < 8) return error.InvalidImageEntry;
            xex.exports_by_name = .{
                .export_table_offset = endian.get32be(raw, 0),
                .export_table_size = endian.get32be(raw, 4),
            };
        },
        else => try xex.unknown_image_entries.append(xex.gpa, .{
            .header = entry,
            .data = try block.clone(xex.gpa),
        }),
    }
}

fn parseBasefileFormat(xex: *model.Xex, raw: []const u8, block: *const DataBlock) Error!void {
    if (raw.len < 8) return error.InvalidImageEntry;
    const enc_type = endian.get16be(raw, 4);
    const comp_type = endian.get16be(raw, 6);
    xex.is_encrypted = enc_type == 1;
    switch (comp_type) {
        1 => xex.is_raw = true,
        2 => xex.is_compressed = true,
        3 => xex.is_delta_compressed = true,
        else => xex.is_binary = true,
    }

    // The C++ converts this entry to host order before storing it and the
    // packer then uses DataBlock::get32/get16. Keep that invariant.
    var converted = DataBlock.init();
    errdefer converted.deinit(xex.gpa);
    try converted.set(xex.gpa, raw, 0, @intCast(raw.len));
    try converted.set32(xex.gpa, endian.get32be(raw, 0), 0);
    try converted.set16(xex.gpa, enc_type, 4);
    try converted.set16(xex.gpa, comp_type, 6);
    if (comp_type == 1) {
        var offset: usize = 8;
        while (offset + 8 <= raw.len) : (offset += 8) {
            try converted.set32(xex.gpa, endian.get32be(raw, offset), @intCast(offset));
            try converted.set32(xex.gpa, endian.get32be(raw, offset + 4), @intCast(offset + 4));
        }
    } else if (comp_type == 2 or comp_type == 3) {
        if (raw.len >= 16) {
            try converted.set32(xex.gpa, endian.get32be(raw, 8), 8);
            try converted.set32(xex.gpa, endian.get32be(raw, 12), 12);
        }
    }
    xex.basefile_format = converted;
    _ = block;
}

fn parseResources(xex: *model.Xex, raw: []const u8, info_size: i32) Error!void {
    if (info_size < 4) return;
    const count = (@as(usize, @intCast(info_size)) - 4) / 16;
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const offset = 4 + i * 16;
        if (offset + 16 > raw.len) return error.OutOfBounds;
        var resource: types.ResourceEntry = .{};
        @memcpy(&resource.name, raw[offset..][0..8]);
        resource.addr = endian.get32be(raw, offset + 8);
        resource.size = @bitCast(endian.get32be(raw, offset + 12));
        try xex.resources.append(xex.gpa, resource);
    }
}

fn parseConsoleIds(xex: *model.Xex, raw: []const u8, info_size: i32) Error!void {
    if (info_size < 4) return;
    const count = (@as(usize, @intCast(info_size)) - 4) / 5;
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const offset = 4 + i * 5;
        if (offset + 5 > raw.len) return error.OutOfBounds;
        var id: types.ConsoleId = .{};
        @memcpy(&id.id, raw[offset..][0..5]);
        try xex.restrict_console_ids.append(xex.gpa, id);
    }
}

fn parseImportLibraries(xex: *model.Xex, raw: []const u8, info_size: i32) Error!void {
    if (info_size < 12) return;
    const name_table_size = endian.get32be(raw, 4);
    const names_start: usize = 12;
    const names_end = names_start + name_table_size;
    if (names_end > raw.len) return error.OutOfBounds;
    const names = raw[names_start..names_end];

    var offset = (names_end + 3) & ~@as(usize, 3);
    const limit: usize = @intCast(info_size);
    while (offset < limit) {
        if (offset + 0x28 > raw.len) return error.OutOfBounds;
        const lib_size = endian.get32be(raw, offset);
        if (lib_size == 0) return error.InvalidImageEntry;
        const module_index = raw[offset + 0x25];
        const num_addresses = endian.get16be(raw, offset + 0x26);
        const module_number = endian.get32be(raw, offset + 0x18);
        const version = endian.get32be(raw, offset + 0x1C);
        const min_version = endian.get32be(raw, offset + 0x20);

        var library: types.ImportLibraryData = .{
            .version = version,
            .min_version = min_version,
            .module_number = module_number,
            .module_index = module_index,
        };
        const name = nameAt(names, module_index) orelse return error.InvalidImageEntry;
        @memcpy(library.name[0..@min(name.len, library.name.len)], name[0..@min(name.len, library.name.len)]);

        const addresses = try xex.gpa.alloc(u32, num_addresses);
        errdefer xex.gpa.free(addresses);
        for (0..num_addresses) |i| {
            addresses[i] = try cursor.readU32beAt(raw, offset + 0x28 + i * 4);
        }
        library.addresses = addresses;
        try xex.import_libraries.append(xex.gpa, library);
        offset += lib_size;
    }
}

fn nameAt(names: []const u8, index: u8) ?[]const u8 {
    var offset: usize = 0;
    var i: u8 = 0;
    while (offset < names.len) : (i += 1) {
        const rel = std.mem.indexOfScalar(u8, names[offset..], 0) orelse return null;
        const end = offset + rel;
        if (i == index) return names[offset..end];
        offset = (end + 1 + 3) & ~@as(usize, 3);
    }
    return null;
}

fn parseStaticLibraries(xex: *model.Xex, raw: []const u8, info_size: i32) Error!void {
    if (info_size < 4) return;
    const count = (@as(usize, @intCast(info_size)) - 4) / 16;
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const offset = 4 + i * 16;
        if (offset + 16 > raw.len) return error.OutOfBounds;
        var library: types.StaticLibraryEntry = .{};
        @memcpy(&library.name, raw[offset..][0..8]);
        library.version = .{
            .major = endian.get16be(raw, offset + 8),
            .minor = endian.get16be(raw, offset + 10),
            .build = endian.get16be(raw, offset + 12),
            .word = endian.get16be(raw, offset + 14),
        };
        try xex.static_libraries.append(xex.gpa, library);
    }
}

fn parseExecutionId(xex: *model.Xex, raw: []const u8) Error!void {
    if (raw.len < 24) return error.InvalidImageEntry;
    xex.execution_id = .{
        .media_id = endian.get32be(raw, 0),
        .version = endian.get32be(raw, 4),
        .base_version = endian.get32be(raw, 8),
        .title_id = endian.get32be(raw, 12),
        .platform = raw[16],
        .exec_type = raw[17],
        .num_disc = raw[18],
        .max_discs = raw[19],
        .save_game_id = endian.get32be(raw, 20),
    };
}

fn parseLogo(xex: *model.Xex, raw: []const u8, info_size: i32) Error!void {
    if (info_size < 8) return;
    const logo_size: usize = @intCast(endian.get32be(raw, 4));
    if (8 + logo_size > raw.len) return error.OutOfBounds;
    var logo = DataBlock.init();
    errdefer logo.deinit(xex.gpa);
    try logo.set(xex.gpa, raw[8..][0..logo_size], 0, @intCast(logo_size));
    xex.logo_data = logo;
}

fn parseMultidiscIds(xex: *model.Xex, raw: []const u8, info_size: i32) Error!void {
    if (info_size < 4) return;
    const count = (@as(usize, @intCast(info_size)) - 4) / 16;
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const offset = 4 + i * 16;
        if (offset + 16 > raw.len) return error.OutOfBounds;
        var media_id: types.MediaId = .{};
        @memcpy(&media_id.data, raw[offset..][0..16]);
        try xex.multidisc_media_ids.append(xex.gpa, media_id);
    }
}

fn parseAltTitleIds(xex: *model.Xex, raw: []const u8, info_size: i32) Error!void {
    if (info_size < 4) return;
    const count = (@as(usize, @intCast(info_size)) - 4) / 4;
    var i: usize = 0;
    while (i < count) : (i += 1) {
        try xex.alt_title_ids.append(xex.gpa, try cursor.readU32beAt(raw, 4 + i * 4));
    }
}

fn testKeys() Keys {
    return Keys.uniform(@splat(0x5A));
}

test "readHeaders: parses a minimal unsigned XEX header tree" {
    var headers: [0x298]u8 = @splat(0);
    @memcpy(headers[0..4], &defines.xex_magic);
    endian.set32be(&headers, 4, defines.module_flag_title_module);
    endian.set32be(&headers, 0x08, 0x298);
    endian.set32be(&headers, 0x10, 0x100);
    endian.set32be(&headers, 0x14, 2);

    endian.set32be(&headers, 0x18, defines.image_key_basefile_format);
    endian.set32be(&headers, 0x1C, 0x80);
    endian.set32be(&headers, 0x20, defines.image_key_execution_id);
    endian.set32be(&headers, 0x24, 0x90);

    endian.set32be(&headers, 0x80, 8);
    endian.set16be(&headers, 0x84, 0);
    endian.set16be(&headers, 0x86, 1);

    endian.set32be(&headers, 0x90, 24);
    endian.set32be(&headers, 0x94, 0x11223344);
    endian.set32be(&headers, 0x9C, 0x52584401);
    headers[0xA0] = 2;
    endian.set32be(&headers, 0xA4, 0x55667788);

    endian.set32be(&headers, 0x100, 0x184);
    endian.set32be(&headers, 0x104, 0x10000);
    endian.set32be(&headers, 0x208, 0x174);
    endian.set32be(&headers, 0x210, 0x82000000);
    endian.set32be(&headers, 0x27C, defines.media_hard_disk);
    endian.set32be(&headers, 0x280, 1);
    endian.set32be(&headers, 0x284, (1 << 4) | defines.section_info_code);

    var block = DataBlock.init();
    defer block.deinit(std.testing.allocator);
    try block.set(std.testing.allocator, &headers, 0, headers.len);

    var xex = model.Xex.init(std.testing.allocator);
    defer xex.deinit();
    const image_size = try readHeaders(&xex, block, testKeys());

    try std.testing.expectEqual(@as(i32, 0x10000), image_size);
    try std.testing.expect(xex.isTitleModule());
    try std.testing.expect(xex.is_raw);
    try std.testing.expect(!xex.is_encrypted);
    try std.testing.expectEqual(@as(u32, 0x82000000), xex.load_address);
    try std.testing.expectEqual(@as(u32, 0x52584401), xex.execution_id.?.title_id);
    try std.testing.expectEqual(@as(u32, defines.media_hard_disk), xex.media_types);
    try std.testing.expectEqual(@as(usize, 1), xex.sections.items.len);
    try std.testing.expectEqual(@as(i32, 0x10000), xex.sections.items[0].size);
    try std.testing.expectEqual(@as(u8, defines.section_info_code), xex.sections.items[0].info);
}
