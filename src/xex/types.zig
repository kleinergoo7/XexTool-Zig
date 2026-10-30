// SPDX-FileCopyrightText: 2026 XexTool Zig rewrite contributors
// SPDX-License-Identifier: GPL-3.0-or-later

const std = @import("std");
const endian = @import("../core/endian.zig");

pub const Hash = struct {
    data: [20]u8 = @splat(0),

    pub fn fromSlice(bytes: []const u8) Hash {
        var value: Hash = .{};
        @memcpy(&value.data, bytes[0..20]);
        return value;
    }
};

pub const MediaId = struct {
    data: [16]u8 = @splat(0),
};

pub const Key = struct {
    data: [16]u8 = @splat(0),
};

pub const ImageHeader = struct {
    magic: [4]u8 = .{ 0, 0, 0, 0 },
    module_flags: u32 = 0,
    size_of_headers: i32 = 0,
    size_of_discardable_headers: i32 = 0,
    security_info_offset: i32 = 0,
    image_entry_count: i32 = 0,
};

pub const ImageEntry = struct {
    key: u32,
    value: u32,
};

pub const HvImageInfo = struct {
    signature: [256]u8 = @splat(0),
    info_size: i32 = 0,
    image_flags: u32 = 0,
    load_address: u32 = 0,
    image_hash: Hash = .{},
    import_table_count: i32 = 0,
    import_hash: Hash = .{},
    media_id: MediaId = .{},
    image_key: Key = .{},
    export_table_address: u32 = 0,
    header_hash: Hash = .{},
    game_region: u32 = 0,
};

pub const SecurityInfo = struct {
    size: i32 = 0,
    image_size: i32 = 0,
    image_info: HvImageInfo = .{},
    allowed_media_types: u32 = 0,
    section_count: i32 = 0,
};

pub const HvSectionInfo = struct {
    dword: u32 = 0,

    pub fn size(self: HvSectionInfo) u32 {
        return self.dword >> 4;
    }

    pub fn info(self: HvSectionInfo) u8 {
        return @truncate(self.dword & 0xF);
    }

    pub fn fromParts(section_size: u32, section_info: u8) HvSectionInfo {
        return .{ .dword = (section_size << 4) | section_info };
    }
};

pub const ResourceEntry = struct {
    name: [8]u8 = @splat(0),
    addr: u32 = 0,
    size: i32 = 0,
};

pub const BaseFileInfoHeader = struct {
    info_size: i32 = 0,
    enc_type: u16 = 0,
    comp_type: u16 = 0,
};

pub const RawBaseFileBlock = struct {
    data_size: i32 = 0,
    zero_size: i32 = 0,
};

pub const CompBaseFileBlock = struct {
    data_size: i32 = 0,
    hash: Hash = .{},
};

pub const CompBaseFileInfo = struct {
    header: BaseFileInfoHeader = .{},
    compression_window: u32 = 0,
    block: CompBaseFileBlock = .{},
};

pub const DeltaPatchDescriptor = struct {
    info_size: i32 = 0,
    target_version: u32 = 0,
    source_version: u32 = 0,
    source_hash: [20]u8 = @splat(0),
    image_key_source: Key = .{},
    target_header_size: i32 = 0,
    delta_header_source_offset: i32 = 0,
    delta_header_source_size: i32 = 0,
    delta_header_target_offset: i32 = 0,
    delta_image_source_offset: i32 = 0,
    delta_image_source_size: i32 = 0,
    delta_image_target_offset: i32 = 0,
    patch_data: []u8 = &.{},
};

pub const ImportLibraryData = struct {
    name: [64]u8 = @splat(0),
    version: u32 = 0,
    min_version: u32 = 0,
    addresses: []u32 = &.{},
    module_number: u32 = 0,
    module_index: u8 = 0,
};

pub const StaticLibraryEntry = struct {
    name: [8]u8 = @splat(0),
    version: VersionInfo = .{},
};

pub const RestrictKvPrivs = struct {
    mask: u64 = 0,
    val: u64 = 0,
};

pub const RestrictDates = struct {
    start: u64 = 0,
    end: u64 = 0,
};

pub const ConsoleId = struct {
    id: [5]u8 = @splat(0),
};

pub const TLSInfo = struct {
    num_slots: i32 = 0,
    raw_address: u32 = 0,
    raw_size: u32 = 0,
    data_size: u32 = 0,
};

pub const PageHeap = struct {
    size: u32 = 0,
    flags: u32 = 0,
};

pub const ExecutionId = struct {
    media_id: u32 = 0,
    version: u32 = 0,
    base_version: u32 = 0,
    title_id: u32 = 0,
    platform: u8 = 0,
    exec_type: u8 = 0,
    num_disc: u8 = 0,
    max_discs: u8 = 0,
    save_game_id: u32 = 0,
};

pub const GameRatings = struct {
    data: [64]u8 = @splat(0),
};

pub const ExportsByName = struct {
    export_table_offset: u32 = 0,
    export_table_size: u32 = 0,
};

pub const VersionInfo = struct {
    major: u16 = 0,
    minor: u16 = 0,
    build: u16 = 0,
    word: u16 = 0,

    pub fn qfe(self: VersionInfo) u8 {
        return @truncate(self.word & 0xFF);
    }

    pub fn approvedLibrary(self: VersionInfo) u2 {
        return @truncate((self.word >> 13) & 0x3);
    }

    pub fn debugBuild(self: VersionInfo) bool {
        return (self.word & 0x8000) != 0;
    }
};

pub const Version32 = struct {
    dword: u32 = 0,

    pub fn major(self: Version32) u4 {
        return @truncate(self.dword >> 28);
    }

    pub fn minor(self: Version32) u4 {
        return @truncate(self.dword >> 24);
    }

    pub fn build(self: Version32) u16 {
        return @truncate(self.dword >> 8);
    }

    pub fn qfe(self: Version32) u8 {
        return @truncate(self.dword);
    }

    pub fn fromParts(major_version: u4, minor_version: u4, build_number: u16, qfe_number: u8) Version32 {
        return .{ .dword = (@as(u32, major_version) << 28) | (@as(u32, minor_version) << 24) | (@as(u32, build_number) << 8) | qfe_number };
    }
};

pub const BasefileSection = struct {
    size: i32,
    info: u8,
};

test "XEX version fields are packed like the original bitfields" {
    const v = Version32.fromParts(1, 2, 0x1234, 0x56);
    try std.testing.expectEqual(@as(u4, 1), v.major());
    try std.testing.expectEqual(@as(u4, 2), v.minor());
    try std.testing.expectEqual(@as(u16, 0x1234), v.build());
    try std.testing.expectEqual(@as(u8, 0x56), v.qfe());
}

test "XEX section dword stores size and info" {
    const s = HvSectionInfo.fromParts(0x12345, 2);
    try std.testing.expectEqual(@as(u32, 0x12345), s.size());
    try std.testing.expectEqual(@as(u8, 2), s.info());
}
