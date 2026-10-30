// SPDX-FileCopyrightText: 2026 XexTool Zig rewrite contributors
// SPDX-License-Identifier: GPL-3.0-or-later

const std = @import("std");
const DataBlock = @import("../core/datablock.zig").DataBlock;
const defines = @import("defines.zig");
const types = @import("types.zig");
const pe = @import("pe.zig");

pub const UnknownImageEntry = struct {
    header: types.ImageEntry,
    data: DataBlock,
};

pub const Xex = struct {
    gpa: std.mem.Allocator,

    original_headers: DataBlock = .{},
    patch_data: DataBlock = .{},
    patch_info: DataBlock = .{},
    basefile: DataBlock = .{},
    basefile_format: DataBlock = .{},

    is_debug: bool = false,
    is_encrypted: bool = false,
    is_binary: bool = false,
    is_raw: bool = false,
    is_compressed: bool = false,
    is_delta_compressed: bool = false,

    module_flags: u32 = 0,
    discardable_header_size: i32 = 0,
    image_flags: u32 = 0,
    system_flags: u32 = 0,
    system_flags2: u32 = 0,
    regions: u32 = 0,
    media_types: u32 = 0,
    load_address: u32 = 0,
    export_table_address: u32 = 0,
    media_id: types.MediaId = .{},
    image_key: types.Key = .{},
    has_original_load_address: bool = false,

    base_reference: ?[20]u8 = null,
    disc_profile_id: ?[16]u8 = null,
    bounding_path: ?[]u8 = null,
    bounding_device_id: ?[20]u8 = null,
    call_cap: ?[2]u32 = null,
    fast_cap: ?u32 = null,
    extra_debug_memory: ?u32 = null,
    page_heap: ?types.PageHeap = null,
    restrict_kv_privs: ?types.RestrictKvPrivs = null,
    restrict_dates: ?types.RestrictDates = null,
    original_pe_name: ?[]u8 = null,
    tls_info: ?types.TLSInfo = null,
    stack_size: ?i32 = null,
    filesystem_cache_size: ?i32 = null,
    heap_size: ?i32 = null,
    execution_id: ?types.ExecutionId = null,
    workspace_size: ?i32 = null,
    game_ratings: ?types.GameRatings = null,
    lan_key: ?[16]u8 = null,
    logo_data: ?DataBlock = null,
    delta_patch_descriptor: ?DataBlock = null,
    exports_by_name: ?types.ExportsByName = null,

    sections: std.ArrayList(types.BasefileSection) = .empty,
    resources: std.ArrayList(types.ResourceEntry) = .empty,
    import_libraries: std.ArrayList(types.ImportLibraryData) = .empty,
    static_libraries: std.ArrayList(types.StaticLibraryEntry) = .empty,
    multidisc_media_ids: std.ArrayList(types.MediaId) = .empty,
    alt_title_ids: std.ArrayList(u32) = .empty,
    restrict_console_ids: std.ArrayList(types.ConsoleId) = .empty,
    unknown_image_entries: std.ArrayList(UnknownImageEntry) = .empty,

    pub fn init(gpa: std.mem.Allocator) Xex {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *Xex) void {
        const gpa = self.gpa;
        self.original_headers.deinit(gpa);
        self.patch_data.deinit(gpa);
        self.patch_info.deinit(gpa);
        self.basefile.deinit(gpa);
        self.basefile_format.deinit(gpa);
        if (self.bounding_path) |path| gpa.free(path);
        if (self.original_pe_name) |name| gpa.free(name);
        if (self.logo_data) |*logo| logo.deinit(gpa);
        if (self.delta_patch_descriptor) |*patch| patch.deinit(gpa);
        for (self.import_libraries.items) |*library| gpa.free(library.addresses);
        for (self.unknown_image_entries.items) |*entry| entry.data.deinit(gpa);
        self.sections.deinit(gpa);
        self.resources.deinit(gpa);
        self.import_libraries.deinit(gpa);
        self.static_libraries.deinit(gpa);
        self.multidisc_media_ids.deinit(gpa);
        self.alt_title_ids.deinit(gpa);
        self.restrict_console_ids.deinit(gpa);
        self.unknown_image_entries.deinit(gpa);
        self.* = undefined;
    }

    pub fn hasModuleFlag(self: *const Xex, flag: u32) bool {
        return (self.module_flags & flag) != 0;
    }

    pub fn hasImageFlag(self: *const Xex, flag: u32) bool {
        return (self.image_flags & flag) != 0;
    }

    pub fn hasSystemFlag(self: *const Xex, flag: u32) bool {
        return (self.system_flags & flag) != 0;
    }

    pub fn hasSystemFlag2(self: *const Xex, flag: u32) bool {
        return (self.system_flags2 & flag) != 0;
    }

    pub fn hasRegion(self: *const Xex, flag: u32) bool {
        return (self.regions & flag) != 0;
    }

    pub fn hasMediaType(self: *const Xex, flag: u32) bool {
        return (self.media_types & flag) != 0;
    }

    pub fn isAllRegions(self: *const Xex) bool {
        return self.regions == defines.region_all;
    }

    pub fn isAllMediaTypes(self: *const Xex) bool {
        return self.media_types == defines.media_all;
    }

    pub fn isBasefilePE(self: *const Xex) bool {
        return pe.Parser.init(self.basefile.data()).isPeFile();
    }

    pub fn isBasefileXUIZ(self: *const Xex) bool {
        return self.basefile.data().len >= 4 and std.mem.eql(u8, self.basefile.data()[0..4], "XUIZ");
    }

    pub fn entryPoint(self: *const Xex) u32 {
        if (!self.isBasefilePE()) return 0;
        return (pe.Parser.init(self.basefile.data()).entryPoint() orelse 0) +% self.load_address;
    }

    pub fn originalLoadAddress(self: *const Xex) u32 {
        if (!self.isBasefilePE()) return 0;
        return pe.Parser.init(self.basefile.data()).loadAddress() orelse 0;
    }

    pub fn checksum(self: *const Xex) u32 {
        if (!self.isBasefilePE()) return 0;
        return pe.Parser.init(self.basefile.data()).checksum() orelse 0;
    }

    pub fn filetime(self: *const Xex) u32 {
        if (!self.isBasefilePE()) return 0;
        return pe.Parser.init(self.basefile.data()).filetime() orelse 0;
    }

    pub fn hasEntryPoint(self: *const Xex) bool {
        return self.isBasefilePE() and self.entryPoint() != self.load_address and self.entryPoint() != 0;
    }

    pub fn hasOriginalLoadAddress(self: *const Xex) bool {
        return self.has_original_load_address and self.isBasefilePE();
    }

    pub fn hasChecksum(self: *const Xex) bool {
        return self.isBasefilePE();
    }

    pub fn hasFiletime(self: *const Xex) bool {
        return self.isBasefilePE();
    }

    pub fn pageSize(self: *const Xex) u32 {
        return if ((self.image_flags & defines.image_flag_4k_pages) != 0) 0x1000 else 0x10000;
    }

    pub fn isTitleModule(self: *const Xex) bool {
        return (self.module_flags & defines.module_flag_title_module) != 0;
    }

    pub fn isDllModule(self: *const Xex) bool {
        return (self.module_flags & defines.module_flag_dll_module) != 0;
    }

    pub fn isPatchModule(self: *const Xex) bool {
        return (self.module_flags & defines.module_flag_patch_module) != 0;
    }

    pub fn isTitleExports(self: *const Xex) bool {
        return (self.module_flags & defines.module_flag_exports_to_title) != 0;
    }

    pub fn isSystemDebugger(self: *const Xex) bool {
        return (self.module_flags & defines.module_flag_system_debugger) != 0;
    }

    pub fn isPatchFull(self: *const Xex) bool {
        return (self.module_flags & defines.module_flag_patch_full) != 0;
    }

    pub fn isPatchDelta(self: *const Xex) bool {
        return (self.module_flags & defines.module_flag_patch_delta) != 0;
    }

    pub fn isUserMode(self: *const Xex) bool {
        return (self.module_flags & defines.module_flag_user_mode) != 0;
    }

    pub fn isManufacturingUtility(self: *const Xex) bool {
        return (self.image_flags & defines.image_flag_manufacturing_utility) != 0;
    }

    pub fn isManufacturingSupportTool(self: *const Xex) bool {
        return (self.image_flags & defines.image_flag_manufacturing_tool) != 0;
    }

    pub fn isPageSize4KB(self: *const Xex) bool {
        return (self.image_flags & defines.image_flag_4k_pages) != 0;
    }

    pub fn hasRequiredRevocationCheck(self: *const Xex) bool {
        return (self.image_flags & defines.image_flag_revocation_check_req) != 0;
    }

    pub fn hasOptionalRevocationCheck(self: *const Xex) bool {
        return (self.image_flags & defines.image_flag_revocation_check_opt) != 0;
    }

    pub fn imageSize(self: *const Xex) i32 {
        return self.basefile.size();
    }
};

test "Xex page size follows the image flag" {
    var xex = Xex.init(std.testing.allocator);
    defer xex.deinit();
    try std.testing.expectEqual(@as(u32, 0x10000), xex.pageSize());
    xex.image_flags |= defines.image_flag_4k_pages;
    try std.testing.expectEqual(@as(u32, 0x1000), xex.pageSize());
}
