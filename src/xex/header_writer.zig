// SPDX-FileCopyrightText: 2026 XexTool Zig rewrite contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Port of the XexHeader write path (`XexHeader::writeHeaders` and helpers).
//! Byte order follows XexHeader.cpp: every on-disk field is big-endian, while
//! the intermediate DataBlocks are assembled with native stores and then
//! converted by `convertImageEntryDataToBe`, exactly like the C++ writer.

const std = @import("std");
const DataBlock = @import("../core/datablock.zig").DataBlock;
const endian = @import("../core/endian.zig");
const crypto = @import("../xecrypt/xecrypt.zig");
const keys = @import("data.zig");
const defines = @import("defines.zig");
const model = @import("model.zig");
const types = @import("types.zig");

pub const Error = error{
    OutOfMemory,
    InvalidRange,
    OutOfBounds,
    HeaderSizeOverflow,
    HeaderLayout,
    ImageEntryCountMismatch,
    InvalidImportTable,
    InvalidSectionLayout,
    InvalidImageEntryData,
    SignatureFailed,
};

pub const image_header_size: i32 = 0x18;
pub const image_entry_size: i32 = 0x8;
pub const security_info_size: i32 = 0x184;
pub const section_info_size: i32 = 0x18;
/// Non-patch headers keep a zero gap between the image entries and security info.
pub const security_gap_size: i32 = 0x80;
pub const header_alignment: i32 = 0x1000;
pub const patch_alignment: i32 = 0x800;

const header_module_flags = 0x004;
const header_size_of_headers = 0x008;
const header_discardable = 0x00C;
const header_security_offset = 0x010;
const header_entry_count = 0x014;

const sec_size = 0x000;
const sec_image_size = 0x004;
const sec_signature = 0x008;
const sec_signature_size = 0x100;
const sec_info_size = 0x108;
const sec_image_flags = 0x10C;
const sec_load_address = 0x110;
const sec_image_hash = 0x114;
const sec_import_table_count = 0x128;
const sec_import_hash = 0x12C;
const sec_media_id = 0x140;
const sec_image_key = 0x150;
const sec_export_table_address = 0x160;
const sec_header_hash = 0x164;
const sec_game_region = 0x178;
const sec_allowed_media_types = 0x17C;
const sec_section_count = 0x180;

/// XexHvImageInfo.infoSize covers imageFlags..gameRegion.
const image_info_size: i32 = sec_allowed_media_types - 0x008;

const resource_entry_size: i32 = 16;
const base_reference_size: i32 = 20;
const restrict_kv_size: i32 = 16;
const restrict_dates_size: i32 = 16;
const console_id_size: i32 = 5;
const disc_profile_id_size: i32 = 16;
const disc_profile_alignment: i32 = 0x10;
const bound_device_id_size: i32 = 20;
const import_directory_size: i32 = 12;
const import_entry_size: i32 = 0x28;
const import_hash_size: i32 = 0x24;
const import_names_size: i32 = 1024;
const checksum_size: i32 = 8;
const callcap_size: i32 = 8;
const static_library_entry_size: i32 = 16;
const tls_info_size: i32 = 16;
const page_heap_size: i32 = 8;
const execution_id_size: i32 = 24;
const game_ratings_size: i32 = 64;
const lan_key_size: i32 = 16;
const exports_by_name_size: i32 = 8;
const string_size_limit: usize = 255;

fn toI32(value: usize) Error!i32 {
    // All header sizes are stored in s32 fields; larger counts cannot be encoded.
    if (value > std.math.maxInt(i32)) return error.HeaderSizeOverflow;
    return @intCast(value);
}

fn alignUp(value: i64, alignment: i32) Error!i32 {
    const mask: i64 = @as(i64, alignment) - 1;
    const aligned = (value + mask) & ~mask;
    return toI32(@intCast(aligned));
}

/// Length of a C string inside a fixed buffer, capped like `strlen` on the
/// 256-byte stack buffer in `getImageEntryDataSize`.
/// shortcut: names over 255 bytes are truncated for the write pass too, while
/// the C++ write pass caps at 1023; upgrade when a fixture needs longer names.
fn boundedStringLength(text: []const u8) usize {
    const limit = @min(text.len, string_size_limit);
    return std.mem.indexOfScalar(u8, text[0..limit], 0) orelse limit;
}

/// `(strlen + 4) & -4`, the padding the C++ writer applies to optional strings.
fn paddedStringLength(length: usize) usize {
    return (length + 4) & ~@as(usize, 3);
}

/// XexWriter::getNumOptionalInfos, in entry order.
pub fn getNumImageEntries(xex: *const model.Xex) i32 {
    var count: i32 = 0;
    if (xex.resources.items.len != 0) count += 1;
    count += 1; // IMAGEKEY_BASEFILE_FORMAT is always present
    if (xex.base_reference != null) count += 1;
    if (xex.delta_patch_descriptor != null) count += 1;
    if (xex.restrict_kv_privs != null) count += 1;
    if (xex.restrict_dates != null) count += 1;
    if (xex.restrict_console_ids.items.len != 0) count += 1;
    if (xex.disc_profile_id != null) count += 1;
    if (xex.bounding_path != null) count += 1;
    if (xex.bounding_device_id != null) count += 1;
    if (xex.hasOriginalLoadAddress()) count += 1;
    if (xex.hasEntryPoint()) count += 1;
    if (xex.isBasefilePE()) count += 1;
    if (xex.import_libraries.items.len != 0) count += 1;
    if (xex.hasChecksum()) count += 1;
    if (xex.call_cap != null) count += 1;
    if (xex.fast_cap != null) count += 1;
    if (xex.original_pe_name != null) count += 1;
    if (xex.static_libraries.items.len != 0) count += 1;
    if (xex.tls_info != null) count += 1;
    if (xex.stack_size != null) count += 1;
    if (xex.filesystem_cache_size != null) count += 1;
    if (xex.heap_size != null) count += 1;
    if (xex.page_heap != null) count += 1;
    if (xex.system_flags != 0) count += 1;
    if (xex.system_flags2 != 0) count += 1;
    if (xex.execution_id != null) count += 1;
    if (xex.workspace_size != null) count += 1;
    if (xex.game_ratings != null) count += 1;
    if (xex.lan_key != null) count += 1;
    if (xex.logo_data != null) count += 1;
    if (xex.multidisc_media_ids.items.len != 0) count += 1;
    if (xex.alt_title_ids.items.len != 0) count += 1;
    if (xex.extra_debug_memory != null) count += 1;
    if (xex.exports_by_name != null) count += 1;
    count += @intCast(xex.unknown_image_entries.items.len); // fits: bounded by a u32 entry count
    return count;
}

const ImportNameTable = struct {
    size: i32,
    count: i32,
};

/// Port of the import-library name table pass. Names are only appended when a
/// higher module index appears, and the table stops at 1024 bytes.
fn buildImportNameTable(xex: *const model.Xex, destination: ?[]u8) Error!ImportNameTable {
    if (xex.import_libraries.items.len > std.math.maxInt(i32)) return error.HeaderSizeOverflow;
    var handled: i32 = -1;
    var size: i32 = 0;
    for (xex.import_libraries.items) |library| {
        if (@as(i32, library.module_index) <= handled) continue;
        // getImportLibrary() forces name[63] = 0 before the writer sees it.
        const raw_length = std.mem.indexOfScalar(u8, library.name[0..], 0) orelse library.name.len;
        const name_length = @min(raw_length, library.name.len - 1);
        const padded = paddedStringLength(name_length);
        if (@as(i64, size) + @as(i64, @intCast(padded)) > import_names_size) break;
        if (destination) |buffer| {
            // Buffer is zeroed; the C++ writer copies only the name bytes.
            @memcpy(buffer[@intCast(size)..][0..name_length], library.name[0..name_length]);
        }
        size += @intCast(padded);
        handled = library.module_index;
    }
    return .{ .size = size, .count = handled + 1 };
}

fn importLibrariesDataSize(xex: *const model.Xex) Error!i32 {
    const table = try buildImportNameTable(xex, null);
    var total: i64 = import_directory_size + table.size;
    for (xex.import_libraries.items) |library| {
        total += import_entry_size;
        total += @as(i64, @intCast(library.addresses.len)) * 4;
        if (total > std.math.maxInt(i32)) return error.HeaderSizeOverflow;
    }
    return @intCast(total);
}

/// XexWriter::getImageEntryDataSize: bytes occupied by image-entry payloads.
pub fn getImageEntryDataSize(xex: *const model.Xex, basefile_format: DataBlock) Error!i32 {
    var total: i64 = 0;
    if (xex.resources.items.len != 0) {
        total += 4 + @as(i64, @intCast(xex.resources.items.len)) * resource_entry_size;
    }
    total += basefile_format.size();
    if (xex.base_reference != null) total += base_reference_size;
    if (xex.delta_patch_descriptor) |patch| total += patch.size();
    if (xex.restrict_kv_privs != null) total += restrict_kv_size;
    // Shipped quirk: the size pass tests hasRestrictKVPrivs() for the dates too.
    if (xex.restrict_kv_privs != null) total += restrict_dates_size;
    if (xex.restrict_console_ids.items.len != 0) {
        total += 4 + @as(i64, @intCast(xex.restrict_console_ids.items.len)) * console_id_size;
    }
    if (xex.disc_profile_id != null) {
        // The writer aligns the id and pads the block even though it may write less.
        total += disc_profile_id_size + disc_profile_alignment;
    }
    if (xex.bounding_path) |path| {
        total += 4 + @as(i64, @intCast(paddedStringLength(boundedStringLength(path))));
    }
    if (xex.bounding_device_id != null) total += bound_device_id_size;
    if (xex.import_libraries.items.len != 0) total += try importLibrariesDataSize(xex);
    if (xex.hasChecksum()) total += checksum_size;
    if (xex.call_cap != null) total += callcap_size;
    if (xex.original_pe_name) |name| {
        total += 4 + @as(i64, @intCast(paddedStringLength(boundedStringLength(name))));
    }
    if (xex.static_libraries.items.len != 0) {
        total += 4 + @as(i64, @intCast(xex.static_libraries.items.len)) * static_library_entry_size;
    }
    if (xex.tls_info != null) total += tls_info_size;
    if (xex.page_heap != null) total += page_heap_size;
    if (xex.execution_id != null) total += execution_id_size;
    if (xex.game_ratings != null) total += game_ratings_size;
    if (xex.lan_key != null) total += lan_key_size;
    if (xex.logo_data) |logo| total += logo.size() + 8;
    if (xex.multidisc_media_ids.items.len != 0) {
        total += 4 + @as(i64, @intCast(xex.multidisc_media_ids.items.len)) * 16;
    }
    if (xex.alt_title_ids.items.len != 0) {
        total += 4 + @as(i64, @intCast(xex.alt_title_ids.items.len)) * 4;
    }
    if (xex.exports_by_name != null) total += exports_by_name_size;
    for (xex.unknown_image_entries.items) |entry| total += entry.data.size();
    if (total > std.math.maxInt(i32)) return error.HeaderSizeOverflow;
    return @intCast(total);
}

/// XexWriter::getSecurityInfo: fills the native-endian security info fields.
pub fn getSecurityInfo(xex: *const model.Xex, sec: *types.SecurityInfo) Error!void {
    if (xex.sections.items.len > std.math.maxInt(i32)) return error.HeaderSizeOverflow;
    if (xex.import_libraries.items.len > std.math.maxInt(i32)) return error.HeaderSizeOverflow;

    sec.* = .{};
    sec.size = security_info_size + @as(i32, @intCast(xex.sections.items.len)) * section_info_size;
    sec.image_size = xex.imageSize();
    sec.image_info.info_size = image_info_size;
    // The model keeps the complete flag word; C++ rebuilds the known bits and
    // ORs the unknown mask, which is the same value for any parsed header.
    sec.image_info.image_flags = rebuildImageFlags(xex.image_flags);
    sec.image_info.load_address = xex.load_address;
    sec.image_info.import_table_count = @intCast(xex.import_libraries.items.len);
    sec.image_info.media_id = xex.media_id;
    sec.image_info.image_key = xex.image_key;
    try encryptImageKey(xex, &sec.image_info.image_key);
    sec.image_info.export_table_address = xex.export_table_address;
    sec.image_info.game_region = rebuildRegions(xex.regions);
    sec.allowed_media_types = rebuildMedia(xex.media_types);
    sec.section_count = @intCast(xex.sections.items.len);
}

/// XexWriter::writeSecurityInfo rebuilds each region field from its predicate
/// and drops unknown bits; writing the raw word changes non-canonical input.
fn rebuildModuleFlags(flags: u32) u32 {
    var rebuilt: u32 = 0;
    for ([_]u32{
        defines.module_flag_title_module,
        defines.module_flag_exports_to_title,
        defines.module_flag_system_debugger,
        defines.module_flag_dll_module,
        defines.module_flag_patch_module,
        defines.module_flag_patch_full,
        defines.module_flag_patch_delta,
        defines.module_flag_user_mode,
    }) |mask| {
        if ((flags & mask) != 0) rebuilt |= mask;
    }
    return rebuilt | (flags & defines.module_flag_unknown);
}

/// Rebuilds the known image bits and preserves IMAGEFLAG_UNKNOWN, matching
/// XexWriter::getSecurityInfo.
fn rebuildImageFlags(flags: u32) u32 {
    var rebuilt: u32 = 0;
    for ([_]u32{
        defines.image_flag_manufacturing_utility,
        defines.image_flag_manufacturing_tool,
        defines.image_flag_xgd2,
        defines.image_flag_cardea_key,
        defines.image_flag_xeika_key,
        defines.image_flag_title_usermode,
        defines.image_flag_system_usermode,
        defines.image_flag_orange0,
        defines.image_flag_orange1,
        defines.image_flag_orange2,
        defines.image_flag_signed_kv_restricted,
        defines.image_flag_iptv_signup_app,
        defines.image_flag_iptv_title_app,
        defines.image_flag_nccp_keys,
        defines.image_flag_activation_req,
        defines.image_flag_4k_pages,
        defines.image_flag_no_game_region,
        defines.image_flag_revocation_check_opt,
        defines.image_flag_revocation_check_req,
    }) |mask| {
        if ((flags & mask) != 0) rebuilt |= mask;
    }
    return rebuilt | (flags & defines.image_flag_unknown);
}

fn rebuildSystemFlags(flags: u32) u32 {
    var rebuilt: u32 = 0;
    for ([_]u32{
        defines.sys_flag_no_force_reboot,
        defines.sys_flag_foreground_tasks,
        defines.sys_flag_no_odd_mapping,
        defines.sys_flag_handle_mce_input,
        defines.sys_flag_restrict_hud_features,
        defines.sys_flag_handle_gamepad_disconnect,
        defines.sys_flag_insecure_sockets,
        defines.sys_flag_xbox1_xsp_interop,
        defines.sys_flag_set_dash_context,
        defines.sys_flag_uses_game_voice_channel,
        defines.sys_flag_pal50_incompatible,
        defines.sys_flag_insecure_utilitydrive,
        defines.sys_flag_has_xam_hooks,
        defines.sys_flag_pii,
        defines.sys_flag_crossplatform_syslink,
        defines.sys_flag_multidisc_swap,
        defines.sys_flag_multidisc_insecure_media,
        defines.sys_flag_ap25_media,
        defines.sys_flag_no_confirm_exit,
        defines.sys_flag_allow_bkgrnd_download,
        defines.sys_flag_create_persist_ramdrive,
        defines.sys_flag_inherit_persist_ramdrive,
        defines.sys_flag_allow_hud_vibration,
        defines.sys_flag_both_utility_partitions,
        defines.sys_flag_handle_iptv_input,
        defines.sys_flag_prefer_bigbutton_input,
        defines.sys_flag_allow_xsam_reservation,
        defines.sys_flag_multidisc_cross_title,
        defines.sys_flag_title_install_incompatible,
        defines.sys_flag_allow_avatar_get_metadata,
        defines.sys_flag_allow_controller_swapping,
        defines.sys_flag_dash_extensibility_module,
    }) |mask| {
        if ((flags & mask) != 0) rebuilt |= mask;
    }
    return rebuilt | (flags & defines.sys_flag_unknown);
}

fn rebuildSystemFlags2(flags: u32) u32 {
    var rebuilt: u32 = 0;
    for ([_]u32{
        defines.sys_flag2_allow_network_read_cancel,
        defines.sys_flag2_uninterruptable_reads,
        defines.sys_flag2_require_full_experience,
        defines.sys_flag2_gamevoice_required_ui,
        defines.sys_flag2_title_set_presence_string,
        defines.sys_flag2_natal_tiltcontrol,
        defines.sys_flag2_requires_skeletal_tracking,
        defines.sys_flag2_supports_skeletal_tracking,
        defines.sys_flag2_use_large_hds_file_cache,
        defines.sys_flag2_title_supports_deep_link,
    }) |mask| {
        if ((flags & mask) != 0) rebuilt |= mask;
    }
    return rebuilt | (flags & defines.sys_flag2_unknown);
}

fn rebuildRegions(regions: u32) u32 {
    var rebuilt: u32 = 0;
    for ([_]u32{
        defines.region_north_america,
        defines.region_japan,
        defines.region_china,
        defines.region_rest_of_asia,
        defines.region_aust_nz,
        defines.region_rest_of_europe,
        defines.region_rest_of_world,
    }) |mask| {
        if ((regions & mask) != 0) rebuilt |= mask;
    }
    return rebuilt;
}

/// Rebuilds the known media bits and preserves MEDIATYPE_UNKNOWN, matching
/// XexWriter::writeSecurityInfo.
fn rebuildMedia(media: u32) u32 {
    var flags: u32 = 0;
    for ([_]u32{
        defines.media_hard_disk,
        defines.media_dvdx2,
        defines.media_dvd_cd,
        defines.media_dvd5,
        defines.media_dvd9,
        defines.media_sys_flash,
        defines.media_mem_unit,
        defines.media_mass_storage,
        defines.media_smb,
        defines.media_ram,
        defines.media_ram_drive,
        defines.media_secure_virt_od,
        defines.media_wireless_n_storage,
        defines.media_sys_ext_partition,
        defines.media_sys_aux_partition,
        defines.media_insecure_pkg,
        defines.media_savegame_pkg,
        defines.media_localsign_pkg,
        defines.media_livesign_pkg,
        defines.media_xbox_pkg,
    }) |mask| {
        if ((media & mask) != 0) flags |= mask;
    }
    return flags | (media & defines.media_unknown);
}

fn encryptImageKey(xex: *const model.Xex, key: *types.Key) Error!void {
    const crypt_key = if (xex.isManufacturingSupportTool() or xex.isManufacturingUtility())
        (if (xex.is_debug) keys.xex_mfg_debug_key else keys.xex_mfg_retail_key)
    else
        (if (xex.is_debug) keys.xex_debug_key else keys.xex_retail_key);
    encryptKey(key, &crypt_key);
}

fn encryptKey(key: *types.Key, crypt_key: []const u8) void {
    var aes: crypto.AesState = undefined;
    crypto.XeCryptAesKey(&aes, crypt_key[0..16]);
    var output: [16]u8 = undefined;
    crypto.XeCryptAesEcb(&aes, &key.data, &output, true);
    key.data = output;
}

/// Writes the security info block in big-endian form, leaving the hashes and
/// the signature zeroed for the update passes.
fn writeSecurityInfo(xex: *const model.Xex, out: []u8) Error!void {
    var info: types.SecurityInfo = .{};
    try getSecurityInfo(xex, &info);
    @memset(out, 0);
    endian.set32be(out, sec_size, @bitCast(info.size));
    endian.set32be(out, sec_image_size, @bitCast(info.image_size));
    @memcpy(out[sec_signature..][0..sec_signature_size], &info.image_info.signature);
    endian.set32be(out, sec_info_size, @bitCast(info.image_info.info_size));
    endian.set32be(out, sec_image_flags, info.image_info.image_flags);
    endian.set32be(out, sec_load_address, info.image_info.load_address);
    @memcpy(out[sec_image_hash..][0..20], &info.image_info.image_hash.data);
    endian.set32be(out, sec_import_table_count, @bitCast(info.image_info.import_table_count));
    @memcpy(out[sec_import_hash..][0..20], &info.image_info.import_hash.data);
    @memcpy(out[sec_media_id..][0..16], &info.image_info.media_id.data);
    @memcpy(out[sec_image_key..][0..16], &info.image_info.image_key.data);
    endian.set32be(out, sec_export_table_address, info.image_info.export_table_address);
    @memcpy(out[sec_header_hash..][0..20], &info.image_info.header_hash.data);
    endian.set32be(out, sec_game_region, info.image_info.game_region);
    endian.set32be(out, sec_allowed_media_types, info.allowed_media_types);
    endian.set32be(out, sec_section_count, @bitCast(info.section_count));
}

/// XexHeader::writeHeaders: builds the complete header area, hashes it and
/// signs it when the model is a debug image.
pub fn writeHeaders(xex: *const model.Xex, headers: *DataBlock, basefile_format: DataBlock) Error!void {
    const num_entries = getNumImageEntries(xex);
    const entry_data_size = try getImageEntryDataSize(xex, basefile_format);
    const section_count = try toI32(xex.sections.items.len);

    var sec_info_offset: i64 = @as(i64, image_header_size) + @as(i64, num_entries) * image_entry_size;
    if (!xex.isPatchModule()) sec_info_offset += security_gap_size;
    const sections_offset: i64 = sec_info_offset + security_info_size;
    const entry_data_offset: i64 = sections_offset + @as(i64, section_count) * section_info_size;
    const unaligned_end = entry_data_offset + entry_data_size;
    const basefile_offset = try alignUp(
        unaligned_end,
        if (xex.isPatchModule()) patch_alignment else header_alignment,
    );
    const headers_size = basefile_offset;

    headers.clear(xex.gpa);
    try headers.fill(xex.gpa, 0, 0, headers_size);
    const buffer = headers.dataMut();

    @memcpy(buffer[0..4], &defines.xex_magic);
    endian.set32be(buffer, header_module_flags, rebuildModuleFlags(xex.module_flags));
    endian.set32be(buffer, header_size_of_headers, @bitCast(headers_size));
    endian.set32be(buffer, header_discardable, @bitCast(xex.discardable_header_size));
    endian.set32be(buffer, header_security_offset, @bitCast(try toI32(@intCast(sec_info_offset))));
    endian.set32be(buffer, header_entry_count, @bitCast(num_entries));

    const sec_start: usize = @intCast(sec_info_offset);
    try writeSecurityInfo(xex, buffer[sec_start..][0..security_info_size]);

    for (xex.sections.items, 0..) |section, index| {
        if (section.size < 0) return error.InvalidSectionLayout;
        const page_size = xex.pageSize();
        const pages = @divTrunc(section.size, @as(i32, @intCast(page_size)));
        // XexHvSectionInfo packs 28 size bits and 4 info bits into one dword.
        const dword = ((@as(u32, @truncate(@as(u32, @intCast(pages)))) & 0x0FFFFFFF) << 4) |
            @as(u32, section.info & 0xF);
        const offset: usize = @intCast(sections_offset + @as(i64, @intCast(index)) * section_info_size);
        endian.set32be(buffer, offset, dword);
    }

    const entries_start: usize = @intCast(image_header_size);
    const entries_end: usize = entries_start + @as(usize, @intCast(num_entries)) * @as(usize, @intCast(image_entry_size));
    if (entries_end > buffer.len) return error.HeaderLayout;
    const data_start: usize = @intCast(entry_data_offset);
    if (data_start > buffer.len) return error.HeaderLayout;
    const written = try getImageEntry(
        xex,
        buffer[entries_start..entries_end],
        buffer[data_start..],
        @intCast(entry_data_offset),
        basefile_format,
    );
    if (written != num_entries) return error.ImageEntryCountMismatch;

    try updateImportHash(xex.gpa, buffer);
    try updateSectionHashes(xex, buffer, @intCast(sections_offset), @intCast(sec_info_offset));
    try updateHeaderHash(buffer, headers_size, @intCast(sec_info_offset));
    if (xex.is_debug) {
        try updateDebugSign(xex, buffer[sec_start..][0..security_info_size]);
    }
}

const EntrySink = struct {
    entries: []u8,
    data: []u8,
    data_offset: i32,
    index: i32 = 0,
    info_offset: i32 = 0,

    fn record(self: *EntrySink, key: u32, value: u32) Error!void {
        const offset: usize = @intCast(self.index * image_entry_size);
        if (offset + @as(usize, @intCast(image_entry_size)) > self.entries.len) return error.ImageEntryCountMismatch;
        endian.set32be(self.entries, offset, key);
        endian.set32be(self.entries, offset + 4, value);
        self.index += 1;
    }

    fn copyBlock(self: *EntrySink, block: *const DataBlock, position: i32) Error!void {
        const size = block.size();
        if (position < 0) return error.OutOfBounds;
        const start: usize = @intCast(position);
        const length: usize = @intCast(size);
        if (start > self.data.len or length > self.data.len - start) return error.OutOfBounds;
        @memcpy(self.data[start..][0..length], block.data());
    }

    fn addData(self: *EntrySink, key: u32, block: *const DataBlock) Error!void {
        try self.copyBlock(block, self.info_offset);
        try self.record(key, try self.dataValue(0));
        self.info_offset += block.size();
    }

    fn addDataAligned(self: *EntrySink, key: u32, block: *const DataBlock, extra: i32) Error!void {
        try self.copyBlock(block, self.info_offset);
        try self.record(key, try self.dataValue(extra));
        self.info_offset += block.size();
    }

    fn dataValue(self: *const EntrySink, extra: i32) Error!u32 {
        const value: i64 = @as(i64, self.data_offset) + self.info_offset + extra;
        if (value < 0 or value > std.math.maxInt(u32)) return error.HeaderSizeOverflow;
        return @intCast(value);
    }
};

fn makeBlock() DataBlock {
    return DataBlock.init();
}

/// XexWriter::getImageEntry, in the exact order the C++ writer emits entries.
/// `entries` receives the directory, `data_region` the payload area.
pub fn getImageEntry(
    xex: *const model.Xex,
    entries: []u8,
    data_region: []u8,
    data_offset: i32,
    basefile_format: DataBlock,
) Error!i32 {
    const gpa = xex.gpa;
    var sink = EntrySink{
        .entries = entries,
        .data = data_region,
        .data_offset = data_offset,
    };

    if (xex.resources.items.len != 0) {
        var block = makeBlock();
        defer block.deinit(gpa);
        for (xex.resources.items, 0..) |resource, index| {
            const offset = 4 + @as(i32, @intCast(index)) * resource_entry_size;
            try block.set(gpa, &resource.name, offset, 8);
            try block.set32(gpa, resource.addr, offset + 8);
            try block.set32(gpa, @bitCast(resource.size), offset + 12);
        }
        try block.set32(gpa, @bitCast(block.size()), 0);
        try convertImageEntryDataToBe(&block, gpa, defines.image_key_resource_section);
        try sink.addData(defines.image_key_resource_section, &block);
    }

    {
        var block = try basefile_format.clone(gpa);
        defer block.deinit(gpa);
        try block.set32(gpa, @bitCast(block.size()), 0);
        try block.set16(gpa, if (xex.is_encrypted) 1 else 0, 4);
        const compression: u16 = if (xex.is_binary or xex.is_raw)
            1
        else if (xex.is_compressed)
            2
        else if (xex.is_delta_compressed)
            3
        else
            0;
        try block.set16(gpa, compression, 6);
        try convertImageEntryDataToBe(&block, gpa, defines.image_key_basefile_format);
        try sink.addData(defines.image_key_basefile_format, &block);
    }

    if (xex.base_reference) |reference| {
        var block = makeBlock();
        defer block.deinit(gpa);
        try block.set(gpa, &reference, 0, base_reference_size);
        try convertImageEntryDataToBe(&block, gpa, defines.image_key_base_reference);
        try sink.addData(defines.image_key_base_reference, &block);
    }

    if (xex.delta_patch_descriptor) |patch| {
        var block = try patch.clone(gpa);
        defer block.deinit(gpa);
        // The reader keeps delta patch data in on-disk big-endian form, so a
        // round-trip copies it verbatim (C++ converts to native and back).
        try sink.addData(defines.image_key_delta_patch_descriptor, &block);
    }

    if (xex.restrict_kv_privs) |privs| {
        var block = makeBlock();
        defer block.deinit(gpa);
        try block.set64(gpa, privs.mask, 0);
        try block.set64(gpa, privs.val, 8);
        try convertImageEntryDataToBe(&block, gpa, defines.image_key_restrict_kv_privs);
        try sink.addData(defines.image_key_restrict_kv_privs, &block);
    }

    if (xex.restrict_dates) |dates| {
        var block = makeBlock();
        defer block.deinit(gpa);
        try block.set64(gpa, dates.start, 0);
        try block.set64(gpa, dates.end, 8);
        try convertImageEntryDataToBe(&block, gpa, defines.image_key_restrict_dates);
        try sink.addData(defines.image_key_restrict_dates, &block);
    }

    if (xex.restrict_console_ids.items.len != 0) {
        var block = makeBlock();
        defer block.deinit(gpa);
        for (xex.restrict_console_ids.items, 0..) |console, index| {
            const offset = 4 + @as(i32, @intCast(index)) * console_id_size;
            try block.set(gpa, &console.id, offset, console_id_size);
        }
        try block.set32(gpa, @bitCast(block.size()), 0);
        try convertImageEntryDataToBe(&block, gpa, defines.image_key_restrict_console_ids);
        try sink.addData(defines.image_key_restrict_console_ids, &block);
    }

    if (xex.disc_profile_id) |profile| {
        const aligned_offset = (disc_profile_alignment -
            (@as(i32, @intCast(sink.data_offset + sink.info_offset)) & 0xF)) & 0xF;
        var block = makeBlock();
        defer block.deinit(gpa);
        try block.set(gpa, &profile, aligned_offset, disc_profile_id_size);
        try convertImageEntryDataToBe(&block, gpa, defines.image_key_disc_profile_id);
        try sink.addDataAligned(defines.image_key_disc_profile_id, &block, aligned_offset);
    }

    if (xex.bounding_path) |path| {
        var block = try makeStringBlock(gpa, path);
        defer block.deinit(gpa);
        try convertImageEntryDataToBe(&block, gpa, defines.image_key_bound_pathname);
        try sink.addData(defines.image_key_bound_pathname, &block);
    }

    if (xex.bounding_device_id) |device_id| {
        var block = makeBlock();
        defer block.deinit(gpa);
        try block.set(gpa, &device_id, 0, bound_device_id_size);
        try convertImageEntryDataToBe(&block, gpa, defines.image_key_bound_device_id);
        try sink.addData(defines.image_key_bound_device_id, &block);
    }

    if (xex.hasOriginalLoadAddress()) {
        try sink.record(defines.image_key_original_base_address, xex.originalLoadAddress());
    }

    if (xex.hasEntryPoint()) {
        try sink.record(defines.image_key_entry_point, xex.entryPoint());
    }

    if (xex.isBasefilePE()) {
        try sink.record(defines.image_key_image_base_address, xex.load_address);
    }

    if (xex.import_libraries.items.len != 0) {
        var block = makeBlock();
        defer block.deinit(gpa);
        var names: [import_names_size]u8 = @splat(0);
        const table = try buildImportNameTable(xex, &names);
        try block.set32(gpa, 0, 0);
        try block.set32(gpa, @bitCast(table.size), 4);
        try block.set32(gpa, @bitCast(table.count), 8);
        try block.set(gpa, names[0..@intCast(table.size)], import_directory_size, table.size);
        var library_offset: i32 = import_directory_size + table.size;
        for (xex.import_libraries.items) |library| {
            if (library.addresses.len > std.math.maxInt(i32)) return error.HeaderSizeOverflow;
            const address_count: i32 = @intCast(library.addresses.len);
            if (address_count > @divTrunc(std.math.maxInt(i32) - import_entry_size, 4)) {
                return error.HeaderSizeOverflow;
            }
            const addresses_size: i32 = address_count * 4;
            const library_size: i32 = import_entry_size + addresses_size;
            try block.set32(gpa, @bitCast(library_size), library_offset);
            try block.set32(gpa, library.module_number, library_offset + 0x18);
            try block.set32(gpa, library.version, library_offset + 0x1C);
            try block.set32(gpa, library.min_version, library_offset + 0x20);
            try block.set8(gpa, 0, library_offset + 0x24);
            try block.set8(gpa, library.module_index, library_offset + 0x25);
            try block.set16(gpa, @intCast(address_count), library_offset + 0x26);
            for (library.addresses, 0..) |address, index| {
                try block.set32(gpa, address, library_offset + 0x28 + @as(i32, @intCast(index)) * 4);
            }
            library_offset += library_size;
        }
        try block.set32(gpa, @bitCast(block.size()), 0);
        try convertImageEntryDataToBe(&block, gpa, defines.image_key_import_libraries);
        // The import block always sits at the end of the entry-data area.
        const block_size: usize = @intCast(block.size());
        if (block_size > data_region.len) return error.OutOfBounds;
        const position = data_region.len - block_size;
        try sink.copyBlock(&block, @intCast(position));
        try sink.record(defines.image_key_import_libraries, try sink.dataValue(@as(i32, @intCast(position)) - sink.info_offset));
    }

    if (xex.hasChecksum()) {
        var block = makeBlock();
        defer block.deinit(gpa);
        try block.set32(gpa, xex.checksum(), 0);
        try block.set32(gpa, xex.filetime(), 4);
        try convertImageEntryDataToBe(&block, gpa, defines.image_key_image_checksum);
        try sink.addData(defines.image_key_image_checksum, &block);
    }

    if (xex.call_cap) |call_cap| {
        var block = makeBlock();
        defer block.deinit(gpa);
        try block.set32(gpa, call_cap[0], 0);
        try block.set32(gpa, call_cap[1], 4);
        try convertImageEntryDataToBe(&block, gpa, defines.image_key_image_callcap);
        try sink.addData(defines.image_key_image_callcap, &block);
    }

    if (xex.fast_cap) |fast_cap| {
        try sink.record(defines.image_key_image_fastcap, fast_cap);
    }

    if (xex.original_pe_name) |name| {
        var block = try makeStringBlock(gpa, name);
        defer block.deinit(gpa);
        try convertImageEntryDataToBe(&block, gpa, defines.image_key_original_pe_name);
        try sink.addData(defines.image_key_original_pe_name, &block);
    }

    if (xex.static_libraries.items.len != 0) {
        var block = makeBlock();
        defer block.deinit(gpa);
        for (xex.static_libraries.items, 0..) |library, index| {
            const offset = 4 + @as(i32, @intCast(index)) * static_library_entry_size;
            try block.set(gpa, &library.name, offset, 8);
            try block.set16(gpa, library.version.major, offset + 8);
            try block.set16(gpa, library.version.minor, offset + 10);
            try block.set16(gpa, library.version.build, offset + 12);
            try block.set16(gpa, library.version.word, offset + 14);
        }
        try block.set32(gpa, @bitCast(block.size()), 0);
        try convertImageEntryDataToBe(&block, gpa, defines.image_key_library_versions);
        try sink.addData(defines.image_key_library_versions, &block);
    }

    if (xex.tls_info) |tls| {
        var block = makeBlock();
        defer block.deinit(gpa);
        try block.set32(gpa, @bitCast(tls.num_slots), 0);
        try block.set32(gpa, tls.raw_address, 4);
        try block.set32(gpa, tls.raw_size, 8);
        try block.set32(gpa, tls.data_size, 12);
        try convertImageEntryDataToBe(&block, gpa, defines.image_key_tls_values);
        try sink.addData(defines.image_key_tls_values, &block);
    }

    if (xex.stack_size) |size| {
        try sink.record(defines.image_key_stack_size, @bitCast(size));
    }
    if (xex.filesystem_cache_size) |size| {
        try sink.record(defines.image_key_filesystem_cache_size, @bitCast(size));
    }
    if (xex.heap_size) |size| {
        try sink.record(defines.image_key_heap_size, @bitCast(size));
    }

    if (xex.page_heap) |heap| {
        var block = makeBlock();
        defer block.deinit(gpa);
        try block.set32(gpa, heap.size, 0);
        try block.set32(gpa, heap.flags, 4);
        try convertImageEntryDataToBe(&block, gpa, defines.image_key_page_heap);
        try sink.addData(defines.image_key_page_heap, &block);
    }

    if (xex.system_flags != 0) {
        try sink.record(defines.image_key_system_flags, rebuildSystemFlags(xex.system_flags));
    }
    if (xex.system_flags2 != 0) {
        try sink.record(defines.image_key_system_flags2, rebuildSystemFlags2(xex.system_flags2));
    }

    if (xex.execution_id) |execution_id| {
        var block = makeBlock();
        defer block.deinit(gpa);
        try block.set32(gpa, execution_id.media_id, 0);
        try block.set32(gpa, execution_id.version, 4);
        try block.set32(gpa, execution_id.base_version, 8);
        try block.set32(gpa, execution_id.title_id, 12);
        try block.set8(gpa, execution_id.platform, 16);
        try block.set8(gpa, execution_id.exec_type, 17);
        try block.set8(gpa, execution_id.num_disc, 18);
        try block.set8(gpa, execution_id.max_discs, 19);
        try block.set32(gpa, execution_id.save_game_id, 20);
        try convertImageEntryDataToBe(&block, gpa, defines.image_key_execution_id);
        try sink.addData(defines.image_key_execution_id, &block);
    }

    if (xex.workspace_size) |size| {
        try sink.record(defines.image_key_title_workspace_size, @bitCast(size));
    }

    if (xex.game_ratings) |ratings| {
        var block = makeBlock();
        defer block.deinit(gpa);
        try block.set(gpa, &ratings.data, 0, game_ratings_size);
        try convertImageEntryDataToBe(&block, gpa, defines.image_key_game_ratings);
        try sink.addData(defines.image_key_game_ratings, &block);
    }

    if (xex.lan_key) |lan_key| {
        var block = makeBlock();
        defer block.deinit(gpa);
        try block.set(gpa, &lan_key, 0, lan_key_size);
        try convertImageEntryDataToBe(&block, gpa, defines.image_key_lan_key);
        try sink.addData(defines.image_key_lan_key, &block);
    }

    if (xex.logo_data) |logo| {
        var block = makeBlock();
        defer block.deinit(gpa);
        try block.set32(gpa, @bitCast(logo.size() + 8), 0);
        try block.set32(gpa, @bitCast(logo.size()), 4);
        try block.set(gpa, logo.data(), 8, logo.size());
        try convertImageEntryDataToBe(&block, gpa, defines.image_key_logo_data);
        try sink.addData(defines.image_key_logo_data, &block);
    }

    if (xex.multidisc_media_ids.items.len != 0) {
        var block = makeBlock();
        defer block.deinit(gpa);
        for (xex.multidisc_media_ids.items, 0..) |media_id, index| {
            const offset = 4 + @as(i32, @intCast(index)) * 16;
            try block.set(gpa, &media_id.data, offset, 16);
        }
        try block.set32(gpa, @bitCast(block.size()), 0);
        try convertImageEntryDataToBe(&block, gpa, defines.image_key_multidisc_media_ids);
        try sink.addData(defines.image_key_multidisc_media_ids, &block);
    }

    if (xex.alt_title_ids.items.len != 0) {
        var block = makeBlock();
        defer block.deinit(gpa);
        for (xex.alt_title_ids.items, 0..) |title_id, index| {
            try block.set32(gpa, title_id, 4 + @as(i32, @intCast(index)) * 4);
        }
        try block.set32(gpa, @bitCast(block.size()), 0);
        try convertImageEntryDataToBe(&block, gpa, defines.image_key_alt_title_ids);
        try sink.addData(defines.image_key_alt_title_ids, &block);
    }

    if (xex.extra_debug_memory) |size| {
        try sink.record(defines.image_key_extra_debug_memory, size);
    }

    if (xex.exports_by_name) |exports| {
        var block = makeBlock();
        defer block.deinit(gpa);
        try block.set32(gpa, exports.export_table_offset, 0);
        try block.set32(gpa, exports.export_table_size, 4);
        try convertImageEntryDataToBe(&block, gpa, defines.image_key_exports_by_name);
        try sink.addData(defines.image_key_exports_by_name, &block);
    }

    for (xex.unknown_image_entries.items) |unknown| {
        var block = try unknown.data.clone(gpa);
        defer block.deinit(gpa);
        const entry_key = unknown.header.key;
        var value = unknown.header.value;
        if (defines.isDataOffset(entry_key)) {
            value = try sink.dataValue(0);
        }
        // Unknown entry payloads are stored in on-disk form by the reader; the
        // C++ writer's converter is a no-op for unknown keys, so copy them.
        try sink.copyBlock(&block, sink.info_offset);
        try sink.record(entry_key, value);
        sink.info_offset += block.size();
    }

    return sink.index;
}

fn makeStringBlock(gpa: std.mem.Allocator, text: []const u8) Error!DataBlock {
    const length = boundedStringLength(text);
    const padded = paddedStringLength(length);
    var block = makeBlock();
    errdefer block.deinit(gpa);
    try block.set(gpa, text[0..length], 4, @intCast(length));
    if (padded > length) try block.fill(gpa, 0, @intCast(4 + length), @intCast(padded - length));
    try block.set32(gpa, @bitCast(block.size()), 0);
    return block;
}

fn toBe16(block: *DataBlock, gpa: std.mem.Allocator, offset: i32) Error!void {
    try block.set16be(gpa, block.get16(offset), offset);
}

fn toBe32(block: *DataBlock, gpa: std.mem.Allocator, offset: i32) Error!void {
    try block.set32be(gpa, block.get32(offset), offset);
}

fn toBe64(block: *DataBlock, gpa: std.mem.Allocator, offset: i32) Error!void {
    try block.set64be(gpa, block.get64(offset), offset);
}

/// XexWriter::convertImageEntryDataToBE, including the shipped quirks: the
/// restrict entries only byte-swap 32 bits of their 64-bit fields and the
/// static-library `word` field is left native.
pub fn convertImageEntryDataToBe(block: *DataBlock, gpa: std.mem.Allocator, key: u32) Error!void {
    const info_size: i32 = @bitCast(block.get32(0));
    if ((key & 0xFF) == 0xFF) try toBe32(block, gpa, 0);

    switch (key) {
        defines.image_key_resource_section => {
            const count = @divTrunc(info_size - 4, resource_entry_size);
            var index: i32 = 0;
            while (index < count) : (index += 1) {
                const offset = 4 + index * resource_entry_size;
                try toBe32(block, gpa, offset + 8);
                try toBe32(block, gpa, offset + 12);
            }
        },
        defines.image_key_basefile_format => {
            const compression = block.get16(6);
            try toBe16(block, gpa, 4);
            try toBe16(block, gpa, 6);
            if (compression == 1) {
                const count = @divTrunc(info_size - 8, 8);
                var index: i32 = 0;
                while (index < count) : (index += 1) {
                    const offset = 8 + index * 8;
                    try toBe32(block, gpa, offset);
                    try toBe32(block, gpa, offset + 4);
                }
            } else if (compression == 2 or compression == 3) {
                try toBe32(block, gpa, 8);
                try toBe32(block, gpa, 12);
            }
        },
        defines.image_key_base_reference => {},
        defines.image_key_delta_patch_descriptor => {
            try toBe32(block, gpa, 4);
            try toBe32(block, gpa, 8);
            try toBe32(block, gpa, 0x30);
            try toBe32(block, gpa, 0x34);
            try toBe32(block, gpa, 0x38);
            try toBe32(block, gpa, 0x3C);
            try toBe32(block, gpa, 0x40);
            try toBe32(block, gpa, 0x44);
            try toBe32(block, gpa, 0x48);
        },
        defines.image_key_restrict_kv_privs => {
            // C++ uses DATABLOCK_TO_BE_32 on the u64 fields.
            try toBe32(block, gpa, 0);
            try toBe32(block, gpa, 8);
        },
        defines.image_key_restrict_dates => {
            try toBe32(block, gpa, 0);
            try toBe32(block, gpa, 8);
        },
        defines.image_key_restrict_console_ids => {},
        defines.image_key_disc_profile_id => {},
        defines.image_key_bound_pathname => {},
        defines.image_key_bound_device_id => {},
        defines.image_key_import_libraries => {
            var offset = 12 + @as(i32, @bitCast(block.get32(4)));
            offset = (offset + 3) & -4;
            try toBe32(block, gpa, 4);
            try toBe32(block, gpa, 8);
            while (offset < info_size) {
                const address_count: i32 = block.get16(offset + 0x26);
                const library_size: i32 = @bitCast(block.get32(offset));
                if (library_size <= 0) return error.InvalidImportTable;
                try toBe32(block, gpa, offset);
                try toBe32(block, gpa, offset + 0x18);
                try toBe32(block, gpa, offset + 0x1C);
                try toBe32(block, gpa, offset + 0x20);
                try toBe16(block, gpa, offset + 0x26);
                var address_index: i32 = 0;
                while (address_index < address_count) : (address_index += 1) {
                    try toBe32(block, gpa, offset + 0x28 + address_index * 4);
                }
                offset += library_size;
            }
        },
        defines.image_key_image_checksum => {
            try toBe32(block, gpa, 0);
            try toBe32(block, gpa, 4);
        },
        defines.image_key_image_callcap => {
            try toBe32(block, gpa, 0);
            try toBe32(block, gpa, 4);
        },
        defines.image_key_image_fastcap => {},
        defines.image_key_original_pe_name => {},
        defines.image_key_library_versions => {
            const count = @divTrunc(info_size - 4, static_library_entry_size);
            var index: i32 = 0;
            while (index < count) : (index += 1) {
                const offset = 4 + index * static_library_entry_size + 8;
                try toBe16(block, gpa, offset);
                try toBe16(block, gpa, offset + 2);
                try toBe16(block, gpa, offset + 4);
                try toBe16(block, gpa, offset + 6);
            }
        },
        defines.image_key_tls_values => {
            try toBe32(block, gpa, 0);
            try toBe32(block, gpa, 12);
            try toBe32(block, gpa, 4);
            try toBe32(block, gpa, 8);
        },
        defines.image_key_page_heap => {
            try toBe32(block, gpa, 0);
            try toBe32(block, gpa, 4);
        },
        defines.image_key_execution_id => {
            try toBe32(block, gpa, 0);
            try toBe32(block, gpa, 4);
            try toBe32(block, gpa, 8);
            try toBe32(block, gpa, 12);
            try toBe32(block, gpa, 20);
        },
        defines.image_key_game_ratings => {},
        defines.image_key_lan_key => {},
        defines.image_key_logo_data => {
            try toBe32(block, gpa, 4);
        },
        defines.image_key_multidisc_media_ids => {},
        defines.image_key_alt_title_ids => {
            var offset: i32 = 0;
            while (offset < info_size - 4) : (offset += 4) {
                try toBe32(block, gpa, 4 + offset);
            }
        },
        defines.image_key_exports_by_name => {
            try toBe32(block, gpa, 0);
            try toBe32(block, gpa, 4);
        },
        else => {},
    }
}

/// XexHeader::updateImportHash: chains the import-library hashes from the last
/// entry to the first and stores the result in the security info.
pub fn updateImportHash(gpa: std.mem.Allocator, headers: []u8) Error!void {
    if (headers.len < 0x18) return error.OutOfBounds;
    const sec_offset = endian.get32be(headers, header_security_offset);
    const entry_count = endian.get32be(headers, header_entry_count);
    var import_offset: ?u32 = null;
    var index: u32 = 0;
    while (index < entry_count) : (index += 1) {
        const offset: usize = 0x18 + @as(usize, index) * 8;
        if (offset + 8 > headers.len) return error.OutOfBounds;
        if (endian.get32be(headers, offset) == defines.image_key_import_libraries) {
            import_offset = endian.get32be(headers, offset + 4);
            break;
        }
    }
    const value = import_offset orelse return;
    const start: usize = value;
    if (start >= headers.len) return error.OutOfBounds;
    if (sec_offset > headers.len or headers.len - sec_offset < sec_import_hash + 20) return error.OutOfBounds;

    const import_data = headers[start..];
    const info_size: u32 = endian.get32be(import_data, 0);
    if (info_size > import_data.len) return error.OutOfBounds;

    var offsets: std.ArrayList(i32) = .empty;
    defer offsets.deinit(gpa);
    var offset: i32 = import_directory_size + @as(i32, @bitCast(endian.get32be(import_data, 4)));
    while (offset < @as(i32, @bitCast(info_size))) {
        if (offset < 0 or @as(usize, @intCast(offset)) + 4 > import_data.len) return error.OutOfBounds;
        try offsets.append(gpa, offset);
        const step: u32 = endian.get32be(import_data, @intCast(offset));
        if (step == 0) return error.InvalidImportTable;
        if (step > std.math.maxInt(i32)) return error.InvalidImportTable;
        offset += @as(i32, @bitCast(step));
    }

    var hash: [20]u8 = @splat(0);
    var lib_index = offsets.items.len;
    while (lib_index > 0) {
        lib_index -= 1;
        const library_offset: usize = @intCast(offsets.items[lib_index]);
        if (library_offset + 0x28 > import_data.len) return error.OutOfBounds;
        const address_count = endian.get16be(import_data, library_offset + 0x26);
        const hash_start: usize = library_offset + 4;
        const hash_size: usize = @as(usize, @intCast(import_hash_size)) + @as(usize, address_count) * 4;
        if (hash_start + hash_size > import_data.len) return error.OutOfBounds;
        @memcpy(import_data[hash_start..][0..20], &hash);
        crypto.XeCryptSha(import_data[hash_start..][0..hash_size], "", "", &hash, 20);
    }

    const sec_start: usize = sec_offset;
    @memcpy(headers[sec_start + sec_import_hash ..][0..20], &hash);
}

/// XexHeader::updateSectionHashes: hashes sections from last to first, feeding
/// each result into the next section and the security-info image hash.
pub fn updateSectionHashes(
    xex: *const model.Xex,
    headers: []u8,
    sections_offset: i32,
    sec_info_offset: i32,
) Error!void {
    var hash: [20]u8 = @splat(0);
    var image_size_left = xex.imageSize();
    if (image_size_left <= 0) return;

    const image = if (xex.isPatchModule()) xex.patch_data.data() else xex.basefile.data();
    const sec_start: usize = @intCast(sec_info_offset);
    if (sec_start > headers.len or headers.len - sec_start < sec_image_hash + 20) return error.OutOfBounds;

    var index = xex.sections.items.len;
    while (index > 0) {
        index -= 1;
        const section = xex.sections.items[index];
        if (section.size < 0) return error.InvalidSectionLayout;
        const section_offset: usize = @intCast(sections_offset + @as(i64, @intCast(index)) * section_info_size);
        if (section_offset + @as(usize, @intCast(section_info_size)) > headers.len) return error.OutOfBounds;

        @memcpy(headers[section_offset + 4 ..][0..20], &hash);

        image_size_left -= section.size;
        if (image_size_left < 0) return error.InvalidSectionLayout;
        const hash_offset: usize = @intCast(image_size_left);
        const hash_size: usize = @intCast(section.size);

        var state: crypto.ShaState = undefined;
        crypto.XeCryptShaInit(&state);
        shaUpdateZeroPadded(&state, image, hash_offset, hash_size);
        crypto.XeCryptShaUpdate(&state, headers[section_offset..][0..@intCast(section_info_size)]);
        crypto.XeCryptShaFinal(&state, &hash, 20);
    }

    @memcpy(headers[sec_start + sec_image_hash ..][0..20], &hash);
}

/// Port of DataBlock::get into SHA input: bytes past the source are zeros.
fn shaUpdateZeroPadded(state: *crypto.ShaState, source: []const u8, offset: usize, length: usize) void {
    const start = @min(offset, source.len);
    const available = @min(length, source.len - start);
    crypto.XeCryptShaUpdate(state, source[start..][0..available]);
    var remaining = length - available;
    const zeros: [512]u8 = @splat(0);
    while (remaining > 0) {
        const count = @min(remaining, zeros.len);
        crypto.XeCryptShaUpdate(state, zeros[0..count]);
        remaining -= count;
    }
}

/// XexHeader::updateHeaderHash: security info tail plus the header prefix.
pub fn updateHeaderHash(headers: []u8, headers_size: i32, security_info_offset: i32) Error!void {
    if (headers_size < 0 or security_info_offset < 0) return error.InvalidRange;
    const total: usize = @intCast(headers_size);
    const sec_start: usize = @intCast(security_info_offset);
    if (total > headers.len) return error.OutOfBounds;
    if (sec_start > total or total - sec_start < sec_allowed_media_types) return error.OutOfBounds;
    const tail_start = sec_start + sec_allowed_media_types;
    const tail_length = total - tail_start;
    const prefix_length: usize = @as(usize, @intCast(security_info_offset)) + 8;
    if (prefix_length > total) return error.OutOfBounds;

    var hash: [20]u8 = undefined;
    crypto.XeCryptSha(
        headers[tail_start..][0..tail_length],
        headers[0..prefix_length],
        "",
        &hash,
        20,
    );
    @memcpy(headers[sec_start + sec_header_hash ..][0..20], &hash);
}

/// XexHeader::updateSign: RotSumSha over the signed info block, RSA with the
/// supplied key, then store the raw 256-byte signature.
pub fn updateSign(
    xex: *const model.Xex,
    sec: []u8,
    public_key: []const u8,
    private_key: []const u8,
) Error!void {
    if (sec.len < security_info_size or private_key.len < 0x390 + 0x100) return error.OutOfBounds;
    const info_size: i32 = @bitCast(endian.get32be(sec, sec_info_size));
    const hash_size = info_size - sec_signature_size;
    if (hash_size < 0) return error.InvalidImageEntryData;
    const hash_start: usize = @intCast(sec_info_size);
    const hash_length: usize = @intCast(hash_size);
    if (hash_start + hash_length > sec.len) return error.OutOfBounds;

    var hash: [20]u8 = undefined;
    crypto.XeCryptRotSumSha(sec[hash_start..][0..hash_length], "", &hash, 20);

    const salt = if (xex.hasRequiredRevocationCheck()) keys.xex_salt_rev[0..] else keys.xex_salt_xex[0..];
    var signature: crypto.Signature = undefined;
    @memcpy(&signature, sec[sec_signature..][0..sec_signature_size]);
    if (!crypto.XeCryptBnQwBeSigCreate(&signature, &hash, salt, public_key)) {
        return error.SignatureFailed;
    }
    if (!crypto.XeCryptBnQwNeModExp(
        &signature,
        &signature,
        private_key[0x390..],
        private_key[0x10..],
        0x20,
    )) return error.SignatureFailed;
    @memcpy(sec[sec_signature..][0..sec_signature_size], &signature);
}

/// XexHeader::updateDebugSign.
pub fn updateDebugSign(xex: *const model.Xex, sec: []u8) Error!void {
    return updateSign(xex, sec, &keys.xex_debug_public_key, &keys.xex_debug_private_key);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const reader = @import("reader.zig");

fn baseFormat(gpa: std.mem.Allocator) !DataBlock {
    var format = DataBlock.init();
    errdefer format.deinit(gpa);
    try format.set32(gpa, 0x10, 0);
    try format.set16(gpa, 0, 4);
    try format.set16(gpa, 1, 6);
    try format.set32(gpa, 0, 8);
    try format.set32(gpa, 0, 12);
    return format;
}

fn minimalPeBasefile(gpa: std.mem.Allocator) !DataBlock {
    var bytes: [0x10000]u8 = @splat(0);
    bytes[0] = 'M';
    bytes[1] = 'Z';
    endian.set32le(&bytes, 0x3C, 0x80);
    bytes[0x80] = 'P';
    bytes[0x81] = 'E';
    endian.set16le(&bytes, 0x86, 1);
    endian.set32le(&bytes, 0x88, 0x11223344);
    endian.set16le(&bytes, 0x94, 0xE0);
    endian.set32le(&bytes, 0x98 + 0x10, 0x82010000);
    endian.set32le(&bytes, 0x98 + 0x1C, 0x82000000);
    endian.set32le(&bytes, 0x98 + 0x40, 0xDEADBEEF);

    var block = DataBlock.init();
    errdefer block.deinit(gpa);
    try block.set(gpa, &bytes, 0, bytes.len);
    return block;
}

fn initImportLibrary(gpa: std.mem.Allocator, name: []const u8, module_index: u8, addresses: []const u32) !types.ImportLibraryData {
    var library: types.ImportLibraryData = .{
        .module_index = module_index,
        .module_number = module_index + 1,
        .version = 0x12345678,
        .min_version = 0x11111111,
    };
    @memcpy(library.name[0..@min(name.len, library.name.len)], name[0..@min(name.len, library.name.len)]);
    library.addresses = try gpa.dupe(u32, addresses);
    return library;
}

test "writeHeaders: minimal raw XEX is parseable" {
    const gpa = std.testing.allocator;
    var xex = model.Xex.init(gpa);
    defer xex.deinit();
    xex.is_raw = true;
    xex.module_flags = defines.module_flag_title_module | 0x100;

    var format = try baseFormat(gpa);
    defer format.deinit(gpa);

    var headers = DataBlock.init();
    defer headers.deinit(gpa);
    try writeHeaders(&xex, &headers, format);

    const bytes = headers.data();
    try std.testing.expectEqual(@as(i32, 0x1000), headers.size());
    try std.testing.expectEqualSlices(u8, &defines.xex_magic, bytes[0..4]);
    try std.testing.expectEqual(@as(u32, 0x101), endian.get32be(bytes, header_module_flags));
    try std.testing.expectEqual(@as(u32, 0x1000), endian.get32be(bytes, header_size_of_headers));
    try std.testing.expectEqual(@as(u32, 0), endian.get32be(bytes, header_discardable));
    try std.testing.expectEqual(@as(u32, 0xA0), endian.get32be(bytes, header_security_offset));
    try std.testing.expectEqual(@as(u32, 1), endian.get32be(bytes, header_entry_count));

    // The only entry is the basefile format, and its payload starts right
    // after the security info (0xA0 + 0x184 = 0x224).
    try std.testing.expectEqual(@as(u32, defines.image_key_basefile_format), endian.get32be(bytes, 0x18));
    try std.testing.expectEqual(@as(u32, 0x224), endian.get32be(bytes, 0x1C));
    try std.testing.expectEqual(@as(u32, 0x10), endian.get32be(bytes, 0x224));
    try std.testing.expectEqual(@as(u16, 0), endian.get16be(bytes, 0x228));
    try std.testing.expectEqual(@as(u16, 1), endian.get16be(bytes, 0x22A));
    try std.testing.expectEqual(@as(u32, 0), endian.get32be(bytes, 0x22C));
    try std.testing.expectEqual(@as(u32, 0), endian.get32be(bytes, 0x230));

    const sec = bytes[0xA0..][0..@intCast(security_info_size)];
    try std.testing.expectEqual(@as(u32, 0x184), endian.get32be(sec, sec_size));
    try std.testing.expectEqual(@as(u32, 0), endian.get32be(sec, sec_image_size));
    try std.testing.expectEqual(@as(u32, 0x174), endian.get32be(sec, sec_info_size));
    try std.testing.expectEqual(@as(u32, 0), endian.get32be(sec, sec_image_flags));
    try std.testing.expectEqual(@as(u32, 0), endian.get32be(sec, sec_import_table_count));
    try std.testing.expectEqual(@as(u32, 0), endian.get32be(sec, sec_section_count));
    // Retail images have no private key: the signature stays zeroed.
    var zero: [0x100]u8 = @splat(0);
    try std.testing.expectEqualSlices(u8, &zero, sec[sec_signature..][0..sec_signature_size]);

    // Header hash covers the tail of the security info and the header prefix.
    var expected: [20]u8 = undefined;
    crypto.XeCryptSha(
        bytes[0xA0 + @as(usize, @intCast(sec_allowed_media_types)) ..],
        bytes[0 .. 0xA0 + 8],
        "",
        &expected,
        20,
    );
    try std.testing.expectEqualSlices(u8, &expected, sec[sec_header_hash..][0..20]);

    var parsed = model.Xex.init(gpa);
    defer parsed.deinit();
    try std.testing.expect(try reader.readBytes(&parsed, bytes));
    try std.testing.expect(parsed.is_raw);
    try std.testing.expect(!parsed.is_debug);
    try std.testing.expectEqual(@as(u32, 0x101), parsed.module_flags);
    try std.testing.expectEqual(@as(usize, 0), parsed.basefile.data().len);
}

test "writeHeaders: debug signature matches the reference signing path" {
    const gpa = std.testing.allocator;
    var xex = model.Xex.init(gpa);
    defer xex.deinit();
    xex.is_raw = true;
    xex.is_debug = true;
    // Required revocation selects the revocation salt.
    xex.image_flags = defines.image_flag_revocation_check_req;

    var format = try baseFormat(gpa);
    defer format.deinit(gpa);

    var headers = DataBlock.init();
    defer headers.deinit(gpa);
    try writeHeaders(&xex, &headers, format);

    const bytes = headers.data();
    const sec_offset: usize = endian.get32be(bytes, header_security_offset);
    const sec = bytes[sec_offset..][0..@intCast(security_info_size)];
    const signature = sec[sec_signature..][0..sec_signature_size];

    var nonzero = false;
    for (signature) |byte| {
        if (byte != 0) nonzero = true;
    }
    try std.testing.expect(nonzero);

    const info_size = endian.get32be(sec, sec_info_size);
    try std.testing.expectEqual(@as(u32, 0x174), info_size);
    var hash: [20]u8 = undefined;
    crypto.XeCryptRotSumSha(sec[sec_info_size..][0 .. info_size - sec_signature_size], "", &hash, 20);
    // Reference signing path: SigCreate with the chosen salt, then the private
    // modular exponentiation. This matches XexHeader::updateSign byte for byte.
    // (crypto.XeCryptBnQwBeSigVerify is not used: it implements plain RSA
    // verification, while XexTool verifies in the Montgomery domain.)
    var expected: crypto.Signature = undefined;
    @memset(&expected, 0);
    try std.testing.expect(crypto.XeCryptBnQwBeSigCreate(
        &expected,
        &hash,
        &keys.xex_salt_rev,
        &keys.xex_debug_public_key,
    ));
    try std.testing.expect(crypto.XeCryptBnQwNeModExp(
        &expected,
        &expected,
        keys.xex_debug_private_key[0x390..],
        keys.xex_debug_private_key[0x10..],
        0x20,
    ));
    try std.testing.expectEqualSlices(u8, signature, &expected);

    var parsed = model.Xex.init(gpa);
    defer parsed.deinit();
    try std.testing.expect(try reader.readBytes(&parsed, bytes));
    try std.testing.expect(parsed.is_debug);
}

test "writeHeaders: entry order, import tail placement and section hashes" {
    const gpa = std.testing.allocator;
    var xex = model.Xex.init(gpa);
    defer xex.deinit();
    xex.is_raw = true;
    xex.is_debug = true;
    xex.module_flags = defines.module_flag_title_module;
    xex.image_flags = defines.image_flag_title_usermode;
    xex.regions = defines.region_north_america;
    xex.media_types = defines.media_hard_disk;
    xex.load_address = 0x82000000;
    xex.export_table_address = 0x82001000;
    xex.discardable_header_size = 0;
    xex.system_flags = defines.sys_flag_no_force_reboot | defines.sys_flag_pii;

    xex.basefile = try minimalPeBasefile(gpa);
    try xex.sections.append(gpa, .{ .size = 0x10000, .info = defines.section_info_code });

    try xex.resources.append(gpa, .{ .name = [_]u8{ 'R', 'E', 'S', 'X', 0, 0, 0, 0 }, .addr = 0x82002000, .size = 0x30 });
    try xex.import_libraries.append(gpa, try initImportLibrary(gpa, "xboxkrnl.exe", 0, &.{ 0x8200A000, 0x8200A004 }));
    try xex.import_libraries.append(gpa, try initImportLibrary(gpa, "xam.xex", 1, &.{0x8200B000}));
    try xex.static_libraries.append(gpa, .{
        .name = .{ 'l', 'i', 'b', 'v', 'e', 'r', 0, 0 },
        .version = .{ .major = 1, .minor = 2, .build = 3, .word = 0x8004 },
    });
    try xex.multidisc_media_ids.append(gpa, .{ .data = @as([16]u8, @splat(0xAA)) });
    try xex.alt_title_ids.append(gpa, 0x52584401);
    try xex.restrict_console_ids.append(gpa, .{ .id = [_]u8{ 1, 2, 3, 4, 5 } });

    xex.has_original_load_address = true;
    xex.base_reference = @as([20]u8, @splat(0x11));
    xex.bounding_path = try gpa.dupe(u8, "\\Device\\Harddisk0\\Partition1");
    xex.original_pe_name = try gpa.dupe(u8, "default.xex");
    xex.disc_profile_id = @as([16]u8, @splat(0x22));
    xex.bounding_device_id = @as([20]u8, @splat(0x33));
    xex.call_cap = .{ 0x82003000, 0x82003004 };
    xex.fast_cap = 0x82004000;
    xex.stack_size = 0x40000;
    xex.filesystem_cache_size = 0x800;
    xex.heap_size = 0x100000;
    xex.workspace_size = 0x200000;
    xex.extra_debug_memory = 0x40;
    xex.page_heap = .{ .size = 0x10000, .flags = 0x2 };
    xex.tls_info = .{ .num_slots = 4, .raw_address = 0x82005000, .raw_size = 0x40, .data_size = 0x10 };
    xex.execution_id = .{
        .media_id = 0x12345678,
        .version = 0x00010002,
        .base_version = 0x00010001,
        .title_id = 0x52584401,
        .platform = 2,
        .exec_type = 1,
        .num_disc = 1,
        .max_discs = 1,
        .save_game_id = 0xAABBCCDD,
    };
    xex.game_ratings = .{ .data = @as([64]u8, @splat(0x44)) };
    xex.lan_key = @as([16]u8, @splat(0x55));
    xex.exports_by_name = .{ .export_table_offset = 0x1000, .export_table_size = 0x20 };
    var logo = DataBlock.init();
    try logo.set(gpa, &[_]u8{ 0x10, 0x20, 0x30, 0x40 }, 0, 4);
    xex.logo_data = logo;
    var delta = DataBlock.init();
    try delta.fill(gpa, 0, 0, 0x4C);
    try delta.set32be(gpa, 0x4C, 0);
    try delta.set32be(gpa, 0x11223344, 4);
    xex.delta_patch_descriptor = delta;
    // Unknown entries keep their on-disk payload bytes.
    var unknown_data = DataBlock.init();
    try unknown_data.set32be(gpa, 0x0C, 0);
    try unknown_data.set(gpa, &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04 }, 4, 8);
    try xex.unknown_image_entries.append(gpa, .{
        .header = .{ .key = 0x000090FF, .value = 0xFFFF },
        .data = unknown_data,
    });

    var format = try baseFormat(gpa);
    defer format.deinit(gpa);

    var headers = DataBlock.init();
    defer headers.deinit(gpa);
    try writeHeaders(&xex, &headers, format);

    const bytes = headers.data();
    const expected_keys = [_]u32{
        defines.image_key_resource_section,
        defines.image_key_basefile_format,
        defines.image_key_base_reference,
        defines.image_key_delta_patch_descriptor,
        defines.image_key_restrict_console_ids,
        defines.image_key_disc_profile_id,
        defines.image_key_bound_pathname,
        defines.image_key_bound_device_id,
        defines.image_key_original_base_address,
        defines.image_key_entry_point,
        defines.image_key_image_base_address,
        defines.image_key_import_libraries,
        defines.image_key_image_checksum,
        defines.image_key_image_callcap,
        defines.image_key_image_fastcap,
        defines.image_key_original_pe_name,
        defines.image_key_library_versions,
        defines.image_key_tls_values,
        defines.image_key_stack_size,
        defines.image_key_filesystem_cache_size,
        defines.image_key_heap_size,
        defines.image_key_page_heap,
        defines.image_key_system_flags,
        defines.image_key_execution_id,
        defines.image_key_title_workspace_size,
        defines.image_key_game_ratings,
        defines.image_key_lan_key,
        defines.image_key_logo_data,
        defines.image_key_multidisc_media_ids,
        defines.image_key_alt_title_ids,
        defines.image_key_extra_debug_memory,
        defines.image_key_exports_by_name,
        0x000090FF,
    };
    const entry_count: usize = endian.get32be(bytes, header_entry_count);
    try std.testing.expectEqual(expected_keys.len, entry_count);
    for (expected_keys, 0..) |key, index| {
        try std.testing.expectEqual(key, endian.get32be(bytes, 0x18 + index * 8));
    }

    const sec_offset: usize = endian.get32be(bytes, header_security_offset);
    const sec = bytes[sec_offset..][0..@intCast(security_info_size)];
    try std.testing.expectEqual(@as(u32, 0x184 + 0x18), endian.get32be(sec, sec_size));
    try std.testing.expectEqual(@as(u32, 0x10000), endian.get32be(sec, sec_image_size));
    try std.testing.expectEqual(@as(u32, 2), endian.get32be(sec, sec_import_table_count));
    try std.testing.expectEqual(@as(u32, 1), endian.get32be(sec, sec_section_count));
    try std.testing.expectEqual(@as(u32, 0x82000000), endian.get32be(sec, sec_load_address));

    // The section hash recorded in the security info is the hash of the first
    // section, which is the last one computed.
    const section_offset = sec_offset + @as(usize, @intCast(security_info_size));
    const section_dword = endian.get32be(bytes, section_offset);
    try std.testing.expectEqual(@as(u32, 1), section_dword >> 4);
    try std.testing.expectEqual(@as(u32, defines.section_info_code), section_dword & 0xF);

    var section_bytes: [0x18]u8 = undefined;
    @memcpy(&section_bytes, bytes[section_offset..][0..0x18]);
    @memset(section_bytes[4..24], 0);
    var section_hash: [20]u8 = undefined;
    crypto.XeCryptSha(xex.basefile.data(), &section_bytes, "", &section_hash, 20);
    try std.testing.expectEqualSlices(u8, &section_hash, sec[sec_image_hash..][0..20]);
    // The last section is hashed first, so its own hash slot holds the initial
    // zero hash; only the security info receives the final digest.
    var zero_hash: [20]u8 = @splat(0);
    try std.testing.expectEqualSlices(u8, &zero_hash, bytes[section_offset + 4 ..][0..20]);

    // The import block is the last payload in the entry-data area.
    const import_index = 11;
    const import_value = endian.get32be(bytes, 0x18 + import_index * 8 + 4);
    const import_block = bytes[import_value..];
    const import_size = endian.get32be(import_block, 0);
    const header_size = endian.get32be(bytes, header_size_of_headers);
    try std.testing.expectEqual(header_size, import_value + import_size);

    // Import hashes chain from the last library to the first; the final digest
    // lands in the security info.
    const names_size = endian.get32be(import_block, 4);
    const first_library = import_value + 12 + names_size;
    const second_library = first_library + endian.get32be(bytes, first_library);
    try std.testing.expectEqual(@as(u16, 1), endian.get16be(bytes, second_library + 0x26));
    try std.testing.expectEqual(@as(u16, 2), endian.get16be(bytes, first_library + 0x26));
    try std.testing.expectEqualSlices(u8, &zero_hash, bytes[second_library + 4 ..][0..20]);
    var chain: [20]u8 = undefined;
    crypto.XeCryptSha(bytes[second_library + 4 ..][0..0x28], "", "", &chain, 20);
    try std.testing.expectEqualSlices(u8, &chain, bytes[first_library + 4 ..][0..20]);
    crypto.XeCryptSha(bytes[first_library + 4 ..][0..0x2C], "", "", &chain, 20);
    try std.testing.expectEqualSlices(u8, &chain, sec[sec_import_hash..][0..20]);

    // Round-trip through the reader.
    var parsed = model.Xex.init(gpa);
    defer parsed.deinit();
    try std.testing.expect(try reader.readBytes(&parsed, bytes));
    try std.testing.expect(parsed.is_debug);
    try std.testing.expectEqual(@as(usize, 1), parsed.resources.items.len);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 'R', 'E', 'S', 'X', 0, 0, 0, 0 }, &parsed.resources.items[0].name);
    try std.testing.expectEqual(@as(usize, 2), parsed.import_libraries.items.len);
    try std.testing.expectEqualSlices(u8, "xboxkrnl.exe", std.mem.sliceTo(&parsed.import_libraries.items[0].name, 0));
    try std.testing.expectEqualSlices(u32, &.{ 0x8200A000, 0x8200A004 }, parsed.import_libraries.items[0].addresses);
    try std.testing.expectEqualSlices(u8, "xam.xex", std.mem.sliceTo(&parsed.import_libraries.items[1].name, 0));
    try std.testing.expectEqual(@as(usize, 1), parsed.static_libraries.items.len);
    try std.testing.expectEqual(@as(u16, 0x8004), parsed.static_libraries.items[0].version.word);
    try std.testing.expectEqual(@as(u32, 0x52584401), parsed.execution_id.?.title_id);
    try std.testing.expectEqual(@as(u32, 0x82005000), parsed.tls_info.?.raw_address);
    try std.testing.expectEqual(@as(u32, 0xAABBCCDD), parsed.execution_id.?.save_game_id);
    try std.testing.expectEqual(@as(usize, 1), parsed.alt_title_ids.items.len);
    try std.testing.expectEqual(@as(u32, 0x52584401), parsed.alt_title_ids.items[0]);
    try std.testing.expectEqual(@as(usize, 1), parsed.restrict_console_ids.items.len);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4, 5 }, &parsed.restrict_console_ids.items[0].id);
    const delta_source = xex.delta_patch_descriptor.?.data();
    const delta_parsed = parsed.delta_patch_descriptor.?.data();
    try std.testing.expectEqualSlices(u8, delta_source, delta_parsed[0..delta_source.len]);
    try std.testing.expectEqual(@as(usize, 1), parsed.unknown_image_entries.items.len);
    try std.testing.expectEqual(@as(u32, 0x000090FF), parsed.unknown_image_entries.items[0].header.key);
    try std.testing.expectEqualSlices(
        u8,
        xex.unknown_image_entries.items[0].data.data(),
        parsed.unknown_image_entries.items[0].data.data(),
    );
}

test "writeHeaders: patched XEX has no security gap and uses 0x800 alignment" {
    const gpa = std.testing.allocator;
    var xex = model.Xex.init(gpa);
    defer xex.deinit();
    xex.is_raw = true;
    xex.module_flags = defines.module_flag_patch_module;

    var format = try baseFormat(gpa);
    defer format.deinit(gpa);

    var headers = DataBlock.init();
    defer headers.deinit(gpa);
    try writeHeaders(&xex, &headers, format);

    const bytes = headers.data();
    // 0x18 + 1 entry, no gap, security info at 0x20.
    try std.testing.expectEqual(@as(u32, 0x20), endian.get32be(bytes, header_security_offset));
    try std.testing.expectEqual(@as(u32, 0x800), endian.get32be(bytes, header_size_of_headers));
    try std.testing.expectEqual(@as(i32, 0x800), headers.size());
}

test "write file round-trips a fixture when XEXTOOL_TEST_DIR is set" {
    const gpa = std.testing.allocator;
    const dir = std.process.Environ.getAlloc(std.testing.environ, std.testing.allocator, "XEXTOOL_TEST_DIR") catch {
        std.debug.print("skipping writer fixture test: XEXTOOL_TEST_DIR is unset\n", .{});
        return;
    };
    defer gpa.free(dir);
    const path = try std.fs.path.join(gpa, &.{ dir, "writer", "input.xex" });
    defer gpa.free(path);
    const input = std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, gpa, .limited(1 << 30)) catch |err| switch (err) {
        error.FileNotFound => {
            std.debug.print("skipping writer fixture test: {s} is missing\n", .{path});
            return;
        },
        else => return err,
    };
    defer gpa.free(input);

    var xex = model.Xex.init(gpa);
    defer xex.deinit();
    try std.testing.expect(try reader.readBytes(&xex, input));

    var output = DataBlock.init();
    defer output.deinit(gpa);
    try @import("writer.zig").write(&xex, &output);
    try std.testing.expectEqualSlices(u8, input, output.data());
}
