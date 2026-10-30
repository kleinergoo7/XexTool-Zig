// SPDX-FileCopyrightText: 2026 XexTool Zig rewrite contributors
// SPDX-License-Identifier: GPL-3.0-or-later

const std = @import("std");
const defines = @import("defines.zig");
const model = @import("model.zig");
const types = @import("types.zig");

extern "c" fn ctime(timer: *const std.c.time_t) ?[*:0]const u8;

pub fn printShort(writer: anytype, xex: *const model.Xex) !void {
    try writer.writeAll("Xex Info\n");
    try writer.print("  {s}\n", .{if (xex.is_debug) "Devkit" else "Retail"});
    if (xex.is_raw) try writer.writeAll("  Uncompressed\n");
    if (xex.is_binary) try writer.writeAll("  Binary (No Compression)\n");
    if (xex.is_compressed) try writer.writeAll("  Compressed\n");
    if (xex.is_delta_compressed) try writer.writeAll("  Delta Compressed\n");
    try writer.print("  {s}\n", .{if (xex.is_encrypted) "Encrypted" else "Not-Encrypted"});

    if (xex.hasModuleFlag(defines.module_flag_title_module)) try writer.writeAll("  Title Module\n");
    if (xex.hasModuleFlag(defines.module_flag_exports_to_title)) try writer.writeAll("  Title Exports\n");
    if (xex.hasModuleFlag(defines.module_flag_system_debugger)) try writer.writeAll("  System Debugger\n");
    if (xex.hasModuleFlag(defines.module_flag_dll_module)) try writer.writeAll("  DLL Module\n");
    if (xex.hasModuleFlag(defines.module_flag_patch_full)) try writer.writeAll("  Full Patch\n");
    if (xex.hasModuleFlag(defines.module_flag_patch_delta)) try writer.writeAll("  Delta Patch\n");
    if (xex.hasModuleFlag(defines.module_flag_user_mode)) try writer.writeAll("  User Mode\n");
    const unknown_module = xex.module_flags & defines.module_flag_unknown;
    if (unknown_module != 0) try writer.print("  Unknown Module Flags: {X:0>8}\n", .{unknown_module});

    try printImageFlags(writer, xex);
    try printSystemFlags(writer, xex);

    if (xex.logo_data != null) try writer.writeAll("  Xbox360 Logo Data Present\n");
    if (xex.exports_by_name != null) try writer.writeAll("  Exports by Name\n");
    if (xex.call_cap) |call_cap| try writer.print("  Has Call Cap Data   ({X:0>8} {X:0>8})\n", .{ call_cap[0], call_cap[1] });
    if (xex.fast_cap) |flags| try writer.print("  Has Fast Cap Data   ({X:0>8})\n", .{flags});
    if (xex.extra_debug_memory) |size| try writer.print("  Requires {d}MB Extra Debug Memory\n", .{size});

    try writer.writeAll("\nBasefile Info\n");
    if (xex.original_pe_name) |name| try writer.print("  Original PE Name:   {s}\n", .{name});
    if (xex.isBasefilePE()) {
        const filetime: std.c.time_t = @intCast(xex.filetime());
        const time_text = ctime(&filetime);
        try writer.print("  Load Address:       {X:0>8}\n", .{xex.load_address});
        try writer.print("  Entry Point:        {X:0>8}\n", .{xex.entryPoint()});
        try writer.print("  Image Size:         {X: >8}\n", .{@as(u32, @bitCast(xex.imageSize()))});
        try writer.print("  Page Size:          {X: >8}\n", .{xex.pageSize()});
        try writer.print("  Checksum:           {X:0>8}\n", .{xex.checksum()});
        if (xex.export_table_address != 0) try writer.print("  Export Table:       {X:0>8}\n", .{xex.export_table_address});
        try writer.print("  Filetime:           {X:0>8} - {s}", .{ xex.filetime(), if (time_text) |text| std.mem.span(text) else "" });
    } else if (xex.isBasefileXUIZ()) {
        try writer.writeAll("  Basefile is a XUIZ file\n");
    } else {
        try writer.writeAll("  Unknown basefile type\n");
    }
    if (xex.stack_size) |size| try writer.print("  Stack Size:         {X: >8}\n", .{@as(u32, @bitCast(size))});
    if (xex.heap_size) |size| try writer.print("  Heap Size:          {X: >8}\n", .{@as(u32, @bitCast(size))});
    if (xex.page_heap) |heap| {
        try writer.print("  Page Heap Size:     {X: >8}\n", .{heap.size});
        try writer.print("  Page Heap Flags:    {X: >8}\n", .{heap.flags});
    }
    if (xex.workspace_size) |size| try writer.print("  Workspace Size:     {X: >8}\n", .{@as(u32, @bitCast(size))});
    if (xex.filesystem_cache_size) |size| try writer.print("  Filesystem Cache Size:  {X: >8}\n", .{@as(u32, @bitCast(size))});

    try writer.writeAll("\nRegions\n");
    if (xex.hasImageFlag(defines.image_flag_no_game_region) or xex.isAllRegions()) {
        try writer.writeAll("  All Regions\n");
    } else {
        if (xex.hasRegion(defines.region_north_america)) try writer.writeAll("  North America\n");
        if (xex.hasRegion(defines.region_japan)) try writer.writeAll("  Japan\n");
        if (xex.hasRegion(defines.region_china)) try writer.writeAll("  China\n");
        if (xex.hasRegion(defines.region_rest_of_asia)) try writer.writeAll("  Rest of Asia\n");
        if (xex.hasRegion(defines.region_aust_nz)) try writer.writeAll("  Australia / New Zealand\n");
        if (xex.hasRegion(defines.region_rest_of_europe)) try writer.writeAll("  Rest of Europe\n");
        if (xex.hasRegion(defines.region_rest_of_world)) try writer.writeAll("  Rest of the World\n");
    }

    try writer.writeAll("\nAllowed Media\n");
    if (!xex.hasImageFlag(defines.image_flag_xgd2) and xex.isAllMediaTypes()) {
        try writer.writeAll("  All Media Types\n");
    } else if (xex.hasImageFlag(defines.image_flag_xgd2) and xex.hasMediaType(defines.media_dvd_cd)) {
        try writer.writeAll("  DVD-XGD2 (Xbox360 Original Disc)\n");
    } else if (xex.hasImageFlag(defines.image_flag_xgd2) and !xex.hasMediaType(defines.media_dvd_cd)) {
        try writer.writeAll("  Updated DVD-XGD2 (Updated version of Xbox360 Original Disc)\n");
    } else {
        if (xex.hasMediaType(defines.media_hard_disk)) try writer.writeAll("  Hard Disk\n");
        if (xex.hasMediaType(defines.media_dvdx2)) try writer.writeAll("  DVD-X2 (Xbox1 Original Disc)\n");
        if (xex.hasMediaType(defines.media_dvd_cd)) try writer.writeAll("  DVD / CD\n");
        if (xex.hasMediaType(defines.media_dvd5)) try writer.writeAll("  DVD5\n");
        if (xex.hasMediaType(defines.media_dvd9)) try writer.writeAll("  DVD9\n");
        if (xex.hasMediaType(defines.media_sys_flash)) try writer.writeAll("  System Flash\n");
        if (xex.hasMediaType(defines.media_mem_unit)) try writer.writeAll("  Memory Unit\n");
        if (xex.hasMediaType(defines.media_mass_storage)) try writer.writeAll("  Usb Mass Storage\n");
        if (xex.hasMediaType(defines.media_smb)) try writer.writeAll("  Networked SMB Share\n");
        if (xex.hasMediaType(defines.media_ram)) try writer.writeAll("  Direct from Ram\n");
        if (xex.hasMediaType(defines.media_ram_drive)) try writer.writeAll("  Ram Drive\n");
        if (xex.hasMediaType(defines.media_secure_virt_od)) try writer.writeAll("  Secure Virtual Optical Device\n");
        if (xex.hasMediaType(defines.media_wireless_n_storage)) try writer.writeAll("  Wireless N Storage\n");
        if (xex.hasMediaType(defines.media_sys_ext_partition)) try writer.writeAll("  System Extended Partition\n");
        if (xex.hasMediaType(defines.media_sys_aux_partition)) try writer.writeAll("  System Auxillary Partition\n");
        if (xex.hasMediaType(defines.media_insecure_pkg)) try writer.writeAll("  Insecure Package (\"CONS\")\n");
        if (xex.hasMediaType(defines.media_savegame_pkg)) try writer.writeAll("  Savegame Package (\"CONS\")\n");
        if (xex.hasMediaType(defines.media_localsign_pkg)) try writer.writeAll("  Locally Signed Package (\"CONS\")\n");
        if (xex.hasMediaType(defines.media_livesign_pkg)) try writer.writeAll("  Live Signed Package (\"LIVE\")\n");
        if (xex.hasMediaType(defines.media_xbox_pkg)) try writer.writeAll("  Xbox Package (\"PIRS\")\n");
        const unknown_media = xex.media_types & defines.media_unknown;
        if (unknown_media != 0) try writer.print("  Unknown Media: {X:0>8}\n", .{unknown_media});
    }

    try writer.writeAll("\nMedia Id \n  ");
    try printHexBytes(writer, &xex.media_id.data);
    try writer.writeAll("\n");
    if (xex.multidisc_media_ids.items.len != 0) {
        try writer.writeAll("\nMultidisc Media Ids \n");
        for (xex.multidisc_media_ids.items) |media_id| {
            try writer.writeAll("  ");
            try printHexBytes(writer, &media_id.data);
            try writer.writeAll("\n");
        }
    }
    if (xex.disc_profile_id) |id| {
        try writer.writeAll("\nDisc Profile Id \n  ");
        try printHexBytes(writer, &id);
        try writer.writeAll("\n");
    }

    try writer.writeAll("\nEncryption Key \n  ");
    try printHexBytes(writer, &xex.image_key.data);
    try writer.writeAll("\n");

    if (xex.lan_key) |key| {
        try writer.writeAll("\nLAN Key \n  ");
        try printHexBytes(writer, &key);
        try writer.writeAll("\n");
    }
    if (xex.base_reference) |ref| {
        try writer.writeAll("\nBase Reference\n  ");
        try printHexBytes(writer, &ref);
        try writer.writeAll("\n");
    }

    if (xex.restrict_dates != null or xex.restrict_kv_privs != null or xex.restrict_console_ids.items.len != 0) {
        try writer.writeAll("\nRestrictions for Use\n");
    }
    if (xex.restrict_dates != null) {
        try writer.writeAll("  Start Date:         \n");
        try writer.writeAll("  End Date:           \n");
    }
    if (xex.restrict_kv_privs != null) {
        try writer.writeAll("  KeyVault Mask:      \n");
        try writer.writeAll("  KeyVault Value:     \n");
    }
    for (xex.restrict_console_ids.items, 0..) |_, i| {
        try writer.print("  ConsoleId {d: >3}:      \n", .{i});
    }

    if (xex.bounding_path) |path| try writer.print("\nBounding Path\n  {s}\n", .{path});
    if (xex.bounding_device_id) |id| {
        try writer.writeAll("\nBounding Device Id\n  ");
        try printHexBytes(writer, &id);
        try writer.writeAll("\n");
    }

    if (xex.tls_info) |tls| {
        try writer.writeAll("\nTLS Info\n");
        try writer.print("  Number of Slots:    {d}\n", .{tls.num_slots});
        try writer.print("  Data Size:          {d}\n", .{tls.data_size});
        try writer.print("  Raw Data Address:   {X:0>8}\n", .{tls.raw_address});
        try writer.print("  Raw Data Size:      {d}\n", .{tls.raw_size});
    }

    if (xex.execution_id) |exec_id| {
        try writer.writeAll("\nExecution Id\n");
        try writer.print("  Media Id:           {X:0>8}\n", .{exec_id.media_id});
        const ch1: u8 = @truncate(exec_id.title_id >> 24);
        const ch2: u8 = @truncate(exec_id.title_id >> 16);
        if (ch1 > ' ' and ch1 <= 'z' and ch2 > ' ' and ch2 <= 'z') {
            try writer.print("  Title Id:           {X:0>8}  ({c}{c}-{d})\n", .{ exec_id.title_id, ch1, ch2, exec_id.title_id & 0xFFFF });
        } else {
            try writer.print("  Title Id:           {X:0>8}\n", .{exec_id.title_id});
        }
        try writer.print("  Savegame Id:        {X:0>8}\n", .{exec_id.save_game_id});
        try printVersion32(writer, "  Version:            ", exec_id.version);
        try printVersion32(writer, "  Base Version:       ", exec_id.base_version);
        try writer.print("  Platform:           {X}\n", .{exec_id.platform});
        try writer.print("  Executable Type:    {X}\n", .{exec_id.exec_type});
        try writer.print("  Disc Number:        {d}\n", .{exec_id.num_disc});
        try writer.print("  Number of Discs:    {d}\n", .{exec_id.max_discs});
    }

    if (xex.alt_title_ids.items.len != 0) {
        try writer.writeAll("\nAlternate Title Ids\n");
        for (xex.alt_title_ids.items) |title_id| {
            const ch1: u8 = @truncate(title_id >> 24);
            const ch2: u8 = @truncate(title_id >> 16);
            if (ch1 > ' ' and ch1 <= 'z' and ch2 > ' ' and ch2 <= 'z') {
                try writer.print("  Title Id:           {X:0>8}  ({c}{c}-{d})\n", .{ title_id, ch1, ch2, title_id & 0xFFFF });
            } else {
                try writer.print("  Title Id:           {X:0>8}\n", .{title_id});
            }
        }
    }

    if (xex.game_ratings) |ratings| try printGameRatings(writer, ratings);

    if (xex.unknown_image_entries.items.len != 0) {
        try writer.writeAll("\nUnknown Image Entries\n");
        for (xex.unknown_image_entries.items, 0..) |entry, entry_num| {
            if (defines.isDataOffset(entry.header.key)) {
                try writer.print("  {d: >3})  {X:0>8}\n", .{ entry_num, entry.header.key });
                var offset: usize = 0;
                while (offset < entry.data.data().len) : (offset += 16) {
                    try writer.writeAll("  ");
                    var col: usize = 0;
                    while (col < 16) : (col += 1) {
                        if (offset + col >= entry.data.data().len) break;
                        try writer.print("{X:0>2} ", .{entry.data.data()[offset + col]});
                    }
                    try writer.writeAll("\n");
                }
            } else {
                try writer.print("  {d: >3})  {X:0>8} - {X:0>8}\n", .{ entry_num, entry.header.key, entry.header.value });
            }
        }
    }
}

pub fn printAll(writer: anytype, xex: *const model.Xex) !void {
    try printShort(writer, xex);

    if (xex.static_libraries.items.len != 0) {
        try writer.writeAll("\nStatic Libraries\n");
        for (xex.static_libraries.items, 0..) |library, index| {
            const name = fixedString(&library.name);
            try writer.print("  {d: >3}) {s:<14} ", .{ index, name });
            try printVersionInfo(writer, library.version);
            try writer.print("  ({s}", .{approvedString(library.version.approvedLibrary())});
            if ((library.version.word & 0x0400) != 0) try writer.writeAll(", Tool Version");
            if ((library.version.word & 0x1000) != 0) try writer.writeAll(", Executable Version");
            if (library.version.debugBuild()) try writer.writeAll(", Debug Build");
            try writer.writeAll(")\n");
        }
    }

    if (xex.import_libraries.items.len != 0) {
        try writer.writeAll("\nImport Libraries\n");
        for (xex.import_libraries.items, 0..) |library, index| {
            const name = fixedString(&library.name);
            try writer.print("  {d: >3}) {s:<14} ", .{ index, name });
            try printVersion32(writer, "", library.version);
            try writer.writeAll("  (min ");
            try printVersion32(writer, "", library.min_version);
            try writer.writeAll(")\n");
        }
    }

    if (xex.resources.items.len != 0) {
        try writer.writeAll("\nResources\n");
        for (xex.resources.items, 0..) |resource, index| {
            try writer.print("  {d: >3}) {X:0>8} - {X:0>8} : {s}\n", .{
                index,
                resource.addr,
                resource.addr +% @as(u32, @bitCast(resource.size)),
                fixedString(&resource.name),
            });
        }
    }

    if (xex.sections.items.len != 0) {
        try writer.writeAll("\nSections\n");
        var address = xex.load_address;
        for (xex.sections.items, 0..) |section, index| {
            const type_name: []const u8 = switch (section.info) {
                defines.section_info_code => "Code",
                defines.section_info_data => "Data",
                defines.section_info_readonly => "Header/Resource",
                else => "Unknown",
            };
            try writer.print("  {d: >3}) {X:0>8} - {X:0>8} : {s}\n", .{
                index,
                address,
                address +% @as(u32, @bitCast(section.size)),
                type_name,
            });
            address +%= @bitCast(section.size);
        }
    }
}

fn printImageFlags(writer: anytype, xex: *const model.Xex) !void {
    if (xex.hasImageFlag(defines.image_flag_manufacturing_utility)) try writer.writeAll("  Manufacturing Utility\n");
    if (xex.hasImageFlag(defines.image_flag_manufacturing_tool)) try writer.writeAll("  Manufacturing Support Tool\n");
    if (xex.hasImageFlag(defines.image_flag_xgd2)) try writer.writeAll("  XGD2 Only\n");
    if (xex.hasImageFlag(defines.image_flag_cardea_key)) try writer.writeAll("  Cardea Key (WMDRM-ND)\n");
    if (xex.hasImageFlag(defines.image_flag_xeika_key)) try writer.writeAll("  Xeika Key (AP25?)\n");
    if (xex.hasImageFlag(defines.image_flag_title_usermode)) try writer.writeAll("  Title Usermode\n");
    if (xex.hasImageFlag(defines.image_flag_system_usermode)) try writer.writeAll("  System Usermode\n");
    if (xex.hasImageFlag(defines.image_flag_orange0)) try writer.writeAll("  Orange0\n");
    if (xex.hasImageFlag(defines.image_flag_orange1)) try writer.writeAll("  Orange1\n");
    if (xex.hasImageFlag(defines.image_flag_orange2)) try writer.writeAll("  Orange2\n");
    if (xex.hasImageFlag(defines.image_flag_signed_kv_restricted)) try writer.writeAll("  Restricted to Signed Kayvault\n");
    if (xex.hasImageFlag(defines.image_flag_iptv_signup_app)) try writer.writeAll("  IPTV Signup Application\n");
    if (xex.hasImageFlag(defines.image_flag_iptv_title_app)) try writer.writeAll("  IPTV Title Application\n");
    if (xex.hasImageFlag(defines.image_flag_nccp_keys)) try writer.writeAll("  NCCP Keys\n");
    if (xex.hasImageFlag(defines.image_flag_activation_req)) try writer.writeAll("  Activation Required\n");
    if (xex.hasImageFlag(defines.image_flag_no_game_region)) try writer.writeAll("  No Game Region\n");
    if (xex.hasImageFlag(defines.image_flag_revocation_check_opt)) try writer.writeAll("  Revocation Check Optional\n");
    if (xex.hasImageFlag(defines.image_flag_revocation_check_req)) try writer.writeAll("  Revocation Check Required\n");
    const unknown = xex.image_flags & defines.image_flag_unknown;
    if (unknown != 0) try writer.print("  Unknown Image Flags: {X:0>8}\n", .{unknown});
}

fn printSystemFlags(writer: anytype, xex: *const model.Xex) !void {
    const flags = [_]struct { value: u32, text: []const u8 }{
        .{ .value = defines.sys_flag_no_force_reboot, .text = "No Forced Reboot" },
        .{ .value = defines.sys_flag_foreground_tasks, .text = "Foreground Tasks" },
        .{ .value = defines.sys_flag_no_odd_mapping, .text = "No ODD Mapping" },
        .{ .value = defines.sys_flag_handle_mce_input, .text = "Handles MCE Input" },
        .{ .value = defines.sys_flag_restrict_hud_features, .text = "Restricted HUD Features" },
        .{ .value = defines.sys_flag_handle_gamepad_disconnect, .text = "Handles Gampad Disconnect" },
        .{ .value = defines.sys_flag_insecure_sockets, .text = "Has Insecure Sockets" },
        .{ .value = defines.sys_flag_xbox1_xsp_interop, .text = "Xbox1 Interoperability" },
        .{ .value = defines.sys_flag_set_dash_context, .text = "Dash Context" },
        .{ .value = defines.sys_flag_uses_game_voice_channel, .text = "Uses Game Voice Channel" },
        .{ .value = defines.sys_flag_pal50_incompatible, .text = "Pal50 Incompatible" },
        .{ .value = defines.sys_flag_insecure_utilitydrive, .text = "Insecure Utility Drive Support" },
        .{ .value = defines.sys_flag_has_xam_hooks, .text = "Xam Hooks" },
        .{ .value = defines.sys_flag_pii, .text = "PII" },
        .{ .value = defines.sys_flag_crossplatform_syslink, .text = "Cross Platform System Link" },
        .{ .value = defines.sys_flag_multidisc_swap, .text = "Multidisc Swap" },
        .{ .value = defines.sys_flag_multidisc_insecure_media, .text = "Supports Insecure Multidisc Media" },
        .{ .value = defines.sys_flag_ap25_media, .text = "AP25 Media" },
        .{ .value = defines.sys_flag_no_confirm_exit, .text = "No Confirm Exit" },
        .{ .value = defines.sys_flag_allow_bkgrnd_download, .text = "Allow Background Downloading" },
        .{ .value = defines.sys_flag_create_persist_ramdrive, .text = "Create Persistable Ram Drive" },
        .{ .value = defines.sys_flag_inherit_persist_ramdrive, .text = "Inherit Persistent Ram Drive" },
        .{ .value = defines.sys_flag_allow_hud_vibration, .text = "Allow HUD Vibration" },
        .{ .value = defines.sys_flag_both_utility_partitions, .text = "Allow Access to Both Utility Partitions" },
        .{ .value = defines.sys_flag_handle_iptv_input, .text = "Handles Input for IPTV" },
        .{ .value = defines.sys_flag_prefer_bigbutton_input, .text = "Prefers Big Button Input" },
        .{ .value = defines.sys_flag_allow_xsam_reservation, .text = "Allow Xsam Reservation" },
        .{ .value = defines.sys_flag_multidisc_cross_title, .text = "Multidisc Cross Title" },
        .{ .value = defines.sys_flag_title_install_incompatible, .text = "Title Install Incompatible" },
        .{ .value = defines.sys_flag_allow_avatar_get_metadata, .text = "Allow Avatar Get Metadata By XUID" },
        .{ .value = defines.sys_flag_allow_controller_swapping, .text = "Allow Controller Swapping" },
        .{ .value = defines.sys_flag_dash_extensibility_module, .text = "Dash Extensibility Module" },
    };
    for (flags) |flag| {
        if (xex.hasSystemFlag(flag.value)) try writer.print("  {s}\n", .{flag.text});
    }
    const flags2 = [_]struct { value: u32, text: []const u8 }{
        .{ .value = defines.sys_flag2_allow_network_read_cancel, .text = "Allow Network Read Cancel" },
        .{ .value = defines.sys_flag2_uninterruptable_reads, .text = "Uninterruptable Reads" },
        .{ .value = defines.sys_flag2_require_full_experience, .text = "Requires NXE" },
        .{ .value = defines.sys_flag2_gamevoice_required_ui, .text = "Gamevoice Required UI" },
        .{ .value = defines.sys_flag2_title_set_presence_string, .text = "Title Sets Presence String" },
        .{ .value = defines.sys_flag2_natal_tiltcontrol, .text = "Natal Tilt Control" },
        .{ .value = defines.sys_flag2_requires_skeletal_tracking, .text = "Supports Skeletal Tracking" },
        .{ .value = defines.sys_flag2_supports_skeletal_tracking, .text = "Requires Skeletal Tracking" },
        .{ .value = defines.sys_flag2_use_large_hds_file_cache, .text = "Uses Large HDS File Cache" },
        .{ .value = defines.sys_flag2_title_supports_deep_link, .text = "Title Supports Deep Link" },
    };
    for (flags2) |flag| {
        if (xex.hasSystemFlag2(flag.value)) try writer.print("  {s}\n", .{flag.text});
    }
    const unknown = xex.system_flags & defines.sys_flag_unknown;
    if (unknown != 0) try writer.print("  Unknown System Flags: {X:0>8}\n", .{unknown});
    const unknown2 = xex.system_flags2 & defines.sys_flag2_unknown;
    if (unknown2 != 0) try writer.print("  Unknown System Flags2: {X:0>8}\n", .{unknown2});
}

fn printHexBytes(writer: anytype, bytes: []const u8) !void {
    for (bytes) |byte| try writer.print("{X:0>2} ", .{byte});
}

fn printVersion32(writer: anytype, prefix: []const u8, value: u32) !void {
    const version = types.Version32{ .dword = value };
    try writer.print("{s}v{d}.{d}.{d}.{d}\n", .{ prefix, version.major(), version.minor(), version.build(), version.qfe() });
}

fn printVersionInfo(writer: anytype, version: types.VersionInfo) !void {
    try writer.print("v{d}.{d}.{d}.{d}", .{ version.major, version.minor, version.build, version.qfe() });
}

fn approvedString(value: u2) []const u8 {
    return switch (value) {
        0 => "Unapproved",
        1 => "Conditionally Approved",
        2 => "Approved",
        3 => "Expired",
    };
}

fn fixedString(bytes: []const u8) []const u8 {
    return std.mem.sliceTo(bytes, 0);
}

fn printGameRatings(writer: anytype, ratings: types.GameRatings) !void {
    try writer.writeAll("\nGame Ratings\n");
    const r = ratings.data;
    try writer.print("  ESRB:      {s:<16}  {X:0>2}\n", .{ esrb(r[0]), r[0] });
    try writer.print("  PEGI:      {s:<16}  {X:0>2}\n", .{ pegi(r[1]), r[1] });
    try writer.print("  PEGI-FI:   {s:<16}  {X:0>2}\n", .{ pegiFi(r[2]), r[2] });
    try writer.print("  PEGI-PT:   {s:<16}  {X:0>2}\n", .{ pegiPt(r[3]), r[3] });
    try writer.print("  PEGI-BBFC: {s:<16}  {X:0>2}\n", .{ pegiBbfc(r[4]), r[4] });
    try writer.print("  CERO:      {s:<16}  {X:0>2}\n", .{ cero(r[5]), r[5] });
    try writer.print("  USK:       {s:<16}  {X:0>2}\n", .{ usk(r[6]), r[6] });
    try writer.print("  OFLCAU:    {s:<16}  {X:0>2}\n", .{ oflcAu(r[7]), r[7] });
    try writer.print("  OFLCNZ:    {s:<16}  {X:0>2}\n", .{ oflcNz(r[8]), r[8] });
    try writer.print("  KMRB:      {s:<16}  {X:0>2}\n", .{ "UNRATED", r[9] });
    try writer.print("  BRASIL:    {s:<16}  {X:0>2}\n", .{ brasil(r[10]), r[10] });
    try writer.print("  FPB:       {s:<16}  {X:0>2}\n", .{ fpb(r[11]), r[11] });
    try writer.print("  Taiwan:    {s:<16}  {X:0>2}\n", .{ taiwan(r[12]), r[11] });
    try writer.print("  Singapore: {s:<16}  {X:0>2}\n", .{ singapore(r[13]), r[11] });
}

fn esrb(v: u8) []const u8 {
    return switch (v) {
        0x00 => "ESRB_EC",
        0x02 => "ESRB_E",
        0x04 => "ESRB_E10+",
        0x06 => "ESRB_T",
        0x08 => "ESRB_M",
        0xFF => "ESRB_RP",
        else => "UNRATED",
    };
}
fn pegi(v: u8) []const u8 {
    return switch (v) {
        0x00 => "PEGI_3",
        0x04 => "PEGI_7",
        0x09 => "PEGI_12",
        0x0D => "PEGI_16",
        0x0E => "PEGI_18",
        else => "UNRATED",
    };
}
fn pegiFi(v: u8) []const u8 {
    return switch (v) {
        0x00 => "PEGI_3",
        0x04 => "PEGI_7",
        0x08 => "PEGI_11",
        0x0C => "PEGI_15",
        0x0E => "PEGI_18",
        else => "UNRATED",
    };
}
fn pegiPt(v: u8) []const u8 {
    return switch (v) {
        0x01 => "PEGI_4",
        0x03 => "PEGI_6",
        0x09 => "PEGI_12",
        0x0D => "PEGI_16",
        0x0E => "PEGI_18",
        else => "UNRATED",
    };
}
fn pegiBbfc(v: u8) []const u8 {
    return switch (v) {
        0x00 => "PEGIBBFC_3",
        0x01 => "PEGIBBFC_4",
        0x04 => "PEGIBBFC_7",
        0x05 => "PEGIBBFC_8",
        0x09 => "PEGIBBFC_12",
        0x0C => "PEGIBBFC_15",
        0x0D => "PEGIBBFC_16",
        0x0E => "PEGIBBFC_18",
        else => "UNRATED",
    };
}
fn cero(v: u8) []const u8 {
    return switch (v) {
        0x00 => "CERO_CHILDREN",
        0x02 => "CERO_12",
        0x04 => "CERO_15",
        0x06 => "CERO_18",
        0x08 => "CERO_Z",
        else => "UNRATED",
    };
}
fn usk(v: u8) []const u8 {
    return switch (v) {
        0x00 => "USK_ALL_AGES",
        0x02 => "USK_6",
        0x04 => "USK_12",
        0x06 => "USK_16",
        0x08 => "USK_NO_YOUTH",
        else => "UNRATED",
    };
}
fn oflcAu(v: u8) []const u8 {
    return switch (v) {
        0x00 => "OFLC_AU_G",
        0x02 => "OFLC_AU_G8",
        0x03 => "OFLC_AU_PG",
        0x04 => "OFLC_AU_M15",
        0x05 => "OFLC_AU_M",
        0x06 => "OFLC_AU_MA15",
        else => "UNRATED",
    };
}
fn oflcNz(v: u8) []const u8 {
    return switch (v) {
        0x00 => "OFLC_NZ_ALL",
        0x02 => "OFLC_NZ_PG",
        0x04 => "OFLC_NZ_M15",
        0x06 => "OFLC_NZ_MA15",
        0x10 => "OFLC_NZ_M",
        0x20 => "OFLC_NZ_R16",
        0x30 => "OFLC_NZ_R18",
        0x40 => "OFLC_NZ_R",
        else => "UNRATED",
    };
}
fn brasil(v: u8) []const u8 {
    return switch (v) {
        0xFF, 0x10 => "BRAZIL_L",
        0x20 => "BRAZIL_10",
        0x30 => "BRAZIL_12",
        0x40 => "BRAZIL_14",
        0x50 => "BRAZIL_16",
        0x60 => "BRAZIL_18",
        else => "UNRATED",
    };
}
fn fpb(v: u8) []const u8 {
    return switch (v) {
        0x00 => "FPB_A",
        0x02, 0x06 => "FPB_PG",
        0x07 => "FPB_10",
        0x08 => "FPB_PG_CURRENT",
        0x0A => "FPB_13",
        0x0D => "FPB_16",
        0x0E => "FPB_18",
        else => "UNRATED",
    };
}
fn taiwan(v: u8) []const u8 {
    return switch (v) {
        0x01 => "TAIWAN_GENERAL",
        0x02 => "TAIWAN_PROTECTED",
        0x03 => "TAIWAN_PG",
        0x04 => "TAIWAN_RESTRICTED",
        else => "UNRATED",
    };
}
fn singapore(v: u8) []const u8 {
    return switch (v) {
        0x01 => "SINGAPORE_GENERAL",
        0x02 => "SINGAPORE_AGE_ADVISORY",
        0x03 => "SINGAPORE_MATURE_18",
        else => "UNRATED",
    };
}
