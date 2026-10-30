// SPDX-FileCopyrightText: 2026 XexTool Zig rewrite contributors
// SPDX-License-Identifier: GPL-3.0-or-later

const std = @import("std");
const defines = @import("defines.zig");
const model = @import("model.zig");
const gameinfo = @import("gameinfo.zig");
const base64 = @import("../core/base64.zig");

pub const Flags = struct {
    basefile: bool = false,
    media_id: bool = false,
    icon: bool = false,
    medias: bool = false,
    name: bool = false,
    bound_path: bool = false,
    regions: bool = false,
    title_id: bool = false,
    machine: bool = false,
};

pub fn print(writer: anytype, xex: *const model.Xex, flags: Flags, gpa: std.mem.Allocator) !void {
    try writer.writeAll("<XexInfo>\n");
    if (flags.basefile) {
        try writer.writeAll("    <BasefileType format=\"string\">");
        if (xex.isTitleModule()) {
            try writer.writeAll("Exe");
        } else if (xex.isDllModule()) {
            try writer.writeAll("Dll");
        } else if (xex.isPatchModule()) {
            try writer.writeAll("Patch");
        } else {
            try writer.writeAll("Other");
        }
        try writer.writeAll("</BasefileType>\n");
    }
    if (flags.media_id) {
        try writer.writeAll("    <MediaId format=\"hex\">");
        try printHex(writer, &xex.media_id.data);
        try writer.writeAll("</MediaId>\n");
    }
    if (flags.icon) {
        if (gameinfo.gameIcon(gpa, xex) catch null) |icon_value| {
            var icon = icon_value;
            defer icon.deinit(gpa);
            try writer.writeAll("    <GameIcon format=\"base64\">\n");
            try base64.encode(writer, icon.data());
            try writer.writeAll("\n    </GameIcon>\n");
        }
    }
    if (flags.medias) {
        try writer.writeAll("    <GameMedias>\n");
        try printMedias(writer, xex);
        try writer.writeAll("    </GameMedias>\n");
    }
    if (flags.name) {
        var gamename: [1024]u8 = undefined;
        if (gameinfo.gameName(gpa, xex, &gamename) catch false) {
            try writer.writeAll("    <GameName format=\"string\">");
            for (std.mem.sliceTo(&gamename, 0)) |ch| {
                if (ch >= ' ' and ch < 127 and ch != '&' and ch != '<' and ch != '>' and ch != '\'' and ch != '"') {
                    try writer.writeByte(ch);
                } else {
                    try writer.print("&#{d};", .{ch});
                }
            }
            try writer.writeAll("</GameName>\n");
        }
    }
    if (flags.bound_path) {
        if (xex.bounding_path) |path| {
            try writer.writeAll("    <BoundingPath>");
            try writer.writeAll(path);
            try writer.writeAll("    </BoundingPath>\n");
        }
    }
    if (flags.regions) {
        try writer.writeAll("    <GameRegions>\n");
        if (xex.isAllRegions()) {
            try writer.writeAll("        <Region format=\"string\">All</Region>\n");
        } else {
            if (xex.hasRegion(defines.region_north_america)) try writer.writeAll("        <Region format=\"string\">North America</Region>\n");
            if (xex.hasRegion(defines.region_japan)) try writer.writeAll("        <Region format=\"string\">Japan</Region>\n");
            if (xex.hasRegion(defines.region_china)) try writer.writeAll("        <Region format=\"string\">China</Region>\n");
            if (xex.hasRegion(defines.region_rest_of_asia)) try writer.writeAll("        <Region format=\"string\">Rest of Asia</Region>\n");
            if (xex.hasRegion(defines.region_aust_nz)) try writer.writeAll("        <Region format=\"string\">Australia / New Zealand</Region>\n");
            if (xex.hasRegion(defines.region_rest_of_europe)) try writer.writeAll("        <Region format=\"string\">Rest of Europe</Region>\n");
            if (xex.hasRegion(defines.region_rest_of_world)) try writer.writeAll("        <Region format=\"string\">Rest of the World</Region>\n");
        }
        try writer.writeAll("    </GameRegions>\n");
    }
    if (flags.title_id) {
        if (xex.execution_id) |exec_id| {
            try writer.print("    <TitleId format=\"hex\">{X:0>8}</TitleId>\n", .{exec_id.title_id});
        }
    }
    if (flags.machine) {
        try writer.writeAll("    <MachineFormat format=\"string\">");
        if (xex.is_debug) {
            try writer.writeAll("Devkit");
        } else {
            try writer.writeAll("Retail");
        }
        try writer.writeAll("</MachineFormat>\n");
    }
    try writer.writeAll("</XexInfo>\n");
}

fn printMedias(writer: anytype, xex: *const model.Xex) !void {
    if (!xex.hasImageFlag(defines.image_flag_xgd2) and xex.isAllMediaTypes()) {
        try writer.writeAll("        <Media format=\"string\">All</Media>\n");
        return;
    }
    if (xex.hasImageFlag(defines.image_flag_xgd2) and xex.hasMediaType(defines.media_dvd_cd)) {
        try writer.writeAll("        <Media format=\"string\">DVD-XGD2 (Xbox360 Original Disc)</Media>\n");
        return;
    }
    if (xex.hasImageFlag(defines.image_flag_xgd2)) {
        try writer.writeAll("        <Media format=\"string\">Updated DVD-XGD2 (Updated version of Xbox360 Original Disc)</Media>\n");
        return;
    }
    if (xex.hasMediaType(defines.media_hard_disk)) try writer.writeAll("        <Media format=\"string\">Hard Disk</Media>\n");
    if (xex.hasMediaType(defines.media_dvdx2)) try writer.writeAll("        <Media format=\"string\">DVD-X2 (Xbox1 Original Disc)</Media>\n");
    if (xex.hasMediaType(defines.media_dvd_cd)) try writer.writeAll("        <Media format=\"string\">DVD / CD</Media>\n");
    if (xex.hasMediaType(defines.media_dvd5)) try writer.writeAll("        <Media format=\"string\">DVD5</Media>\n");
    if (xex.hasMediaType(defines.media_dvd9)) try writer.writeAll("        <Media format=\"string\">DVD9</Media>\n");
    if (xex.hasMediaType(defines.media_sys_flash)) try writer.writeAll("        <Media format=\"string\">System Flash</Media>\n");
    if (xex.hasMediaType(defines.media_mem_unit)) try writer.writeAll("        <Media format=\"string\">Memory Unit</Media>\n");
    if (xex.hasMediaType(defines.media_mass_storage)) try writer.writeAll("        <Media format=\"string\">Usb Mass Storage</Media>\n");
    if (xex.hasMediaType(defines.media_smb)) try writer.writeAll("        <Media format=\"string\">Networked SMB Share</Media>\n");
    if (xex.hasMediaType(defines.media_ram)) try writer.writeAll("        <Media format=\"string\">Direct from Ram</Media>\n");
    if (xex.hasMediaType(defines.media_ram_drive)) try writer.writeAll("        <Media format=\"string\">Ram Drive</Media>\n");
    if (xex.hasMediaType(defines.media_secure_virt_od)) try writer.writeAll("        <Media format=\"string\">Secure Virtual Optical Device</Media>\n");
    if (xex.hasMediaType(defines.media_wireless_n_storage)) try writer.writeAll("        <Media format=\"string\">Wireless N Storage</Media>\n");
    if (xex.hasMediaType(defines.media_sys_ext_partition)) try writer.writeAll("        <Media format=\"string\">System Extended Partition</Media>\n");
    if (xex.hasMediaType(defines.media_sys_aux_partition)) try writer.writeAll("        <Media format=\"string\">System Auxillary Partition</Media>\n");
    if (xex.hasMediaType(defines.media_insecure_pkg)) try writer.writeAll("        <Media format=\"string\">Insecure Package (\"CONS\")</Media>\n");
    if (xex.hasMediaType(defines.media_savegame_pkg)) try writer.writeAll("        <Media format=\"string\">Savegame Package (\"CONS\")</Media>\n");
    if (xex.hasMediaType(defines.media_localsign_pkg)) try writer.writeAll("        <Media format=\"string\">Locally Signed Package (\"CONS\")</Media>\n");
    if (xex.hasMediaType(defines.media_livesign_pkg)) try writer.writeAll("        <Media format=\"string\">Live Signed Package (\"LIVE\")</Media>\n");
    if (xex.hasMediaType(defines.media_xbox_pkg)) try writer.writeAll("        <Media format=\"string\">Xbox Package (\"PIRS\")</Media>\n");
    const unknown = xex.media_types & defines.media_unknown;
    if (unknown != 0) try writer.print("        <Media format=\"string\">Unknown Media: {X:0>8}</Media>\n", .{unknown});
}

fn printHex(writer: anytype, bytes: []const u8) !void {
    for (bytes) |byte| try writer.print("{X:0>2}", .{byte});
}
