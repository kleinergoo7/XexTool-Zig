// SPDX-FileCopyrightText: 2026 XexTool Zig rewrite contributors
// SPDX-License-Identifier: GPL-3.0-or-later

const std = @import("std");
const file = @import("../core/file.zig");
const defines = @import("defines.zig");
const model = @import("model.zig");

pub fn writeInfo(io: std.Io, xex: *const model.Xex, path: []const u8, gpa: std.mem.Allocator) !void {
    var buffer: std.Io.Writer.Allocating = .init(gpa);
    defer buffer.deinit();
    try print(&buffer.writer, xex);
    try file.writeAll(io, path, buffer.written());
}

pub fn print(writer: *std.Io.Writer, xex: *const model.Xex) !void {
    try writer.writeAll("<xex>\n");
    try writer.print("  <moduleflags  flags=\"{X:0>8}\"/>\n", .{xex.module_flags});
    try writer.print("  <imageflags   flags=\"{X:0>8}\"/>\n", .{xex.image_flags});
    try writer.print("  <regions      flags=\"{X:0>8}\"/>\n", .{xex.regions});
    try writer.print("  <mediatypes   flags=\"{X:0>8}\"/>\n", .{xex.media_types});
    try writer.print("  <systemflags  flags=\"{X:0>8}\"/>\n", .{xex.system_flags});
    try writer.print("  <systemflags2 flags=\"{X:0>8}\"/>\n", .{xex.system_flags2});
    try writer.print("  <machine type=\"{s}\"/>\n", .{if (xex.is_debug) "debug" else "retail"});

    try writer.writeAll("  <mediaid id=\"");
    try printHex(writer, &xex.media_id.data);
    try writer.writeAll("\"/>\n");
    for (xex.multidisc_media_ids.items) |media_id| {
        try writer.writeAll("  <altmediaid id=\"");
        try printHex(writer, &media_id.data);
        try writer.writeAll("\"/>\n");
    }

    if (xex.execution_id) |exec_id| {
        try writer.print("  <mediaid32 id=\"{X:0>8}\"/>\n", .{exec_id.media_id});
        try writer.print("  <version ver32=\"{X:0>8}\"/>\n", .{exec_id.version});
        try writer.print("  <baseversion ver32=\"{X:0>8}\"/>\n", .{exec_id.base_version});
        try writer.print("  <titleid id=\"{X:0>8}\"/>\n", .{exec_id.title_id});
        try writer.print("  <execother id=\"{X:0>2}{X:0>2}{X:0>2}{X:0>2}\"/>\n", .{ exec_id.platform, exec_id.exec_type, exec_id.num_disc, exec_id.max_discs });
        try writer.print("  <savegameid id=\"{X:0>8}\"/>\n", .{exec_id.save_game_id});
    }
    for (xex.alt_title_ids.items) |title_id| {
        try writer.print("  <alttitleid id=\"{X:0>8}\"/>\n", .{title_id});
    }
    if (xex.disc_profile_id) |id| {
        try writer.writeAll("  <discprofileid id=\"");
        try printHex(writer, &id);
        try writer.writeAll("\"/>\n");
    }
    if (xex.lan_key) |key| {
        try writer.writeAll("  <lankey id=\"");
        try printHex(writer, &key);
        try writer.writeAll("\"/>\n");
    }
    if (xex.logo_data) |logo| {
        try writer.writeAll("  <logodata data=\"");
        try printHex(writer, logo.data());
        try writer.writeAll("\"/>\n");
    }
    if (xex.bounding_path) |path_text| {
        try writer.print("  <boundingpath path=\"{s}\"/>\n", .{path_text});
    }
    if (xex.bounding_device_id) |id| {
        try writer.writeAll("  <boundingdeviceid id=\"");
        try printHex(writer, &id);
        try writer.writeAll("\"/>\n");
    }
    if (xex.game_ratings) |ratings| {
        try writer.writeAll("  <gameratings data=\"");
        try printHex(writer, &ratings.data);
        try writer.writeAll("\"/>\n");
    }

    if (xex.resources.items.len > 0 and xex.execution_id != null) {
        const title_id = xex.execution_id.?.title_id;
        var title_text: [8]u8 = undefined;
        _ = try std.fmt.bufPrint(&title_text, "{X:0>8}", .{title_id});
        for (xex.resources.items, 0..) |resource, index| {
            const name = std.mem.sliceTo(&resource.name, 0);
            if (!std.mem.eql(u8, &title_text, name)) continue;
            const data = try resourceData(xex, index);
            try writer.print("  <spa name=\"{s}\" data=\"", .{name});
            try printHex(writer, data);
            try writer.writeAll("/>\n");
            break;
        }
    }

    try writer.writeAll("</xex>\n");
}

fn resourceData(xex: *const model.Xex, index: usize) ![]const u8 {
    if (index >= xex.resources.items.len) return error.InvalidResource;
    const resource = xex.resources.items[index];
    if (resource.size < 0) return error.InvalidResource;
    const offset = resource.addr -% xex.load_address;
    const size: usize = @intCast(resource.size);
    if (offset > xex.basefile.data().len or size > xex.basefile.data().len - offset) return error.OutOfBounds;
    return xex.basefile.data()[offset..][0..size];
}

fn printHex(writer: anytype, bytes: []const u8) !void {
    for (bytes) |byte| try writer.print("{X:0>2}", .{byte});
}
