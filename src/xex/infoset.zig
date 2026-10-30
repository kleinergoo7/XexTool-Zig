// SPDX-FileCopyrightText: 2026 XexTool Zig rewrite contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Port of the `-z s` info XML overlay in XexTool/src/main.cpp.

const std = @import("std");
const DataBlock = @import("../core/datablock.zig").DataBlock;
const tinyxml2 = @import("../tinyxml2/tinyxml2.zig");
const model = @import("model.zig");
const types = @import("types.zig");

pub const Error = error{
    OutOfMemory,
    InvalidXml,
    InvalidValue,
    InvalidRange,
};

pub fn apply(io: std.Io, xex: *model.Xex, path: []const u8, gpa: std.mem.Allocator) Error!void {
    var document: tinyxml2.XMLDocument = undefined;
    document.init(gpa, .{});
    defer document.deinit();

    const result = document.loadFile(io, path) catch return error.InvalidXml;
    if (result != .success) return error.InvalidXml;
    const root = document.rootElement() orelse return error.InvalidXml;
    if (!std.ascii.eqlIgnoreCase(root.name(), "xex")) return error.InvalidXml;

    xex.multidisc_media_ids.clearRetainingCapacity();
    xex.execution_id = null;
    xex.alt_title_ids.clearRetainingCapacity();
    xex.disc_profile_id = null;
    xex.lan_key = null;
    if (xex.bounding_path) |old| gpa.free(old);
    xex.bounding_path = null;
    xex.bounding_device_id = null;
    xex.game_ratings = null;

    var element = root.firstChildElement(null);
    while (element) |node| : (element = node.nextSiblingElement(null)) {
        const name = node.name();
        if (std.ascii.eqlIgnoreCase(name, "moduleflags")) {
            xex.module_flags = parseAttrU32(node, "flags") orelse return error.InvalidValue;
        } else if (std.ascii.eqlIgnoreCase(name, "imageflags")) {
            xex.image_flags = parseAttrU32(node, "flags") orelse return error.InvalidValue;
        } else if (std.ascii.eqlIgnoreCase(name, "regions")) {
            xex.regions = parseAttrU32(node, "flags") orelse return error.InvalidValue;
        } else if (std.ascii.eqlIgnoreCase(name, "mediatypes")) {
            xex.media_types = parseAttrU32(node, "flags") orelse return error.InvalidValue;
        } else if (std.ascii.eqlIgnoreCase(name, "systemflags")) {
            xex.system_flags = parseAttrU32(node, "flags") orelse return error.InvalidValue;
        } else if (std.ascii.eqlIgnoreCase(name, "systemflags2")) {
            xex.system_flags2 = parseAttrU32(node, "flags") orelse return error.InvalidValue;
        } else if (std.ascii.eqlIgnoreCase(name, "machine")) {
            const value = node.attribute("type", null) orelse return error.InvalidValue;
            if (std.ascii.eqlIgnoreCase(value, "retail")) {
                xex.is_debug = false;
            } else if (std.ascii.eqlIgnoreCase(value, "debug")) {
                xex.is_debug = true;
            } else {
                return error.InvalidValue;
            }
        } else if (std.ascii.eqlIgnoreCase(name, "mediaid")) {
            var media_id: [16]u8 = @splat(0);
            if (!parseHexBytes(node.attribute("id", null) orelse return error.InvalidValue, &media_id)) return error.InvalidValue;
            xex.media_id = .{ .data = media_id };
        } else if (std.ascii.eqlIgnoreCase(name, "multidiscmediaid")) {
            var media_id: [16]u8 = @splat(0);
            if (!parseHexBytes(node.attribute("id", null) orelse return error.InvalidValue, &media_id)) return error.InvalidValue;
            try xex.multidisc_media_ids.append(gpa, .{ .data = media_id });
        } else if (std.ascii.eqlIgnoreCase(name, "mediaid32")) {
            var execution = xex.execution_id orelse types.ExecutionId{};
            execution.media_id = parseAttrU32(node, "id") orelse return error.InvalidValue;
            xex.execution_id = execution;
        } else if (std.ascii.eqlIgnoreCase(name, "version")) {
            var execution = xex.execution_id orelse types.ExecutionId{};
            execution.version = parseAttrU32(node, "ver32") orelse return error.InvalidValue;
            xex.execution_id = execution;
        } else if (std.ascii.eqlIgnoreCase(name, "baseversion")) {
            var execution = xex.execution_id orelse types.ExecutionId{};
            execution.base_version = parseAttrU32(node, "ver32") orelse return error.InvalidValue;
            xex.execution_id = execution;
        } else if (std.ascii.eqlIgnoreCase(name, "titleid")) {
            var execution = xex.execution_id orelse types.ExecutionId{};
            execution.title_id = parseAttrU32(node, "id") orelse return error.InvalidValue;
            xex.execution_id = execution;
        } else if (std.ascii.eqlIgnoreCase(name, "execother")) {
            var execution = xex.execution_id orelse types.ExecutionId{};
            const value = parseAttrU32(node, "id") orelse return error.InvalidValue;
            execution.platform = @truncate(value >> 24);
            execution.exec_type = @truncate(value >> 16);
            execution.num_disc = @truncate(value >> 8);
            execution.max_discs = @truncate(value);
            xex.execution_id = execution;
        } else if (std.ascii.eqlIgnoreCase(name, "savegameid")) {
            var execution = xex.execution_id orelse types.ExecutionId{};
            execution.save_game_id = parseAttrU32(node, "id") orelse return error.InvalidValue;
            xex.execution_id = execution;
        } else if (std.ascii.eqlIgnoreCase(name, "alttitleid")) {
            try xex.alt_title_ids.append(gpa, parseAttrU32(node, "id") orelse return error.InvalidValue);
        } else if (std.ascii.eqlIgnoreCase(name, "discprofileid")) {
            var id: [16]u8 = @splat(0);
            if (!parseHexBytes(node.attribute("id", null) orelse return error.InvalidValue, &id)) return error.InvalidValue;
            xex.disc_profile_id = id;
        } else if (std.ascii.eqlIgnoreCase(name, "lankey")) {
            var key: [16]u8 = @splat(0);
            if (!parseHexBytes(node.attribute("id", null) orelse return error.InvalidValue, &key)) return error.InvalidValue;
            xex.lan_key = key;
        } else if (std.ascii.eqlIgnoreCase(name, "logodata")) {
            const text = node.attribute("id", null) orelse return error.InvalidValue;
            const length = text.len / 2;
            const bytes = try gpa.alloc(u8, length);
            defer gpa.free(bytes);
            if (!parseHexBytesCount(text, bytes)) return error.InvalidValue;
            var logo = DataBlock.init();
            errdefer logo.deinit(gpa);
            try logo.set(gpa, bytes, 0, @intCast(length));
            if (xex.logo_data) |*old| old.deinit(gpa);
            xex.logo_data = logo;
        } else if (std.ascii.eqlIgnoreCase(name, "boundingpath")) {
            const text = node.attribute("path", null) orelse return error.InvalidValue;
            if (xex.bounding_path) |old| gpa.free(old);
            xex.bounding_path = try gpa.dupe(u8, text);
        } else if (std.ascii.eqlIgnoreCase(name, "boundingdeviceid")) {
            var id: [20]u8 = @splat(0);
            if (!parseHexBytes(node.attribute("id", null) orelse return error.InvalidValue, &id)) return error.InvalidValue;
            xex.bounding_device_id = id;
        } else if (std.ascii.eqlIgnoreCase(name, "gameratings")) {
            var ratings: types.GameRatings = .{};
            if (!parseHexBytes(node.attribute("data", null) orelse return error.InvalidValue, &ratings.data)) return error.InvalidValue;
            xex.game_ratings = ratings;
        } else if (std.ascii.eqlIgnoreCase(name, "spa")) {
            // The C++ parser accepts <spa> but has no resource-insertion path.
        }
    }
}

fn parseAttrU32(node: *tinyxml2.XMLNode, name: []const u8) ?u32 {
    const text = node.attribute(name, null) orelse return null;
    return parseU32(text);
}

fn parseU32(text: []const u8) ?u32 {
    var rest = std.mem.trimStart(u8, text, " \t\r\n");
    var base: u8 = 10;
    if (std.mem.startsWith(u8, rest, "0x") or std.mem.startsWith(u8, rest, "0X")) {
        rest = rest[2..];
        base = 16;
    } else if (rest.len > 1 and rest[0] == '0') {
        base = 8;
    }
    const end = std.mem.indexOfAny(u8, rest, " \t\r\n") orelse rest.len;
    return std.fmt.parseInt(u32, rest[0..end], base) catch 0;
}

fn parseHexBytes(text: []const u8, output: anytype) bool {
    return parseHexBytesCount(text, output);
}

fn parseHexBytesCount(text: []const u8, output: anytype) bool {
    var rest = std.mem.trimStart(u8, text, " \t");
    if (std.mem.startsWith(u8, rest, "0x") or std.mem.startsWith(u8, rest, "0X")) rest = rest[2..];
    var count: usize = 0;
    var index: usize = 0;
    while (index < rest.len) {
        if (rest[index] == ' ' or rest[index] == '\t') {
            index += 1;
            continue;
        }
        if (index + 1 >= rest.len or count >= output.len) return false;
        const hi = std.fmt.charToDigit(rest[index], 16) catch return false;
        const lo = std.fmt.charToDigit(rest[index + 1], 16) catch return false;
        output[count] = (hi << 4) | lo;
        count += 1;
        index += 2;
    }
    return count == output.len;
}
