// SPDX-FileCopyrightText: 2026 XexTool Zig rewrite contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Port of XexTool/src/ApplyXexXml.cpp: overlay imagexex-style <xex> XML onto
// the in-memory XEX model. File writing belongs to the caller.

const std = @import("std");
const file = @import("../core/file.zig");
const tinyxml2 = @import("../tinyxml2/tinyxml2.zig");
const defines = @import("defines.zig");
const model = @import("model.zig");
const pe = @import("pe.zig");
const types = @import("types.zig");

pub const Error = error{
    OutOfMemory,
    InvalidXml,
    InvalidValue,
    SectionFile,
    OutOfBounds,
    InvalidRange,
    WriteFailed,
};

pub const usage =
    "Usage:    XexTool applyxml <input.xex> --xml <file.xml> [-o <output.xex>]\n" ++
    "\n" ++
    "Apply an imagexex-style <xex> XML onto an existing XEX (title id, privileges,\n" ++
    "LAN key, heap/workspace sizes, export-by-name, additional sections).\n" ++
    "Unspecified fields are left alone. If -o is omitted the input file is overwritten.\n";

pub fn apply(io: std.Io, xex: *model.Xex, xml_path: []const u8, gpa: std.mem.Allocator, out: anytype) Error!void {
    var document: tinyxml2.XMLDocument = undefined;
    document.init(gpa, .{});
    defer document.deinit();

    const result = document.loadFile(io, xml_path) catch return error.InvalidXml;
    if (result != .success) return error.InvalidXml;

    const root = document.rootElement() orelse return error.InvalidXml;
    if (!std.ascii.eqlIgnoreCase(root.name(), "xex")) return error.InvalidXml;

    var element = root.firstChildElement(null);
    while (element) |node| : (element = node.nextSiblingElement(null)) {
        const name = node.name();
        if (std.ascii.eqlIgnoreCase(name, "titleid")) {
            const value = elemAttrOrText(node, "id") orelse return error.InvalidValue;
            var execution = xex.execution_id orelse types.ExecutionId{};
            execution.title_id = parseU32(value) orelse return error.InvalidValue;
            xex.execution_id = execution;
        } else if (std.ascii.eqlIgnoreCase(name, "alttitleid")) {
            const value = elemAttrOrText(node, "id") orelse return error.InvalidValue;
            try xex.alt_title_ids.append(gpa, parseU32(value) orelse return error.InvalidValue);
        } else if (std.ascii.eqlIgnoreCase(name, "privilege")) {
            const value = elemAttrOrText(node, "id") orelse return error.InvalidValue;
            applyPrivilege(xex, parseU32(value) orelse return error.InvalidValue);
        } else if (std.ascii.eqlIgnoreCase(name, "lankey")) {
            const value = elemAttrOrText(node, "id") orelse return error.InvalidValue;
            var key: [16]u8 = @splat(0);
            if (!parseHexBytes(value, &key)) return error.InvalidValue;
            xex.lan_key = key;
        } else if (std.ascii.eqlIgnoreCase(name, "xapiheap") or std.ascii.eqlIgnoreCase(name, "heap")) {
            const value = elemAttrOrText(node, "size") orelse elemAttrOrText(node, "id") orelse return error.InvalidValue;
            xex.heap_size = @bitCast(parseU32(value) orelse return error.InvalidValue);
        } else if (std.ascii.eqlIgnoreCase(name, "workspace")) {
            const value = elemAttrOrText(node, "size") orelse elemAttrOrText(node, "id") orelse return error.InvalidValue;
            xex.workspace_size = @bitCast(parseU32(value) orelse return error.InvalidValue);
        } else if (std.ascii.eqlIgnoreCase(name, "exportnames")) {
            xex.module_flags |= defines.module_flag_exports_to_title;
        } else if (std.ascii.eqlIgnoreCase(name, "mediatypes")) {
            try applyMediaTypes(xex, node, out);
        } else if (std.ascii.eqlIgnoreCase(name, "section")) {
            const section_name = elemAttrOrText(node, "name") orelse return error.InvalidValue;
            const file_name = node.attribute("file", null) orelse node.attribute("path", null) orelse return error.InvalidValue;
            try applySection(io, xex, section_name, file_name, xml_path, gpa, out);
        } else if (std.ascii.eqlIgnoreCase(name, "baseaddr")) {
            try out.print("applyxml: skipping <baseaddr> (load address is fixed at link time)\n", .{});
        } else {
            try out.print("applyxml: ignoring unknown tag <{s}>\n", .{name});
        }
    }

    stripOddIncompatibleMedia(xex, out);
}

fn applyPrivilege(xex: *model.Xex, id: u32) void {
    if (id < 32) {
        xex.system_flags |= @as(u32, 1) << @intCast(id);
    } else if (id < 64) {
        xex.system_flags2 |= @as(u32, 1) << @intCast(id - 32);
    }
}

fn stripOddIncompatibleMedia(xex: *model.Xex, out: anytype) void {
    if (!xex.hasSystemFlag(defines.sys_flag_no_odd_mapping)) return;
    const drop = defines.media_dvd_cd | defines.media_dvdx2;
    if ((xex.media_types & drop) != 0) {
        xex.media_types &= ~drop;
        out.print("applyxml: privilege 2: dropped DVD/CD media (imagexex IM1069)\n", .{}) catch {};
    }
    if (xex.hasImageFlag(defines.image_flag_xgd2)) {
        xex.image_flags &= ~defines.image_flag_xgd2;
        out.print("applyxml: privilege 2: cleared XGD2-only (imagexex IM1069)\n", .{}) catch {};
    }
}

fn applyMediaTypes(xex: *model.Xex, element: *tinyxml2.XMLNode, out: anytype) Error!void {
    if (element.attribute("flags", null)) |flags_text| {
        if (flags_text.len != 0) {
            xex.media_types = parseU32(flags_text) orelse return error.InvalidValue;
            return;
        }
    }

    var flags: u32 = 0;
    var xgd2 = false;
    var child = element.firstChildElement(null);
    while (child) |node| : (child = node.nextSiblingElement(null)) {
        const name = node.name();
        if (std.ascii.eqlIgnoreCase(name, "harddisk")) {
            flags |= defines.media_hard_disk;
        } else if (std.ascii.eqlIgnoreCase(name, "cd")) {
            flags |= defines.media_dvd_cd;
        } else if (std.ascii.eqlIgnoreCase(name, "dvdx2")) {
            flags |= defines.media_dvdx2;
        } else if (std.ascii.eqlIgnoreCase(name, "dvdxgd2")) {
            flags |= defines.media_dvd_cd;
            xgd2 = true;
        } else if (std.ascii.eqlIgnoreCase(name, "flash")) {
            flags |= defines.media_sys_flash;
        } else if (std.ascii.eqlIgnoreCase(name, "mu")) {
            flags |= defines.media_mem_unit;
        } else if (std.ascii.eqlIgnoreCase(name, "usbmass")) {
            flags |= defines.media_mass_storage;
        } else if (std.ascii.eqlIgnoreCase(name, "network")) {
            flags |= defines.media_smb;
        } else if (std.ascii.eqlIgnoreCase(name, "ram")) {
            flags |= defines.media_ram;
        } else if (std.ascii.eqlIgnoreCase(name, "ramdrive")) {
            flags |= defines.media_ram_drive;
        } else if (std.ascii.eqlIgnoreCase(name, "svod")) {
            flags |= defines.media_secure_virt_od;
        } else if (std.ascii.eqlIgnoreCase(name, "livepackage")) {
            flags |= defines.media_livesign_pkg;
        } else if (std.ascii.eqlIgnoreCase(name, "signedpackage")) {
            flags |= defines.media_xbox_pkg;
        } else if (std.ascii.eqlIgnoreCase(name, "localpackage")) {
            flags |= defines.media_localsign_pkg;
        } else if (std.ascii.eqlIgnoreCase(name, "consolepackage")) {
            flags |= defines.media_savegame_pkg;
        } else if (std.ascii.eqlIgnoreCase(name, "allpackages")) {
            flags |= defines.media_insecure_pkg | defines.media_savegame_pkg |
                defines.media_localsign_pkg | defines.media_livesign_pkg |
                defines.media_xbox_pkg | 0xE0000000;
        } else {
            try out.print("applyxml: ignoring unknown mediatype <{s}>\n", .{name});
        }
    }
    xex.media_types = flags;
    if (xgd2) xex.image_flags |= defines.image_flag_xgd2 else xex.image_flags &= ~defines.image_flag_xgd2;
}

fn applySection(io: std.Io, xex: *model.Xex, section_name: []const u8, file_name: []const u8, xml_path: []const u8, gpa: std.mem.Allocator, out: anytype) Error!void {
    if (section_name.len == 0) return error.InvalidValue;
    if (file_name.len == 0) return error.InvalidValue;

    const path = try joinPath(gpa, dirnameOf(xml_path), file_name);
    defer gpa.free(path);

    const blob = file.readAll(io, path, gpa) catch return error.SectionFile;
    defer gpa.free(blob);
    if (blob.len == 0) return error.SectionFile;

    var page = xex.pageSize();
    if (page == 0) page = 0x10000;
    const old_size = xex.basefile.size();
    const rva = try nextSectionRva(xex, gpa);
    const need = rva + @as(u32, @intCast(blob.len));
    var new_size = @as(u32, @intCast(old_size));
    if (need > new_size) {
        new_size = need;
        const remainder = new_size % page;
        if (remainder != 0) new_size += page - remainder;
        try xex.basefile.fill(gpa, 0, old_size, @intCast(new_size - @as(u32, @intCast(old_size))));
    }
    try xex.basefile.set(gpa, blob, @intCast(rva), @intCast(blob.len));

    var resource_name: [8]u8 = @splat(0);
    @memcpy(resource_name[0..@min(section_name.len, 8)], section_name[0..@min(section_name.len, 8)]);
    try xex.resources.append(gpa, .{
        .name = resource_name,
        .addr = xex.load_address +% rva,
        .size = @intCast(blob.len),
    });

    const extra = xex.basefile.size() - old_size;
    if (extra > 0) try xex.sections.append(gpa, .{ .size = extra, .info = defines.section_info_readonly });
    try out.print("applyxml: section {s} {s} -> 0x{X:0>8} ({d} bytes)\n", .{ section_name, path, xex.load_address +% rva, blob.len });
}

fn nextSectionRva(xex: *model.Xex, gpa: std.mem.Allocator) Error!u32 {
    _ = gpa;
    var cursor: u32 = 0;
    if (xex.isBasefilePE()) {
        const parser = pe.Parser.init(xex.basefile.data());
        const count = parser.numberOfSections() orelse 0;
        var i: u16 = 0;
        while (i < count) : (i += 1) {
            if (parser.section(i)) |section| {
                const end = section.virtual_address +% section.virtual_size;
                if (end > cursor) cursor = end;
            }
        }
    }
    for (xex.resources.items) |resource| {
        if (resource.addr >= xex.load_address) {
            const end = (resource.addr - xex.load_address) +% @as(u32, @bitCast(resource.size));
            if (end > cursor) cursor = end;
        }
    }
    if (cursor == 0) cursor = @intCast(xex.basefile.size());
    const remainder = cursor % 0x80;
    if (remainder != 0) cursor += 0x80 - remainder;
    return cursor;
}

fn elemAttrOrText(element: *tinyxml2.XMLNode, name: []const u8) ?[]const u8 {
    if (element.attribute(name, null)) |value| {
        if (value.len != 0) return value;
    }
    return element.getText();
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
    return std.fmt.parseInt(u32, rest[0..end], base) catch null;
}

fn parseHexBytes(text: []const u8, output: *[16]u8) bool {
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

fn dirnameOf(path: []const u8) []const u8 {
    const slash = std.mem.lastIndexOfAny(u8, path, "\\/") orelse return ".";
    return path[0..slash];
}

fn joinPath(gpa: std.mem.Allocator, directory: []const u8, name: []const u8) Error![]u8 {
    if (name.len == 0) return error.InvalidValue;
    if (name[0] == '/' or name[0] == '\\' or (name.len > 1 and name[1] == ':')) return gpa.dupe(u8, name);
    if (directory.len == 0 or std.mem.eql(u8, directory, ".")) return gpa.dupe(u8, name);
    const separator: []const u8 = if (std.mem.indexOfScalar(u8, directory, '/') != null and std.mem.indexOfScalar(u8, directory, '\\') == null) "/" else "\\";
    return std.fmt.allocPrint(gpa, "{s}{s}{s}", .{ directory, separator, name });
}
