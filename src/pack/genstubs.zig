// SPDX-FileCopyrightText: 2026 XexTool Zig rewrite contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Port of `XexGenStubs.cpp`: resolve the kernel imports a title needs from
//! the XDK `.lib` short-import members and emit the PPC thunk assembly plus the
//! JSON import manifest the packer consumes.

const std = @import("std");

const image_file_machine_powerpcbe: u16 = 0x01F2;

const Supplemental = struct {
    name: []const u8,
    ordinal: u32,
};

/// Kernel exports the console has but the public XDK import libs omit.
const supplemental = [_]Supplemental{
    .{ .name = "KeTlsAlloc", .ordinal = 0x152 },
    .{ .name = "KeTlsFree", .ordinal = 0x153 },
    .{ .name = "KeTlsGetValue", .ordinal = 0x154 },
    .{ .name = "KeTlsSetValue", .ordinal = 0x155 },
};

const genstubs_usage = "Usage: XexTool genstubs --xdk <lib dir> --names <a,b,..> -o <stubs.s> [--manifest <json>]\n";

pub const Import = struct {
    module: []const u8,
    ordinal: u32,
    is_var: bool,
};

pub const Entry = struct {
    name: []const u8,
    ordinal: u32,
    is_var: bool,
};

pub const Member = struct {
    name: []const u8,
    data: []const u8,
};

pub const ShortImport = struct {
    symbol: []const u8,
    dll: []const u8,
    ordinal: u16,
    import_type: u16,

    pub fn isVariable(self: ShortImport) bool {
        return self.import_type == 1 or self.import_type == 2;
    }
};

pub const Index = struct {
    gpa: std.mem.Allocator,
    map: std.StringHashMap(Import),
    owned: std.ArrayList([]u8) = .empty,

    pub fn init(gpa: std.mem.Allocator) Index {
        return .{ .gpa = gpa, .map = std.StringHashMap(Import).init(gpa) };
    }

    pub fn deinit(self: *Index) void {
        for (self.owned.items) |text| self.gpa.free(text);
        self.owned.deinit(self.gpa);
        self.map.deinit();
    }

    fn intern(self: *Index, text: []const u8) ![]const u8 {
        const copy = try self.gpa.dupe(u8, text);
        errdefer self.gpa.free(copy);
        try self.owned.append(self.gpa, copy);
        return copy;
    }

    /// Setdefault semantics: the first library that defines a symbol wins.
    fn add(self: *Index, symbol: []const u8, module: []const u8, ordinal: u32, is_var: bool) !void {
        if (self.map.contains(symbol)) return;
        const key = try self.intern(symbol);
        const value = Import{ .module = try self.intern(module), .ordinal = ordinal, .is_var = is_var };
        try self.map.put(key, value);
    }
};

pub const Resolution = struct {
    modules: std.ArrayList([]const u8) = .empty,
    entries: std.ArrayList(std.ArrayList(Entry)) = .empty,
    unresolved: std.ArrayList([]const u8) = .empty,

    pub fn deinit(self: *Resolution, gpa: std.mem.Allocator) void {
        for (self.entries.items) |*list| list.deinit(gpa);
        self.modules.deinit(gpa);
        self.entries.deinit(gpa);
        self.unresolved.deinit(gpa);
    }
};

// ---------------------------------------------------------------------------
// Microsoft !<arch> archives
// ---------------------------------------------------------------------------

const archive_magic = "!<arch>\n";
const archive_header_size: usize = 60;
const archive_name_size: usize = 16;
const archive_size_offset: usize = 48;
const archive_size_size: usize = 10;

fn decimalField(text: []const u8) usize {
    var value: usize = 0;
    var index: usize = 0;
    while (index < text.len) : (index += 1) {
        const byte = text[index];
        if (byte == ' ') {
            if (value == 0) continue;
            break;
        }
        if (byte < '0' or byte > '9') break;
        value = value *% 10 +% (byte - '0');
    }
    return value;
}

/// Walks the members of a Microsoft archive. Malformed member headers stop the
/// walk exactly like the reference loop.
pub fn parseMembers(gpa: std.mem.Allocator, blob: []const u8) !std.ArrayList(Member) {
    var members: std.ArrayList(Member) = .empty;
    errdefer members.deinit(gpa);
    if (blob.len < archive_magic.len or !std.mem.eql(u8, blob[0..archive_magic.len], archive_magic)) return members;

    var position: usize = archive_magic.len;
    while (position + archive_header_size <= blob.len) {
        const header = blob[position..][0..archive_header_size];
        if (header[58] != '`' or header[59] != '\n') break;

        var name: []const u8 = header[0..archive_name_size];
        if (std.mem.indexOfScalar(u8, name, 0)) |nul| name = name[0..nul];
        while (name.len != 0 and name[name.len - 1] == ' ') {
            name = name[0 .. name.len - 1];
        }

        const size = decimalField(header[archive_size_offset..][0..archive_size_size]);
        const data_offset = position + archive_header_size;
        if (size > blob.len - data_offset) break;
        try members.append(gpa, .{ .name = name, .data = blob[data_offset..][0..size] });
        // Members are padded to a 2-byte boundary.
        position = data_offset + size + (size & 1);
    }
    return members;
}

fn readLe16(bytes: []const u8, offset: usize) u16 {
    return @as(u16, bytes[offset]) | (@as(u16, bytes[offset + 1]) << 8);
}

/// COFF short-import object: ordinal/hint at 16, type at 18, then the symbol
/// and DLL names as consecutive NUL-terminated strings.
pub fn parseShortImport(data: []const u8) ?ShortImport {
    if (data.len < 22) return null;
    const ordinal = readLe16(data, 16);
    const import_type = readLe16(data, 18) & 0x3;
    const strings = data[20..];
    const symbol_length = std.mem.indexOfScalar(u8, strings, 0) orelse return null;
    const after_symbol = strings[symbol_length + 1 ..];
    const dll_length = std.mem.indexOfScalar(u8, after_symbol, 0) orelse after_symbol.len;
    return .{
        .symbol = strings[0..symbol_length],
        .dll = after_symbol[0..dll_length],
        .ordinal = ordinal,
        .import_type = import_type,
    };
}

fn moduleForBase(base: []const u8) []const u8 {
    if (std.ascii.eqlIgnoreCase(base, "xboxkrnl")) return "xboxkrnl.exe";
    if (std.ascii.eqlIgnoreCase(base, "xbdm")) return "xbdm.xex";
    return "";
}

fn trimModuleSuffix(module: []const u8) []const u8 {
    var text = module;
    if (std.mem.indexOfScalar(u8, text, '@')) |at| text = text[0..at];
    while (text.len != 0 and (text[text.len - 1] == ' ' or text[text.len - 1] == '\t')) {
        text = text[0 .. text.len - 1];
    }
    return text;
}

/// Name -> (module, ordinal, isVar) across every `*.lib` in the XDK lib dir.
pub fn buildOrdinalIndex(gpa: std.mem.Allocator, io: std.Io, xdk_lib_dir: []const u8) !Index {
    var index = Index.init(gpa);
    errdefer index.deinit();

    for (supplemental) |symbol| {
        try index.add(symbol.name, "xboxkrnl.exe", symbol.ordinal, false);
    }

    // The reference treats an unopenable directory as an empty range.
    var dir = std.Io.Dir.cwd().openDir(io, xdk_lib_dir, .{ .iterate = true }) catch return index;
    defer dir.close(io);

    var iterator = dir.iterate();
    while (try iterator.next(io)) |entry| {
        if (entry.kind == .directory) continue;
        if (entry.name.len < 4 or !std.ascii.eqlIgnoreCase(entry.name[entry.name.len - 4 ..], ".lib")) continue;
        const stem = entry.name[0 .. entry.name.len - 4];

        // The reference readFile yields an empty blob when a library cannot be
        // opened, so skip it rather than aborting the whole directory scan.
        const blob = dir.readFileAlloc(io, entry.name, gpa, .limited(1 << 40)) catch continue;
        defer gpa.free(blob);

        var members = try parseMembers(gpa, blob);
        defer members.deinit(gpa);
        for (members.items) |member| {
            if (std.mem.eql(u8, member.name, "/") or std.mem.eql(u8, member.name, "//")) continue;
            if (member.data.len >= 2 and readLe16(member.data, 0) == image_file_machine_powerpcbe) continue;
            const import = parseShortImport(member.data) orelse continue;
            if (import.ordinal == 0) continue;

            var module = trimModuleSuffix(import.dll);
            if (module.len == 0) module = moduleForBase(stem);
            if (module.len == 0) continue;
            try index.add(import.symbol, module, import.ordinal, import.isVariable());
        }
    }
    return index;
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

pub fn splitNames(gpa: std.mem.Allocator, text: []const u8) !std.ArrayList([]const u8) {
    var names: std.ArrayList([]const u8) = .empty;
    errdefer names.deinit(gpa);
    var start: usize = 0;
    while (start <= text.len) {
        const comma = std.mem.indexOfScalarPos(u8, text, start, ',');
        const end = comma orelse text.len;
        if (end > start) try names.append(gpa, text[start..end]);
        if (comma == null) break;
        start = end + 1;
    }
    return names;
}

fn moduleOffset(resolution: *const Resolution, module: []const u8) ?usize {
    for (resolution.modules.items, 0..) |candidate, index| {
        if (std.mem.eql(u8, candidate, module)) return index;
    }
    return null;
}

/// Preserves module insertion order and name order within a module.
pub fn resolve(gpa: std.mem.Allocator, index: *const Index, names: []const []const u8) !Resolution {
    var resolution = Resolution{};
    errdefer resolution.deinit(gpa);

    for (names) |name| {
        const import = index.map.get(name) orelse {
            try resolution.unresolved.append(gpa, name);
            continue;
        };
        var module_index = moduleOffset(&resolution, import.module);
        if (module_index == null) {
            try resolution.modules.append(gpa, import.module);
            try resolution.entries.append(gpa, .empty);
            module_index = resolution.modules.items.len - 1;
        }
        try resolution.entries.items[module_index.?].append(gpa, .{
            .name = name,
            .ordinal = import.ordinal,
            .is_var = import.is_var,
        });
    }
    return resolution;
}

// ---------------------------------------------------------------------------
// Emitters
// ---------------------------------------------------------------------------

fn appendLine(out: *std.ArrayList(u8), gpa: std.mem.Allocator, first: *bool, line: []const u8) !void {
    if (!first.*) try out.append(gpa, '\n');
    first.* = false;
    try out.appendSlice(gpa, line);
}

fn appendFmtLine(out: *std.ArrayList(u8), gpa: std.mem.Allocator, first: *bool, comptime fmt: []const u8, args: anytype) !void {
    if (!first.*) try out.append(gpa, '\n');
    first.* = false;
    try out.print(gpa, fmt, args);
}

fn recordFor(module_index: usize, entry: Entry) u32 {
    // Module number in the high half, export ordinal in the low half.
    return (@as(u32, @intCast(module_index)) << 16) | (entry.ordinal & 0xFFFF);
}

pub fn emitStubs(gpa: std.mem.Allocator, resolution: *const Resolution) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var first = true;

    try appendLine(&out, gpa, &first, "# Generated import thunks -- do not edit.");
    try appendLine(&out, gpa, &first, "    .section .kthunks,\"ax\"");
    try appendLine(&out, gpa, &first, "");
    for (resolution.modules.items, 0..) |_, module_index| {
        for (resolution.entries.items[module_index].items) |entry| {
            if (entry.is_var) continue;
            const record = recordFor(module_index, entry);
            try appendFmtLine(&out, gpa, &first, "    .globl {s}", .{entry.name});
            try appendFmtLine(&out, gpa, &first, "{s}:", .{entry.name});
            try appendFmtLine(&out, gpa, &first, "    .long 0x{X:0>8}, 0x{X:0>8}, 0x7D6903A6, 0x4E800420", .{
                0x01000000 | record,
                0x02000000 | record,
            });
            try appendLine(&out, gpa, &first, "");
        }
    }
    try appendLine(&out, gpa, &first, "    .section .kvars,\"aw\"");
    try appendLine(&out, gpa, &first, "");
    for (resolution.modules.items, 0..) |_, module_index| {
        for (resolution.entries.items[module_index].items) |entry| {
            const record = recordFor(module_index, entry);
            try appendFmtLine(&out, gpa, &first, "    .globl __imp_{s}", .{entry.name});
            if (entry.is_var) {
                try appendFmtLine(&out, gpa, &first, "    .globl {s}", .{entry.name});
                try appendLine(&out, gpa, &first, "    .p2align 2");
                try appendFmtLine(&out, gpa, &first, "{s}:", .{entry.name});
            }
            try appendFmtLine(&out, gpa, &first, "__imp_{s}:", .{entry.name});
            try appendFmtLine(&out, gpa, &first, "    .long 0x{X:0>8}", .{record});
            try appendLine(&out, gpa, &first, "");
        }
    }
    return out.toOwnedSlice(gpa);
}

pub fn emitManifest(gpa: std.mem.Allocator, resolution: *const Resolution) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);

    try out.print(gpa, "{{\n  \"libraries\": [\n", .{});
    for (resolution.modules.items, 0..) |module, module_index| {
        try out.print(gpa, "    {{\n      \"module\": \"{s}\",\n      \"records\": [\n", .{module});
        var record_count: usize = 0;
        for (resolution.entries.items[module_index].items) |entry| {
            record_count += if (entry.is_var) 1 else 2;
        }
        var written: usize = 0;
        for (resolution.entries.items[module_index].items) |entry| {
            try out.print(gpa, "        \"__imp_{s}\"", .{entry.name});
            written += 1;
            if (!entry.is_var) {
                try out.append(gpa, ',');
                try out.print(gpa, "\n        \"{s}\"", .{entry.name});
                written += 1;
            }
            if (written < record_count) try out.append(gpa, ',');
            try out.append(gpa, '\n');
        }
        try out.print(gpa, "      ]\n    }}", .{});
        if (module_index + 1 < resolution.modules.items.len) try out.append(gpa, ',');
        try out.append(gpa, '\n');
    }
    try out.print(gpa, "  ]\n}}", .{});
    return out.toOwnedSlice(gpa);
}

pub fn writeSummary(out: anytype, out_path: []const u8, resolution: *const Resolution) !void {
    var total: usize = 0;
    var variables: usize = 0;
    for (resolution.entries.items, 0..) |_, module_index| {
        for (resolution.entries.items[module_index].items) |entry| {
            total += 1;
            if (entry.is_var) variables += 1;
        }
    }
    try out.print("{s}: {d} imports across {d} module(s)", .{ out_path, total, resolution.modules.items.len });
    if (variables != 0) try out.print(" ({d} variable)", .{variables});
    try out.writeAll("\n");
    for (resolution.modules.items, 0..) |module, module_index| {
        try out.print("  {s}: ", .{module});
        for (resolution.entries.items[module_index].items, 0..) |entry, entry_index| {
            try out.print("{s}{s}(0x{X}{s})", .{
                if (entry_index == 0) "" else ", ",
                entry.name,
                entry.ordinal,
                if (entry.is_var) "/var" else "",
            });
        }
        try out.writeAll("\n");
    }
    if (resolution.unresolved.items.len != 0) {
        try out.writeAll("  unresolved (not kernel imports): ");
        for (resolution.unresolved.items, 0..) |name, index| {
            try out.print("{s}{s}", .{ if (index == 0) "" else ", ", name });
        }
        try out.writeAll("\n");
    }
}

// ---------------------------------------------------------------------------
// "genstubs" sub-command
// ---------------------------------------------------------------------------

fn writeOutput(io: std.Io, path: []const u8, bytes: []const u8) bool {
    std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = bytes }) catch return false;
    return true;
}

fn runInternal(gpa: std.mem.Allocator, io: std.Io, args: []const []const u8, out: anytype, errw: anytype) !u8 {
    var xdk: []const u8 = "";
    var names: []const u8 = "";
    var output_path: []const u8 = "stubs.s";
    var manifest_path: []const u8 = "";

    var index: usize = 2;
    while (index < args.len) : (index += 1) {
        const argument = args[index];
        if (std.mem.eql(u8, argument, "--xdk")) {
            if (index + 1 < args.len) {
                index += 1;
                xdk = args[index];
            }
        } else if (std.mem.eql(u8, argument, "--names")) {
            if (index + 1 < args.len) {
                index += 1;
                names = args[index];
            }
        } else if (std.mem.eql(u8, argument, "-o") or std.mem.eql(u8, argument, "--out")) {
            if (index + 1 < args.len) {
                index += 1;
                output_path = args[index];
            }
        } else if (std.mem.eql(u8, argument, "--manifest")) {
            if (index + 1 < args.len) {
                index += 1;
                manifest_path = args[index];
            }
        } else if (std.mem.eql(u8, argument, "-h") or std.mem.eql(u8, argument, "--help")) {
            try out.writeAll(genstubs_usage);
            return 1;
        }
    }

    if (xdk.len == 0 or names.len == 0) {
        try errw.writeAll("genstubs: --xdk and --names are required\n");
        return 1;
    }

    const derived_manifest = if (manifest_path.len != 0)
        null
    else if (std.mem.lastIndexOfScalar(u8, output_path, '.')) |dot|
        try std.fmt.allocPrint(gpa, "{s}.imports.json", .{output_path[0..dot]})
    else
        try std.fmt.allocPrint(gpa, "{s}.imports.json", .{output_path});
    defer if (derived_manifest) |path| gpa.free(path);
    if (derived_manifest) |path| manifest_path = path;

    var ordinal_index = try buildOrdinalIndex(gpa, io, xdk);
    defer ordinal_index.deinit();

    var undefined_names = try splitNames(gpa, names);
    defer undefined_names.deinit(gpa);

    var resolution = try resolve(gpa, &ordinal_index, undefined_names.items);
    defer resolution.deinit(gpa);

    const stubs = try emitStubs(gpa, &resolution);
    defer gpa.free(stubs);
    if (!writeOutput(io, output_path, stubs)) {
        try out.print("genstubs: cannot write {s}\n", .{output_path});
        return 1;
    }

    const manifest = try emitManifest(gpa, &resolution);
    defer gpa.free(manifest);
    if (!writeOutput(io, manifest_path, manifest)) {
        try out.print("genstubs: cannot write {s}\n", .{manifest_path});
        return 1;
    }

    try writeSummary(out, output_path, &resolution);
    return 0;
}

pub fn run(io: std.Io, args: []const []const u8, out: anytype) !u8 {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    return runWithAllocator(arena.allocator(), io, args, out);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn buildArchive(gpa: std.mem.Allocator, members: []const Member) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.appendSlice(gpa, archive_magic);
    for (members) |member| {
        const header_start = out.items.len;
        try out.appendNTimes(gpa, ' ', archive_header_size);
        const header = out.items[header_start..][0..archive_header_size];
        @memcpy(header[0..@min(member.name.len, archive_name_size)], member.name[0..@min(member.name.len, archive_name_size)]);
        var size_text: [archive_size_size]u8 = @splat(' ');
        const size_string = try std.fmt.bufPrint(&size_text, "{d}", .{member.data.len});
        @memcpy(header[archive_size_offset..][0..size_string.len], size_string);
        header[58] = '`';
        header[59] = '\n';
        try out.appendSlice(gpa, member.data);
        if (member.data.len % 2 != 0) try out.append(gpa, '\n');
    }
    return out.toOwnedSlice(gpa);
}

fn buildShortImport(gpa: std.mem.Allocator, symbol: []const u8, dll: []const u8, ordinal: u16, import_type: u16) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.appendNTimes(gpa, 0, 20);
    var raw: [2]u8 = undefined;
    std.mem.writeInt(u16, &raw, ordinal, .little);
    @memcpy(out.items[16..18], &raw);
    std.mem.writeInt(u16, &raw, import_type, .little);
    @memcpy(out.items[18..20], &raw);
    try out.appendSlice(gpa, symbol);
    try out.append(gpa, 0);
    try out.appendSlice(gpa, dll);
    try out.append(gpa, 0);
    return out.toOwnedSlice(gpa);
}

test "parseMembers walks an archive and honours two-byte alignment" {
    const gpa = testing.allocator;
    const members = [_]Member{
        .{ .name = "/", .data = "linker" },
        .{ .name = "abc.obj/", .data = "odd" },
        .{ .name = "def.obj/", .data = "even" },
    };
    const blob = try buildArchive(gpa, &members);
    defer gpa.free(blob);

    var parsed = try parseMembers(gpa, blob);
    defer parsed.deinit(gpa);
    try testing.expectEqual(@as(usize, 3), parsed.items.len);
    try testing.expectEqualStrings("/", parsed.items[0].name);
    try testing.expectEqualStrings("linker", parsed.items[0].data);
    try testing.expectEqualStrings("abc.obj/", parsed.items[1].name);
    try testing.expectEqualStrings("odd", parsed.items[1].data);
    try testing.expectEqualStrings("even", parsed.items[2].data);

    var not_archive = try parseMembers(gpa, "nope");
    defer not_archive.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), not_archive.items.len);
}

test "parseShortImport reads ordinal, type, symbol and DLL" {
    const gpa = testing.allocator;
    const data = try buildShortImport(gpa, "KeTlsAlloc", "xboxkrnl.exe", 0x152, 1);
    defer gpa.free(data);

    const parsed = parseShortImport(data).?;
    try testing.expectEqualStrings("KeTlsAlloc", parsed.symbol);
    try testing.expectEqualStrings("xboxkrnl.exe", parsed.dll);
    try testing.expectEqual(@as(u16, 0x152), parsed.ordinal);
    try testing.expectEqual(@as(u16, 1), parsed.import_type);
    try testing.expect(parsed.isVariable());

    try testing.expect(parseShortImport(data[0..21]) == null);
    const no_nul: [22]u8 = @splat('x');
    try testing.expect(parseShortImport(&no_nul) == null);
}

test "buildOrdinalIndex resolves libraries and keeps first definition" {
    const gpa = testing.allocator;

    const first_import = try buildShortImport(gpa, "TestFunc", "", 0x200, 0);
    defer gpa.free(first_import);
    const first_data = try buildShortImport(gpa, "TestData", "xam.xex@extra", 0x111, 1);
    defer gpa.free(first_data);
    const duplicate_import = try buildShortImport(gpa, "TestFunc", "xam.xex", 0x999, 0);
    defer gpa.free(duplicate_import);
    const machine_member = try gpa.alloc(u8, 24);
    defer gpa.free(machine_member);
    @memset(machine_member, 0);
    std.mem.writeInt(u16, machine_member[0..2], image_file_machine_powerpcbe, .little);

    const first_members = [_]Member{
        .{ .name = "/", .data = "linker" },
        .{ .name = "a.obj/", .data = first_import },
        .{ .name = "b.obj/", .data = first_data },
        .{ .name = "c.obj/", .data = machine_member },
    };
    const first_lib = try buildArchive(gpa, &first_members);
    defer gpa.free(first_lib);
    const second_members = [_]Member{.{ .name = "d.obj/", .data = duplicate_import }};
    const second_lib = try buildArchive(gpa, &second_members);
    defer gpa.free(second_lib);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "xboxkrnl.LIB", .data = first_lib });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "xam.lib", .data = second_lib });

    const dir_path = try std.fs.path.join(gpa, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer gpa.free(dir_path);
    var index = try buildOrdinalIndex(gpa, std.testing.io, dir_path);
    defer index.deinit();

    const tls = index.map.get("KeTlsAlloc").?;
    try testing.expectEqualStrings("xboxkrnl.exe", tls.module);
    try testing.expectEqual(@as(u32, 0x152), tls.ordinal);

    const function = index.map.get("TestFunc").?;
    try testing.expectEqualStrings("xboxkrnl.exe", function.module);
    try testing.expectEqual(@as(u32, 0x200), function.ordinal);
    try testing.expect(!function.is_var);

    const data_import = index.map.get("TestData").?;
    try testing.expectEqualStrings("xam.xex", data_import.module);
    try testing.expectEqual(@as(u32, 0x111), data_import.ordinal);
    try testing.expect(data_import.is_var);
}

test "emitStubs and emitManifest match the reference formatting" {
    const gpa = testing.allocator;
    var resolution = Resolution{};
    defer resolution.deinit(gpa);
    try resolution.modules.append(gpa, "xboxkrnl.exe");
    var functions: std.ArrayList(Entry) = .empty;
    try functions.append(gpa, .{ .name = "KeTlsAlloc", .ordinal = 0x152, .is_var = false });
    try functions.append(gpa, .{ .name = "KeTlsGetValue", .ordinal = 0x154, .is_var = true });
    try resolution.entries.append(gpa, functions);
    try resolution.modules.append(gpa, "xam.xex");
    var xam_entries: std.ArrayList(Entry) = .empty;
    try xam_entries.append(gpa, .{ .name = "XamFoo", .ordinal = 0x7, .is_var = false });
    try resolution.entries.append(gpa, xam_entries);

    const stubs = try emitStubs(gpa, &resolution);
    defer gpa.free(stubs);
    const expected_stubs =
        "# Generated import thunks -- do not edit.\n" ++
        "    .section .kthunks,\"ax\"\n" ++
        "\n" ++
        "    .globl KeTlsAlloc\n" ++
        "KeTlsAlloc:\n" ++
        "    .long 0x01000152, 0x02000152, 0x7D6903A6, 0x4E800420\n" ++
        "\n" ++
        "    .globl XamFoo\n" ++
        "XamFoo:\n" ++
        "    .long 0x01010007, 0x02010007, 0x7D6903A6, 0x4E800420\n" ++
        "\n" ++
        "    .section .kvars,\"aw\"\n" ++
        "\n" ++
        "    .globl __imp_KeTlsAlloc\n" ++
        "__imp_KeTlsAlloc:\n" ++
        "    .long 0x00000152\n" ++
        "\n" ++
        "    .globl __imp_KeTlsGetValue\n" ++
        "    .globl KeTlsGetValue\n" ++
        "    .p2align 2\n" ++
        "KeTlsGetValue:\n" ++
        "__imp_KeTlsGetValue:\n" ++
        "    .long 0x00000154\n" ++
        "\n" ++
        "    .globl __imp_XamFoo\n" ++
        "__imp_XamFoo:\n" ++
        "    .long 0x00010007\n";
    try testing.expectEqualSlices(u8, expected_stubs, stubs);

    const manifest = try emitManifest(gpa, &resolution);
    defer gpa.free(manifest);
    const expected_manifest =
        "{\n  \"libraries\": [\n" ++
        "    {\n      \"module\": \"xboxkrnl.exe\",\n      \"records\": [\n" ++
        "        \"__imp_KeTlsAlloc\",\n" ++
        "        \"KeTlsAlloc\",\n" ++
        "        \"__imp_KeTlsGetValue\"\n" ++
        "      ]\n    },\n" ++
        "    {\n      \"module\": \"xam.xex\",\n      \"records\": [\n" ++
        "        \"__imp_XamFoo\",\n" ++
        "        \"XamFoo\"\n" ++
        "      ]\n    }\n" ++
        "  ]\n}";
    try testing.expectEqualSlices(u8, expected_manifest, manifest);
}

test "run writes stubs, manifest and the summary" {
    const gpa = testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "libs");
    const dir_path = try std.fs.path.join(gpa, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer gpa.free(dir_path);
    const xdk_path = try std.fs.path.join(gpa, &.{ dir_path, "libs" });
    defer gpa.free(xdk_path);
    const stubs_path = try std.fs.path.join(gpa, &.{ dir_path, "stubs.s" });
    defer gpa.free(stubs_path);
    const manifest_path = try std.fs.path.join(gpa, &.{ dir_path, "stubs.imports.json" });
    defer gpa.free(manifest_path);

    var printed: std.Io.Writer.Allocating = .init(gpa);
    defer printed.deinit();
    const code = try runWithAllocator(gpa, std.testing.io, &.{
        "XexTool", "genstubs", "--xdk", xdk_path, "--names", "KeTlsAlloc,Foo", "-o", stubs_path,
    }, &printed.writer);
    try testing.expectEqual(@as(u8, 0), code);

    const stubs = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, stubs_path, gpa, .limited(1 << 20));
    defer gpa.free(stubs);
    try testing.expectEqualSlices(u8, "# Generated import thunks -- do not edit.\n" ++
        "    .section .kthunks,\"ax\"\n\n" ++
        "    .globl KeTlsAlloc\n" ++
        "KeTlsAlloc:\n" ++
        "    .long 0x01000152, 0x02000152, 0x7D6903A6, 0x4E800420\n\n" ++
        "    .section .kvars,\"aw\"\n\n" ++
        "    .globl __imp_KeTlsAlloc\n" ++
        "__imp_KeTlsAlloc:\n" ++
        "    .long 0x00000152\n", stubs);

    const manifest = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, manifest_path, gpa, .limited(1 << 20));
    defer gpa.free(manifest);
    try testing.expectEqualSlices(u8, "{\n  \"libraries\": [\n" ++
        "    {\n      \"module\": \"xboxkrnl.exe\",\n      \"records\": [\n" ++
        "        \"__imp_KeTlsAlloc\",\n" ++
        "        \"KeTlsAlloc\"\n" ++
        "      ]\n    }\n" ++
        "  ]\n}", manifest);

    const expected = try std.fmt.allocPrint(gpa, "{s}: 1 imports across 1 module(s)\n" ++
        "  xboxkrnl.exe: KeTlsAlloc(0x152)\n" ++
        "  unresolved (not kernel imports): Foo\n", .{stubs_path});
    defer gpa.free(expected);
    try testing.expectEqualStrings(expected, printed.written());
}

test "run preserves the usage text and required-argument error" {
    const gpa = testing.allocator;
    var printed: std.Io.Writer.Allocating = .init(gpa);
    defer printed.deinit();

    const help = try runWithAllocator(gpa, std.testing.io, &.{ "XexTool", "genstubs", "--help" }, &printed.writer);
    try testing.expectEqual(@as(u8, 1), help);
    try testing.expectEqualStrings(genstubs_usage, printed.written());

    printed.clearRetainingCapacity();
    const missing = try runWithAllocator(gpa, std.testing.io, &.{ "XexTool", "genstubs" }, &printed.writer);
    try testing.expectEqual(@as(u8, 1), missing);
    try testing.expectEqualStrings("genstubs: --xdk and --names are required\n", printed.written());
}

test "splitNames keeps order and skips empty fields" {
    const gpa = testing.allocator;
    var names = try splitNames(gpa, "a,,b,");
    defer names.deinit(gpa);
    try testing.expectEqual(@as(usize, 2), names.items.len);
    try testing.expectEqualStrings("a", names.items[0]);
    try testing.expectEqualStrings("b", names.items[1]);
}
