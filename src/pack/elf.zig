// SPDX-FileCopyrightText: 2026 XexTool Zig rewrite contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Port of `ElfPacker.cpp`: wrap a linked big-endian PPC ELF in an
//! uncompressed, unencrypted devkit XEX2.
//!
//! The reference packer builds the XEX bytes itself instead of going through
//! `XexWriter` (that writer inserts an 0x80 security gap and recomputes hashes),
//! so byte fidelity requires the same direct layout here.

const std = @import("std");
const endian = @import("../core/endian.zig");

pub const Error = error{ OutOfMemory, PackFailed, WriteFailed };

const page: u32 = 0x1000;
const file_align: u32 = 0x1000;

const key_basefile_format: u32 = 0x000003FF;
const key_entry_point: u32 = 0x00010100;
const key_image_base_address: u32 = 0x00010201;
const key_import_libraries: u32 = 0x000103FF;
const key_original_base_address: u32 = 0x00010001;
const key_checksum_timestamp: u32 = 0x00018002;
const key_tls_info: u32 = 0x00020104;
const key_stack_size: u32 = 0x00020200;
const key_execution_info: u32 = 0x00040006;

const default_stack_size: u32 = 0x40000;
const default_tls_slots: u32 = 64;
const default_title_id: u32 = 0x52584401;
const moduleflag_title_module: u32 = 0x00000001;

const sectioninfo_code: u32 = 1;
const sectioninfo_data: u32 = 2;
const sectioninfo_readonly: u32 = 3;

const shf_write: u32 = 0x1;
const shf_alloc: u32 = 0x2;
const shf_execinstr: u32 = 0x4;
const sht_symtab: u32 = 2;
const sht_nobits: u32 = 8;
const pt_load: u32 = 1;

const pe_machine_powerpcbe: u16 = 0x01F2;
const pe_file_executable_image: u16 = 0x0002;
const pe_file_32bit_machine: u16 = 0x0100;
const pe_optional_magic_pe32: u16 = 0x010B;
const pe_subsystem_xbox: u16 = 14;
const pe_sizeof_optional_header: u32 = 224;
const pe_scn_code: u32 = 0x00000020;
const pe_scn_init_data: u32 = 0x00000040;
const pe_scn_uninit_data: u32 = 0x00000080;
const pe_scn_mem_execute: u32 = 0x20000000;
const pe_scn_mem_read: u32 = 0x40000000;
const pe_scn_mem_write: u32 = 0x80000000;

const pe_e_lfanew: u32 = 0x40;
const pe_coff_header_size: u32 = 20;
const pe_signature_size: u32 = 4;
const pe_section_header_size: u32 = 40;
const pe_data_directory_count: u32 = 16;

/// Reference diagnostics are plain strings printed by the caller, so a failure
/// carries the exact C++ text instead of an enum-only error.
pub const Diagnostic = struct {
    gpa: std.mem.Allocator,
    text: std.ArrayList(u8) = .empty,

    pub fn init(gpa: std.mem.Allocator) Diagnostic {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *Diagnostic) void {
        self.text.deinit(self.gpa);
    }

    pub fn message(self: *const Diagnostic) []const u8 {
        return self.text.items;
    }

    fn fail(self: *Diagnostic, comptime fmt: []const u8, args: anytype) Error {
        self.text.clearRetainingCapacity();
        self.text.print(self.gpa, fmt, args) catch return error.OutOfMemory;
        return error.PackFailed;
    }
};

pub const PageDescriptor = struct {
    pages: u32,
    info: u32,
};

pub const ElfSection = struct {
    name: []const u8,
    vaddr: u32,
    memsize: u32,
    flags: u32,
    typ: u32,
    data: []const u8,
};

pub const Elf = struct {
    base: u32,
    entry: u32,
    sections: std.ArrayList(ElfSection) = .empty,

    pub fn deinit(self: *Elf, gpa: std.mem.Allocator) void {
        self.sections.deinit(gpa);
    }
};

pub const Symbol = struct {
    name: []const u8,
    value: u32,
};

pub const Library = struct {
    module: []const u8,
    records: std.ArrayList([]const u8) = .empty,
};

pub const Manifest = struct {
    libraries: std.ArrayList(Library) = .empty,

    pub fn deinit(self: *Manifest, gpa: std.mem.Allocator) void {
        for (self.libraries.items) |*library| library.records.deinit(gpa);
        self.libraries.deinit(gpa);
    }
};

pub const ResolvedLibrary = struct {
    module: []const u8,
    addresses: []u32,
};

pub const Resolved = struct {
    libraries: std.ArrayList(ResolvedLibrary) = .empty,

    pub fn deinit(self: *Resolved, gpa: std.mem.Allocator) void {
        for (self.libraries.items) |library| gpa.free(library.addresses);
        self.libraries.deinit(gpa);
    }
};

pub const PackOptions = struct {
    has_base: bool = false,
    base: u32 = 0,
    import_manifest: []const u8 = "",
};

// ---------------------------------------------------------------------------
// Byte helpers
// ---------------------------------------------------------------------------

fn putLe16(bytes: *std.ArrayList(u8), gpa: std.mem.Allocator, value: u16) !void {
    var raw: [2]u8 = undefined;
    endian.set16le(&raw, 0, value);
    try bytes.appendSlice(gpa, &raw);
}

fn putLe32(bytes: *std.ArrayList(u8), gpa: std.mem.Allocator, value: u32) !void {
    var raw: [4]u8 = undefined;
    endian.set32le(&raw, 0, value);
    try bytes.appendSlice(gpa, &raw);
}

fn putBe16(bytes: *std.ArrayList(u8), gpa: std.mem.Allocator, value: u16) !void {
    var raw: [2]u8 = undefined;
    endian.set16be(&raw, 0, value);
    try bytes.appendSlice(gpa, &raw);
}

fn putBe32(bytes: *std.ArrayList(u8), gpa: std.mem.Allocator, value: u32) !void {
    var raw: [4]u8 = undefined;
    endian.set32be(&raw, 0, value);
    try bytes.appendSlice(gpa, &raw);
}

fn putZeros(bytes: *std.ArrayList(u8), gpa: std.mem.Allocator, count: usize) !void {
    try bytes.appendNTimes(gpa, 0, count);
}

fn alignUp(value: u32, alignment: u32) u32 {
    return (value +% alignment -% 1) & ~(alignment -% 1);
}

/// Valid at 0x82000000 (64 KiB pages) and above 0x90000000 (4 KiB pages).
fn pageSizeFor(base: u32) u32 {
    return if (base < 0x90000000) 0x10000 else 0x1000;
}

fn readCStringAt(bytes: []const u8, start: u64) []const u8 {
    if (start >= bytes.len) return "";
    // start < bytes.len and fits usize on every supported host.
    const offset: usize = @intCast(start);
    const terminator = std.mem.indexOfScalar(u8, bytes[offset..], 0);
    const end = if (terminator) |relative| offset + relative else bytes.len;
    return bytes[offset..end];
}

// ---------------------------------------------------------------------------
// ELF model
// ---------------------------------------------------------------------------

const sh_field_offset64 = [_]u8{ 0, 4, 8, 16, 24, 32, 40, 44, 48, 56 };
const sh_field_width64 = [_]u8{ 4, 4, 8, 8, 8, 8, 4, 4, 8, 8 };

/// Section-header field by logical index: 0 name, 1 type, 2 flags, 3 addr,
/// 4 offset, 5 size, 6 link, 7 info, 8 addralign, 9 entsize.
fn shField(
    bytes: []const u8,
    shoff: u32,
    shentsize: u32,
    index: u32,
    field: u8,
    is64: bool,
    diag: *Diagnostic,
) Error!u32 {
    const base: u64 = @as(u64, shoff) + @as(u64, index) * @as(u64, shentsize);
    const offset: u64 = if (is64) sh_field_offset64[field] else @as(u64, field) * 4;
    const width: u64 = if (is64) sh_field_width64[field] else 4;
    if (base + offset + width > bytes.len) return diag.fail("ELF section header {d} is truncated", .{index});
    // Bounds checked above; base+offset < bytes.len.
    const position: usize = @intCast(base + offset);
    if (width == 8) {
        // The C++ packer narrows every (<= 4 GiB) ELF64 field to u32.
        return @truncate(endian.get64be(bytes, position));
    }
    return endian.get32be(bytes, position);
}

pub fn readElf(bytes: []const u8, gpa: std.mem.Allocator, diag: *Diagnostic) Error!Elf {
    if (bytes.len < 0x34 or bytes[0] != 0x7f or bytes[1] != 'E' or bytes[2] != 'L' or bytes[3] != 'F') {
        return diag.fail("not an ELF file", .{});
    }
    const is64 = bytes[4] == 2;
    if (bytes[5] != 2 or (bytes[4] != 1 and bytes[4] != 2)) {
        return diag.fail("expected a big-endian 32- or 64-bit ELF (PPC)", .{});
    }
    if (bytes.len < (if (is64) @as(usize, 0x40) else @as(usize, 0x34))) {
        return diag.fail("ELF truncated", .{});
    }

    var e_entry: u32 = undefined;
    var e_phoff: u32 = undefined;
    var e_shoff: u32 = undefined;
    var e_phentsize: u16 = undefined;
    var e_phnum: u16 = undefined;
    var e_shentsize: u16 = undefined;
    var e_shnum: u16 = undefined;
    var e_shstrndx: u16 = undefined;
    if (is64) {
        // Bounds 0x18..0x30 and 0x36..0x40 were checked above.
        e_entry = @truncate(endian.get64be(bytes, 0x18));
        e_phoff = @truncate(endian.get64be(bytes, 0x20));
        e_shoff = @truncate(endian.get64be(bytes, 0x28));
        e_phentsize = endian.get16be(bytes, 0x36);
        e_phnum = endian.get16be(bytes, 0x38);
        e_shentsize = endian.get16be(bytes, 0x3A);
        e_shnum = endian.get16be(bytes, 0x3C);
        e_shstrndx = endian.get16be(bytes, 0x3E);
    } else {
        e_entry = endian.get32be(bytes, 0x18);
        e_phoff = endian.get32be(bytes, 0x1C);
        e_shoff = endian.get32be(bytes, 0x20);
        e_phentsize = endian.get16be(bytes, 0x2A);
        e_phnum = endian.get16be(bytes, 0x2C);
        e_shentsize = endian.get16be(bytes, 0x2E);
        e_shnum = endian.get16be(bytes, 0x30);
        e_shstrndx = endian.get16be(bytes, 0x32);
    }

    // Image base = lowest PT_LOAD vaddr, which `--image-base` set at link time.
    var have_base = false;
    var image_base: u32 = 0;
    var ph_index: u16 = 0;
    while (ph_index < e_phnum) : (ph_index += 1) {
        const offset: u64 = @as(u64, e_phoff) + @as(u64, ph_index) * @as(u64, e_phentsize);
        const needed: u64 = if (is64) 24 else 12;
        if (offset + needed > bytes.len) break;
        // Bounds checked; offset < bytes.len.
        const position: usize = @intCast(offset);
        const p_type = endian.get32be(bytes, position);
        const p_vaddr: u32 = if (is64)
            @truncate(endian.get64be(bytes, position + 16))
        else
            endian.get32be(bytes, position + 8);
        if (p_type == pt_load and (!have_base or p_vaddr < image_base)) {
            image_base = p_vaddr;
            have_base = true;
        }
    }

    if (e_shoff == 0 or e_shstrndx >= e_shnum) {
        return diag.fail("ELF has no section headers", .{});
    }
    const strtab_offset = try shField(bytes, e_shoff, e_shentsize, e_shstrndx, 4, is64, diag);

    var elf = Elf{ .base = 0, .entry = 0 };
    errdefer elf.deinit(gpa);

    const skip = [_][]const u8{ ".comment", ".note", ".ARM." };
    var section_index: u16 = 0;
    while (section_index < e_shnum) : (section_index += 1) {
        const name_offset = try shField(bytes, e_shoff, e_shentsize, section_index, 0, is64, diag);
        const typ = try shField(bytes, e_shoff, e_shentsize, section_index, 1, is64, diag);
        const flags = try shField(bytes, e_shoff, e_shentsize, section_index, 2, is64, diag);
        const addr = try shField(bytes, e_shoff, e_shentsize, section_index, 3, is64, diag);
        const offset = try shField(bytes, e_shoff, e_shentsize, section_index, 4, is64, diag);
        const size = try shField(bytes, e_shoff, e_shentsize, section_index, 5, is64, diag);
        if ((flags & shf_alloc) == 0 or size == 0) continue;

        const name = readCStringAt(bytes, @as(u64, strtab_offset) + name_offset);
        var skipped = false;
        for (skip) |prefix| {
            if (std.mem.startsWith(u8, name, prefix)) {
                skipped = true;
                break;
            }
        }
        if (skipped) continue;

        var data: []const u8 = "";
        if (typ != sht_nobits and @as(u64, offset) + size <= bytes.len) {
            const start: usize = @intCast(offset);
            data = bytes[start..][0..size];
        }
        try elf.sections.append(gpa, .{
            .name = name,
            .vaddr = addr,
            .memsize = size,
            .flags = flags,
            .typ = typ,
            .data = data,
        });
    }

    if (elf.sections.items.len == 0) return diag.fail("no allocatable sections", .{});

    std.mem.sort(ElfSection, elf.sections.items, {}, struct {
        fn lessThan(_: void, lhs: ElfSection, rhs: ElfSection) bool {
            return lhs.vaddr < rhs.vaddr;
        }
    }.lessThan);

    elf.base = if (have_base) image_base else elf.sections.items[0].vaddr;
    elf.entry = e_entry;
    return elf;
}

/// Defined symbols (name -> virtual address) from the ELF symtab.
pub fn readSymbolAddrs(bytes: []const u8, gpa: std.mem.Allocator, out: *std.ArrayList(Symbol), diag: *Diagnostic) Error!void {
    if (bytes.len < 0x40 or bytes[0] != 0x7f or bytes[1] != 'E' or bytes[2] != 'L' or bytes[3] != 'F') {
        return diag.fail("not an ELF file", .{});
    }
    const is64 = bytes[4] == 2;
    if (!is64 and bytes.len < 0x34) return diag.fail("ELF truncated", .{});

    const e_shoff: u32 = if (is64) @truncate(endian.get64be(bytes, 0x28)) else endian.get32be(bytes, 0x20);
    const e_shentsize: u16 = if (is64) endian.get16be(bytes, 0x3A) else endian.get16be(bytes, 0x2E);
    const e_shnum: u16 = if (is64) endian.get16be(bytes, 0x3C) else endian.get16be(bytes, 0x30);

    var sym_offset: u32 = 0;
    var sym_size: u32 = 0;
    var sym_entry: u32 = 0;
    var str_offset: u32 = 0;
    var have = false;
    var index: u16 = 0;
    while (index < e_shnum) : (index += 1) {
        if (try shField(bytes, e_shoff, e_shentsize, index, 1, is64, diag) == sht_symtab) {
            sym_offset = try shField(bytes, e_shoff, e_shentsize, index, 4, is64, diag);
            sym_size = try shField(bytes, e_shoff, e_shentsize, index, 5, is64, diag);
            const link = try shField(bytes, e_shoff, e_shentsize, index, 6, is64, diag);
            sym_entry = try shField(bytes, e_shoff, e_shentsize, index, 9, is64, diag);
            str_offset = try shField(bytes, e_shoff, e_shentsize, link, 4, is64, diag);
            have = true;
        }
    }
    if (!have or sym_entry == 0) return;

    const count = sym_size / sym_entry;
    var symbol_index: u32 = 0;
    while (symbol_index < count) : (symbol_index += 1) {
        const offset: u64 = @as(u64, sym_offset) + @as(u64, symbol_index) * sym_entry;
        const needed: u64 = if (is64) 24 else 16;
        if (offset + needed > bytes.len) return diag.fail("ELF symbol table is truncated", .{});
        // Bounds checked above.
        const position: usize = @intCast(offset);
        const st_name = endian.get32be(bytes, position);
        const st_value: u32 = if (is64)
            @truncate(endian.get64be(bytes, position + 8))
        else
            endian.get32be(bytes, position + 4);
        if (st_name != 0 and st_value != 0) {
            const name = readCStringAt(bytes, @as(u64, str_offset) + st_name);
            try out.append(gpa, .{ .name = name, .value = st_value });
        }
    }
}

// ---------------------------------------------------------------------------
// Little-endian PPC PE32 basefile
// ---------------------------------------------------------------------------

fn peSectionFlags(section: ElfSection) u32 {
    var flags: u32 = pe_scn_mem_read;
    if ((section.flags & shf_execinstr) != 0) {
        flags |= pe_scn_code | pe_scn_mem_execute;
    } else if (section.typ == sht_nobits) {
        flags |= pe_scn_uninit_data;
    } else {
        flags |= pe_scn_init_data;
    }
    if ((section.flags & shf_write) != 0) flags |= pe_scn_mem_write;
    return flags;
}

/// Builds the little-endian PPC PE32 image the XEX loader maps.
pub fn buildPeBasefile(
    gpa: std.mem.Allocator,
    base: u32,
    sections: []const ElfSection,
    entry: u32,
    diag: *Diagnostic,
) Error![]u8 {
    const section_count: u32 = @intCast(sections.len);
    const headers_end = pe_e_lfanew + pe_signature_size + pe_coff_header_size +
        pe_sizeof_optional_header + section_count * pe_section_header_size;
    const size_of_headers = alignUp(headers_end, file_align);

    const page_size = pageSizeFor(base);
    var image_end: u32 = base;
    for (sections) |section| {
        image_end = @max(image_end, section.vaddr +% section.memsize);
    }
    const size_of_image = alignUp(image_end -% base, page_size);

    var code_rva = size_of_headers;
    var size_of_code: u32 = 0;
    var size_of_data: u32 = 0;
    var have_code = false;
    for (sections) |section| {
        if ((section.flags & shf_execinstr) != 0) {
            if (!have_code) {
                code_rva = section.vaddr -% base;
                have_code = true;
            }
            size_of_code +%= @intCast(section.data.len);
        } else {
            size_of_data +%= @intCast(section.data.len);
        }
    }

    for (sections) |section| {
        if ((section.vaddr -% base) < size_of_headers) {
            return diag.fail(
                "section {s} at RVA 0x{X} overlaps the PE headers (0x{X}); link with headroom below the first section",
                .{ section.name, section.vaddr -% base, size_of_headers },
            );
        }
    }

    var image: std.ArrayList(u8) = .empty;
    errdefer image.deinit(gpa);
    try image.appendNTimes(gpa, 0, size_of_image);
    const output = image.items;

    output[0] = 'M';
    output[1] = 'Z';
    output[2] = 0x90;
    output[3] = 0x00;
    endian.set32le(output, 0x3C, pe_e_lfanew);

    var position: usize = pe_e_lfanew;
    endian.set32le(output, position, 0x00004550); // "PE\0\0"
    position += 4;
    endian.set16le(output, position, pe_machine_powerpcbe);
    position += 2;
    endian.set16le(output, position, @intCast(section_count));
    position += 2;
    endian.set32le(output, position, 0);
    position += 4;
    endian.set32le(output, position, 0);
    position += 4;
    endian.set32le(output, position, 0);
    position += 4;
    endian.set16le(output, position, @intCast(pe_sizeof_optional_header));
    position += 2;
    endian.set16le(output, position, pe_file_executable_image | pe_file_32bit_machine);
    position += 2;

    endian.set16le(output, position, pe_optional_magic_pe32);
    position += 2;
    output[position] = 0;
    output[position + 1] = 0;
    position += 2;
    endian.set32le(output, position, size_of_code);
    position += 4;
    endian.set32le(output, position, size_of_data);
    position += 4;
    endian.set32le(output, position, 0);
    position += 4;
    endian.set32le(output, position, entry -% base);
    position += 4;
    endian.set32le(output, position, code_rva);
    position += 4;
    endian.set32le(output, position, 0); // BaseOfData
    position += 4;
    endian.set32le(output, position, base); // ImageBase
    position += 4;
    endian.set32le(output, position, page_size);
    position += 4;
    endian.set32le(output, position, file_align);
    position += 4;
    endian.set16le(output, position, 4); // MajorOperatingSystemVersion
    position += 2;
    position += 10; // Remaining five u16 version words are zero.
    endian.set32le(output, position, 0); // Win32VersionValue
    position += 4;
    endian.set32le(output, position, size_of_image);
    position += 4;
    endian.set32le(output, position, size_of_headers);
    position += 4;
    endian.set32le(output, position, 0); // CheckSum
    position += 4;
    endian.set16le(output, position, pe_subsystem_xbox);
    position += 2;
    endian.set16le(output, position, 0);
    position += 2;
    endian.set32le(output, position, 0x40000);
    position += 4;
    endian.set32le(output, position, 0x1000);
    position += 4;
    endian.set32le(output, position, 0x100000);
    position += 4;
    endian.set32le(output, position, 0x1000);
    position += 4;
    endian.set32le(output, position, 0); // LoaderFlags
    position += 4;
    endian.set32le(output, position, pe_data_directory_count);
    position += 4;

    const directories_offset = position;
    const exception_directory_index: u32 = 3;
    for (sections) |section| {
        if (std.mem.eql(u8, section.name, ".pdata")) {
            const directory = directories_offset + exception_directory_index * 8;
            endian.set32le(output, directory, section.vaddr -% base);
            endian.set32le(output, directory + 4, section.memsize);
            break;
        }
    }
    position += pe_data_directory_count * 8;
    if (position != pe_e_lfanew + pe_signature_size + pe_coff_header_size + pe_sizeof_optional_header) {
        return diag.fail("internal: optional header size", .{});
    }

    var section_headers = position;
    for (sections) |section| {
        const name_length = @min(@as(usize, 8), section.name.len);
        @memcpy(output[section_headers..][0..name_length], section.name[0..name_length]);
        const rva = section.vaddr -% base;
        const raw_size = alignUp(@intCast(section.data.len), file_align);
        endian.set32le(output, section_headers + 8, section.memsize);
        endian.set32le(output, section_headers + 12, rva);
        endian.set32le(output, section_headers + 16, raw_size);
        endian.set32le(output, section_headers + 20, rva); // PointerToRawData = RVA
        endian.set32le(output, section_headers + 24, 0);
        endian.set32le(output, section_headers + 28, 0);
        endian.set16le(output, section_headers + 32, 0);
        endian.set16le(output, section_headers + 34, 0);
        endian.set32le(output, section_headers + 36, peSectionFlags(section));
        section_headers += pe_section_header_size;
    }

    for (sections) |section| {
        if (section.data.len == 0) continue;
        const rva: usize = @intCast(section.vaddr -% base);
        @memcpy(output[rva..][0..section.data.len], section.data);
    }

    return image.toOwnedSlice(gpa);
}

// ---------------------------------------------------------------------------
// XEX2 structures
// ---------------------------------------------------------------------------

fn buildBasefileFormat(gpa: std.mem.Allocator, image_size: u32, zero_size: u32) ![]u8 {
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(gpa);
    try putBe32(&bytes, gpa, 8 + 8);
    try putBe16(&bytes, gpa, 0); // encType: unencrypted
    try putBe16(&bytes, gpa, 1); // compType: uncompressed
    try putBe32(&bytes, gpa, image_size);
    try putBe32(&bytes, gpa, zero_size);
    return bytes.toOwnedSlice(gpa);
}

fn buildExecutionInfo(gpa: std.mem.Allocator, title_id: u32) ![]u8 {
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(gpa);
    try putBe32(&bytes, gpa, 0);
    try putBe32(&bytes, gpa, 0);
    try putBe32(&bytes, gpa, 0);
    try putBe32(&bytes, gpa, title_id);
    try bytes.appendSlice(gpa, &.{ 0, 0, 1, 1 });
    try putBe32(&bytes, gpa, 0);
    return bytes.toOwnedSlice(gpa);
}

const PageInfo = struct {
    descriptors: std.ArrayList(PageDescriptor) = .empty,
    notes: std.ArrayList([]const u8) = .empty,

    fn deinit(self: *PageInfo, gpa: std.mem.Allocator) void {
        self.descriptors.deinit(gpa);
        self.notes.deinit(gpa);
    }
};

fn buildPageDescriptors(
    gpa: std.mem.Allocator,
    base: u32,
    sections: []const ElfSection,
    image_size: u32,
    page_size: u32,
    diag: *Diagnostic,
) Error!PageInfo {
    var info = PageInfo{};
    errdefer info.deinit(gpa);

    const num_pages = image_size / page_size;
    var kinds: std.ArrayList(u32) = .empty;
    defer kinds.deinit(gpa);
    var shared_code_write = false;

    var page_index: u32 = 0;
    while (page_index < num_pages) : (page_index += 1) {
        const lo = page_index * page_size;
        const hi = lo + page_size;
        var has_exec = false;
        var has_write = false;
        for (sections) |section| {
            const section_lo = section.vaddr -% base;
            const section_hi = section_lo +% section.memsize;
            if (section_hi <= lo or section_lo >= hi) continue;
            if ((section.flags & shf_execinstr) != 0) {
                has_exec = true;
            } else if ((section.flags & shf_write) != 0) {
                has_write = true;
            }
        }
        if (has_write and has_exec) shared_code_write = true;
        const kind = if (has_write) sectioninfo_data else if (has_exec) sectioninfo_code else sectioninfo_readonly;
        try kinds.append(gpa, kind);
    }

    var forced = false;
    var have_code = false;
    for (kinds.items) |kind| {
        if (kind == sectioninfo_code) have_code = true;
    }
    if (!have_code and kinds.items.len != 0) {
        kinds.items[0] = sectioninfo_code;
        forced = true;
    }

    // One HV descriptor per page, like ImageXex.
    for (kinds.items) |kind| {
        try info.descriptors.append(gpa, .{ .pages = 1, .info = kind });
    }
    if (shared_code_write) {
        try info.notes.append(gpa, "a writable section shares a page with code; align the writable region (.data/.bss) to the page size to map it read-write");
    }
    if (forced) {
        try info.notes.append(gpa, "no page held only code, so page 0 was forced CODE for the code hash; writable data on that page stays read-only");
    }
    if (info.descriptors.items.len != num_pages) return diag.fail("internal: page descriptor count mismatch", .{});
    return info;
}

fn buildSecurityInfo(
    gpa: std.mem.Allocator,
    image_size: u32,
    load_address: u32,
    sections: []const PageDescriptor,
) ![]u8 {
    var image_info: std.ArrayList(u8) = .empty;
    defer image_info.deinit(gpa);
    try putZeros(&image_info, gpa, 256); // signature
    try putBe32(&image_info, gpa, 0x174); // infoSize
    try putBe32(&image_info, gpa, 0); // imageFlags
    try putBe32(&image_info, gpa, load_address);
    try putZeros(&image_info, gpa, 20); // imageHash
    try putBe32(&image_info, gpa, 0); // importTableCount
    try putZeros(&image_info, gpa, 20); // importHash
    try putZeros(&image_info, gpa, 16); // mediaId
    try putZeros(&image_info, gpa, 16); // imageKey
    try putBe32(&image_info, gpa, 0); // exportTableAddress
    try putZeros(&image_info, gpa, 20); // headerHash
    try putBe32(&image_info, gpa, 0xFFFFFFFF); // gameRegion

    var section_bytes: std.ArrayList(u8) = .empty;
    defer section_bytes.deinit(gpa);
    for (sections) |section| {
        try putBe32(&section_bytes, gpa, (section.pages << 4) | (section.info & 0xF));
        try putZeros(&section_bytes, gpa, 20);
    }

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    const total: u32 = @intCast(0x184 + section_bytes.items.len);
    try putBe32(&out, gpa, total);
    try putBe32(&out, gpa, image_size);
    try out.appendSlice(gpa, image_info.items);
    try putBe32(&out, gpa, 0xFFFFFFFF); // allowedMediaTypes
    try putBe32(&out, gpa, @intCast(sections.len)); // sectionCount
    try out.appendSlice(gpa, section_bytes.items);
    return out.toOwnedSlice(gpa);
}

fn moduleId(module: []const u8) u32 {
    if (std.mem.eql(u8, module, "xboxkrnl.exe")) return 0x45DC17E0;
    if (std.mem.eql(u8, module, "xam.xex")) return 0xFCA15C76;
    if (std.mem.eql(u8, module, "xbdm.xex")) return 0xECEB8109;
    return 0;
}

fn buildImportLibraries(gpa: std.mem.Allocator, imports: []const ResolvedLibrary) ![]u8 {
    var name_data: std.ArrayList(u8) = .empty;
    defer name_data.deinit(gpa);
    for (imports) |library| {
        try name_data.appendSlice(gpa, library.module);
        try name_data.append(gpa, 0);
        while (name_data.items.len % 4 != 0) try name_data.append(gpa, 0);
    }

    var libs: std.ArrayList(u8) = .empty;
    defer libs.deinit(gpa);
    for (imports, 0..) |library, index| {
        const count: u32 = @intCast(library.addresses.len);
        try putBe32(&libs, gpa, 0x28 + count * 4);
        try putZeros(&libs, gpa, 0x14); // next_import_digest
        try putBe32(&libs, gpa, moduleId(library.module)); // HV export-table id
        try putBe32(&libs, gpa, 0x20530800); // version v2.0.21256
        try putBe32(&libs, gpa, 0x20074500); // min v2.0.1861
        try putBe16(&libs, gpa, @intCast(index)); // name_index
        try putBe16(&libs, gpa, @intCast(count));
        for (library.addresses) |address| try putBe32(&libs, gpa, address);
    }

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    const total: u32 = @intCast(12 + name_data.items.len + libs.items.len);
    try putBe32(&out, gpa, total);
    try putBe32(&out, gpa, @intCast(name_data.items.len));
    try putBe32(&out, gpa, @intCast(imports.len));
    try out.appendSlice(gpa, name_data.items);
    try out.appendSlice(gpa, libs.items);
    return out.toOwnedSlice(gpa);
}

// ---------------------------------------------------------------------------
// Minimal import-manifest JSON reader
// ---------------------------------------------------------------------------

fn nextQuoted(source: []const u8, position: *usize, out: *[]const u8) bool {
    const open = std.mem.indexOfScalarPos(u8, source, position.*, '"') orelse return false;
    const close = std.mem.indexOfScalarPos(u8, source, open + 1, '"') orelse return false;
    out.* = source[open + 1 .. close];
    position.* = close + 1;
    return true;
}

/// Parses `{"libraries":[{"module":"m","records":["a","b"]}]}` as emitted by
/// `gen_import_stubs.py`. Tolerant of whitespace; only this shape is understood.
pub fn parseManifest(bytes: []const u8, path: []const u8, gpa: std.mem.Allocator, diag: *Diagnostic) Error!Manifest {
    var manifest = Manifest{};
    errdefer manifest.deinit(gpa);

    var position: usize = 0;
    while (true) {
        const module_marker = std.mem.indexOfPos(u8, bytes, position, "\"module\"") orelse break;
        const colon = std.mem.indexOfScalarPos(u8, bytes, module_marker + 8, ':') orelse
            return diag.fail("manifest: malformed module", .{});
        var cursor = colon;
        var module: []const u8 = undefined;
        if (!nextQuoted(bytes, &cursor, &module)) {
            return diag.fail("manifest: malformed module name", .{});
        }

        const records_marker = std.mem.indexOfPos(u8, bytes, cursor, "\"records\"") orelse
            return diag.fail("manifest: library has no records", .{});
        const left = std.mem.indexOfScalarPos(u8, bytes, records_marker, '[');
        const right = if (left) |begin|
            std.mem.indexOfScalarPos(u8, bytes, begin, ']')
        else
            std.mem.indexOfScalarPos(u8, bytes, records_marker, ']');
        if (left == null or right == null) {
            return diag.fail("manifest: malformed records array", .{});
        }

        var library = Library{ .module = module };
        errdefer library.records.deinit(gpa);
        var record_position = left.? + 1;
        while (record_position < right.?) {
            var record: []const u8 = undefined;
            // nextQuoted must not run past the closing bracket.
            if (!nextQuoted(bytes[0..right.?], &record_position, &record)) break;
            try library.records.append(gpa, record);
        }
        try manifest.libraries.append(gpa, library);
        position = right.? + 1;
    }

    if (manifest.libraries.items.len == 0) {
        return diag.fail("manifest: no libraries found in {s}", .{path});
    }
    return manifest;
}

// ---------------------------------------------------------------------------
// Pack
// ---------------------------------------------------------------------------

fn readFileOrFail(io: std.Io, gpa: std.mem.Allocator, path: []const u8, diag: *Diagnostic) Error![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(1 << 40)) catch
        diag.fail("cannot open {s}", .{path});
}

fn resolveImports(
    gpa: std.mem.Allocator,
    libraries: []const Library,
    symbols: []const Symbol,
    elf_path: []const u8,
    diag: *Diagnostic,
) Error!Resolved {
    var resolved = Resolved{};
    errdefer resolved.deinit(gpa);

    for (libraries) |library| {
        const addresses = try gpa.alloc(u32, library.records.items.len);
        errdefer gpa.free(addresses);
        for (library.records.items, 0..) |wanted, index| {
            var found = false;
            for (symbols) |symbol| {
                if (std.mem.eql(u8, symbol.name, wanted)) {
                    addresses[index] = symbol.value;
                    found = true;
                    break;
                }
            }
            if (!found) {
                return diag.fail("import symbol '{s}' not found in {s}", .{ wanted, elf_path });
            }
        }
        try resolved.libraries.append(gpa, .{ .module = library.module, .addresses = addresses });
    }
    return resolved;
}

const ImageEntry = struct {
    key: u32,
    value: u32,
};

fn entryLessThan(_: void, lhs: ImageEntry, rhs: ImageEntry) bool {
    if (lhs.key != rhs.key) return lhs.key < rhs.key;
    return lhs.value < rhs.value;
}

pub fn packElfToXex(
    gpa: std.mem.Allocator,
    io: std.Io,
    elf_path: []const u8,
    out_path: []const u8,
    options: PackOptions,
    out: anytype,
) Error!void {
    var diag = Diagnostic.init(gpa);
    defer diag.deinit();
    try packElfToXexDiag(gpa, io, elf_path, out_path, options, out, &diag);
}

fn packElfToXexDiag(
    gpa: std.mem.Allocator,
    io: std.Io,
    elf_path: []const u8,
    out_path: []const u8,
    options: PackOptions,
    out: anytype,
    diag: *Diagnostic,
) Error!void {
    const blob = try readFileOrFail(io, gpa, elf_path, diag);
    defer gpa.free(blob);

    var elf = try readElf(blob, gpa, diag);
    defer elf.deinit(gpa);

    if (options.has_base and options.base != elf.base) {
        return diag.fail(
            "ELF is linked at 0x{X:0>8}, not 0x{X:0>8}; link it at the target base instead of overriding here",
            .{ elf.base, options.base },
        );
    }

    var import_block: ?[]u8 = null;
    defer if (import_block) |block| gpa.free(block);
    if (options.import_manifest.len != 0) {
        const manifest_bytes = try readFileOrFail(io, gpa, options.import_manifest, diag);
        defer gpa.free(manifest_bytes);
        var manifest = try parseManifest(manifest_bytes, options.import_manifest, gpa, diag);
        defer manifest.deinit(gpa);

        var symbols: std.ArrayList(Symbol) = .empty;
        defer symbols.deinit(gpa);
        try readSymbolAddrs(blob, gpa, &symbols, diag);

        var resolved = try resolveImports(gpa, manifest.libraries.items, symbols.items, elf_path, diag);
        defer resolved.deinit(gpa);
        import_block = try buildImportLibraries(gpa, resolved.libraries.items);
    }

    const image = try buildPeBasefile(gpa, elf.base, elf.sections.items, elf.entry, diag);
    defer gpa.free(image);

    const page_size = pageSizeFor(elf.base);
    const pages = @as(u32, @intCast(image.len)) / page_size;
    const basefile_format = try buildBasefileFormat(gpa, @intCast(image.len), 0);
    defer gpa.free(basefile_format);

    var page_info = try buildPageDescriptors(gpa, elf.base, elf.sections.items, @intCast(image.len), page_size, diag);
    defer page_info.deinit(gpa);

    const security = try buildSecurityInfo(gpa, @intCast(image.len), elf.base, page_info.descriptors.items);
    defer gpa.free(security);

    const checksum_timestamp = try gpa.alloc(u8, 8);
    defer gpa.free(checksum_timestamp);
    @memset(checksum_timestamp, 0);

    var tls = std.ArrayList(u8).empty;
    defer tls.deinit(gpa);
    try putBe32(&tls, gpa, default_tls_slots);
    try putBe32(&tls, gpa, 0);
    try putBe32(&tls, gpa, 0);
    try putBe32(&tls, gpa, 0);

    const execution_info = try buildExecutionInfo(gpa, default_title_id);
    defer gpa.free(execution_info);

    const OffBlock = struct {
        key: u32,
        data: []const u8,
    };
    var off_blocks: std.ArrayList(OffBlock) = .empty;
    defer off_blocks.deinit(gpa);
    try off_blocks.append(gpa, .{ .key = key_basefile_format, .data = basefile_format });
    try off_blocks.append(gpa, .{ .key = key_checksum_timestamp, .data = checksum_timestamp });
    try off_blocks.append(gpa, .{ .key = key_tls_info, .data = tls.items });
    try off_blocks.append(gpa, .{ .key = key_execution_info, .data = execution_info });
    if (import_block) |block| try off_blocks.append(gpa, .{ .key = key_import_libraries, .data = block });

    const n_entries: u32 = @intCast(4 + off_blocks.items.len);
    const header_size: u32 = 0x18 + n_entries * 8;
    const security_offset = header_size;
    var cursor: u32 = security_offset + @as(u32, @intCast(security.len));
    var block_offsets: std.ArrayList(u32) = .empty;
    defer block_offsets.deinit(gpa);
    for (off_blocks.items) |block| {
        try block_offsets.append(gpa, cursor);
        cursor +%= @intCast(block.data.len);
    }
    const basefile_offset = alignUp(cursor, page);

    var directory: std.ArrayList(ImageEntry) = .empty;
    defer directory.deinit(gpa);
    try directory.append(gpa, .{ .key = key_entry_point, .value = elf.entry });
    try directory.append(gpa, .{ .key = key_image_base_address, .value = elf.base });
    try directory.append(gpa, .{ .key = key_original_base_address, .value = elf.base });
    try directory.append(gpa, .{ .key = key_stack_size, .value = default_stack_size });
    for (off_blocks.items, 0..) |block, index| {
        try directory.append(gpa, .{ .key = block.key, .value = block_offsets.items[index] });
    }
    std.mem.sort(ImageEntry, directory.items, {}, entryLessThan);

    var file: std.ArrayList(u8) = .empty;
    defer file.deinit(gpa);
    try file.appendSlice(gpa, "XEX2");
    try putBe32(&file, gpa, moduleflag_title_module);
    try putBe32(&file, gpa, basefile_offset);
    try putBe32(&file, gpa, 0); // sizeOfDiscardableHeaders
    try putBe32(&file, gpa, security_offset);
    try putBe32(&file, gpa, n_entries);
    for (directory.items) |entry| {
        try putBe32(&file, gpa, entry.key);
        try putBe32(&file, gpa, entry.value);
    }
    if (file.items.len != security_offset) return diag.fail("internal: header size", .{});
    try file.appendSlice(gpa, security);
    for (off_blocks.items) |block| try file.appendSlice(gpa, block.data);
    if (file.items.len > basefile_offset) return diag.fail("internal: basefile offset", .{});
    try putZeros(&file, gpa, basefile_offset - @as(u32, @intCast(file.items.len)));
    try file.appendSlice(gpa, image);

    std.Io.Dir.cwd().writeFile(io, .{ .sub_path = out_path, .data = file.items }) catch
        return diag.fail("cannot write {s}", .{out_path});

    try out.print(
        "wrote {s}: base 0x{X:0>8} entry 0x{X:0>8} image {d} bytes ({d} pages), file {d} bytes\n",
        .{ out_path, elf.base, elf.entry, image.len, pages, file.items.len },
    );
    try out.writeAll("  pages:");
    for (page_info.descriptors.items, 0..) |descriptor, index| {
        const label = if (descriptor.info == sectioninfo_code)
            "CODE"
        else if (descriptor.info == sectioninfo_data)
            "RWDATA"
        else
            "RODATA";
        try out.print("{s} {d}x{s}", .{ if (index != 0) "," else "", descriptor.pages, label });
    }
    try out.writeAll("\n");
    for (page_info.notes.items) |note| try out.print("  note: {s}\n", .{note});
}

// ---------------------------------------------------------------------------
// "pack" sub-command
// ---------------------------------------------------------------------------

const pack_usage =
    "Usage:    XexTool pack <input.elf> -o <output.xex> [options]\n" ++
    "\n" ++
    "Wrap a linked big-endian PPC ELF executable (32- or 64-bit class) in an\n" ++
    "uncompressed, unencrypted devkit\n" ++
    "XEX2 (the form a debug kit loads without a signature).\n" ++
    "\n" ++
    "Options:\n" ++
    "          -o, --out <file>          output xex (required)\n" ++
    "          --base <addr>             load base, e.g. 0x82000000 (default: from the ELF)\n" ++
    "          --import-manifest <file>  JSON import manifest (module -> records),\n" ++
    "                                    as produced by gen_import_stubs.py / mktitle.py\n" ++
    "          -h, --help                show this help\n";

/// `strtoul(value, NULL, 0)`: leading space, optional sign, 0x / 0 / decimal.
/// Trailing junk is ignored, overflow saturates at ULONG_MAX, result truncates to u32.
fn parseCUnsigned(text: []const u8) u32 {
    var index: usize = 0;
    while (index < text.len and std.ascii.isWhitespace(text[index])) index += 1;
    var negative = false;
    if (index < text.len and (text[index] == '+' or text[index] == '-')) {
        negative = text[index] == '-';
        index += 1;
    }
    var radix: u64 = 10;
    if (index + 1 < text.len and text[index] == '0' and (text[index + 1] == 'x' or text[index + 1] == 'X')) {
        radix = 16;
        index += 2;
    } else if (index < text.len and text[index] == '0') {
        radix = 8;
        index += 1;
    }
    var value: u64 = 0;
    var overflow = false;
    while (index < text.len) : (index += 1) {
        const digit = std.fmt.charToDigit(text[index], @intCast(radix)) catch break;
        const product = @mulWithOverflow(value, radix);
        const sum = @addWithOverflow(product[0], digit);
        if (product[1] != 0 or sum[1] != 0) {
            overflow = true;
            value = std.math.maxInt(u64);
            continue;
        }
        value = sum[0];
    }
    if (overflow) value = std.math.maxInt(u64);
    if (negative) value = 0 -% value;
    return @truncate(value);
}

pub fn runWithAllocator(gpa: std.mem.Allocator, io: std.Io, args: []const []const u8, out: anytype) !u8 {
    var input: []const u8 = "";
    var output_path: []const u8 = "";
    var manifest: []const u8 = "";
    var options = PackOptions{};

    var index: usize = 2;
    while (index < args.len) : (index += 1) {
        const argument = args[index];
        const is_help = std.mem.eql(u8, argument, "-h") or std.mem.eql(u8, argument, "--help");
        if (is_help) {
            try out.writeAll(pack_usage);
            return 0;
        }
        if (std.mem.eql(u8, argument, "-o") or std.mem.eql(u8, argument, "--out")) {
            if (index + 1 >= args.len) {
                try out.writeAll(pack_usage);
                return 1;
            }
            index += 1;
            output_path = args[index];
        } else if (std.mem.eql(u8, argument, "--base")) {
            if (index + 1 >= args.len) {
                try out.writeAll(pack_usage);
                return 1;
            }
            index += 1;
            options.base = parseCUnsigned(args[index]);
            options.has_base = true;
        } else if (std.mem.eql(u8, argument, "--import-manifest")) {
            if (index + 1 >= args.len) {
                try out.writeAll(pack_usage);
                return 1;
            }
            index += 1;
            manifest = args[index];
        } else if (argument.len != 0 and argument[0] == '-') {
            try out.print("Unknown option: {s}\n\n{s}", .{ argument, pack_usage });
            return 1;
        } else if (input.len == 0) {
            input = argument;
        } else {
            try out.print("Unexpected argument: {s}\n\n{s}", .{ argument, pack_usage });
            return 1;
        }
    }

    if (input.len == 0 or output_path.len == 0) {
        if (input.len == 0) {
            try out.writeAll("error: no input ELF given\n\n");
        } else {
            try out.writeAll("error: no output given (use -o)\n\n");
        }
        try out.writeAll(pack_usage);
        return 1;
    }

    options.import_manifest = manifest;
    var diagnostics = Diagnostic.init(gpa);
    defer diagnostics.deinit();
    packElfToXexDiag(gpa, io, input, output_path, options, out, &diagnostics) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.PackFailed => {
            try out.print("pack failed: {s}\n", .{diagnostics.message()});
            return 1;
        },
        error.WriteFailed => return error.WriteFailed,
    };
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

fn writeShdr32(output: []u8, offset: *u32, header: [10]u32) void {
    for (header, 0..) |word, index| {
        endian.set32be(output, offset.* + @as(u32, @intCast(index)) * 4, word);
    }
    offset.* += 40;
}

fn buildTestElf32(gpa: std.mem.Allocator) ![]u8 {
    const shstr = "\x00.text\x00.data\x00.bss\x00.comment\x00.shstrtab\x00.symtab\x00.strtab\x00";
    const strtab = "\x00KeTlsAlloc\x00foo_data\x00";
    const text_offset: u32 = 0x54;
    const data_offset: u32 = text_offset + 8;
    const shstr_offset: u32 = data_offset + 4;
    const strtab_offset: u32 = shstr_offset + @as(u32, @intCast(shstr.len));
    const symtab_offset: u32 = strtab_offset + @as(u32, @intCast(strtab.len));
    const shoff: u32 = symtab_offset + 3 * 16;

    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(gpa);
    try bytes.appendNTimes(gpa, 0, shoff + 8 * 40);
    const output = bytes.items;

    output[0] = 0x7f;
    output[1] = 'E';
    output[2] = 'L';
    output[3] = 'F';
    output[4] = 1; // ELFCLASS32
    output[5] = 2; // ELFDATA2MSB
    output[6] = 1;
    endian.set16be(output, 0x10, 2); // ET_EXEC
    endian.set16be(output, 0x12, 20); // EM_PPC
    endian.set32be(output, 0x14, 1);
    endian.set32be(output, 0x18, 0x82010004); // e_entry
    endian.set32be(output, 0x1C, 0x34); // e_phoff
    endian.set32be(output, 0x20, shoff);
    endian.set16be(output, 0x28, 0x34);
    endian.set16be(output, 0x2A, 32);
    endian.set16be(output, 0x2C, 1);
    endian.set16be(output, 0x2E, 40);
    endian.set16be(output, 0x30, 8);
    endian.set16be(output, 0x32, 5);

    endian.set32be(output, 0x34, pt_load);
    endian.set32be(output, 0x38, 0);
    endian.set32be(output, 0x3C, 0x82000000);
    endian.set32be(output, 0x40, 0x82000000);
    endian.set32be(output, 0x44, shoff);
    endian.set32be(output, 0x48, shoff);
    endian.set32be(output, 0x4C, 5);
    endian.set32be(output, 0x50, 0x1000);

    @memcpy(output[text_offset..][0..8], &[_]u8{ 0x60, 0x00, 0x00, 0x00, 0x4E, 0x80, 0x00, 0x20 });
    @memcpy(output[data_offset..][0..4], &[_]u8{ 0x12, 0x34, 0x56, 0x78 });
    @memcpy(output[shstr_offset..][0..shstr.len], shstr);
    @memcpy(output[strtab_offset..][0..strtab.len], strtab);

    endian.set32be(output, symtab_offset, 1); // st_name "KeTlsAlloc"
    endian.set32be(output, symtab_offset + 4, 0x82010000); // st_value
    endian.set32be(output, symtab_offset + 8, 8);
    output[symtab_offset + 12] = 0x12;
    endian.set16be(output, symtab_offset + 14, 1);
    const second = symtab_offset + 16;
    endian.set32be(output, second, 12); // st_name "foo_data"
    endian.set32be(output, second + 4, 0x82020000);
    endian.set32be(output, second + 8, 4);
    output[second + 12] = 0x11;
    endian.set16be(output, second + 14, 2);

    var section_header_offset: u32 = shoff;
    writeShdr32(output, &section_header_offset, .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 });
    writeShdr32(output, &section_header_offset, .{ 1, 1, 6, 0x82010000, text_offset, 8, 0, 0, 4, 0 });
    writeShdr32(output, &section_header_offset, .{ 7, 1, 3, 0x82020000, data_offset, 4, 0, 0, 4, 0 });
    writeShdr32(output, &section_header_offset, .{ 13, sht_nobits, 3, 0x82030000, data_offset, 0x100, 0, 0, 4, 0 });
    writeShdr32(output, &section_header_offset, .{ 18, 1, 0, 0, shstr_offset, @intCast(shstr.len), 0, 0, 1, 0 });
    writeShdr32(output, &section_header_offset, .{ 27, 3, 0, 0, shstr_offset, @intCast(shstr.len), 0, 0, 1, 0 });
    writeShdr32(output, &section_header_offset, .{ 37, sht_symtab, 0, 0, symtab_offset, 32, 7, 1, 4, 16 });
    writeShdr32(output, &section_header_offset, .{ 45, 3, 0, 0, strtab_offset, @intCast(strtab.len), 0, 0, 1, 0 });
    return bytes.toOwnedSlice(gpa);
}

fn buildTestElf64(gpa: std.mem.Allocator) ![]u8 {
    const shstr = "\x00.text\x00.shstrtab\x00";
    const shoff: u32 = 0x100;
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(gpa);
    try bytes.appendNTimes(gpa, 0, shoff + 3 * 64);
    const output = bytes.items;

    output[0] = 0x7f;
    output[1] = 'E';
    output[2] = 'L';
    output[3] = 'F';
    output[4] = 2; // ELFCLASS64
    output[5] = 2; // ELFDATA2MSB
    output[6] = 1;
    endian.set16be(output, 0x10, 2);
    endian.set16be(output, 0x12, 21); // EM_PPC64
    endian.set64be(output, 0x18, 0x82001004);
    endian.set64be(output, 0x28, shoff);
    endian.set16be(output, 0x34, 64);
    endian.set16be(output, 0x3A, 64);
    endian.set16be(output, 0x3C, 3);
    endian.set16be(output, 0x3E, 2);

    @memcpy(output[0x40..][0..shstr.len], shstr);
    @memcpy(output[0x50..][0..4], &[_]u8{ 0x11, 0x22, 0x33, 0x44 });

    const text_header = shoff + 64;
    endian.set32be(output, text_header, 1); // name ".text"
    endian.set32be(output, text_header + 4, 1); // SHT_PROGBITS
    endian.set64be(output, text_header + 8, shf_alloc | shf_execinstr);
    endian.set64be(output, text_header + 16, 0x82001000);
    endian.set64be(output, text_header + 24, 0x50);
    endian.set64be(output, text_header + 32, 4);
    endian.set64be(output, text_header + 48, 4);

    const shstr_header = shoff + 128;
    endian.set32be(output, shstr_header, 7); // name ".shstrtab"
    endian.set32be(output, shstr_header + 4, 3); // SHT_STRTAB
    endian.set64be(output, shstr_header + 24, 0x40);
    endian.set64be(output, shstr_header + 32, shstr.len);
    endian.set64be(output, shstr_header + 48, 1);

    return bytes.toOwnedSlice(gpa);
}

test "readElf parses ELF32 sections, base and entry" {
    const gpa = testing.allocator;
    const blob = try buildTestElf32(gpa);
    defer gpa.free(blob);

    var diag = Diagnostic.init(gpa);
    defer diag.deinit();
    var elf = try readElf(blob, gpa, &diag);
    defer elf.deinit(gpa);

    try testing.expectEqual(@as(u32, 0x82000000), elf.base);
    try testing.expectEqual(@as(u32, 0x82010004), elf.entry);
    try testing.expectEqual(@as(usize, 3), elf.sections.items.len);
    try testing.expectEqualStrings(".text", elf.sections.items[0].name);
    try testing.expectEqual(@as(u32, 0x82010000), elf.sections.items[0].vaddr);
    try testing.expectEqual(@as(u32, 8), elf.sections.items[0].memsize);
    try testing.expectEqualSlices(u8, &.{ 0x60, 0x00, 0x00, 0x00, 0x4E, 0x80, 0x00, 0x20 }, elf.sections.items[0].data);
    try testing.expectEqualStrings(".data", elf.sections.items[1].name);
    try testing.expectEqualStrings(".bss", elf.sections.items[2].name);
    try testing.expectEqual(@as(u32, sht_nobits), elf.sections.items[2].typ);
    try testing.expectEqual(@as(usize, 0), elf.sections.items[2].data.len);
}

test "readElf parses ELF64 ILP32 image with no program headers" {
    const gpa = testing.allocator;
    const blob = try buildTestElf64(gpa);
    defer gpa.free(blob);

    var diag = Diagnostic.init(gpa);
    defer diag.deinit();
    var elf = try readElf(blob, gpa, &diag);
    defer elf.deinit(gpa);

    try testing.expectEqual(@as(u32, 0x82001000), elf.base);
    try testing.expectEqual(@as(u32, 0x82001004), elf.entry);
    try testing.expectEqual(@as(usize, 1), elf.sections.items.len);
    try testing.expectEqualStrings(".text", elf.sections.items[0].name);
    try testing.expectEqualSlices(u8, &.{ 0x11, 0x22, 0x33, 0x44 }, elf.sections.items[0].data);
}

test "readElf reports the reference diagnostics" {
    const gpa = testing.allocator;
    var diag = Diagnostic.init(gpa);
    defer diag.deinit();

    try testing.expectError(error.PackFailed, readElf("nope", gpa, &diag));
    try testing.expectEqualStrings("not an ELF file", diag.message());

    var elf_bytes: [0x40]u8 = @splat(0);
    elf_bytes[0] = 0x7f;
    elf_bytes[1] = 'E';
    elf_bytes[2] = 'L';
    elf_bytes[3] = 'F';
    elf_bytes[4] = 1;
    elf_bytes[5] = 1;
    try testing.expectError(error.PackFailed, readElf(&elf_bytes, gpa, &diag));
    try testing.expectEqualStrings("expected a big-endian 32- or 64-bit ELF (PPC)", diag.message());

    elf_bytes[5] = 2;
    try testing.expectError(error.PackFailed, readElf(&elf_bytes, gpa, &diag));
    try testing.expectEqualStrings("ELF has no section headers", diag.message());
}

test "readSymbolAddrs returns defined symbol virtual addresses" {
    const gpa = testing.allocator;
    const blob = try buildTestElf32(gpa);
    defer gpa.free(blob);

    var diag = Diagnostic.init(gpa);
    defer diag.deinit();
    var symbols: std.ArrayList(Symbol) = .empty;
    defer symbols.deinit(gpa);
    try readSymbolAddrs(blob, gpa, &symbols, &diag);

    try testing.expectEqual(@as(usize, 2), symbols.items.len);
    try testing.expectEqualStrings("KeTlsAlloc", symbols.items[0].name);
    try testing.expectEqual(@as(u32, 0x82010000), symbols.items[0].value);
    try testing.expectEqualStrings("foo_data", symbols.items[1].name);
    try testing.expectEqual(@as(u32, 0x82020000), symbols.items[1].value);
}

test "buildPeBasefile emits the little-endian PPC PE32 image" {
    const gpa = testing.allocator;
    const blob = try buildTestElf32(gpa);
    defer gpa.free(blob);
    var diag = Diagnostic.init(gpa);
    defer diag.deinit();
    var elf = try readElf(blob, gpa, &diag);
    defer elf.deinit(gpa);

    const image = try buildPeBasefile(gpa, elf.base, elf.sections.items, elf.entry, &diag);
    defer gpa.free(image);

    try testing.expectEqual(@as(usize, 0x40000), image.len);
    try testing.expectEqualSlices(u8, &.{ 'M', 'Z', 0x90, 0x00 }, image[0..4]);
    try testing.expectEqual(@as(u32, 0x40), endian.get32le(image, 0x3C));
    try testing.expectEqual(@as(u32, 0x00004550), endian.get32le(image, 0x40));
    try testing.expectEqual(@as(u16, pe_machine_powerpcbe), endian.get16le(image, 0x44));
    try testing.expectEqual(@as(u16, 3), endian.get16le(image, 0x46));
    try testing.expectEqual(@as(u16, pe_sizeof_optional_header), endian.get16le(image, 0x54));
    try testing.expectEqual(@as(u16, pe_optional_magic_pe32), endian.get16le(image, 0x58));
    try testing.expectEqual(@as(u32, 0x82000000), endian.get32le(image, 0x74)); // ImageBase
    try testing.expectEqual(@as(u32, 0x10000), endian.get32le(image, 0x78)); // SectionAlignment
    try testing.expectEqual(@as(u32, 0x40000), endian.get32le(image, 0x90)); // SizeOfImage
    try testing.expectEqual(@as(u32, 0x1000), endian.get32le(image, 0x94)); // SizeOfHeaders

    const section_table = 0x58 + pe_sizeof_optional_header;
    try testing.expectEqualStrings(".text", image[section_table..][0..5]);
    try testing.expectEqual(@as(u32, 0x10000), endian.get32le(image, section_table + 12));
    try testing.expectEqual(@as(u32, 0x1000), endian.get32le(image, section_table + 16));
    try testing.expectEqual(@as(u32, 0x60000020), endian.get32le(image, section_table + 36));
    try testing.expectEqual(@as(u32, 0xC0000040), endian.get32le(image, section_table + 40 + 36));
    try testing.expectEqual(@as(u32, 0xC0000080), endian.get32le(image, section_table + 80 + 36));
    try testing.expectEqualSlices(u8, &.{ 0x60, 0x00, 0x00, 0x00, 0x4E, 0x80, 0x00, 0x20 }, image[0x10000..][0..8]);
}

test "parseManifest reads modules and records in order" {
    const gpa = testing.allocator;
    const text =
        "{\n  \"libraries\": [\n" ++
        "    {\n      \"module\": \"xboxkrnl.exe\",\n      \"records\": [\n        \"__imp_A\",\n        \"A\"\n      ]\n    },\n" ++
        "    {\n      \"module\": \"xam.xex\",\n      \"records\": [ \"B\" ]\n    }\n" ++
        "  ]\n}";
    var diag = Diagnostic.init(gpa);
    defer diag.deinit();
    var manifest = try parseManifest(text, "m.json", gpa, &diag);
    defer manifest.deinit(gpa);

    try testing.expectEqual(@as(usize, 2), manifest.libraries.items.len);
    try testing.expectEqualStrings("xboxkrnl.exe", manifest.libraries.items[0].module);
    try testing.expectEqual(@as(usize, 2), manifest.libraries.items[0].records.items.len);
    try testing.expectEqualStrings("__imp_A", manifest.libraries.items[0].records.items[0]);
    try testing.expectEqualStrings("A", manifest.libraries.items[0].records.items[1]);
    try testing.expectEqualStrings("xam.xex", manifest.libraries.items[1].module);
    try testing.expectEqualStrings("B", manifest.libraries.items[1].records.items[0]);
}

test "parseManifest rejects malformed input with the reference text" {
    const gpa = testing.allocator;
    var diag = Diagnostic.init(gpa);
    defer diag.deinit();

    try testing.expectError(error.PackFailed, parseManifest("{}", "empty.json", gpa, &diag));
    try testing.expectEqualStrings("manifest: no libraries found in empty.json", diag.message());

    try testing.expectError(error.PackFailed, parseManifest("{\"module\"}", "bad.json", gpa, &diag));
    try testing.expectEqualStrings("manifest: malformed module", diag.message());

    try testing.expectError(error.PackFailed, parseManifest("{\"module\":\"x\"}", "bad.json", gpa, &diag));
    try testing.expectEqualStrings("manifest: library has no records", diag.message());
}

test "buildImportLibraries writes names, ids, versions and records" {
    const gpa = testing.allocator;
    var addresses = [_]u32{ 0x82001000, 0x82002000 };
    const libraries = [_]ResolvedLibrary{
        .{ .module = "xboxkrnl.exe", .addresses = &addresses },
        .{ .module = "xam.xex", .addresses = &[_]u32{} },
    };
    const block = try buildImportLibraries(gpa, &libraries);
    defer gpa.free(block);

    const name_data_size = 16 + 8; // 14-byte name padded, then 8-byte name padded
    try testing.expectEqual(@as(u32, 124), endian.get32be(block, 0));
    try testing.expectEqual(@as(u32, name_data_size), endian.get32be(block, 4));
    try testing.expectEqual(@as(u32, 2), endian.get32be(block, 8));
    try testing.expectEqualStrings("xboxkrnl.exe", block[12..24]);
    try testing.expectEqual(@as(u8, 0), block[26]);
    try testing.expectEqualStrings("xam.xex", block[28..35]);

    const first = 12 + name_data_size;
    try testing.expectEqual(@as(u32, 0x28 + 8), endian.get32be(block, first));
    try testing.expectEqual(@as(u32, 0x45DC17E0), endian.get32be(block, first + 0x18));
    try testing.expectEqual(@as(u32, 0x20530800), endian.get32be(block, first + 0x1C));
    try testing.expectEqual(@as(u32, 0x20074500), endian.get32be(block, first + 0x20));
    try testing.expectEqual(@as(u16, 0), endian.get16be(block, first + 0x24));
    try testing.expectEqual(@as(u16, 2), endian.get16be(block, first + 0x26));
    try testing.expectEqual(@as(u32, 0x82001000), endian.get32be(block, first + 0x28));
    try testing.expectEqual(@as(u32, 0x82002000), endian.get32be(block, first + 0x2C));
}

test "packElfToXex round-trips a minimal ELF into the reference layout" {
    const gpa = testing.allocator;
    const elf_blob = try buildTestElf32(gpa);
    defer gpa.free(elf_blob);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "in.elf", .data = elf_blob });

    const dir_path = try std.fs.path.join(gpa, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer gpa.free(dir_path);
    const elf_path = try std.fs.path.join(gpa, &.{ dir_path, "in.elf" });
    defer gpa.free(elf_path);
    const out_path = try std.fs.path.join(gpa, &.{ dir_path, "out.xex" });
    defer gpa.free(out_path);

    var printed: std.Io.Writer.Allocating = .init(gpa);
    defer printed.deinit();
    try packElfToXex(gpa, std.testing.io, elf_path, out_path, .{}, &printed.writer);

    const file = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, out_path, gpa, .limited(1 << 24));
    defer gpa.free(file);

    try testing.expectEqual(@as(usize, 0x41000), file.len);
    try testing.expectEqualSlices(u8, "XEX2", file[0..4]);
    try testing.expectEqual(@as(u32, moduleflag_title_module), endian.get32be(file, 0x04));
    try testing.expectEqual(@as(u32, 0x1000), endian.get32be(file, 0x08));
    try testing.expectEqual(@as(u32, 0), endian.get32be(file, 0x0C));
    try testing.expectEqual(@as(u32, 0x58), endian.get32be(file, 0x10));
    try testing.expectEqual(@as(u32, 8), endian.get32be(file, 0x14));

    const keys = [_]u32{ 0x000003FF, 0x00010001, 0x00010100, 0x00010201, 0x00018002, 0x00020104, 0x00020200, 0x00040006 };
    for (keys, 0..) |key, index| {
        try testing.expectEqual(key, endian.get32be(file, 0x18 + index * 8));
    }
    try testing.expectEqual(@as(u32, 0x82010004), endian.get32be(file, 0x18 + 2 * 8 + 4));
    try testing.expectEqual(@as(u32, 0x82000000), endian.get32be(file, 0x18 + 3 * 8 + 4));
    try testing.expectEqual(@as(u32, 0x00040000), endian.get32be(file, 0x18 + 6 * 8 + 4));

    try testing.expectEqual(@as(u32, 0x1E4), endian.get32be(file, 0x58));
    try testing.expectEqual(@as(u32, 0x40000), endian.get32be(file, 0x5C));
    try testing.expectEqual(@as(u32, 0x174), endian.get32be(file, 0x58 + 0x108));
    try testing.expectEqual(@as(u32, 0x82000000), endian.get32be(file, 0x58 + 0x110));
    try testing.expectEqual(@as(u32, 0xFFFFFFFF), endian.get32be(file, 0x58 + 0x17C));
    try testing.expectEqual(@as(u32, 4), endian.get32be(file, 0x58 + 0x180));
    try testing.expectEqual(@as(u32, 1 << 4 | sectioninfo_readonly), endian.get32be(file, 0x58 + 0x184));
    try testing.expectEqual(@as(u32, 1 << 4 | sectioninfo_code), endian.get32be(file, 0x58 + 0x184 + 0x18));

    try testing.expectEqualSlices(u8, "MZ", file[0x1000..0x1002]);
    try testing.expectEqual(@as(u32, 0x40), endian.get32le(file, 0x103C));
    try testing.expectEqual(@as(u32, 0x00004550), endian.get32le(file, 0x1040));
    try testing.expectEqual(@as(u16, 3), endian.get16le(file, 0x1046));
    try testing.expectEqual(@as(u32, 0x82000000), endian.get32le(file, 0x1074));
    try testing.expectEqual(@as(u32, 0x40000), endian.get32le(file, 0x1090));

    const expected = try std.fmt.allocPrint(gpa, "wrote {s}: base 0x82000000 entry 0x82010004 image 262144 bytes (4 pages), file 266240 bytes\n" ++
        "  pages: 1xRODATA, 1xCODE, 1xRWDATA, 1xRWDATA\n", .{out_path});
    defer gpa.free(expected);
    try testing.expectEqualStrings(expected, printed.written());
}

test "run parses options and preserves the help text" {
    const gpa = testing.allocator;
    var printed: std.Io.Writer.Allocating = .init(gpa);
    defer printed.deinit();

    const help = try runWithAllocator(gpa, std.testing.io, &.{ "XexTool", "pack", "--help" }, &printed.writer);
    try testing.expectEqual(@as(u8, 0), help);
    try testing.expectEqualStrings(pack_usage, printed.written());

    printed.clearRetainingCapacity();
    const missing = try runWithAllocator(gpa, std.testing.io, &.{ "XexTool", "pack" }, &printed.writer);
    try testing.expectEqual(@as(u8, 1), missing);
    try testing.expect(std.mem.startsWith(u8, printed.written(), "error: no input ELF given\n\nUsage:    XexTool pack"));

    printed.clearRetainingCapacity();
    const unknown = try runWithAllocator(gpa, std.testing.io, &.{ "XexTool", "pack", "--bogus" }, &printed.writer);
    try testing.expectEqual(@as(u8, 1), unknown);
    try testing.expect(std.mem.startsWith(u8, printed.written(), "Unknown option: --bogus\n\nUsage:    XexTool pack"));
}

test "parseCUnsigned follows strtoul base 0" {
    try testing.expectEqual(@as(u32, 0x82000000), parseCUnsigned("0x82000000"));
    try testing.expectEqual(@as(u32, 0x82000000), parseCUnsigned("0X82000000"));
    try testing.expectEqual(@as(u32, 8), parseCUnsigned("010"));
    try testing.expectEqual(@as(u32, 42), parseCUnsigned("  +42junk"));
    try testing.expectEqual(@as(u32, 0), parseCUnsigned("zzz"));
    try testing.expectEqual(@as(u32, 0xFFFFFFFF), parseCUnsigned("-1"));
}
