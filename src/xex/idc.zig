// SPDX-FileCopyrightText: 2026 XexTool Zig rewrite contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Port of `XexTool/src/XexIdcCreator.cpp`: writes the IDA IDC script that
//! rebuilds the basefile layout (sections, resources, imports, exports).

const std = @import("std");
const DataBlock = @import("../core/datablock.zig").DataBlock;
const endian = @import("../core/endian.zig");
const file = @import("../core/file.zig");
const model = @import("model.zig");

/// The C++ splits each library into 0x100-import IDC functions because IDA
/// cannot handle bigger script functions.
const imports_per_func: u32 = 0x100;

const section_flag_execute: u32 = 0x20000000;
const section_flag_read: u32 = 0x40000000;
const section_flag_write: u32 = 0x80000000;

// IMAGE_DOS_HEADER / IMAGE_FILE_HEADER / IMAGE_SECTION_HEADER offsets.
// src/xex/pe.zig reads NumberOfSections at e_lfanew + 8 where the C++ reads
// e_lfanew + 4 + offsetof(IMAGE_FILE_HEADER, NumberOfSections) = e_lfanew + 6,
// so the section table is read here with the C++ offsets.
const dos_lfanew_offset: usize = 0x3C;
const pe_signature_size: usize = 4;
const file_header_size: usize = 0x14;
const section_header_size: usize = 0x28;
const file_header_section_count_offset: usize = 0x02;
const file_header_optional_size_offset: usize = 0x10;
const section_virtual_size_offset: usize = 0x08;
const section_virtual_address_offset: usize = 0x0C;
const section_characteristics_offset: usize = 0x24;

const Section = struct {
    name: [8]u8,
    virtual_size: u32,
    virtual_address: u32,
    characteristics: u32,
};

// XexHvExportTable (XexDefines.h); funcAddrs[1] ends at 0x30.
const hv_export_image_base: u32 = 0x20;
const hv_export_count: u32 = 0x24;
const hv_export_base: u32 = 0x28;
const hv_export_func_addrs: u32 = 0x2C;
const hv_export_header_size: u32 = 0x30;

// ExportByNameTable (XexImageEntryTypes.h). The C++ reads these with the
// host-native DataBlock::get32/get16; the reference host is little-endian.
const ebn_ordinal_base: u32 = 0x10;
const ebn_func_addrs: u32 = 0x1C;
const ebn_func_names: u32 = 0x20;
const ebn_num_names: u32 = 0x18;
const ebn_name_ordinals: u32 = 0x24;

const script_header =
    "//\n" ++
    "// Xbox360 Basefile Info - Created by XexTool\n" ++
    "//\n" ++
    "\n" ++
    "#include <idc.idc>\n" ++
    "#include <x360_imports.idc>\n" ++
    "\n" ++
    "\n";

const make_name_force_script =
    "static MakeNameForce(addr, name)\n" ++
    "{\n" ++
    "    auto num, name_fixed;\n" ++
    "    if( MakeNameEx(addr, name, SN_NOWARN) )\n" ++
    "        return;\n" ++
    "    for(num=0; num<999; num++)\n" ++
    "    {\n" ++
    "        name_fixed = form(\"%s_%d\", name, num);\n" ++
    "        if( MakeNameEx(addr, name_fixed, SN_NOWARN) )\n" ++
    "            return;\n" ++
    "    }\n" ++
    "}\n" ++
    "\n";

const get_section_addr_script =
    "static GetSectionAddr(sectName)\n" ++
    "{\n" ++
    "\tauto seg_addr, seg_base;\n" ++
    "\tseg_base = SegByName(sectName);\n" ++
    "\treturn SegByBase(seg_base);\n" ++
    "}\n" ++
    "\n";

const setup_section_script =
    "static SetupSection(startAddr, endAddr, segClass, perms, name, base)\n" ++
    "{\n" ++
    "    SetSelector(base, 0);\n" ++
    "    SegCreate(startAddr, endAddr, base, 1, 3, 2);\n" ++
    "    SegClass(startAddr, segClass);\n" ++
    "    SegRename(startAddr, name);\n" ++
    "    SetSegmentAttr(startAddr, SEGATTR_PERM, perms); // 4=read, 2=write, 1=execute\n" ++
    "    SetSegmentAttr(startAddr, SEGATTR_FLAGS, 0x10); // SFL_LOADER\n" ++
    "    SegDefReg(startAddr, \"%r26\", 0);\n" ++
    "    SegDefReg(startAddr, \"%r27\", 0);\n" ++
    "    SegDefReg(startAddr, \"%r28\", 0);\n" ++
    "    SegDefReg(startAddr, \"%r29\", 0);\n" ++
    "    SegDefReg(startAddr, \"%r30\", 0);\n" ++
    "    SegDefReg(startAddr, \"%r31\", 0);\n" ++
    "}\n" ++
    "\n";

const setup_sections_script =
    "static SetupSections()\n" ++
    "{\n" ++
    "    auto addr;\n\n";

const setup_sections_footer =
    "\n" ++
    "    // remove unused \"leftovers\" of the original binary segment\n" ++
    "    while( (addr = SegByBase(0)) != BADADDR )\n" ++
    "        DelSeg(addr, SEGMOD_KILL|SEGMOD_SILENT);\n" ++
    "}\n" ++
    "\n";

const setup_resources_script =
    "static SetupResources()\n" ++
    "{\n";

const setup_resources_footer =
    "}\n" ++
    "\n";

const remove_empty_sections_script =
    "static RemoveEmptySections()\n" ++
    "{\n" ++
    "    auto seg_addr, seg_num;\n" ++
    "    for(seg_num=0; seg_num<500; seg_num=seg_num+1)\n" ++
    "    {\n" ++
    "        seg_addr = GetSectionAddr(form( \"seg%03d\", seg_num) );\n" ++
    "        if(seg_addr != -1)\n" ++
    "            SegDelete(seg_addr, 1);\n" ++
    "    }\n" ++
    "}\n" ++
    "\n" ++
    "\n";

const setup_import_func_script =
    "static SetupImportFunc(importAddr, funcAddr, importNum, name)\n" ++
    "{\n" ++
    "    auto func_name;\n" ++
    "    func_name = DoNameGen(name, 0, importNum);\n" ++
    "\n" ++
    "    MakeNameForce(importAddr, \"__imp__\" + func_name);\n" ++
    "    MakeDword(importAddr);\n" ++
    "\n" ++
    "    PatchWord(funcAddr, 0x3860);\n" ++
    "    PatchWord(funcAddr + 4, 0x3880);\n" ++
    "    MakeUnknown(funcAddr, 0x10, 0); // DOUNK_SIMPLE\n" ++
    "    MakeCode(funcAddr);\n" ++
    "    MakeNameForce(funcAddr, func_name);\n" ++
    "    MakeFunction(funcAddr, funcAddr + 0x10);\n" ++
    "    SetFunctionFlags(funcAddr, FUNC_LIB);\n" ++
    "}\n" ++
    "\n";

const setup_import_data_script =
    "static SetupImportData(importAddr, importNum, name)\n" ++
    "{\n" ++
    "    auto data_name;\n" ++
    "    data_name = DoNameGen(name, 0, importNum);\n" ++
    "\n" ++
    "    MakeNameForce(importAddr, data_name);\n" ++
    "    MakeDword(importAddr);\n" ++
    "}\n" ++
    "\n";

const setup_imports_script =
    "static SetupImports()\n" ++
    "{\n";

const setup_imports_footer =
    "}\n" ++
    "\n" ++
    "\n";

const setup_export_func_script =
    "static SetupExportFunc(funcAddr, exportNum, funcName)\n" ++
    "{\n" ++
    "    MakeUnkn(funcAddr, 0);\n" ++
    "    MakeCode(funcAddr); \n" ++
    "    MakeNameForce(funcAddr, funcName);\n" ++
    "    MakeFunction(funcAddr, BADADDR);\n" ++
    "    AddEntryPoint(exportNum, funcAddr, funcName, 1);\n" ++
    "}\n" ++
    "\n";

const setup_export_data_script =
    "static SetupExportData(dataAddr, exportNum, name)\n" ++
    "{\n" ++
    "    auto data_name;\n" ++
    "    data_name = DoNameGen(name, 0, exportNum);\n" ++
    "\n" ++
    "    AddEntryPoint(exportNum, dataAddr, data_name, 0);\n" ++
    "    MakeNameForce(dataAddr, data_name);\n" ++
    "    MakeDword(dataAddr);\n" ++
    "}\n" ++
    "\n";

const setup_exports_script =
    "static SetupExports()\n" ++
    "{\n" ++
    "    auto name;\n" ++
    "    name = GetInputFile();\n" ++
    "\n";

const setup_exports_footer =
    "}\n" ++
    "\n";

const setup_exports_by_name_script =
    "static SetupExportsByName()\n" ++
    "{\n";

const setup_exports_by_name_footer =
    "}\n" ++
    "\n";

const setup_reg_saves_script =
    "static SetupRegSaves()\n" ++
    "{\n" ++
    "\tauto currAddr, i;\n" ++
    "\t\n" ++
    "\t// find all saves of gp regs\n" ++
    "\tfor(currAddr=0; currAddr != BADADDR; currAddr=currAddr+4)\n" ++
    "\t{\n" ++
    "\t\t// find \"std %r14, -0x98(%sp)\" followed by \"std %r15, -0x90(%sp)\"\n" ++
    "\t\tcurrAddr = FindBinary(currAddr, SEARCH_DOWN, \"F9 C1 FF 68 F9 E1 FF 70\");\n" ++
    "\t\tif(currAddr == BADADDR)\n" ++
    "\t\t\tbreak;\n" ++
    "\t\tfor(i=14; i<=31; i++)\n" ++
    "\t\t{\n" ++
    "\t\t\tMakeUnknown(currAddr, 4, 0); // DOUNK_SIMPLE\n" ++
    "\t\t\tMakeCode(currAddr);\n" ++
    "\t\t\tif(i != 31)\n" ++
    "\t\t\t\tMakeFunction(currAddr, currAddr + 4);\n" ++
    "\t\t\telse\n" ++
    "\t\t\t\tMakeFunction(currAddr, currAddr + 0x0C);\n" ++
    "\t\t\tMakeNameForce(currAddr, form(\"__savegprlr_%d\", i));\n" ++
    "\t\t\tcurrAddr = currAddr + 4;\n" ++
    "\t\t}\n" ++
    "\t}\n" ++
    "\t\n" ++
    "\t// find all loads of gp regs\n" ++
    "\tfor(currAddr=0; currAddr != BADADDR; currAddr=currAddr+4)\n" ++
    "\t{\n" ++
    "\t\t// find \"ld  %r14, var_98(%sp)\" followed by \"ld  %r15, var_90(%sp)\"\n" ++
    "\t\tcurrAddr = FindBinary(currAddr, SEARCH_DOWN, \"E9 C1 FF 68 E9 E1 FF 70\");\n" ++
    "\t\tif(currAddr == BADADDR)\n" ++
    "\t\t\tbreak;\n" ++
    "\t\tfor(i=14; i<=31; i++)\n" ++
    "\t\t{\n" ++
    "\t\t\tMakeUnknown(currAddr, 4, 0); // DOUNK_SIMPLE\n" ++
    "\t\t\tMakeCode(currAddr);\n" ++
    "\t\t\tif(i != 31)\n" ++
    "\t\t\t\tMakeFunction(currAddr, currAddr + 4);\n" ++
    "\t\t\telse\n" ++
    "\t\t\t\tMakeFunction(currAddr, currAddr + 0x10);\n" ++
    "\t\t\tMakeNameForce(currAddr, form(\"__restgprlr_%d\", i));\n" ++
    "\t\t\tcurrAddr = currAddr + 4;\n" ++
    "\t\t}\n" ++
    "\t}\n" ++
    "}\n" ++
    "\n";

const convert_to_code_script =
    "static ConvertToCode(startAddr, endAddr)\n" ++
    "{\n" ++
    "    auto addr;\n" ++
    "    if(startAddr == BADADDR || endAddr == BADADDR || startAddr>endAddr)\n" ++
    "        return;\n" ++
    "    \n" ++
    "    MakeUnknown(startAddr, endAddr-startAddr, 0); // DOUNK_SIMPLE\n" ++
    "    for(addr=startAddr&0xFFFFFFFC; addr<endAddr; addr=addr+4)\n" ++
    "    {\n" ++
    "        MakeCode(addr);\n" ++
    "    }\n" ++
    "    AnalyzeArea(startAddr, endAddr);\n" ++
    "}\n" ++
    "\n";

const main_script =
    "static main()\n" ++
    "{\n" ++
    "    // ensure file was loaded in as binary\n" ++
    "    // if it was loaded in as PE then addresses will be incorrect\n" ++
    "    if( GetShortPrm(INF_FILETYPE) != FT_BIN )\n" ++
    "    {\n" ++
    "        Warning(\"The file must be loaded as a BINARY file to use this script.\\n\"\n" ++
    "                \"Close this database and create a new one, ensuring you\\n\"\n" ++
    "                \"select \\\"Binary File\\\" on IDAs \\\"Load a new file\\\" dialog.\");\n" ++
    "        return;\n" ++
    "    }\n" ++
    "    \n" ++
    "    // ensure file was loaded in as PPC\n" ++
    "    if( GetCharPrm(INF_PROCNAME+0) != 'P' ||\n" ++
    "        GetCharPrm(INF_PROCNAME+1) != 'P' ||\n" ++
    "        GetCharPrm(INF_PROCNAME+2) != 'C' ||\n" ++
    "        GetCharPrm(INF_PROCNAME+3) != '\\0' )\n" ++
    "    {\n" ++
    "        Warning(\"The file must be loaded for the PPC processor.\\n\"\n" ++
    "                \"Close this database and create a new one, ensuring you\\n\"\n" ++
    "                \"select \\\"PowerPC: ppc\\\" on IDAs \\\"Load a new file\\\" dialog.\");\n" ++
    "        return;\n" ++
    "    }\n" ++
    "\n" ++
    "    // set up resources\n" ++
    "    if( 1 == AskYN(0, \"Would you like to load reources as segments?\") )\n" ++
    "        SetupResources();\n" ++
    "\n" ++
    "    // set up sections\n" ++
    "    SetupSections();\n" ++
    "\n" ++
    "    // remove empty sections\n" ++
    "    RemoveEmptySections();\n" ++
    "\n" ++
    "    // analyse code\n" ++
    "    if( 1 == AskYN(1, \"Would you like to analyse the file as code?\") )\n" ++
    "        ConvertToCode( GetSectionAddr(\".text\"), SegEnd(GetSectionAddr(\".text\")) );\n" ++
    "\n" ++
    "    // set up imports\n" ++
    "    SetupImports();\n" ++
    "\n" ++
    "    // set up exports\n" ++
    "    SetupExports();\n" ++
    "\n" ++
    "    // set up exports by name\n" ++
    "    SetupExportsByName();\n" ++
    "\n" ++
    "    // setup all reg loads/stores\n" ++
    "    SetupRegSaves();\n" ++
    "\n" ++
    "    // done\n" ++
    "    Message(\"done\\n\\n\");\n" ++
    "}\n" ++
    "\n";

/// Writes the IDC script for `xex` to `path`.
pub fn dump(io: std.Io, xex: *const model.Xex, path: []const u8, gpa: std.mem.Allocator) !void {
    var buffer: std.Io.Writer.Allocating = .init(gpa);
    defer buffer.deinit();
    try write(&buffer.writer, xex, gpa);
    try file.writeAll(io, path, buffer.written());
}

/// Writes the IDC script to `writer`. Fails with `error.NotPeBasefile` when the
/// basefile is not a PE image, matching the `false` result of the C++ tool.
pub fn write(writer: *std.Io.Writer, xex: *const model.Xex, gpa: std.mem.Allocator) !void {
    if (!xex.isBasefilePE()) return error.NotPeBasefile;

    const basefile = xex.basefile.data();

    try writer.writeAll(script_header);
    try writer.writeAll(make_name_force_script);
    try writer.writeAll(get_section_addr_script);
    try writer.writeAll(setup_section_script);
    try writer.writeAll(setup_sections_script);
    const section_base = try writeSections(writer, xex, basefile);
    try writer.writeAll(setup_sections_footer);
    try writeResources(writer, xex, section_base);
    try writer.writeAll(remove_empty_sections_script);
    try writer.writeAll(setup_import_func_script);
    try writer.writeAll(setup_import_data_script);
    try writeImportFunctions(writer, xex);
    try writer.writeAll(setup_imports_script);
    try writeImportCalls(writer, xex);
    try writer.writeAll(setup_imports_footer);
    try writer.writeAll(setup_export_func_script);
    try writer.writeAll(setup_export_data_script);
    try writer.writeAll(setup_exports_script);
    try writeExports(writer, xex, gpa);
    try writer.writeAll(setup_exports_footer);
    try writer.writeAll(setup_exports_by_name_script);
    try writeExportsByName(writer, xex, gpa);
    try writer.writeAll(setup_exports_by_name_footer);
    try writer.writeAll(setup_reg_saves_script);
    try writer.writeAll(convert_to_code_script);
    try writer.writeAll(main_script);
}

fn writeSections(writer: *std.Io.Writer, xex: *const model.Xex, basefile: []const u8) !u32 {
    var section_base: u32 = 1;
    const count = sectionCount(basefile) orelse return error.InvalidPe;
    var section_index: u16 = 0;
    while (section_index < count) : (section_index += 1) {
        const section = sectionAt(basefile, section_index) orelse return error.InvalidPeSection;
        const addr = section.virtual_address +% xex.load_address;

        // Sections that start inside a resource are covered by SetupResources.
        if (insideResource(xex, addr)) continue;

        const flags = section.characteristics;
        var perms: u32 = 0;
        if (flags & section_flag_execute != 0) perms |= 1;
        if (flags & section_flag_write != 0) perms |= 2;
        if (flags & section_flag_read != 0) perms |= 4;
        const segment_class: []const u8 = if (flags & section_flag_execute != 0) "CODE" else "DATA";

        try writer.print("    SetupSection(0x{X:0>8}, 0x{X:0>8}, \"{s}\", {d}, \"{s}\", {d});\n", .{
            addr,
            addr +% section.virtual_size,
            segment_class,
            perms,
            std.mem.sliceTo(&section.name, 0),
            section_base,
        });
        section_base += 1;
    }
    return section_base;
}

fn insideResource(xex: *const model.Xex, addr: u32) bool {
    for (xex.resources.items) |resource| {
        const size: u32 = @bitCast(resource.size);
        if (addr >= resource.addr and addr < resource.addr +% size) return true;
    }
    return false;
}

fn writeResources(writer: *std.Io.Writer, xex: *const model.Xex, first_base: u32) !void {
    try writer.writeAll(setup_resources_script);
    var section_base = first_base;
    for (xex.resources.items) |resource| {
        const size: u32 = @bitCast(resource.size);
        try writer.print("    SetupSection(0x{X:0>8}, 0x{X:0>8}, \"DATA\", 4, \"{s}\", {d});\n", .{
            resource.addr,
            resource.addr +% size,
            std.mem.sliceTo(&resource.name, 0),
            section_base,
        });
        section_base += 1;
    }
    try writer.writeAll(setup_resources_footer);
}

fn writeImportFunctions(writer: *std.Io.Writer, xex: *const model.Xex) !void {
    for (xex.import_libraries.items, 0..) |library, library_index| {
        const original_name = libraryName(&library.name);
        const fixed_name = fixedLibraryName(&library.name);
        const num_imports: u64 = library.addresses.len;

        var import_num: u32 = 0;
        while (@as(u64, import_num) < num_imports) {
            try writer.print("static setupImports_{d}_{s}_{d}()\n{{\n", .{
                library_index,
                fixed_name.bytes[0..fixed_name.len],
                import_num / imports_per_func,
            });

            var func_import_num: u32 = 0;
            while (func_import_num < imports_per_func) : (func_import_num += 1) {
                const index = @as(u64, import_num) + func_import_num;
                if (index >= num_imports) break;

                const this_import_addr = importAddress(library.addresses, index);
                const this_import_num = try readBe16(&xex.basefile, (this_import_addr -% xex.load_address) +% 2);

                // The C++ reads the next entry's first byte even when it is one
                // past the end (DataBlock zero fills), and leaves the type 0 at
                // the end of a full 0x100 chunk.
                var next_import_addr: u32 = 0;
                var next_import_type: u8 = 0;
                if (func_import_num + 1 < imports_per_func) {
                    next_import_addr = importAddress(library.addresses, index + 1);
                    next_import_type = try readU8(&xex.basefile, next_import_addr -% xex.load_address);
                }

                if (next_import_type != 0) {
                    try writer.print("    SetupImportFunc(0x{X:0>8}, 0x{X:0>8}, 0x{X:0>3}, \"{s}\");\n", .{
                        this_import_addr,
                        next_import_addr,
                        this_import_num,
                        original_name,
                    });
                    func_import_num += 1;
                } else {
                    try writer.print("    SetupImportData(0x{X:0>8},             0x{X:0>3}, \"{s}\");\n", .{
                        this_import_addr,
                        this_import_num,
                        original_name,
                    });
                }
            }

            try writer.writeAll("}\n\n");

            const next = @as(u64, import_num) + imports_per_func;
            if (next >= num_imports) break;
            import_num = @intCast(next);
        }
    }
}

fn writeImportCalls(writer: *std.Io.Writer, xex: *const model.Xex) !void {
    for (xex.import_libraries.items, 0..) |library, library_index| {
        const fixed_name = fixedLibraryName(&library.name);
        const num_imports: u64 = library.addresses.len;

        var import_num: u32 = 0;
        while (@as(u64, import_num) < num_imports) {
            try writer.print("    setupImports_{d}_{s}_{d}();\n", .{
                library_index,
                fixed_name.bytes[0..fixed_name.len],
                import_num / imports_per_func,
            });
            const next = @as(u64, import_num) + imports_per_func;
            if (next >= num_imports) break;
            import_num = @intCast(next);
        }
    }
}

fn writeExports(writer: *std.Io.Writer, xex: *const model.Xex, gpa: std.mem.Allocator) !void {
    if (xex.export_table_address != 0) {
        const table_address = xex.export_table_address -% xex.load_address;
        const count_raw = try readBe32(&xex.basefile, table_address +% hv_export_count);
        const num_exports: i32 = @bitCast(count_raw);
        if (num_exports < 0) return error.InvalidExportTable;

        // sizeof(XexHvExportTable) + (count - 1) * 4
        const block_size: i64 = @as(i64, hv_export_header_size) + (@as(i64, num_exports) - 1) * 4;
        if (block_size < 0 or block_size > std.math.maxInt(i32)) return error.InvalidExportTable;

        var export_block = DataBlock.init();
        defer export_block.deinit(gpa);
        try export_block.setBlock(gpa, &xex.basefile, try blockOffset(table_address), 0, @intCast(block_size));

        const image_base_addr = (try readBe32(&export_block, hv_export_image_base)) *% 0x10000;
        const ordinal_base_num = try readBe32(&export_block, hv_export_base);

        var export_index: u32 = 0;
        while (export_index < @as(u32, @intCast(num_exports))) : (export_index += 1) {
            const func_addr = try readBe32(&export_block, hv_export_func_addrs + export_index * 4) +% image_base_addr;
            const func_num = ordinal_base_num +% export_index;
            if (func_addr == image_base_addr) continue;
            try writer.print("    SetupExportFunc(0x{X:0>8}, 0x{X:0>3}, DoNameGen(name, 0, 0x{X:0>3}));\n", .{
                func_addr,
                func_num,
                func_num,
            });
        }
    }

    if (xex.hasEntryPoint()) {
        try writer.print("\n    // set start entry point\n    SetupExportFunc(0x{X:0>8}, 0x{X:0>8}, \"start\");\n", .{
            xex.entryPoint(),
            xex.entryPoint(),
        });
    }
}

fn writeExportsByName(writer: *std.Io.Writer, xex: *const model.Xex, gpa: std.mem.Allocator) !void {
    const info = xex.exports_by_name orelse return;
    const block_offset: i32 = @bitCast(info.export_table_offset);
    const block_size: i32 = @bitCast(info.export_table_size);
    if (block_offset < 0 or block_size < 0) return error.InvalidExportTable;

    var block = DataBlock.init();
    defer block.deinit(gpa);
    try block.setBlock(gpa, &xex.basefile, block_offset, 0, block_size);

    // The C++ also reads numberOfFunctions at 0x14 and the module name offset
    // but never uses either value.
    const ordinal_base_num = try readLe32(&block, ebn_ordinal_base);
    const num_export_names = try readLe32(&block, ebn_num_names);
    const func_addr_offset = try readLe32(&block, ebn_func_addrs);
    const func_name_offset = try readLe32(&block, ebn_func_names);
    const func_ord_offset = try readLe32(&block, ebn_name_ordinals);

    var export_index: u32 = 0;
    while (export_index < num_export_names) : (export_index += 1) {
        const func_addr = try readLe32(&block, func_addr_offset +% export_index *% 4) +% xex.load_address;
        const func_num = @as(u32, try readLe16(&block, func_ord_offset +% export_index *% 2)) +% ordinal_base_num;

        // The C++ sprintf()s a default name first and then overwrites it with
        // the table bytes. Index 256 stays 0, so an unterminated name is still
        // printable instead of reproducing the C++ over-read.
        var func_name: [257]u8 = @splat(0);
        _ = std.fmt.bufPrint(func_name[0..], "export_by_name_{d}", .{func_num}) catch unreachable; // 257 bytes is enough

        const name_address = try readLe32(&block, func_name_offset +% export_index *% 4);
        var name_index: u32 = 0;
        while (name_index < 256) : (name_index += 1) {
            const byte = try readU8(&block, name_address +% name_index);
            func_name[name_index] = byte;
            if (byte == 0) break;
        }

        try writer.print("    SetupExportFunc(0x{X:0>8}, 0x{X:0>3}, \"{s}\");\n", .{
            func_addr,
            func_num,
            std.mem.sliceTo(&func_name, 0),
        });
    }
}

fn peHeaderOffset(basefile: []const u8) ?usize {
    if (basefile.len < dos_lfanew_offset + 4) return null;
    const e_lfanew: usize = endian.get32le(basefile, dos_lfanew_offset);
    if (e_lfanew > basefile.len or basefile.len - e_lfanew < pe_signature_size + file_header_size) return null;
    if (basefile[e_lfanew] != 'P' or basefile[e_lfanew + 1] != 'E') return null;
    return e_lfanew + pe_signature_size;
}

/// `PEParser::getNumSections`.
fn sectionCount(basefile: []const u8) ?u16 {
    const pe = peHeaderOffset(basefile) orelse return null;
    return endian.get16le(basefile, pe + file_header_section_count_offset);
}

/// `PEParser::getSectionsOffset` + `getSection`.
fn sectionAt(basefile: []const u8, index: u16) ?Section {
    const pe = peHeaderOffset(basefile) orelse return null;
    const table = pe + file_header_size + endian.get16le(basefile, pe + file_header_optional_size_offset);
    const offset = table + @as(usize, index) * section_header_size;
    if (offset > basefile.len or basefile.len - offset < section_header_size) return null;

    var name: [8]u8 = undefined;
    @memcpy(&name, basefile[offset..][0..8]);
    return .{
        .name = name,
        .virtual_size = endian.get32le(basefile, offset + section_virtual_size_offset),
        .virtual_address = endian.get32le(basefile, offset + section_virtual_address_offset),
        .characteristics = endian.get32le(basefile, offset + section_characteristics_offset),
    };
}

/// `getImportLibrary` copies at most 63 bytes and forces `name[63] = 0`.
fn libraryName(raw: *const [64]u8) []const u8 {
    return std.mem.sliceTo(raw[0..63], 0);
}

const FixedLibraryName = struct {
    bytes: [64]u8 = @splat(0),
    len: usize = 0,
};

fn fixedLibraryName(raw: *const [64]u8) FixedLibraryName {
    const name = libraryName(raw);
    var result: FixedLibraryName = .{ .len = name.len };
    @memcpy(result.bytes[0..name.len], name);
    for (result.bytes[0..name.len]) |*character| {
        if (character.* == '.') character.* = '_';
    }
    return result;
}

fn importAddress(addresses: []const u32, index: u64) u32 {
    const at = std.math.cast(usize, index) orelse return 0; // DataBlock past the end reads zero
    if (at >= addresses.len) return 0;
    return addresses[at];
}

/// The C++ hands the wrapped u32 difference to a s32 offset. A negative result
/// cannot occur for a valid XEX (addresses are at or above the load address).
fn blockOffset(address: u32) !i32 {
    const offset: i32 = @bitCast(address);
    if (offset < 0) return error.InvalidOffset;
    return offset;
}

fn readBe16(block: *const DataBlock, address: u32) !u16 {
    return block.get16be(try blockOffset(address));
}

fn readBe32(block: *const DataBlock, address: u32) !u32 {
    return block.get32be(try blockOffset(address));
}

fn readLe16(block: *const DataBlock, address: u32) !u16 {
    return block.get16le(try blockOffset(address));
}

fn readLe32(block: *const DataBlock, address: u32) !u32 {
    return block.get32le(try blockOffset(address));
}

fn readU8(block: *const DataBlock, address: u32) !u8 {
    return block.get8(try blockOffset(address));
}

test "idc: sections and resources share the segment base counter" {
    const allocator = std.testing.allocator;
    var xex = model.Xex.init(allocator);
    defer xex.deinit();
    xex.load_address = 0x82000000;
    try writePe(&xex, allocator, 2, &.{ 0x60000020, 0xC0000040 });
    try xex.resources.append(allocator, .{
        .name = .{ 'r', 'e', 's', 0, 0, 0, 0, 0 },
        .addr = 0x82001000,
        .size = 0x100,
    });

    var buffer: std.Io.Writer.Allocating = .init(allocator);
    defer buffer.deinit();
    try write(&buffer.writer, &xex, allocator);
    const output = buffer.written();

    try std.testing.expect(std.mem.startsWith(u8, output, "//\n// Xbox360 Basefile Info - Created by XexTool\n//\n\n#include <idc.idc>\n"));
    // .text starts inside the resource, so it is skipped; .data gets base 1.
    try std.testing.expectEqual(@as(?usize, null), std.mem.indexOf(u8, output, "SetupSection(0x82001000, 0x82002000"));
    try std.testing.expect(std.mem.indexOf(u8, output, "    SetupSection(0x82002000, 0x82003000, \"DATA\", 6, \".data\", 1);\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "    SetupSection(0x82001000, 0x82001100, \"DATA\", 4, \"res\", 2);\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, output, "    Message(\"done\\n\\n\");\n}\n\n"));
}

test "idc: imports split functions from data references" {
    const allocator = std.testing.allocator;
    var xex = model.Xex.init(allocator);
    defer xex.deinit();
    xex.load_address = 0x82000000;
    try writePe(&xex, allocator, 1, &.{0x60000020});

    const addresses = try allocator.alloc(u32, 4);
    addresses[0] = 0x82000200;
    addresses[1] = 0x82000210;
    addresses[2] = 0x82000220;
    addresses[3] = 0x82000230;
    var name: [64]u8 = @splat(0);
    @memcpy(name[0..12], "xboxkrnl.exe");
    try xex.import_libraries.append(allocator, .{
        .name = name,
        .addresses = addresses,
    });

    try xex.basefile.set16be(allocator, 0x111, 0x202);
    try xex.basefile.set(allocator, &.{0x05}, 0x220, 1);
    try xex.basefile.set16be(allocator, 0x222, 0x212);
    try xex.basefile.set16be(allocator, 0x333, 0x232);

    var buffer: std.Io.Writer.Allocating = .init(allocator);
    defer buffer.deinit();
    try write(&buffer.writer, &xex, allocator);
    const output = buffer.written();

    try std.testing.expect(std.mem.indexOf(u8, output, "static setupImports_0_xboxkrnl_exe_0()\n{\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "    SetupImportData(0x82000200,             0x111, \"xboxkrnl.exe\");\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "    SetupImportFunc(0x82000210, 0x82000220, 0x222, \"xboxkrnl.exe\");\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "    SetupImportData(0x82000230,             0x333, \"xboxkrnl.exe\");\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "    setupImports_0_xboxkrnl_exe_0();\n") != null);
}

test "idc: export table skips the image base sentinel" {
    const allocator = std.testing.allocator;
    var xex = model.Xex.init(allocator);
    defer xex.deinit();
    xex.load_address = 0x82000000;
    try writePe(&xex, allocator, 1, &.{0x60000020});
    xex.export_table_address = 0x82000300;

    try xex.basefile.set32be(allocator, 2, 0x324); // count
    try xex.basefile.set32be(allocator, 0x00008200, 0x320); // imageBaseAddress
    try xex.basefile.set32be(allocator, 1, 0x328); // ordinal base
    try xex.basefile.set32be(allocator, 0x1234, 0x32C);
    try xex.basefile.set32be(allocator, 0, 0x330); // sentinel, skipped

    var buffer: std.Io.Writer.Allocating = .init(allocator);
    defer buffer.deinit();
    try write(&buffer.writer, &xex, allocator);
    const output = buffer.written();

    try std.testing.expect(std.mem.indexOf(u8, output, "    SetupExportFunc(0x82001234, 0x001, DoNameGen(name, 0, 0x001));\n") != null);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, output, "DoNameGen(name, 0, 0x"));
}

test "idc: exports by name read the little-endian table" {
    const allocator = std.testing.allocator;
    var xex = model.Xex.init(allocator);
    defer xex.deinit();
    xex.load_address = 0x82000000;
    try writePe(&xex, allocator, 1, &.{0x60000020});
    xex.exports_by_name = .{ .export_table_offset = 0x340, .export_table_size = 0x60 };

    try xex.basefile.set32le(allocator, 1, 0x350); // ordinal base
    try xex.basefile.set32le(allocator, 1, 0x358); // numberOfNames
    try xex.basefile.set32le(allocator, 0x40, 0x35C); // addressOfFunctions
    try xex.basefile.set32le(allocator, 0x44, 0x360); // addressOfNames
    try xex.basefile.set32le(allocator, 0x48, 0x364); // addressOfNameOrdinals
    try xex.basefile.set32le(allocator, 0x3000, 0x380); // function address
    try xex.basefile.set32le(allocator, 0x50, 0x384); // name string pointer
    try xex.basefile.set16le(allocator, 2, 0x388); // ordinal
    try xex.basefile.set(allocator, "MyExport\x00", 0x390, 9);

    var buffer: std.Io.Writer.Allocating = .init(allocator);
    defer buffer.deinit();
    try write(&buffer.writer, &xex, allocator);
    const output = buffer.written();

    try std.testing.expect(std.mem.indexOf(u8, output, "static SetupExportsByName()\n{\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "    SetupExportFunc(0x82003000, 0x003, \"MyExport\");\n") != null);
}

test "idc: a non-PE basefile is rejected" {
    var xex = model.Xex.init(std.testing.allocator);
    defer xex.deinit();
    try xex.basefile.set(std.testing.allocator, "not a pe", 0, 8);

    var buffer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer buffer.deinit();
    try std.testing.expectError(error.NotPeBasefile, write(&buffer.writer, &xex, std.testing.allocator));
}

/// Builds the smallest PE image the IDC writer accepts: DOS stub at 0, NT
/// header at 0x80, optional header at 0x98, section table at 0x178.
fn writePe(xex: *model.Xex, gpa: std.mem.Allocator, section_count: u16, characteristics: []const u32) !void {
    var bytes: [0x400]u8 = @splat(0);
    bytes[0] = 'M';
    bytes[1] = 'Z';
    endian.set32le(&bytes, 0x3C, 0x80);
    bytes[0x80] = 'P';
    bytes[0x81] = 'E';
    endian.set16le(&bytes, 0x86, section_count);
    endian.set16le(&bytes, 0x94, 0xE0);

    const names = [_][]const u8{ ".text", ".data" };
    for (characteristics, 0..) |flags, index| {
        const header = 0x178 + index * 0x28;
        @memcpy(bytes[header..][0..names[index].len], names[index]);
        endian.set32le(&bytes, header + 0x08, 0x1000); // VirtualSize
        endian.set32le(&bytes, header + 0x0C, 0x1000 + @as(u32, @intCast(index)) * 0x1000); // VirtualAddress
        endian.set32le(&bytes, header + 0x24, flags);
    }

    try xex.basefile.set(gpa, &bytes, 0, bytes.len);
}
