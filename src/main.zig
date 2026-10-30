// SPDX-FileCopyrightText: 2026 XexTool Zig rewrite contributors
// SPDX-License-Identifier: GPL-3.0-or-later

const std = @import("std");
const xextool = @import("xextool");
const getopt_mod = xextool.getopt;
const usage = @import("cli/usage.zig").usage;
const defines = xextool.xex.defines;

const title = "XexTool v7.0  -  xorloser 2006-2017 (Build Fri Oct 30 11:01:45 2026)";

const Options = struct {
    print_extended: bool = false,
    print_shortened: bool = false,
    dump_basefile: bool = false,
    dump_resources: bool = false,
    dump_idc: bool = false,
    output_new_exe: bool = false,
    xml_output: bool = false,
    add_bounding_path: bool = false,
    bounding_path: []const u8 = "",
    force_devkit: bool = false,
    force_retail: bool = false,
    force_compressed: bool = false,
    force_uncompressed: bool = false,
    force_binary: bool = false,
    force_decrypted: bool = false,
    force_encrypted: bool = false,
    remove_media: bool = false,
    remove_region: bool = false,
    remove_bounding_path: bool = false,
    remove_bounding_device: bool = false,
    remove_console_id: bool = false,
    remove_dates: bool = false,
    remove_kv: bool = false,
    remove_signed_kv: bool = false,
    remove_library_limit: bool = false,
    remove_revocation: bool = false,
    remove_media_id: bool = false,
    xex_altered: bool = false,
    xml: xextool.xex.xmlout.Flags = .{},
    info_get: bool = false,
    info_set: bool = false,
    info_path: []const u8 = "",
    base_filename: []const u8 = "",
    res_dirname: []const u8 = "",
    idc_filename: []const u8 = "",
    out_filename: []const u8 = "",
    xex_filename: []const u8 = "",
};

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_file_writer: std.Io.File.Writer = .init(.stdout(), init.io, &stdout_buffer);
    const out = &stdout_file_writer.interface;

    var stderr_buffer: [1024]u8 = undefined;
    var stderr_file_writer: std.Io.File.Writer = .init(.stderr(), init.io, &stderr_buffer);
    const err = &stderr_file_writer.interface;

    if (args.len == 1) {
        try out.print("{s}\n{s}\n", .{ title, usage });
        try out.flush();
        std.process.exit(1);
    }

    if (std.mem.eql(u8, args[1], "applyxml")) {
        try runApplyXml(init, args, out);
        return;
    }
    if (std.mem.eql(u8, args[1], "pack") or std.mem.eql(u8, args[1], "genstubs")) {
        try out.print("Error: subcommand {s} is not implemented yet\n", .{args[1]});
        try out.flush();
        std.process.exit(1);
    }

    var options = Options{};
    var getopt = getopt_mod.Getopt.init(args);
    while (args.len > 2) {
        const option = try getopt.next("lp:b:i:d:o:a:us:r:m:c:e:x:z:", err);
        if (option == null) break;
        switch (option.?) {
            'l' => options.print_extended = true,
            'b' => {
                options.dump_basefile = true;
                options.base_filename = getopt.optarg.?;
            },
            'i' => {
                options.dump_idc = true;
                options.idc_filename = getopt.optarg.?;
            },
            'd' => {
                options.dump_resources = true;
                options.res_dirname = getopt.optarg.?;
                if (options.res_dirname.len > 0 and options.res_dirname[options.res_dirname.len - 1] == '\\') {
                    options.res_dirname = options.res_dirname[0 .. options.res_dirname.len - 1];
                }
            },
            'o' => {
                options.output_new_exe = true;
                options.out_filename = getopt.optarg.?;
                options.xex_altered = true;
            },
            'x' => {
                options.xml_output = true;
                const arg = getopt.optarg.?;
                for (arg) |letter| switch (letter) {
                    'b' => options.xml.basefile = true,
                    'd' => options.xml.media_id = true,
                    'i' => options.xml.icon = true,
                    'm' => options.xml.medias = true,
                    'n' => options.xml.name = true,
                    'p' => options.xml.bound_path = true,
                    'r' => options.xml.regions = true,
                    't' => options.xml.title_id = true,
                    'x' => options.xml.machine = true,
                    'a' => {
                        options.xml.basefile = true;
                        options.xml.media_id = true;
                        options.xml.icon = true;
                        options.xml.medias = true;
                        options.xml.name = true;
                        options.xml.bound_path = true;
                        options.xml.regions = true;
                        options.xml.title_id = true;
                        options.xml.machine = true;
                    },
                    else => {},
                };
            },
            'z' => {
                const arg = getopt.optarg.?;
                if (arg.len >= 1 and arg[0] == 'g') {
                    options.info_get = true;
                } else if (arg.len >= 1 and arg[0] == 's') {
                    options.info_set = true;
                } else {
                    try out.print("{s}\nError unknown info param\n", .{title});
                    try out.flush();
                    std.process.exit(1);
                }
                if (arg.len > 1) {
                    options.info_path = arg[1..];
                } else if (getopt.optind < args.len) {
                    options.info_path = args[getopt.optind];
                    getopt.optind += 1;
                } else {
                    try out.print("Error getting info filename\n", .{});
                    try out.flush();
                    std.process.exit(1);
                }
            },
            'a' => {
                options.add_bounding_path = true;
                options.bounding_path = getopt.optarg.?;
                options.xex_altered = true;
            },
            'u' => {
                try out.print("Error: -u is not implemented yet\n", .{});
                try out.flush();
                std.process.exit(1);
            },
            's' => {
                try out.print("Error: -s is not implemented yet\n", .{});
                try out.flush();
                std.process.exit(1);
            },
            'p' => {
                try out.print("Error: -p is not implemented yet\n", .{});
                try out.flush();
                std.process.exit(1);
            },
            'r' => {
                const arg = getopt.optarg.?;
                if (std.mem.indexOfScalar(u8, arg, 'a') != null) {
                    options.remove_media = true;
                    options.remove_region = true;
                    options.remove_bounding_path = true;
                    options.remove_bounding_device = true;
                    options.remove_console_id = true;
                    options.remove_dates = true;
                    options.remove_kv = true;
                    options.remove_signed_kv = true;
                    options.remove_library_limit = true;
                    options.remove_revocation = true;
                    options.remove_media_id = true;
                }
                if (std.mem.indexOfScalar(u8, arg, 'm') != null) options.remove_media = true;
                if (std.mem.indexOfScalar(u8, arg, 'r') != null) options.remove_region = true;
                if (std.mem.indexOfScalar(u8, arg, 'b') != null) options.remove_bounding_path = true;
                if (std.mem.indexOfScalar(u8, arg, 'd') != null) options.remove_bounding_device = true;
                if (std.mem.indexOfScalar(u8, arg, 'i') != null) options.remove_console_id = true;
                if (std.mem.indexOfScalar(u8, arg, 'y') != null) options.remove_dates = true;
                if (std.mem.indexOfScalar(u8, arg, 'v') != null) options.remove_kv = true;
                if (std.mem.indexOfScalar(u8, arg, 'k') != null) options.remove_signed_kv = true;
                if (std.mem.indexOfScalar(u8, arg, 'l') != null) options.remove_library_limit = true;
                if (std.mem.indexOfScalar(u8, arg, 'c') != null) options.remove_revocation = true;
                if (std.mem.indexOfScalar(u8, arg, 'z') != null) options.remove_media_id = true;
                options.xex_altered = true;
            },
            'm' => {
                const arg = getopt.optarg.?;
                if (std.mem.indexOfScalar(u8, arg, 'd') != null or std.mem.indexOfScalar(u8, arg, '0') != null) options.force_devkit = true;
                if (std.mem.indexOfScalar(u8, arg, 'r') != null or std.mem.indexOfScalar(u8, arg, '1') != null) options.force_retail = true;
                if (options.force_devkit and options.force_retail) {
                    try out.print("{s}\nError trying to force to more than one machine format\n", .{title});
                    try out.flush();
                    std.process.exit(1);
                }
                options.xex_altered = true;
            },
            'c' => {
                const arg = getopt.optarg.?;
                if (std.mem.indexOfScalar(u8, arg, 'u') != null or std.mem.indexOfScalar(u8, arg, '0') != null) options.force_uncompressed = true;
                if (std.mem.indexOfScalar(u8, arg, 'c') != null or std.mem.indexOfScalar(u8, arg, '1') != null) options.force_compressed = true;
                if (std.mem.indexOfScalar(u8, arg, 'b') != null) options.force_binary = true;
                const count = @intFromBool(options.force_uncompressed) + @intFromBool(options.force_compressed) + @intFromBool(options.force_binary);
                if (count > 1) {
                    try out.print("{s}\nError trying to force to more than one compression format\n", .{title});
                    try out.flush();
                    std.process.exit(1);
                }
                options.xex_altered = true;
            },
            'e' => {
                const arg = getopt.optarg.?;
                if (std.mem.indexOfScalar(u8, arg, 'd') != null or std.mem.indexOfScalar(u8, arg, 'u') != null or std.mem.indexOfScalar(u8, arg, '0') != null) options.force_decrypted = true;
                if (std.mem.indexOfScalar(u8, arg, 'e') != null or std.mem.indexOfScalar(u8, arg, '1') != null) options.force_encrypted = true;
                if (options.force_decrypted and options.force_encrypted) {
                    try out.print("{s}\nError trying to force to more than one encryption format\n", .{title});
                    try out.flush();
                    std.process.exit(1);
                }
                options.xex_altered = true;
            },
            '?' => {
                try out.print("{s}\nError unknown option \"{s}\"\n", .{ title, args[getopt.optind - 1] });
                try out.flush();
                std.process.exit(1);
            },
            else => unreachable,
        }
    }

    if (args.len == 2) {
        options.print_shortened = true;
        options.xex_filename = args[1];
    } else if (getopt.optind >= args.len) {
        try out.print("No xex filename specified\n", .{});
        try out.flush();
        std.process.exit(1);
    } else if (getopt.optind + 1 < args.len) {
        try out.print("Extra params specified at the end of the command line\n", .{});
        try out.flush();
        std.process.exit(1);
    } else {
        options.xex_filename = args[getopt.optind];
    }

    var xex = xextool.xex.model.Xex.init(arena);
    defer xex.deinit();

    if (!options.xml_output) {
        try out.print("{s}\n", .{title});
        try out.print("Reading and parsing input xex file...\n", .{});
    }
    if (!try xextool.xex.reader.readFile(&xex, init.io, options.xex_filename)) {
        try out.print("Error reading xex file {s}\n", .{options.xex_filename});
        if (xex.is_delta_compressed) {
            try out.print("\"{s}\" is a delta compressed patch file\nIt's contents only make sense when used with the required xex file!\n\n", .{options.xex_filename});
        } else {
            try out.flush();
            std.process.exit(2);
        }
    }

    if (options.print_extended or options.print_shortened) {
        try out.print("\n", .{});
        if (options.print_extended) try xextool.xex.printer.printAll(out, &xex);
        if (options.print_shortened) try xextool.xex.printer.printShort(out, &xex);
        try out.print("\n", .{});
    }

    if (options.dump_basefile) {
        xextool.xex.dump.dumpBasefile(init.io, &xex, options.base_filename) catch {
            try out.print("Error dumping basefile to {s}\n", .{options.base_filename});
            try out.flush();
            std.process.exit(1);
        };
        try out.print("Successfully dumped basefile to {s}\n", .{options.base_filename});
        if (xex.isBasefilePE()) {
            try out.print("\nLoad basefile into IDA with the following details\nDO NOT load as a PE or EXE file as the format is not valid\nFile Type:       Binary file\nProcessor Type:  PowerPC: ppc\nLoad Address:    0x{X:0>8}\nEntry Point:     0x{X:0>8}\n", .{ xex.load_address, xex.entryPoint() });
        }
    }

    if (options.dump_idc) {
        xextool.xex.idc.dump(init.io, &xex, options.idc_filename, arena) catch {
            try out.print("Error dumping basefile idc to {s}\n", .{options.idc_filename});
            try out.flush();
            std.process.exit(1);
        };
        try out.print("Successfully dumped basefile idc to {s}\n", .{options.idc_filename});
    }

    if (options.dump_resources) {
        if (xex.resources.items.len == 0) {
            try out.print("File contains no resources\n", .{});
        } else {
            xextool.xex.dump.dumpResources(init.io, &xex, options.res_dirname, arena) catch {
                try out.print("Error dumping resources to {s}\n", .{options.res_dirname});
                try out.flush();
                std.process.exit(1);
            };
            try out.print("Successfully dumped {d} resource{s} to {s}\n", .{ xex.resources.items.len, if (xex.resources.items.len > 1) "s" else "", options.res_dirname });
        }
    }

    if (options.add_bounding_path) {
        if (xex.bounding_path) |old| arena.free(old);
        xex.bounding_path = try arena.dupe(u8, options.bounding_path);
        try out.print("  added bounding path: {s}\n", .{options.bounding_path});
        options.xex_altered = true;
    }
    if (options.remove_media) {
        xex.media_types = defines.media_all;
        xex.image_flags &= ~defines.image_flag_xgd2;
        try out.print("  removed media limit\n", .{});
    }
    if (options.remove_region) {
        xex.regions = defines.region_all;
        try out.print("  removed region limit\n", .{});
    }
    if (options.remove_bounding_path) {
        if (xex.bounding_path) |old| arena.free(old);
        xex.bounding_path = null;
        try out.print("  removed bounding path limit\n", .{});
    }
    if (options.remove_bounding_device) {
        xex.bounding_device_id = null;
        try out.print("  removed bounding device id limit\n", .{});
    }
    if (options.remove_console_id) {
        xex.restrict_console_ids.clearRetainingCapacity();
        try out.print("  removed console id restriction\n", .{});
    }
    if (options.remove_dates) {
        xex.restrict_dates = null;
        try out.print("  removed date restriction\n", .{});
    }
    if (options.remove_kv) {
        xex.restrict_kv_privs = null;
        try out.print("  removed keyvault privilege restriction\n", .{});
    }
    if (options.remove_signed_kv) {
        xex.image_flags &= ~defines.image_flag_signed_kv_restricted;
        try out.print("  removed signed keyvault only limit\n", .{});
    }
    if (options.remove_library_limit) {
        for (xex.import_libraries.items) |*library| library.min_version = 0;
        try out.print("  removed library version limit\n", .{});
    }
    if (options.remove_revocation) {
        xex.image_flags &= ~defines.image_flag_revocation_check_req;
        try out.print("  removed required revocation check\n", .{});
    }
    if (options.remove_media_id) {
        xex.media_id = .{};
        try out.print("  removed media id limit\n", .{});
    }
    if (options.force_devkit) xex.is_debug = true;
    if (options.force_retail) xex.is_debug = false;
    if (options.force_uncompressed) {
        xex.is_raw = true;
        xex.is_binary = false;
        xex.is_compressed = false;
        xex.is_delta_compressed = false;
    }
    if (options.force_binary) {
        xex.is_raw = false;
        xex.is_binary = true;
        xex.is_compressed = false;
        xex.is_delta_compressed = false;
    }
    if (options.force_compressed) {
        xex.is_raw = false;
        xex.is_binary = false;
        xex.is_compressed = true;
        xex.is_delta_compressed = false;
    }
    if (options.force_decrypted) xex.is_encrypted = false;
    if (options.force_encrypted) xex.is_encrypted = true;

    if (options.xml_output) {
        try xextool.xex.xmlout.print(out, &xex, options.xml, arena);
    }

    if (options.info_set) {
        xextool.xex.infoset.apply(init.io, &xex, options.info_path, arena) catch {
            try out.print("Error reading and parsing info file: {s}\n", .{options.info_path});
            try out.flush();
            std.process.exit(1);
        };
        try out.print("Info was successfully set into xex file\n", .{});
        options.xex_altered = true;
    }

    if (options.info_get) {
        xextool.xex.infoget.writeInfo(init.io, &xex, options.info_path, arena) catch {
            try out.print("Error creating info file {s}\n", .{options.info_path});
            try out.flush();
            std.process.exit(1);
        };
        try out.print("Wrote info to {s}\n", .{options.info_path});
    }

    if (options.xex_altered) {
        const filename = if (options.output_new_exe) options.out_filename else options.xex_filename;
        try out.print("Creating and writing output xex file...\n", .{});
        xextool.xex.writer.writeFile(&xex, init.io, filename) catch {
            try out.print("Error writing altered xex to {s}\n", .{filename});
            try out.flush();
            std.process.exit(1);
        };
        try out.print("Successfully wrote altered xex to {s}\n", .{filename});
        try out.print("\n{s} is {s} {s} {s}.\n", .{
            filename,
            if (xex.is_debug) "devkit" else "retail",
            if (xex.is_encrypted) "encrypted" else "unencrypted",
            if (xex.is_compressed) "compressed" else if (xex.is_raw) "uncompressed" else "binary",
        });
    }

    try out.flush();
    try err.flush();
}

fn runApplyXml(init: std.process.Init, args: []const []const u8, out: anytype) !void {
    var input: []const u8 = "";
    var xml_path: []const u8 = "";
    var output_path: []const u8 = "";

    var index: usize = 2;
    while (index < args.len) : (index += 1) {
        const arg = args[index];
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            try out.print("{s}", .{xextool.xex.applyxml.usage});
            try out.flush();
            return;
        } else if (std.mem.eql(u8, arg, "-o") or std.mem.eql(u8, arg, "--out")) {
            index += 1;
            if (index >= args.len) {
                try out.print("{s}", .{xextool.xex.applyxml.usage});
                try out.flush();
                std.process.exit(1);
            }
            output_path = args[index];
        } else if (std.mem.eql(u8, arg, "--xml")) {
            index += 1;
            if (index >= args.len) {
                try out.print("{s}", .{xextool.xex.applyxml.usage});
                try out.flush();
                std.process.exit(1);
            }
            xml_path = args[index];
        } else if (arg.len != 0 and arg[0] == '-') {
            try out.print("Unknown option: {s}\n\n{s}", .{ arg, xextool.xex.applyxml.usage });
            try out.flush();
            std.process.exit(1);
        } else if (input.len == 0) {
            input = arg;
        } else {
            try out.print("Unexpected argument: {s}\n\n{s}", .{ arg, xextool.xex.applyxml.usage });
            try out.flush();
            std.process.exit(1);
        }
    }

    if (input.len == 0 or xml_path.len == 0) {
        try out.print("{s}", .{xextool.xex.applyxml.usage});
        try out.flush();
        std.process.exit(1);
    }
    if (output_path.len == 0) output_path = input;

    var xex = xextool.xex.model.Xex.init(init.arena.allocator());
    defer xex.deinit();
    const read_ok = xextool.xex.reader.readFile(&xex, init.io, input) catch false;
    if (!read_ok) {
        try out.print("applyxml: failed to read {s}\n", .{input});
        try out.flush();
        std.process.exit(1);
    }

    xextool.xex.applyxml.apply(init.io, &xex, xml_path, init.arena.allocator(), out) catch {
        try out.print("applyxml: failed to apply {s}\n", .{xml_path});
        try out.flush();
        std.process.exit(1);
    };

    xextool.xex.writer.writeFile(&xex, init.io, output_path) catch {
        try out.print("applyxml: failed to write {s}\n", .{output_path});
        try out.flush();
        std.process.exit(1);
    };
    try out.print("applyxml: wrote {s}\n", .{output_path});
    try out.flush();
}
