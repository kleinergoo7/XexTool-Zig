// SPDX-FileCopyrightText: 2026 XexTool Zig rewrite contributors
// SPDX-License-Identifier: GPL-3.0-or-later

const std = @import("std");
const xextool = @import("xextool");
const getopt_mod = xextool.getopt;
const usage = @import("cli/usage.zig").usage;

const title = "XexTool v7.0  -  xorloser 2006-2017 (Build Fri Oct 30 11:01:45 2026)";

const Options = struct {
    print_extended: bool = false,
    print_shortened: bool = false,
    dump_basefile: bool = false,
    dump_resources: bool = false,
    output_new_exe: bool = false,
    xml_output: bool = false,
    xml: xextool.xex.xmlout.Flags = .{},
    info_get: bool = false,
    info_set: bool = false,
    info_path: []const u8 = "",
    base_filename: []const u8 = "",
    res_dirname: []const u8 = "",
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

    if (std.mem.eql(u8, args[1], "pack") or std.mem.eql(u8, args[1], "genstubs") or std.mem.eql(u8, args[1], "applyxml")) {
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
            'p' => {
                try out.print("Error: -p is not implemented yet\n", .{});
                try out.flush();
                std.process.exit(1);
            },
            'b' => {
                options.dump_basefile = true;
                options.base_filename = getopt.optarg.?;
            },
            'i' => {
                try out.print("Error: -i is not implemented yet\n", .{});
                try out.flush();
                std.process.exit(1);
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
                    try out.print("Error: -z s is not implemented yet\n", .{});
                    try out.flush();
                    std.process.exit(1);
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
            'a', 'u', 's', 'r', 'm', 'c', 'e' => {
                try out.print("Error: option -{c} is not implemented yet\n", .{option.?});
                try out.flush();
                std.process.exit(1);
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

    if (options.xml_output) {
        try xextool.xex.xmlout.print(out, &xex, options.xml);
    }

    if (options.info_get) {
        xextool.xex.infoget.writeInfo(init.io, &xex, options.info_path, arena) catch {
            try out.print("Error creating info file {s}\n", .{options.info_path});
            try out.flush();
            std.process.exit(1);
        };
        try out.print("Wrote info to {s}\n", .{options.info_path});
    }

    if (options.output_new_exe) {
        try out.print("Error: writing a new xex is not implemented yet\n", .{});
        try out.flush();
        std.process.exit(1);
    }

    try out.flush();
    try err.flush();
}
