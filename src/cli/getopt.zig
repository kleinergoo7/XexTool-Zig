// SPDX-FileCopyrightText: 2026 XexTool Zig rewrite contributors
// SPDX-License-Identifier: GPL-3.0-or-later

const std = @import("std");

pub const Getopt = struct {
    args: []const []const u8,
    optind: usize = 1,
    char_index: usize = 1,
    optarg: ?[]const u8 = null,
    optopt: u8 = 0,
    opterr: bool = true,

    pub fn init(args: []const []const u8) Getopt {
        return .{ .args = args };
    }

    pub fn next(self: *Getopt, optstring: []const u8, err_writer: anytype) !?u8 {
        self.optarg = null;
        if (self.char_index == 1) {
            if (self.optind >= self.args.len) return null;
            const arg = self.args[self.optind];
            if (arg.len < 2 or arg[0] != '-') return null;
            if (std.mem.eql(u8, arg, "--")) {
                self.optind += 1;
                return null;
            }
        }

        const arg = self.args[self.optind];
        if (self.char_index >= arg.len) return null;
        const c = arg[self.char_index];
        self.optopt = c;
        const match = if (c == ':') null else std.mem.indexOfScalar(u8, optstring, c);
        if (match == null) {
            if (self.opterr) try err_writer.print("{s}: unrecognised option -- {c}\n", .{ self.args[0], c });
            self.char_index += 1;
            if (self.char_index >= arg.len) {
                self.optind += 1;
                self.char_index = 1;
            }
            return '?';
        }

        const index = match.?;
        if (index + 1 >= optstring.len or optstring[index + 1] != ':') {
            self.char_index += 1;
            if (self.char_index >= arg.len) {
                self.optind += 1;
                self.char_index = 1;
            }
            return c;
        }

        if (self.char_index + 1 < arg.len) {
            self.optarg = arg[self.char_index + 1 ..];
        } else {
            self.optind += 1;
            if (self.optind >= self.args.len) {
                if (self.opterr) try err_writer.print("{s}: option requires an argument -- {c}\n", .{ self.args[0], c });
                self.char_index = 1;
                return '?';
            }
            self.optarg = self.args[self.optind];
        }
        self.optind += 1;
        self.char_index = 1;
        return c;
    }
};

test "getopt handles clustered flags and attached arguments" {
    const args = [_][]const u8{ "XexTool", "-lud", "mrl", "-ofoo.xex", "in.xex" };
    var getopt = Getopt.init(&args);
    var err_buffer: [256]u8 = undefined;
    var err_writer = std.Io.Writer.fixed(&err_buffer);

    try std.testing.expectEqual(@as(?u8, 'l'), try getopt.next("lp:b:i:d:o:a:us:r:m:c:e:x:z:", &err_writer));
    try std.testing.expectEqual(@as(?u8, 'u'), try getopt.next("lp:b:i:d:o:a:us:r:m:c:e:x:z:", &err_writer));
    try std.testing.expectEqual(@as(?u8, 'd'), try getopt.next("lp:b:i:d:o:a:us:r:m:c:e:x:z:", &err_writer));
    try std.testing.expectEqualStrings("mrl", getopt.optarg.?);
    try std.testing.expectEqual(@as(?u8, 'o'), try getopt.next("lp:b:i:d:o:a:us:r:m:c:e:x:z:", &err_writer));
    try std.testing.expectEqualStrings("foo.xex", getopt.optarg.?);
    try std.testing.expectEqual(@as(?u8, null), try getopt.next("lp:b:i:d:o:a:us:r:m:c:e:x:z:", &err_writer));
    try std.testing.expectEqual(@as(usize, 4), getopt.optind);
}
