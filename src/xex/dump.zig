// SPDX-FileCopyrightText: 2026 XexTool Zig rewrite contributors
// SPDX-License-Identifier: GPL-3.0-or-later

const std = @import("std");
const file = @import("../core/file.zig");
const model = @import("model.zig");

pub const Error = error{
    InvalidResource,
    OutOfMemory,
    FileOpen,
    FileRead,
    FileWrite,
    OutOfBounds,
};

pub fn dumpBasefile(io: std.Io, xex: *const model.Xex, path: []const u8) !void {
    // C++ fwrite(size=0, count=1) returns 0, so an empty basefile is a failure.
    if (xex.basefile.size() == 0) return error.EmptyBasefile;
    try file.writeAll(io, path, xex.basefile.data());
}

pub fn dumpResources(io: std.Io, xex: *const model.Xex, directory: []const u8, gpa: std.mem.Allocator) !void {
    for (xex.resources.items, 0..) |resource, index| {
        const name = std.mem.sliceTo(&resource.name, 0);
        const filename = if (name.len != 0)
            try std.fmt.allocPrint(gpa, "{s}\\{s}", .{ directory, name })
        else
            try std.fmt.allocPrint(gpa, "{s}\\resource_{d}", .{ directory, index });
        defer gpa.free(filename);

        const offset = resource.addr -% xex.load_address;
        if (resource.size < 0) return error.InvalidResource;
        const size: usize = @intCast(resource.size);
        if (offset > xex.basefile.data().len or size > xex.basefile.data().len - offset) return error.OutOfBounds;
        try file.writeAll(io, filename, xex.basefile.data()[offset..][0..size]);
    }
}

test "resource dump path uses the C++ backslash join" {
    var xex = model.Xex.init(std.testing.allocator);
    defer xex.deinit();
    xex.load_address = 0x82000000;
    try xex.basefile.set(std.testing.allocator, &.{ 1, 2, 3, 4 }, 0, 4);
    try xex.resources.append(std.testing.allocator, .{ .name = .{ 'a', 0, 0, 0, 0, 0, 0, 0 }, .addr = 0x82000002, .size = 2 });

    const filename = try std.fmt.allocPrint(std.testing.allocator, "{s}\\{s}", .{ "out", std.mem.sliceTo(&xex.resources.items[0].name, 0) });
    defer std.testing.allocator.free(filename);
    try std.testing.expectEqualStrings("out\\a", filename);
    try std.testing.expectEqualSlices(u8, &.{ 3, 4 }, xex.basefile.data()[2..4]);
}
