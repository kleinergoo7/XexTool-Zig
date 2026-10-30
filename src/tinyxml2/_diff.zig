const std = @import("std");
const tx = @import("tinyxml2.zig");

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    var rbuf: [4096]u8 = undefined;
    var stdin_reader = std.Io.File.stdin().reader(io, &rbuf);
    const raw = try stdin_reader.interface.allocRemaining(gpa, .unlimited);
    defer gpa.free(raw);
    const nl = std.mem.indexOfScalar(u8, raw, '\n') orelse raw.len;
    const mode = raw[0..nl];
    const in = if (nl < raw.len) raw[nl + 1 ..] else "";
    const compact = std.mem.eql(u8, mode, "compact");
    const noproc = std.mem.eql(u8, mode, "noproc");
    var ws: tx.Whitespace = .preserve;
    if (std.mem.eql(u8, mode, "collapse")) ws = .collapse;
    if (std.mem.eql(u8, mode, "pedantic")) ws = .pedantic;
    var doc: tx.XMLDocument = undefined;
    doc.init(gpa, .{ .process_entities = !noproc, .whitespace = ws });
    defer doc.deinit();
    _ = try doc.parse(in);
    var wbuf: [4096]u8 = undefined;
    var out_writer = std.Io.File.stdout().writer(io, &wbuf);
    const ww = &out_writer.interface;
    try ww.print("ERR {d} {s}\n", .{ @as(i32, @backingInt(doc.errorID())), doc.errorName() });
    try ww.print("STR {s}\n", .{doc.errorStr()});
    try ww.print("LINE {d}\n", .{doc.errorLineNum()});
    try ww.print("BOM {d}\n", .{@intFromBool(doc.hasBOM())});
    var p = try tx.XMLPrinter.init(gpa, .{ .compact = compact });
    defer p.deinit();
    try doc.print(&p);
    try ww.writeAll("OUT ");
    for (p.cstr()) |ch| {
        if (ch == '\n') try ww.writeAll("\\n") else if (ch == '\r') try ww.writeAll("\\r") else if (ch == '\\') try ww.writeAll("\\\\") else if (ch < 32 or ch >= 127) try ww.print("\\x{x:0>2}", .{ch}) else try ww.writeByte(ch);
    }
    try ww.writeAll("\n");
    try ww.flush();
}
