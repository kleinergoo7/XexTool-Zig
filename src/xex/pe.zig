// SPDX-FileCopyrightText: 2026 XexTool Zig rewrite contributors
// SPDX-License-Identifier: GPL-3.0-or-later

const std = @import("std");
const endian = @import("../core/endian.zig");

pub const Parser = struct {
    data: []const u8,

    pub fn init(data: []const u8) Parser {
        return .{ .data = data };
    }

    fn u16le(self: Parser, offset: usize) u16 {
        return endian.get16le(self.data, offset);
    }

    fn u32le(self: Parser, offset: usize) u32 {
        return endian.get32le(self.data, offset);
    }

    fn peOffset(self: Parser) ?usize {
        if (self.data.len < 0x40) return null;
        const e_lfanew = self.u32le(0x3C);
        const offset = @as(usize, e_lfanew) + 4;
        if (offset < 4 or offset > self.data.len or self.data.len - offset < 0x18) return null;
        return offset;
    }

    fn optionalHeaderOffset(self: Parser) ?usize {
        const pe = self.peOffset() orelse return null;
        return pe + 0x14;
    }

    fn sectionsOffset(self: Parser) ?usize {
        const pe = self.peOffset() orelse return null;
        const optional = self.optionalHeaderOffset() orelse return null;
        if (pe + 0x14 > self.data.len or self.data.len - (pe + 0x14) < 2) return null;
        const optional_size = self.u16le(pe + 0x10);
        const result = optional + optional_size;
        if (result > self.data.len) return null;
        return result;
    }

    pub fn isPeFile(self: Parser) bool {
        if (self.data.len < 2 or self.data[0] != 'M' or self.data[1] != 'Z') return false;
        const pe = self.peOffset() orelse return false;
        return pe >= 4 and pe - 4 + 2 <= self.data.len and self.data[pe - 4] == 'P' and self.data[pe - 3] == 'E';
    }

    pub fn numberOfSections(self: Parser) ?u16 {
        const pe = self.peOffset() orelse return null;
        if (self.data.len - (pe + 0x04) < 2) return null;
        return self.u16le(pe + 0x04);
    }

    pub fn entryPoint(self: Parser) ?u32 {
        const optional = self.optionalHeaderOffset() orelse return null;
        if (self.data.len - optional < 0x18) return null;
        return self.u32le(optional + 0x10);
    }

    pub fn loadAddress(self: Parser) ?u32 {
        const optional = self.optionalHeaderOffset() orelse return null;
        if (self.data.len - optional < 0x1C) return null;
        return self.u32le(optional + 0x1C);
    }

    pub fn checksum(self: Parser) ?u32 {
        const optional = self.optionalHeaderOffset() orelse return null;
        if (self.data.len - optional < 0x40) return null;
        return self.u32le(optional + 0x40);
    }

    pub fn filetime(self: Parser) ?u32 {
        const pe = self.peOffset() orelse return null;
        if (self.data.len - (pe + 0x08) < 4) return null;
        return self.u32le(pe + 0x08);
    }

    pub const Section = struct {
        name: [8]u8,
        virtual_size: u32,
        virtual_address: u32,
        characteristics: u32,
    };

    pub fn section(self: Parser, index: u16) ?Section {
        const sections = self.sectionsOffset() orelse return null;
        const count = self.numberOfSections() orelse return null;
        if (index >= count) return null;
        const offset = sections + @as(usize, index) * 0x28;
        if (offset > self.data.len or self.data.len - offset < 0x28) return null;
        var result: Section = .{
            .name = undefined,
            .virtual_size = self.u32le(offset + 0x08),
            .virtual_address = self.u32le(offset + 0x0C),
            .characteristics = self.u32le(offset + 0x24),
        };
        @memcpy(&result.name, self.data[offset..][0..8]);
        return result;
    }
};

test "PE parser reads the DOS and NT headers" {
    var bytes: [0x100]u8 = @splat(0);
    bytes[0] = 'M';
    bytes[1] = 'Z';
    endian.set32le(&bytes, 0x3C, 0x80);
    bytes[0x80] = 'P';
    bytes[0x81] = 'E';
    endian.set16le(&bytes, 0x84, 1);
    endian.set32le(&bytes, 0x88, 0x11223344);
    endian.set16le(&bytes, 0x94, 0xE0);
    endian.set32le(&bytes, 0x98 + 0x10, 0x82010000);
    endian.set32le(&bytes, 0x98 + 0x1C, 0x82000000);
    endian.set32le(&bytes, 0x98 + 0x40, 0xDEADBEEF);

    const parser = Parser.init(&bytes);
    try std.testing.expect(parser.isPeFile());
    try std.testing.expectEqual(@as(u16, 1), parser.numberOfSections().?);
    try std.testing.expectEqual(@as(u32, 0x82010000), parser.entryPoint().?);
    try std.testing.expectEqual(@as(u32, 0x82000000), parser.loadAddress().?);
    try std.testing.expectEqual(@as(u32, 0xDEADBEEF), parser.checksum().?);
    try std.testing.expectEqual(@as(u32, 0x11223344), parser.filetime().?);
}
