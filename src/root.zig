// SPDX-FileCopyrightText: 2026 XexTool Zig rewrite contributors
// SPDX-License-Identifier: GPL-3.0-or-later

pub const endian = @import("core/endian.zig");
pub const text = @import("core/text.zig");
pub const DataBlock = @import("core/datablock.zig").DataBlock;
pub const cursor = @import("core/cursor.zig");
pub const getopt = @import("cli/getopt.zig");
pub const xecrypt = @import("xecrypt/xecrypt.zig");
pub const xex = struct {
    pub const defines = @import("xex/defines.zig");
    pub const types = @import("xex/types.zig");
    pub const model = @import("xex/model.zig");
    pub const data = @import("xex/data.zig");
    pub const header = @import("xex/header.zig");
    pub const pe = @import("xex/pe.zig");
    pub const packer = @import("xex/packer.zig");
    pub const reader = @import("xex/reader.zig");
    pub const printer = @import("xex/printer.zig");
    pub const dump = @import("xex/dump.zig");
    pub const xmlout = @import("xex/xmlout.zig");
    pub const infoget = @import("xex/infoget.zig");
    pub const infoset = @import("xex/infoset.zig");
    pub const gameinfo = @import("xex/gameinfo.zig");
    pub const idc = @import("xex/idc.zig");
    pub const applyxml = @import("xex/applyxml.zig");
    pub const patcher = @import("xex/patcher.zig");
    pub const special = @import("xex/special.zig");
    pub const writer = @import("xex/writer.zig");
    pub const header_writer = @import("xex/header_writer.zig");
    pub const pack = struct {
        pub const elf = @import("pack/elf.zig");
        pub const genstubs = @import("pack/genstubs.zig");
    };
};

test {
    @import("std").testing.refAllDecls(@This());
}
