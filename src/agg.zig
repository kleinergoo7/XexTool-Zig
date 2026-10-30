// SPDX-FileCopyrightText: 2026 XexTool Zig rewrite contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Aggregates module tests so `zig build test` observes every ported unit.

const std = @import("std");

test {
    std.testing.refAllDecls(@import("core/base64.zig"));
    std.testing.refAllDecls(@import("core/cursor.zig"));
    std.testing.refAllDecls(@import("core/datablock.zig"));
    std.testing.refAllDecls(@import("core/endian.zig"));
    std.testing.refAllDecls(@import("xecrypt/xecrypt.zig"));
    std.testing.refAllDecls(@import("xex/defines.zig"));
    std.testing.refAllDecls(@import("xex/types.zig"));
    std.testing.refAllDecls(@import("xex/model.zig"));
    std.testing.refAllDecls(@import("xex/pe.zig"));
    std.testing.refAllDecls(@import("xex/header.zig"));
    std.testing.refAllDecls(@import("xex/packer.zig"));
    std.testing.refAllDecls(@import("xex/reader.zig"));
    std.testing.refAllDecls(@import("xex/printer.zig"));
    std.testing.refAllDecls(@import("xex/dump.zig"));
    std.testing.refAllDecls(@import("xex/infoget.zig"));
    std.testing.refAllDecls(@import("xex/xmlout.zig"));
    std.testing.refAllDecls(@import("xex/gameinfo.zig"));
    std.testing.refAllDecls(@import("xex/idc.zig"));
    std.testing.refAllDecls(@import("xex/applyxml.zig"));
    std.testing.refAllDecls(@import("xex/patcher.zig"));
    std.testing.refAllDecls(@import("xex/writer.zig"));
    std.testing.refAllDecls(@import("xex/header_writer.zig"));
}
