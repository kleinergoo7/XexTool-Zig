// SPDX-FileCopyrightText: 2026 XexTool Zig rewrite contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Console AES keys supplied by the caller. This module holds no key bytes, so
//! linking the library never embeds one. The stock CLI keeps its defaults in
//! `default_keys.zig`, which the library root does not export.

pub const Keys = struct {
    retail: [16]u8,
    mfg_retail: [16]u8,
    debug: [16]u8,
    mfg_debug: [16]u8,

    /// Uses one key for every slot. Correct for retail images; a debug image
    /// needs its own key in `debug`.
    pub fn uniform(key: [16]u8) Keys {
        return .{ .retail = key, .mfg_retail = key, .debug = key, .mfg_debug = key };
    }

    pub fn select(keys: Keys, is_debug: bool, is_mfg: bool) [16]u8 {
        if (is_mfg) return if (is_debug) keys.mfg_debug else keys.mfg_retail;
        return if (is_debug) keys.debug else keys.retail;
    }
};

test "select picks the slot for the image kind" {
    var keys = Keys.uniform(@splat(1));
    keys.mfg_retail = @splat(2);
    keys.debug = @splat(3);
    keys.mfg_debug = @splat(4);

    try @import("std").testing.expectEqual(@as(u8, 1), keys.select(false, false)[0]);
    try @import("std").testing.expectEqual(@as(u8, 2), keys.select(false, true)[0]);
    try @import("std").testing.expectEqual(@as(u8, 3), keys.select(true, false)[0]);
    try @import("std").testing.expectEqual(@as(u8, 4), keys.select(true, true)[0]);
}
