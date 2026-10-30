// SPDX-FileCopyrightText: 2026 XexTool Zig rewrite contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This file is part of the Zig port of tinyxml2 11.0.0 by Lee Thomason
// (zlib license); see tinyxml2.zig for the retained original notice.

//! Utility layer of the tinyxml2 port: error ids, string normalization,
//! numeric conversions, and float formatting.
//!
//! The normalization and conversion routines reproduce tinyxml2 11.0.0
//! (`tinyxml2.cpp`) byte for byte, including its handling of unknown
//! entities and its scanf/snprintf style numeric formats.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// Mirrors `enum XMLError` in tinyxml2.h; values are part of the API.
pub const XMLError = enum(i32) {
    success = 0,
    no_attribute = 1,
    wrong_attribute_type = 2,
    error_file_not_found = 3,
    error_file_could_not_be_opened = 4,
    error_file_read_error = 5,
    error_parsing_element = 6,
    error_parsing_attribute = 7,
    error_parsing_text = 8,
    error_parsing_cdata = 9,
    error_parsing_comment = 10,
    error_parsing_declaration = 11,
    error_parsing_unknown = 12,
    error_empty_document = 13,
    error_mismatched_element = 14,
    error_parsing = 15,
    can_not_convert_text = 16,
    no_text_node = 17,
    element_depth_exceeded = 18,
};

/// Number of entries in `XMLError` (`XML_ERROR_COUNT`).
pub const error_count: usize = 19;

/// Must stay in the same order as `XMLError`, as in the reference
/// `XMLDocument::_errorNames`.
pub const error_names: [error_count][]const u8 = .{
    "XML_SUCCESS",
    "XML_NO_ATTRIBUTE",
    "XML_WRONG_ATTRIBUTE_TYPE",
    "XML_ERROR_FILE_NOT_FOUND",
    "XML_ERROR_FILE_COULD_NOT_BE_OPENED",
    "XML_ERROR_FILE_READ_ERROR",
    "XML_ERROR_PARSING_ELEMENT",
    "XML_ERROR_PARSING_ATTRIBUTE",
    "XML_ERROR_PARSING_TEXT",
    "XML_ERROR_PARSING_CDATA",
    "XML_ERROR_PARSING_COMMENT",
    "XML_ERROR_PARSING_DECLARATION",
    "XML_ERROR_PARSING_UNKNOWN",
    "XML_ERROR_EMPTY_DOCUMENT",
    "XML_ERROR_MISMATCHED_ELEMENT",
    "XML_ERROR_PARSING",
    "XML_CAN_NOT_CONVERT_TEXT",
    "XML_NO_TEXT_NODE",
    "XML_ELEMENT_DEPTH_EXCEEDED",
};

pub fn errorIDToName(id: XMLError) []const u8 {
    // Enum values are 0..error_count-1 by construction.
    return error_names[@intCast(@backingInt(id))];
}

pub fn errorIDFromInt(raw: i32) ?XMLError {
    // error_count is 19, so the i32 cast is exact.
    if (raw < 0 or raw >= @as(i32, @intCast(error_count))) return null;
    return @fromBackingInt(@intCast(raw)); // range checked above
}

// ---------- character classes ---------- //

/// `XMLUtil::IsWhiteSpace`: any high-bit byte is treated as non-space.
pub fn isWhitespace(c: u8) bool {
    return c < 0x80 and std.ascii.isWhitespace(c);
}

pub fn isNameStartChar(c: u8) bool {
    if (c >= 128) return true;
    return std.ascii.isAlphabetic(c) or c == ':' or c == '_';
}

pub fn isNameChar(c: u8) bool {
    return isNameStartChar(c) or std.ascii.isDigit(c) or c == '.' or c == '-';
}

pub fn skipWhitespace(bytes: []const u8, start: usize, line: *i32) usize {
    var p = start;
    while (p < bytes.len and isWhitespace(bytes[p])) {
        if (bytes[p] == '\n') line.* += 1;
        p += 1;
    }
    return p;
}

/// `XMLUtil::IsPrefixHex`: note that a leading sign defeats the check,
/// exactly like the reference.
pub fn isPrefixHex(s: []const u8) bool {
    var p: usize = 0;
    while (p < s.len and isWhitespace(s[p])) p += 1;
    return p + 1 < s.len and s[p] == '0' and (s[p + 1] == 'x' or s[p + 1] == 'X');
}

pub fn readBOM(bytes: []const u8, start: usize) struct { pos: usize, has_bom: bool } {
    if (start + 2 < bytes.len and bytes[start] == 0xef and bytes[start + 1] == 0xbb and bytes[start + 2] == 0xbf) {
        return .{ .pos = start + 3, .has_bom = true };
    }
    return .{ .pos = start, .has_bom = false };
}

// ---------- entities ---------- //

pub const Entity = struct {
    pattern: []const u8,
    value: u8,
};

pub const entities: [5]Entity = .{
    .{ .pattern = "quot", .value = '"' },
    .{ .pattern = "amp", .value = '&' },
    .{ .pattern = "apos", .value = '\'' },
    .{ .pattern = "lt", .value = '<' },
    .{ .pattern = "gt", .value = '>' },
};

const max_code_point: u32 = 0x10ffff;

/// Result of decoding one `&#...;` reference.
pub const CharRef = struct {
    bytes: [4]u8,
    len: u8,
    next: usize,
};

/// `XMLUtil::ConvertUTF32ToUTF8`. Returns null for code points the reference
/// refuses to encode (>= 0x200000).
pub fn convertUTF32ToUTF8(input: u32) ?struct { bytes: [4]u8, len: u8 } {
    // Every branch below masks the output byte with 0xFF, so all @intCast
    // conversions are in range for u8.
    var out: [4]u8 = undefined;
    if (input < 0x80) {
        out[0] = @intCast(input);
        return .{ .bytes = out, .len = 1 };
    }
    if (input < 0x800) {
        out[0] = @intCast(0xc0 | (input >> 6));
        out[1] = @intCast(0x80 | (input & 0x3f));
        return .{ .bytes = out, .len = 2 };
    }
    if (input < 0x10000) {
        out[0] = @intCast(0xe0 | (input >> 12));
        out[1] = @intCast(0x80 | ((input >> 6) & 0x3f));
        out[2] = @intCast(0x80 | (input & 0x3f));
        return .{ .bytes = out, .len = 3 };
    }
    if (input < 0x200000) {
        out[0] = @intCast(0xf0 | (input >> 18));
        out[1] = @intCast(0x80 | ((input >> 12) & 0x3f));
        out[2] = @intCast(0x80 | ((input >> 6) & 0x3f));
        out[3] = @intCast(0x80 | (input & 0x3f));
        return .{ .bytes = out, .len = 4 };
    }
    return null;
}

fn at(bytes: []const u8, i: usize) u8 {
    return if (i < bytes.len) bytes[i] else 0;
}

/// `XMLUtil::GetCharacterRef`. `bytes` is NUL terminated logically (reads stop
/// at the first NUL). `pos` points at `&`. Returns null when the reference is
/// not a valid character reference; the caller then keeps the literal `&`.
pub fn getCharacterRef(bytes: []const u8, pos: usize) ?CharRef {
    if (at(bytes, pos + 1) != '#' or at(bytes, pos + 2) == 0) return null;

    var hex = false;
    var radix: u32 = 10;
    var terminator: u8 = '#';
    var q: usize = pos + 2;
    if (at(bytes, pos + 2) == 'x') {
        hex = true;
        radix = 16;
        terminator = 'x';
        q = pos + 3;
    }
    if (at(bytes, q) == 0) return null;

    // Find the semicolon; strchr stops at the NUL.
    var semi = q;
    while (at(bytes, semi) != 0 and at(bytes, semi) != ';') semi += 1;
    if (at(bytes, semi) != ';') return null;

    var ucs: u32 = 0;
    var mult: u32 = 1;
    var scan = semi - 1;
    while (at(bytes, scan) != terminator) {
        const c = at(bytes, scan);
        var digit: u32 = 0;
        if (c >= '0' and c <= '9') {
            digit = c - '0';
        } else if (hex and c >= 'a' and c <= 'f') {
            digit = c - 'a' + 10;
        } else if (hex and c >= 'A' and c <= 'F') {
            digit = c - 'A' + 10;
        } else {
            return null;
        }
        const scaled = mult *% digit;
        if (scaled > max_code_point or ucs > max_code_point - scaled) return null;
        ucs += scaled;
        mult *%= radix;
        if (mult > max_code_point) mult = max_code_point;
        if (scan == pos) return null; // no terminator before '&'; malformed
        scan -= 1;
    }
    if (ucs > max_code_point) return null;

    const encoded = convertUTF32ToUTF8(ucs) orelse return null;
    return .{ .bytes = encoded.bytes, .len = encoded.len, .next = semi + 1 };
}

// ---------- string flags / StrPair ---------- //

pub const StrFlags = packed struct {
    entities: bool = false,
    newlines: bool = false,
    collapse: bool = false,
};

pub const text_element: StrFlags = .{ .entities = true, .newlines = true };
pub const text_element_leave_entities: StrFlags = .{ .newlines = true };
pub const attribute_name: StrFlags = .{};
pub const attribute_value: StrFlags = .{ .entities = true, .newlines = true };
pub const attribute_value_leave_entities: StrFlags = .{ .newlines = true };
pub const comment: StrFlags = .{ .newlines = true };
pub const plain: StrFlags = .{};

/// Value storage. The reference keeps a pointer pair and normalizes lazily in
/// place; this port copies the input slice and normalizes it immediately. The
/// observable string is identical, including the stale-byte quirk for an
/// unknown named entity that follows a shortened entity.
pub const StrPair = struct {
    owned: ?[:0]u8 = null,
    interned: []const u8 = "",
    text: []const u8 = "",

    pub fn deinit(self: *StrPair, gpa: Allocator) void {
        if (self.owned) |buf| gpa.free(buf);
        self.* = .{};
    }

    pub fn reset(self: *StrPair, gpa: Allocator) void {
        self.deinit(gpa);
    }

    pub fn isEmpty(self: *const StrPair) bool {
        return self.text.len == 0;
    }

    pub fn getStr(self: *const StrPair) []const u8 {
        return self.text;
    }

    /// `StrPair::Set` with eager normalization.
    pub fn set(self: *StrPair, gpa: Allocator, raw: []const u8, flags: StrFlags) Allocator.Error!void {
        self.deinit(gpa);
        const buf = try gpa.allocSentinel(u8, raw.len, 0);
        @memcpy(buf, raw);
        self.owned = buf;
        self.text = normalize(buf.ptr, raw.len, flags);
    }

    /// `StrPair::SetStr`.
    pub fn setStr(self: *StrPair, gpa: Allocator, str: []const u8) Allocator.Error!void {
        try self.set(gpa, str, plain);
    }

    /// `StrPair::SetInternedStr`: the caller guarantees `str` outlives this pair.
    pub fn setInterned(self: *StrPair, gpa: Allocator, str: []const u8) void {
        self.deinit(gpa);
        self.interned = str;
        self.text = str;
    }

    /// `StrPair::TransferTo`, used to hand a closing element name to its parent.
    pub fn transferTo(self: *StrPair, gpa: Allocator, other: *StrPair) void {
        if (self == other) return;
        other.deinit(gpa);
        other.* = self.*;
        self.* = .{};
    }
};

fn normalizeStart(ptr: [*]u8, len: usize, flags: StrFlags) []const u8 {
    if (!flags.entities and !flags.newlines) {
        return ptr[0..len];
    }

    var p: usize = 0;
    var q: usize = 0;
    while (p < len) {
        const c = ptr[p];
        if (flags.newlines and c == '\r') {
            if (at(ptr[0..len], p + 1) == '\n') p += 2 else p += 1;
            ptr[q] = '\n';
            q += 1;
        } else if (flags.newlines and c == '\n') {
            if (at(ptr[0..len], p + 1) == '\r') p += 2 else p += 1;
            ptr[q] = '\n';
            q += 1;
        } else if (flags.entities and c == '&') {
            if (at(ptr[0..len], p + 1) == '#') {
                if (getCharacterRef(ptr[0..len], p)) |ref| {
                    @memcpy(ptr[q..][0..ref.len], ref.bytes[0..ref.len]);
                    q += ref.len;
                    p = ref.next;
                } else {
                    ptr[q] = c;
                    p += 1;
                    q += 1;
                }
            } else {
                var found = false;
                for (entities) |entity| {
                    if (at(ptr[0..len], p + 1) == entity.pattern[0] and
                        p + 1 + entity.pattern.len <= len and
                        std.mem.eql(u8, ptr[p + 1 ..][0..entity.pattern.len], entity.pattern) and
                        at(ptr[0..len], p + entity.pattern.len + 1) == ';')
                    {
                        ptr[q] = entity.value;
                        q += 1;
                        p += entity.pattern.len + 2;
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    // Reference quirk: no write, so the previous byte survives.
                    p += 1;
                    q += 1;
                }
            }
        } else {
            ptr[q] = c;
            p += 1;
            q += 1;
        }
    }
    ptr[q] = 0;
    return ptr[0..q];
}

fn normalize(ptr: [*]u8, len: usize, flags: StrFlags) []const u8 {
    const transformed = normalizeStart(ptr, len, flags);
    if (!flags.collapse) return transformed;

    // `StrPair::CollapseWhitespace`; trims leading and trailing space runs.
    const bytes = ptr[0..transformed.len];
    var start: usize = 0;
    while (start < bytes.len and isWhitespace(bytes[start])) start += 1;
    var out: usize = start;
    var p = start;
    while (p < bytes.len and bytes[p] != 0) {
        if (isWhitespace(bytes[p])) {
            var next = p;
            while (next < bytes.len and isWhitespace(bytes[next])) next += 1;
            if (next >= bytes.len or bytes[next] == 0) break;
            bytes[out] = ' ';
            out += 1;
            p = next;
        }
        bytes[out] = bytes[p];
        out += 1;
        p += 1;
    }
    // The buffer is sentinel terminated; store through the pointer because the
    // slice length may end exactly at the sentinel.
    ptr[out] = 0;
    return bytes[start..out];
}

// ---------- numeric parsing ---------- //

const ScannedInt = struct {
    negative: bool,
    magnitude: u64,
    /// strtoul/strtoull report ULLONG_MAX on overflow, without the sign.
    overflowed: bool,
};

fn saturatingAdd(value: *u64, digit: u64, radix: u64) bool {
    const limit = std.math.maxInt(u64);
    if (value.* > (limit - digit) / radix) {
        value.* = limit;
        return true;
    }
    value.* = value.* * radix + digit;
    return false;
}

fn scanInt(s: []const u8, radix: u64) ?ScannedInt {
    var p: usize = 0;
    while (p < s.len and isWhitespace(s[p])) p += 1;

    var negative = false;
    if (p < s.len and (s[p] == '+' or s[p] == '-')) {
        negative = s[p] == '-';
        p += 1;
    }

    if (radix == 16 and p + 1 < s.len and s[p] == '0' and (s[p + 1] == 'x' or s[p + 1] == 'X')) {
        p += 2;
    }

    var magnitude: u64 = 0;
    var digits: usize = 0;
    var overflowed = false;
    while (p < s.len) : (p += 1) {
        const c = s[p];
        const digit: u64 = if (c >= '0' and c <= '9')
            c - '0'
        else if (radix == 16 and c >= 'a' and c <= 'f')
            c - 'a' + 10
        else if (radix == 16 and c >= 'A' and c <= 'F')
            c - 'A' + 10
        else
            break;
        if (digit >= radix) break;
        overflowed = saturatingAdd(&magnitude, digit, radix) or overflowed;
        digits += 1;
    }
    if (digits == 0) return null;
    return .{ .negative = negative, .magnitude = magnitude, .overflowed = overflowed };
}

/// `XMLUtil::ToInt`: scanf "%d" or "%x", trailing garbage allowed.
/// The casts model C's assignment of a strtol/strtoul result to `int`:
/// truncate to 32 bits, then reinterpret the bit pattern.
pub fn toInt(s: []const u8, value: *i32) bool {
    if (isPrefixHex(s)) {
        const scanned = scanInt(s, 16) orelse return false;
        var raw = scanned.magnitude;
        if (scanned.negative and !scanned.overflowed) raw = 0 -% raw;
        value.* = @bitCast(@as(u32, @truncate(raw)));
        return true;
    }
    const scanned = scanInt(s, 10) orelse return false;
    var signed: i64 = undefined;
    if (scanned.negative) {
        if (scanned.magnitude > @as(u64, @intCast(std.math.maxInt(i64))) + 1) {
            signed = std.math.minInt(i64);
        } else {
            signed = -%@as(i64, @bitCast(scanned.magnitude));
        }
    } else {
        if (scanned.magnitude > @as(u64, @intCast(std.math.maxInt(i64)))) {
            signed = std.math.maxInt(i64);
        } else {
            signed = @intCast(scanned.magnitude);
        }
    }
    value.* = @bitCast(@as(u32, @truncate(@as(u64, @bitCast(signed)))));
    return true;
}

/// `XMLUtil::ToUnsigned`: scanf "%u" or "%x".
pub fn toUnsigned(s: []const u8, value: *u32) bool {
    const scanned = scanInt(s, if (isPrefixHex(s)) 16 else 10) orelse return false;
    var raw = scanned.magnitude;
    if (scanned.negative and !scanned.overflowed) raw = 0 -% raw;
    value.* = @truncate(raw);
    return true;
}

/// `XMLUtil::ToInt64`: scanf "%lld" or "%llx". The bit casts preserve the
/// two's-complement assignment semantics of the C version.
pub fn toInt64(s: []const u8, value: *i64) bool {
    if (isPrefixHex(s)) {
        const scanned = scanInt(s, 16) orelse return false;
        var raw = scanned.magnitude;
        if (scanned.negative and !scanned.overflowed) raw = 0 -% raw;
        value.* = @bitCast(raw);
        return true;
    }
    const scanned = scanInt(s, 10) orelse return false;
    if (scanned.negative) {
        if (scanned.magnitude > @as(u64, @intCast(std.math.maxInt(i64))) + 1) {
            value.* = std.math.minInt(i64);
        } else {
            value.* = -%@as(i64, @bitCast(scanned.magnitude));
        }
    } else {
        value.* = if (scanned.magnitude > @as(u64, @intCast(std.math.maxInt(i64))))
            std.math.maxInt(i64)
        else
            @intCast(scanned.magnitude);
    }
    return true;
}

/// `XMLUtil::ToUnsigned64`: scanf "%llu" or "%llx".
pub fn toUnsigned64(s: []const u8, value: *u64) bool {
    const scanned = scanInt(s, if (isPrefixHex(s)) 16 else 10) orelse return false;
    value.* = if (scanned.negative and !scanned.overflowed) 0 -% scanned.magnitude else scanned.magnitude;
    return true;
}

/// `XMLUtil::ToBool`.
pub fn toBool(s: []const u8, value: *bool) bool {
    var ival: i32 = 0;
    if (toInt(s, &ival)) {
        value.* = ival != 0;
        return true;
    }
    const true_vals = [_][]const u8{ "true", "True", "TRUE" };
    const false_vals = [_][]const u8{ "false", "False", "FALSE" };
    for (true_vals) |candidate| {
        if (std.mem.eql(u8, s, candidate)) {
            value.* = true;
            return true;
        }
    }
    for (false_vals) |candidate| {
        if (std.mem.eql(u8, s, candidate)) {
            value.* = false;
            return true;
        }
    }
    return false;
}

fn equalsIgnoreCaseAscii(s: []const u8, lit: []const u8) bool {
    if (s.len < lit.len) return false;
    for (lit, 0..) |c, i| {
        if (std.ascii.toLower(s[i]) != c) return false;
    }
    return true;
}

fn scanFloatPrefix(s: []const u8, start: usize) ?usize {
    var p = start;
    while (p < s.len and isWhitespace(s[p])) p += 1;
    if (p < s.len and (s[p] == '+' or s[p] == '-')) p += 1;

    if (equalsIgnoreCaseAscii(s[p..], "inf")) {
        p += 3;
        if (equalsIgnoreCaseAscii(s[p..], "inity")) p += 5;
        return p;
    }
    if (equalsIgnoreCaseAscii(s[p..], "nan")) {
        p += 3;
        if (p < s.len and s[p] == '(') {
            var close = p + 1;
            while (close < s.len and s[close] != ')') close += 1;
            if (close < s.len) p = close + 1;
        }
        return p;
    }

    if (p + 1 < s.len and s[p] == '0' and (s[p + 1] == 'x' or s[p + 1] == 'X')) {
        var q = p + 2;
        var digits: usize = 0;
        while (q < s.len and std.ascii.isHex(s[q])) : (q += 1) digits += 1;
        if (q < s.len and s[q] == '.') {
            q += 1;
            while (q < s.len and std.ascii.isHex(s[q])) : (q += 1) digits += 1;
        }
        if (digits == 0) return null;
        if (q < s.len and (s[q] == 'p' or s[q] == 'P')) {
            var e = q + 1;
            if (e < s.len and (s[e] == '+' or s[e] == '-')) e += 1;
            const exp_start = e;
            while (e < s.len and std.ascii.isDigit(s[e])) e += 1;
            if (e == exp_start) return null; // scanf fails on a bare exponent
            q = e;
        }
        return q;
    }

    var digits: usize = 0;
    while (p < s.len and std.ascii.isDigit(s[p])) : (p += 1) digits += 1;
    if (p < s.len and s[p] == '.') {
        p += 1;
        while (p < s.len and std.ascii.isDigit(s[p])) : (p += 1) digits += 1;
    }
    if (digits == 0) return null;
    if (p < s.len and (s[p] == 'e' or s[p] == 'E')) {
        var e = p + 1;
        if (e < s.len and (s[e] == '+' or s[e] == '-')) e += 1;
        const exp_start = e;
        while (e < s.len and std.ascii.isDigit(s[e])) e += 1;
        if (e == exp_start) return null; // scanf fails on a bare exponent
        p = e;
    }
    return p;
}

fn parseFloatPrefix(comptime T: type, s: []const u8) ?T {
    const end = scanFloatPrefix(s, 0) orelse return null;
    var start: usize = 0;
    while (start < end and isWhitespace(s[start])) start += 1;
    if (start == end) return null;

    var hex_start = start;
    if (hex_start < end and (s[hex_start] == '+' or s[hex_start] == '-')) hex_start += 1;
    if (hex_start + 1 < end and s[hex_start] == '0' and (s[hex_start + 1] == 'x' or s[hex_start + 1] == 'X')) {
        return parseHexFloatExact(T, s[start..end]);
    }
    return std.fmt.parseFloat(T, s[start..end]) catch null;
}

/// Exact `strtod`-style hex float conversion. Zig's `parseFloat` differs by an
/// ulp for mantissas longer than 64 bits, so the value is rounded here with
/// integer arithmetic and a single correctly rounded `ldexp`.
fn parseHexFloatExact(comptime T: type, text: []const u8) ?T {
    var p: usize = 0;
    var negative = false;
    if (p < text.len and (text[p] == '+' or text[p] == '-')) {
        negative = text[p] == '-';
        p += 1;
    }
    if (p + 1 >= text.len or text[p] != '0' or (text[p + 1] != 'x' and text[p + 1] != 'X')) return null;
    p += 2;

    var c: u128 = 0;
    var collected: usize = 0;
    var total: usize = 0;
    var frac_digits: usize = 0;
    var seen_point = false;
    var seen_significant = false;

    while (p < text.len) : (p += 1) {
        const ch = text[p];
        var digit: u8 = 0;
        if (ch >= '0' and ch <= '9') {
            digit = ch - '0';
        } else if (ch >= 'a' and ch <= 'f') {
            digit = ch - 'a' + 10;
        } else if (ch >= 'A' and ch <= 'F') {
            digit = ch - 'A' + 10;
        } else if (ch == '.' and !seen_point) {
            seen_point = true;
            continue;
        } else if (ch == 'p' or ch == 'P') {
            break;
        } else {
            return null;
        }

        if (seen_point) frac_digits += 1;
        if (!seen_significant and digit == 0) continue;
        seen_significant = true;
        total += 1;
        if (collected < 32) {
            c = (c << 4) | digit;
            collected += 1;
        }
    }

    if (total == 0) {
        return if (negative) -@as(T, 0) else 0;
    }

    var exponent: i64 = 0;
    if (p < text.len and (text[p] == 'p' or text[p] == 'P')) {
        p += 1;
        var exp_negative = false;
        if (p < text.len and (text[p] == '+' or text[p] == '-')) {
            exp_negative = text[p] == '-';
            p += 1;
        }
        if (p == text.len) return null;
        var seen_digit = false;
        while (p < text.len and std.ascii.isDigit(text[p])) : (p += 1) {
            seen_digit = true;
            exponent = exponent *| 10 +| @as(i64, text[p] - '0');
        }
        if (!seen_digit) return null;
        if (exp_negative) exponent = -exponent;
    }

    // Both counts are bounded by the input slice length (< 2^63).
    const tail: i64 = @as(i64, @intCast(total - collected));
    const frac: i64 = @intCast(frac_digits);
    var e2: i64 = 4 *| (tail - frac) +| exponent;

    // floatMantissaBits() excludes the implicit leading bit.
    const precision = std.math.floatMantissaBits(T) + 1;
    const bit_length: u32 = 128 - @as(u32, @clz(c));
    var q: u128 = c;
    var shift: u32 = 0;
    if (bit_length > precision) {
        shift = bit_length - precision;
        // shift is at most 128 - 24, so both shift expressions fit u128/u7.
        const half = @as(u128, 1) << @intCast(shift - 1);
        const mask = (half << 1) - 1;
        const remainder = c & mask;
        q = c >> @intCast(shift);
        if (remainder > half or (remainder == half and (q & 1) == 1)) {
            q += 1;
            if (q == (@as(u128, 1) << precision)) {
                q >>= 1;
                e2 = e2 +| 1;
            }
        }
    }
    e2 = e2 +| @as(i64, @intCast(shift)); // shift <= 128

    // Clamp before the i32 conversion; ldexp already maps overflow to inf and
    // severe underflow to zero.
    const be: i32 = if (e2 > 100000)
        100000
    else if (e2 < -100000)
        -100000
    else
        @intCast(e2); // clamped to [-100000, 100000], fits i32

    const value: T = std.math.ldexp(@as(T, @floatFromInt(q)), be);
    return if (negative) -value else value;
}

/// `XMLUtil::ToFloat`: scanf "%f".
pub fn toFloat(s: []const u8, value: *f32) bool {
    value.* = parseFloatPrefix(f32, s) orelse return false;
    return true;
}

/// `XMLUtil::ToDouble`: scanf "%lf".
pub fn toDouble(s: []const u8, value: *f64) bool {
    value.* = parseFloatPrefix(f64, s) orelse return false;
    return true;
}

// ---------- numeric formatting ---------- //

pub var bool_true: []const u8 = "true";
pub var bool_false: []const u8 = "false";

/// `XMLUtil::SetBoolSerialization`; null restores the default word.
pub fn setBoolSerialization(write_true: ?[]const u8, write_false: ?[]const u8) void {
    bool_true = write_true orelse "true";
    bool_false = write_false orelse "false";
}

fn integerSlice(buf: []u8, value: anytype) []const u8 {
    // 200 bytes as in tinyxml2's BUF_SIZE; the longest integer is 21 bytes.
    return std.fmt.bufPrint(buf, "{d}", .{value}) catch unreachable;
}

pub fn formatInt(buf: []u8, v: i32) []const u8 {
    return integerSlice(buf, v);
}

pub fn formatUnsigned(buf: []u8, v: u32) []const u8 {
    return integerSlice(buf, v);
}

pub fn formatInt64(buf: []u8, v: i64) []const u8 {
    return integerSlice(buf, v);
}

pub fn formatUnsigned64(buf: []u8, v: u64) []const u8 {
    return integerSlice(buf, v);
}

pub fn formatBool(buf: []u8, v: bool, unused: usize) []const u8 {
    _ = unused;
    const word = if (v) bool_true else bool_false;
    const n = @min(word.len, buf.len);
    @memcpy(buf[0..n], word[0..n]);
    return buf[0..n];
}

/// C `%.8g` (float promoted to double) and `%.17g` (double), without the
/// printf locale.
///
/// Every integer cast below is bounded by the IEEE-754 field widths (11, 52,
/// 63) or by the 800-digit scratch buffer.
///
/// Zig's float renderer emits the shortest round-trip form; `%.17g` needs the
/// correctly rounded 17-significant-digit form, which can differ in the last
/// digit. The exact value `m * 2^e` is converted with integer arithmetic:
/// `m * 5^k * 10^-k` for negative exponents, so no floating point is involved.
fn formatG(buf: []u8, value: f64, precision_in: usize) []const u8 {
    const precision = if (precision_in == 0) 1 else precision_in;
    const bits: u64 = @bitCast(value);
    const negative = (bits >> 63) != 0;

    if (std.math.isNan(value)) {
        var n: usize = 0;
        if (negative) {
            buf[n] = '-';
            n += 1;
        }
        @memcpy(buf[n..][0..3], "nan");
        return buf[0 .. n + 3];
    }
    if (std.math.isInf(value)) {
        var n: usize = 0;
        if (negative) {
            buf[n] = '-';
            n += 1;
        }
        @memcpy(buf[n..][0..3], "inf");
        return buf[0 .. n + 3];
    }

    const frac_bits = std.math.floatFractionalBits(f64); // 52
    const exp_bits = std.math.floatExponentBits(f64); // 11
    const bias: i32 = (@as(i32, 1) << @intCast(exp_bits - 1)) - 1;
    const exp_raw: u64 = (bits >> frac_bits) & ((@as(u64, 1) << @intCast(exp_bits)) - 1);
    const frac: u64 = bits & ((@as(u64, 1) << @intCast(frac_bits)) - 1);
    const mantissa: u64 = if (exp_raw == 0) frac else frac | (@as(u64, 1) << @intCast(frac_bits));
    const binary_exp: i32 = if (exp_raw == 0)
        (1 - bias - @as(i32, @intCast(frac_bits)))
    else
        @as(i32, @intCast(exp_raw)) - bias - @as(i32, @intCast(frac_bits));

    var digits: [800]u8 = undefined;
    var ndigits: usize = 0;
    var decimal_exp: i32 = 0;

    if (mantissa == 0) {
        digits[0] = 0;
        ndigits = 1;
    } else {
        var big = BigInt{};
        big.setU64(mantissa);
        var scale: i32 = 0;
        if (binary_exp >= 0) {
            big.shl(@intCast(binary_exp));
        } else {
            scale = -binary_exp;
            var i: i32 = 0;
            while (i < scale) : (i += 1) big.mulSmall(5);
        }

        var reversed: [800]u8 = undefined;
        ndigits = big.toDecimal(&reversed);
        if (ndigits > digits.len) unreachable; // f64 carries at most 767 digits
        for (0..ndigits) |i| digits[i] = reversed[ndigits - 1 - i];
        decimal_exp = @as(i32, @intCast(ndigits)) - 1 - scale;

        if (ndigits > precision) {
            const next = digits[precision];
            var round_up = false;
            if (next > 5) {
                round_up = true;
            } else if (next == 5) {
                var tail_nonzero = false;
                for (digits[precision + 1 .. ndigits]) |digit| {
                    if (digit != 0) {
                        tail_nonzero = true;
                        break;
                    }
                }
                // printf uses the current (round-to-nearest-even) mode.
                round_up = tail_nonzero or (digits[precision - 1] % 2 == 1);
            }
            ndigits = precision;
            if (round_up) {
                var carry = true;
                var i = ndigits;
                while (i > 0 and carry) {
                    i -= 1;
                    if (digits[i] == 9) {
                        digits[i] = 0;
                    } else {
                        digits[i] += 1;
                        carry = false;
                    }
                }
                if (carry) {
                    digits[0] = 1;
                    decimal_exp += 1;
                }
            }
        }
    }

    var sig_end = ndigits;
    while (sig_end > 1 and digits[sig_end - 1] == 0) sig_end -= 1;

    var n: usize = 0;
    if (negative) {
        buf[n] = '-';
        n += 1;
    }

    if (decimal_exp < -4 or decimal_exp >= @as(i32, @intCast(precision))) {
        // Scientific: d[.ddd]e±XX
        buf[n] = '0' + digits[0];
        n += 1;
        if (sig_end > 1) {
            buf[n] = '.';
            n += 1;
            for (digits[1..sig_end]) |digit| {
                buf[n] = '0' + digit;
                n += 1;
            }
        }
        buf[n] = 'e';
        n += 1;
        var exp = decimal_exp;
        if (exp < 0) {
            buf[n] = '-';
            exp = -exp;
        } else {
            buf[n] = '+';
        }
        n += 1;
        var exp_buf: [16]u8 = undefined;
        const exp_text = std.fmt.bufPrint(&exp_buf, "{d}", .{exp}) catch unreachable;
        if (exp_text.len < 2) {
            buf[n] = '0';
            n += 1;
        }
        @memcpy(buf[n..][0..exp_text.len], exp_text);
        n += exp_text.len;
        return buf[0..n];
    }

    if (decimal_exp >= 0) {
        const int_digits: usize = @intCast(decimal_exp + 1);
        if (int_digits >= sig_end) {
            for (digits[0..sig_end]) |digit| {
                buf[n] = '0' + digit;
                n += 1;
            }
            var zeros = int_digits - sig_end;
            while (zeros > 0) : (zeros -= 1) {
                buf[n] = '0';
                n += 1;
            }
        } else {
            for (digits[0..int_digits]) |digit| {
                buf[n] = '0' + digit;
                n += 1;
            }
            buf[n] = '.';
            n += 1;
            for (digits[int_digits..sig_end]) |digit| {
                buf[n] = '0' + digit;
                n += 1;
            }
        }
        return buf[0..n];
    }

    // 0.00ddd
    buf[n] = '0';
    buf[n + 1] = '.';
    n += 2;
    var zeros: usize = @intCast(-decimal_exp - 1);
    while (zeros > 0) : (zeros -= 1) {
        buf[n] = '0';
        n += 1;
    }
    for (digits[0..sig_end]) |digit| {
        buf[n] = '0' + digit;
        n += 1;
    }
    return buf[0..n];
}

/// Little-endian base-2^64 integer, large enough for `m * 5^1074` (about
/// 2547 bits). Only the operations needed for exact float-to-decimal are here.
const BigInt = struct {
    // All narrowing/widening casts below stay inside u64 limbs: the u128
    // product split is 64+64 bits, and each division remainder is < divisor.
    limbs: [64]u64 = @splat(0),
    len: usize = 0,

    fn setU64(self: *BigInt, value: u64) void {
        self.limbs[0] = value;
        self.len = if (value == 0) 0 else 1;
    }

    fn mulSmall(self: *BigInt, multiplier: u64) void {
        var carry: u64 = 0;
        var i: usize = 0;
        while (i < self.len) : (i += 1) {
            const product = @as(u128, self.limbs[i]) * multiplier + carry;
            self.limbs[i] = @truncate(product);
            carry = @intCast(product >> 64);
        }
        if (carry != 0) {
            self.limbs[self.len] = carry;
            self.len += 1;
        }
    }

    fn shl(self: *BigInt, amount: usize) void {
        if (self.len == 0 or amount == 0) return;
        const word_shift = amount / 64;
        const bit_shift: u6 = @intCast(amount % 64);

        const new_len = self.len + word_shift + @intFromBool(bit_shift != 0);
        var clear = new_len;
        while (clear > self.len) {
            clear -= 1;
            self.limbs[clear] = 0;
        }

        var i = self.len;
        while (i > 0) {
            i -= 1;
            const shifted = @as(u128, self.limbs[i]) << bit_shift;
            self.limbs[i + word_shift] = @truncate(shifted);
            if (bit_shift != 0) {
                self.limbs[i + word_shift + 1] |= @intCast(shifted >> 64);
            }
        }
        self.len = new_len;
        while (self.len > 0 and self.limbs[self.len - 1] == 0) self.len -= 1;
    }

    fn divSmall(self: *BigInt, divisor: u64) u64 {
        var remainder: u64 = 0;
        var i = self.len;
        while (i > 0) {
            i -= 1;
            const current = (@as(u128, remainder) << 64) | self.limbs[i];
            self.limbs[i] = @intCast(current / divisor);
            remainder = @intCast(current % divisor);
        }
        while (self.len > 0 and self.limbs[self.len - 1] == 0) self.len -= 1;
        return remainder;
    }

    /// Writes decimal digits least significant first. Returns the count; zero
    /// produces zero digits and is handled by the caller.
    fn toDecimal(self: *BigInt, out: *[800]u8) usize {
        var count: usize = 0;
        while (self.len > 0) {
            out[count] = @intCast(self.divSmall(10));
            count += 1;
        }
        return count;
    }
};

/// `XMLUtil::ToStr(float)` -> "%.8g".
pub fn formatFloat(buf: []u8, v: f32) []const u8 {
    return formatG(buf, @floatCast(v), 8);
}

/// `XMLUtil::ToStr(double)` -> "%.17g".
pub fn formatDouble(buf: []u8, v: f64) []const u8 {
    return formatG(buf, v, 17);
}

// ---------- tests ---------- //

test "error names match the reference table" {
    try std.testing.expectEqualStrings("XML_SUCCESS", errorIDToName(.success));
    try std.testing.expectEqualStrings("XML_ELEMENT_DEPTH_EXCEEDED", errorIDToName(.element_depth_exceeded));
    try std.testing.expectEqual(@as(i32, 7), @backingInt(XMLError.error_parsing_attribute));
    try std.testing.expectEqual(@as(usize, 19), error_count);
}

test "character classes" {
    try std.testing.expect(isNameStartChar('_'));
    try std.testing.expect(isNameStartChar(':'));
    try std.testing.expect(isNameStartChar(0xd0));
    try std.testing.expect(!isNameStartChar('1'));
    try std.testing.expect(isNameChar('-'));
    try std.testing.expect(isNameChar('.'));
    try std.testing.expect(isWhitespace('\n'));
    try std.testing.expect(!isWhitespace(0xa0));
}

test "character references and bounds" {
    const one = getCharacterRef("&#x41;", 0) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("A", one.bytes[0..one.len]);
    try std.testing.expectEqual(@as(usize, 6), one.next);

    const max = getCharacterRef("&#x10FFFF;", 0) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, &.{ 0xf4, 0x8f, 0xbf, 0xbf }, max.bytes[0..max.len]);

    try std.testing.expect(getCharacterRef("&#x110000;", 0) == null);
    try std.testing.expect(getCharacterRef("&#5000000000;", 0) == null);
    try std.testing.expect(getCharacterRef("&#ABC;", 0) == null);
    try std.testing.expect(getCharacterRef("&#0", 0) == null);
}

test "StrPair entity and newline normalization" {
    const gpa = std.testing.allocator;
    var pair: StrPair = .{};
    defer pair.deinit(gpa);

    try pair.set(gpa, "a\r\nb\rc\n\rd", text_element);
    try std.testing.expectEqualStrings("a\nb\nc\nd", pair.getStr());

    try pair.set(gpa, "&lt;&amp;&gt;&quot;&apos;", text_element);
    try std.testing.expectEqualStrings("<&>\"'", pair.getStr());

    try pair.set(gpa, "&#65;&#x42;", text_element);
    try std.testing.expectEqualStrings("AB", pair.getStr());
}

test "StrPair unknown entity keeps stale byte like the reference" {
    const gpa = std.testing.allocator;
    var pair: StrPair = .{};
    defer pair.deinit(gpa);
    // C++ decodes &amp; to one byte, then copies "ttk;" over the old buffer
    // without writing the '&', leaving the stale 'a' behind it.
    try pair.set(gpa, "&amp;&ttk;", text_element);
    try std.testing.expectEqualStrings("&attk;", pair.getStr());
}

test "StrPair collapse whitespace" {
    const gpa = std.testing.allocator;
    var pair: StrPair = .{};
    defer pair.deinit(gpa);
    try pair.set(gpa, " This \nis &apos;  text  &apos; ", .{ .entities = true, .newlines = true, .collapse = true });
    try std.testing.expectEqualStrings("This is ' text '", pair.getStr());

    try pair.set(gpa, "    ", .{ .newlines = true, .collapse = true });
    try std.testing.expectEqualStrings("", pair.getStr());
}

test "integer conversions follow scanf" {
    var i: i32 = 0;
    try std.testing.expect(toInt("  -24", &i));
    try std.testing.expectEqual(@as(i32, -24), i);
    try std.testing.expect(toInt("2.0", &i));
    try std.testing.expectEqual(@as(i32, 2), i);
    try std.testing.expect(!toInt("foo", &i));
    try std.testing.expect(toInt("0x2020", &i));
    try std.testing.expectEqual(@as(i32, 0x2020), i);
    // IsPrefixHex sees the '-', so this goes through %d and stops at 'x'.
    try std.testing.expect(toInt("-0x10", &i));
    try std.testing.expectEqual(@as(i32, 0), i);

    var u: u32 = 0;
    try std.testing.expect(toUnsigned("0X2020", &u));
    try std.testing.expectEqual(@as(u32, 0x2020), u);

    var b: bool = false;
    try std.testing.expect(toBool("TRUE", &b));
    try std.testing.expect(b);
    try std.testing.expect(toBool("0", &b));
    try std.testing.expect(!b);
    try std.testing.expect(!toBool("TRUE ", &b));

    var v64: i64 = 0;
    try std.testing.expect(toInt64("-123456789012345678", &v64));
    try std.testing.expectEqual(@as(i64, -123456789012345678), v64);
}

test "float conversions follow scanf" {
    var f: f32 = 0;
    try std.testing.expect(toFloat("1.5x", &f));
    try std.testing.expectEqual(@as(f32, 1.5), f);
    var d: f64 = 0;
    try std.testing.expect(toDouble("0.123456789", &d));
    try std.testing.expectApproxEqAbs(@as(f64, 0.123456789), d, 1e-12);
    try std.testing.expect(!toDouble("abc", &d));

    // scanf skips leading space but fails when an exponent marker is bare.
    try std.testing.expect(toFloat(" 9418194x", &f));
    try std.testing.expectEqual(@as(f32, 9418194), f);
    try std.testing.expect(!toFloat("73e", &f));
    try std.testing.expect(!toFloat("1e+", &f));
    try std.testing.expect(toFloat("1e3x", &f));
    try std.testing.expectEqual(@as(f32, 1000), f);
}

test "hex float parsing is correctly rounded" {
    var f: f32 = 0;
    try std.testing.expect(toFloat("0X3713654", &f));
    try std.testing.expectEqual(@as(u32, 0x4c5c4d95), @as(u32, @bitCast(f)));
    try std.testing.expect(toFloat("0x1.8e2", &f));
    try std.testing.expectEqual(@as(u32, 0x3fc71000), @as(u32, @bitCast(f)));

    var d: f64 = 0;
    // 21 hex mantissa digits: Zig's own parser rounds this one ulp low.
    try std.testing.expect(toDouble("0X589424928447897330638e-3", &d));
    try std.testing.expectEqual(@as(u64, 0x4556250924a111e2), @as(u64, @bitCast(d)));
    try std.testing.expect(toDouble("0x1p3", &d));
    try std.testing.expectEqual(@as(f64, 8), d);
}

test "unsigned overflow saturates without applying the sign" {
    var u: u32 = 0;
    try std.testing.expect(toUnsigned("-88991526152165896575abc", &u));
    try std.testing.expectEqual(std.math.maxInt(u32), u);

    var u64_value: u64 = 0;
    try std.testing.expect(toUnsigned64("-7571920365723977676541x", &u64_value));
    try std.testing.expectEqual(std.math.maxInt(u64), u64_value);
}

test "float formatting matches printf %g" {
    var buf: [200]u8 = undefined;
    try std.testing.expectEqualStrings("1.5", formatDouble(&buf, 1.5));
    try std.testing.expectEqualStrings("100", formatDouble(&buf, 100.0));
    try std.testing.expectEqualStrings("123456789.12345679", formatDouble(&buf, 123456789.123456789));
    try std.testing.expectEqualStrings("1001000000", formatDouble(&buf, 1.001e9));
    try std.testing.expectEqualStrings("1e+20", formatDouble(&buf, 1.0e20));
    try std.testing.expectEqualStrings("1e-10", formatDouble(&buf, 1.0e-10));
    try std.testing.expectEqualStrings("0.123456789", formatDouble(&buf, 0.123456789));
    try std.testing.expectEqualStrings("1.2345679e+08", formatFloat(&buf, 123456789.123456789));
    try std.testing.expectEqualStrings("1.001e+09", formatFloat(&buf, 1.001e9));
    try std.testing.expectEqualStrings("1e+20", formatFloat(&buf, 1.0e20));
    try std.testing.expectEqualStrings("0.12345679", formatFloat(&buf, 0.123456789));
    try std.testing.expectEqualStrings("-0", formatDouble(&buf, -0.0));
    try std.testing.expectEqualStrings("inf", formatDouble(&buf, std.math.inf(f64)));
    try std.testing.expectEqualStrings("nan", formatDouble(&buf, std.math.nan(f64)));

    // Values where the 17th significant digit matters; Zig's shortest form
    // would print 16 digits and lose the correct last digit.
    try std.testing.expectEqualStrings("6.2946752411953861e-44", formatDouble(&buf, @bitCast(@as(u64, 0x36f675cc81e74ef5))));
    try std.testing.expectEqualStrings("4.7083251603875462e+207", formatDouble(&buf, @bitCast(@as(u64, 0x6b0d549b6f03675a))));
}
